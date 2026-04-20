require("dotenv").config();

const https = require('https');
const crypto = require('crypto');

async function requestTSA(rootHex) {
  return new Promise((resolve) => {
    try {
      const { execSync } = require('child_process');
      const fs = require('fs');
      const tmpDir = '/tmp';
      const hashFile = `${tmpDir}/tsa_hash_${Date.now()}.bin`;
      const reqFile = `${tmpDir}/tsa_req_${Date.now()}.tsq`;
      const respFile = `${tmpDir}/tsa_resp_${Date.now()}.tsr`;
      
      // Write root hash as binary
      fs.writeFileSync(hashFile, Buffer.from(rootHex, 'hex'));
      
      // Create TSA request with openssl
      execSync(`openssl ts -query -data ${hashFile} -sha256 -cert -no_nonce -out ${reqFile}`, { timeout: 5000 });
      
      // Send to FreeTSA
      execSync(`curl -s -S -H "Content-Type: application/timestamp-query" --data-binary @${reqFile} https://freetsa.org/tsr -o ${respFile}`, { timeout: 10000 });
      
      // Parse response time with openssl
      const tsInfo = execSync(`openssl ts -reply -in ${respFile} -text 2>&1`, { encoding: 'utf8', timeout: 5000 });
      
      // Extract time
      const timeMatch = tsInfo.match(/Time stamp: (.+)/);
      const tsaTime = timeMatch ? new Date(timeMatch[1]).toISOString() : new Date().toISOString();
      
      // Cleanup
      let tokenB64 = '';
      try { tokenB64 = require('fs').readFileSync(respFile).toString('base64'); } catch(_) {}
      try { fs.unlinkSync(hashFile); fs.unlinkSync(reqFile); fs.unlinkSync(respFile); } catch(_) {}
      
      resolve({
        present: true,
        provider: 'freetsa',
        time: tsaTime,
        token_b64: tokenB64
      });
    } catch(e) {
      resolve({ present: false, provider: 'freetsa', error: e.message.slice(0, 100) });
    }
  });
}


const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS seals (
      seal_id TEXT PRIMARY KEY,
      artifact_hash TEXT,
      repo TEXT,
      commit_hash TEXT,
      status TEXT DEFAULT 'queued',
      created_at TIMESTAMP DEFAULT NOW(),
      verify_url TEXT
    )
  `);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS pack_hash TEXT`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS evidence_pack_url TEXT`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS verdict TEXT DEFAULT 'PENDING'`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS pack_path TEXT`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS verify_output_json TEXT`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS tsa_json TEXT`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS pack_json TEXT`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS mail_body TEXT`);
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS mail_body_sha256 TEXT`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_seals_artifact_hash ON seals(artifact_hash)`);
  log("info", "db.ready");
log("info", "boot", { api_version: "1.0.0", engine: "isc_pack_v5", pack_version: "5.1", key_path: KEY_PATH });
}

// Structured JSON logger
function log(level, event, data = {}) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    level,
    event,
    ...data
  }));
}


// Key lifecycle — initialize once at startup
const KEY_PATH = (() => {
  if (require('fs').existsSync('/etc/secrets/buildseal.key.json')) {
    return '/etc/secrets/buildseal.key.json';
  } else if (process.env.BUILDSEAL_KEY_JSON) {
    const kp = '/tmp/buildseal_runtime.key.json';
    require('fs').writeFileSync(kp, process.env.BUILDSEAL_KEY_JSON, { mode: 0o600 });
    log("info", "key.init", { path: kp });
    return kp;
  } else {
    log("warn", "key.fallback", { path: __dirname + "/buildseal_new.key.json" });
    return __dirname + '/buildseal_new.key.json';
  }
})();

initDb();

const app = express();
app.use(cors());
app.use(express.json());
app.use(require('express').static(require('path').join(__dirname, 'public')));

app.get("/health", (req, res) => res.json({ status: "ok", db: true, api_version: "1.0.0", engine: "isc_pack_v5", pack_version: "5.1" }));

app.get("/version", (req, res) => res.json({
  api_version: "1.0.0",
  engine: "isc_pack_v5",
  pack_version: "5.1",
  key_fingerprint: (() => { try { return require(KEY_PATH).fingerprint || null; } catch(_) { return null; } })(),
  tsa_provider: "freetsa.org",
  tsa_protocol: "RFC 3161"
}));

app.get("/download/isc_verify", (req, res) => {
  res.download(__dirname + "/public/isc_verify", "isc_verify");
});

app.post("/seal", async (req, res) => {
  const { artifact_hash, repo, commit, filename } = req.body;
  if (!artifact_hash) return res.status(400).json({ error: "artifact_hash required" });

  const seal_id = "seal_" + Date.now() + "_" + Math.random().toString(36).slice(2, 10);
  const verify_url = (process.env.BASE_URL || "https://buildseal-api-production-3ca5.up.railway.app") + "/seal/" + seal_id;
  const evidence_pack_url = "https://verify.buildseal.io/pack/" + seal_id;
  const sealed_at = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  await pool.query(
    "INSERT INTO seals (seal_id, artifact_hash, repo, commit_hash, verify_url, evidence_pack_url, status) VALUES ($1,$2,$3,$4,$5,$6,'processing')",
    [seal_id, artifact_hash, repo || 'web', commit || 'direct', verify_url, evidence_pack_url]
  );

  const fs = require('fs');
  const path = require('path');
  const { execSync } = require('child_process');
  const tmpContent = path.join('/tmp', seal_id + '.content');
  fs.writeFileSync(tmpContent, artifact_hash);

  const binPath = __dirname + '/isc_pack_v5_bin';
  const keyPath = KEY_PATH;

  let packData = null;
  let status = 'completed';

  try {
    execSync(
      `cd /tmp && ${binPath} ${tmpContent} seal ${seal_id} --key ${keyPath} --sealed-at "${sealed_at}"`,
      { encoding: 'utf8' }
    );
    const packPath = `/tmp/${seal_id}_v5_pack.json`;
    let tsaResult = { present: false, provider: 'freetsa' };
    try {
      const packJson = JSON.parse(require('fs').readFileSync(packPath, 'utf8'));
      const root = packJson.root || '';
      if (root) tsaResult = await requestTSA(root);
    } catch(e) { tsaResult.error = e.message; }
    packData = JSON.parse(fs.readFileSync(packPath, 'utf8'));
    await pool.query(
      "UPDATE seals SET status='completed', pack_hash=$1 WHERE seal_id=$2",
      [packData.root, seal_id]
    );
    // packPath line 268'den sonra siliniyor
  } catch(e) {
    status = 'failed';
    log("error", "seal.failed", { error: e.message });
    await pool.query("UPDATE seals SET status='failed' WHERE seal_id=$1", [seal_id]);
  }

  try { fs.unlinkSync(tmpContent); } catch(_) {}

  res.json({
    seal_id,
    status,
    verify_url,
    timestamp: sealed_at,
    root: packData?.root || null,
    content_hash: packData?.content_hash || null,
    tsa: null
  });
});


app.get("/seal/:seal_id", async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM seals WHERE seal_id=$1", [req.params.seal_id]);
  if (!rows.length) return res.status(404).json({ error: "not found" });
  const r = rows[0];
  res.json({
    seal_id: r.seal_id,
    artifact_hash: r.artifact_hash,
    repo: r.repo,
    commit: r.commit_hash,
    status: r.status,
    created_at: r.created_at,
    verify_url: r.verify_url,
    root: r.pack_hash || null,
    tsa: r.tsa_json ? JSON.parse(r.tsa_json) : { present: false }
  });
});

app.post("/seal/:seal_id/pack", async (req, res) => {
  const { seal_id } = req.params;
  const { pack_hash, evidence_pack_url } = req.body;
  const { rows } = await pool.query("SELECT * FROM seals WHERE seal_id=$1", [seal_id]);
  if (!rows.length) return res.status(404).json({ error: "not found" });
  await pool.query(
    "UPDATE seals SET status='verified', pack_hash=$1, evidence_pack_url=$2 WHERE seal_id=$3",
    [pack_hash, evidence_pack_url, seal_id]
  );
  res.json({ seal_id, status: "unmodified", integrity: "Artifact has not changed since sealing", provenance: "Not verified — source origin is outside this proof" });
});



const { execSync } = require('child_process');
const multer = require('multer');
const upload = multer({
  dest: '/tmp/uploads/',
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    if (!file.originalname || file.originalname.includes('..')) {
      return cb(new Error('INVALID_FILENAME'));
    }
    cb(null, true);
  }
});

// Multer error handler
function handleMulterError(err, req, res, next) {
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File too large', code: 'FILE_TOO_LARGE', max_bytes: 50 * 1024 * 1024 });
  }
  if (err.message === 'INVALID_FILENAME') {
    return res.status(400).json({ error: 'Invalid filename', code: 'INVALID_FILENAME' });
  }
  next(err);
}

app.post('/upload-and-seal', upload.single('file'), async (req, res) => {
  const _t = Date.now();
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'no file' });
    if (file.size === 0) return res.status(400).json({ error: 'empty file', code: 'EMPTY_FILE' });

    const seal_id = 'seal_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const verify_url = 'https://verify.buildseal.io/release/' + seal_id;
    const evidence_pack_url = 'https://verify.buildseal.io/pack/' + seal_id;

    await pool.query(
      "INSERT INTO seals (seal_id, artifact_hash, repo, commit_hash, verify_url, evidence_pack_url, status, verdict) VALUES ($1,$2,$3,$4,$5,$6,'PROCESSING','PENDING')",
      [seal_id, '', 'web-upload', 'direct', verify_url, evidence_pack_url]
    );

    const packDir = '/tmp';
    const keyFile = KEY_PATH;
    const v5bin = '/app/isc_pack_v5_bin';

    const packOut = execSync(
      `cd ${packDir} && ${v5bin} ${file.path} iscproof/document ${seal_id} --key ${keyFile}`,
      { encoding: 'utf8' }
    );

    const packPath = `${packDir}/${seal_id}_v5_pack.json`;
    let tsaResult = { present: false, provider: 'freetsa' };
    try {
      const packJsonTsa = JSON.parse(require('fs').readFileSync(`${packDir}/${seal_id}_v5_pack.json`, 'utf8'));
      const rootHash = packJsonTsa.root || '';
      if (rootHash) tsaResult = await requestTSA(rootHash);
    } catch(e) { tsaResult.error = e.message; }
    // TSA token'ı pack.json'a yaz
    try {
      const packData = JSON.parse(require('fs').readFileSync(`${packDir}/${seal_id}_v5_pack.json`, 'utf8'));
      packData.tsa = {
        present: tsaResult.present,
        provider: tsaResult.provider || 'freetsa',
        time: tsaResult.time || null,
        algorithm: 'sha256',
        token_b64: tsaResult.token_b64 || ''
      };
      require('fs').writeFileSync(`${packDir}/${seal_id}_v5_pack.json`, JSON.stringify(packData, null, 2));
    } catch(e) { log("error", "tsa.pack_write_failed", { error: e.message }); }

    let verdict = 'INVALID';
    let verifyOut = '';
    try {
      const packExists = require('fs').existsSync(packPath);
      const packContent = packExists ? JSON.parse(require('fs').readFileSync(packPath, 'utf8')) : {};
      log("debug", "pack.exists", { exists: packExists, path: packPath });
      log("debug", "pack.tsa", { tsa: packContent.tsa });
      verifyOut = execSync(`/app/isc_pack_v5_bin --verify ${packPath}`, { encoding: 'utf8' });
      const packVerified = verifyOut.includes('PACK VERIFIED') || verifyOut.trimStart().startsWith('VALID');
      const tsaVerified = verifyOut.includes('tsa:         VERIFIED');
      if (packVerified && tsaVerified) verdict = 'VALID';
      else if (packVerified && !tsaVerified) verdict = 'UNVERIFIED';
      else verdict = 'INVALID';
    } catch(verifyErr) {
      verifyOut = verifyErr.stderr || verifyErr.message || 'VERIFICATION FAILED';
      verdict = 'INVALID';
    }

    let artifactHash = '';
    try {
      const packJson = JSON.parse(require('fs').readFileSync(packPath, 'utf8'));
      artifactHash = packJson.content_hash && packJson.content_hash.digest ? packJson.content_hash.digest : '';
    } catch(e) {}
    const verifyJson = { verdict, output: verifyOut };
    await pool.query(
      "UPDATE seals SET status='DONE', verdict=$1, pack_path=$2, verify_output_json=$3, verified_at=NOW(), artifact_hash=$4, tsa_json=$5, pack_json=$6 WHERE seal_id=$7",
      [verdict, packPath, verifyOut, artifactHash, JSON.stringify(tsaResult), require("fs").existsSync(packPath) ? require("fs").readFileSync(packPath, "utf8") : null, seal_id]
    );

    const pdfCmd = `cd /home/hakan/ali && source venv/bin/activate && python3 /app/tools/generate_proof_pdf.py ${packPath}`;
    try { execSync(`bash -c "${pdfCmd}"`, { encoding: 'utf8' }); } catch(e) {}
    try { fs.unlinkSync(packPath); } catch(_) {}
    const rootMatch = verifyOut.match(/root:\s+([a-f0-9]+)/);
    const sealedAtMatch = verifyOut.match(/sealed_at:\s+(\S+)/);
    const root_hash = rootMatch ? rootMatch[1] : '';
    let sealed_at = sealedAtMatch ? sealedAtMatch[1] : '';
    if (!sealed_at) { try { const pj = JSON.parse(require('fs').readFileSync(packPath, 'utf8')); sealed_at = pj.sealed_at || ''; } catch(e) {} }
    const tsa = tsaResult.present ? { present: true, provider: tsaResult.provider, time: tsaResult.time } : { present: false };
    log("info", "seal.complete", { seal_id, verdict, tsa_present: tsa.present, duration_ms: Date.now() - _t });
    res.json({ seal_id, verdict, verify_url, evidence_pack_url, root_hash, sealed_at, tsa, verify_output: verifyJson });

  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});



app.post('/verify-by-hash', async (req, res) => {
  const { artifact_hash } = req.body;
  if (!artifact_hash) return res.status(400).json({ found: false, error: "artifact_hash required" });
  const { rows } = await pool.query(
    "SELECT * FROM seals WHERE artifact_hash=$1 ORDER BY created_at DESC LIMIT 1",
    [artifact_hash]
  );
  if (!rows.length) return res.json({ found: false });
  const r = rows[0];
  const tsa = r.tsa_json ? JSON.parse(r.tsa_json) : { present: false };
  res.json({
    found: true,
    seal_id: r.seal_id,
    status: r.status,
    verify_url: r.verify_url,
    timestamp: r.verified_at || r.created_at,
    root: r.pack_hash || (r.pack_json ? JSON.parse(r.pack_json).root : null),
    artifact_hash: r.artifact_hash,
    tsa
  });
});

app.get('/pack/:seal_id', async (req, res) => {
  const { seal_id } = req.params;
  const { rows } = await pool.query("SELECT * FROM seals WHERE seal_id=$1", [seal_id]);
  if (!rows.length) return res.status(404).json({ error: "seal not found" });
  const r = rows[0];
  // Önce DB'den oku
  if (r.pack_json) {
    res.setHeader('Content-Disposition', `attachment; filename="${seal_id}_v5_pack.json"`);
    res.setHeader('Content-Type', 'application/json');
    return res.send(r.pack_json);
  }
  // DB'de yoksa /tmp'den oku
  const packPath = r.pack_path || `/tmp/${seal_id}_v5_pack.json`;
  const fs = require('fs');
  if (!fs.existsSync(packPath)) {
    return res.status(404).json({ error: "pack file not found — pack may have expired", seal_id });
  }
  const pack = JSON.parse(fs.readFileSync(packPath, 'utf8'));
  res.setHeader('Content-Disposition', `attachment; filename="${seal_id}_v5_pack.json"`);
  res.setHeader('Content-Type', 'application/json');
  res.json(pack);
});
app.get('/verify/:id', async (req, res) => {
  const { rows } = await pool.query("SELECT * FROM seals WHERE seal_id=$1", [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'not found' });
  const r = rows[0];
  const { pack_json, tsa_json, verify_output_json, ...rest } = r;
  let decision_summary = null;
  try {
    if (r.mail_body) {
      const ev = JSON.parse(r.mail_body);
      if (ev.decision_payload) decision_summary = ev.decision_payload;
    }
  } catch(e) {}
  res.json({ ...rest, verdict: r.verdict || 'PENDING', tsa: tsa_json ? JSON.parse(tsa_json) : { present: false }, verify_detail: parseVerifyOutput(verify_output_json), decision_summary, evidence_url: 'https://verify.buildseal.io/evidence/' + r.seal_id });
});

function parseVerifyOutput(raw) {
  if (!raw) return null;
  const lines = raw.split('\n').filter(Boolean);
  const result = { raw, verified: false, fields: {} };
  for (const line of lines) {
    if (line.includes('PACK VERIFIED')) result.verified = true;
    if (line.includes('VERIFICATION FAILED')) { result.verified = false; result.failed = true; }
    const m = line.match(/^(\w+):\s+(.+)/);
    if (m) result.fields[m[1].trim()] = m[2].trim();
    const code = line.match(/^Code:\s+(.+)/);
    if (code) result.error_code = code[1].trim();
    const reason = line.match(/^Reason:\s+(.+)/);
    if (reason) result.error_reason = reason[1].trim();
  }
  // Derived booleans — safe for UI consumption
  result.root_match = result.verified === true && result.error_code !== 'ROOT_MISMATCH';
  result.sig_valid = result.verified === true && result.error_code !== 'SIGNATURE_INVALID';
  result.tsa_verified = typeof result.fields.tsa === 'string' && result.fields.tsa.includes('VERIFIED');
  result.pack_version = '5.1';
  result.root = result.fields.root || null;
  return result;
}

app.post('/verify-pack', upload.single('pack'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'no file' });
    const v5bin = '/app/isc_pack_v5_bin';
    let verifyOut = '';
    let verdict = 'INVALID';
    try {
      verifyOut = require('child_process').execSync(`${v5bin} --verify ${req.file.path}`, { encoding: 'utf8' });
      verdict = verifyOut.includes('PACK VERIFIED') ? 'VALID' : 'INVALID';
    } catch(e) { verifyOut = e.stderr || e.message; }
    const parsed = parseVerifyOutput(verifyOut);
    res.json({ verdict, verify_detail: parsed });
  } catch(e) { res.status(500).json({ error: e.message }); }
});



app.post('/evidence/:seal_id', async (req, res) => {
  try {
    const { mail_body, mail_body_sha256, final_body, final_body_sha256, decision_payload } = req.body;
    if (!mail_body) return res.status(400).json({ error: 'mail_body required' });
    const computed = require('crypto').createHash('sha256').update(mail_body).digest('hex');
    if (mail_body_sha256 && computed !== mail_body_sha256) {
      return res.status(400).json({ error: 'INTEGRITY_MISMATCH', computed, provided: mail_body_sha256 });
    }
    const finalComputed = final_body ? require('crypto').createHash('sha256').update(final_body).digest('hex') : null;
    if (final_body_sha256 && finalComputed !== final_body_sha256) {
      return res.status(400).json({ error: 'FINAL_INTEGRITY_MISMATCH', computed: finalComputed, provided: final_body_sha256 });
    }
    await pool.query(
      "UPDATE seals SET mail_body=$1, mail_body_sha256=$2 WHERE seal_id=$3",
      [JSON.stringify({ draft: mail_body, draft_sha256: computed, final: final_body || null, final_sha256: finalComputed, decision_payload: decision_payload || null }), computed, req.params.seal_id]
    );
    log("info", "evidence.stored", { seal_id: req.params.seal_id, draft_sha256: computed, final_sha256: finalComputed });
    res.json({ seal_id: req.params.seal_id, mail_body_sha256: computed, final_body_sha256: finalComputed, stored: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/evidence/:seal_id', async (req, res) => {
  const { rows } = await pool.query("SELECT seal_id, mail_body, mail_body_sha256, created_at FROM seals WHERE seal_id=$1", [req.params.seal_id]);
  if (!rows.length) return res.status(404).json({ error: 'not found' });
  const r = rows[0];
  if (!r.mail_body) return res.status(404).json({ error: 'no evidence stored for this seal' });
  let evidence;
  try { evidence = JSON.parse(r.mail_body); } catch(e) { evidence = { draft: r.mail_body }; }
  const draftComputed = require('crypto').createHash('sha256').update(evidence.draft || '').digest('hex');
  const finalComputed = evidence.final ? require('crypto').createHash('sha256').update(evidence.final).digest('hex') : null;
  res.json({
    seal_id: r.seal_id,
    draft_body: evidence.draft,
    draft_sha256: evidence.draft_sha256,
    draft_integrity: draftComputed === evidence.draft_sha256 ? 'OK' : 'MISMATCH',
    final_body: evidence.final || null,
    final_sha256: evidence.final_sha256 || null,
    final_integrity: evidence.final && finalComputed ? (finalComputed === evidence.final_sha256 ? 'OK' : 'MISMATCH') : 'N/A',
    decision_payload: evidence.decision_payload || null,
    created_at: r.created_at,
    pack_url: 'https://verify.buildseal.io/pack/' + r.seal_id,
    verify_url: 'https://verify.buildseal.io/release/' + r.seal_id
  });
});



// POST /seal-answer — Answer Proof v1.1
app.post('/seal-answer', async (req, res) => {
  const crypto = require('crypto');
  const fs = require('fs');
  const path = require('path');
  const { execFileSync } = require('child_process');

  function canonicalize(value) {
    if (value === null) return 'null';
    const t = typeof value;
    if (t === 'number') {
      if (!Number.isFinite(value)) throw new Error('Non-finite number');
      return JSON.stringify(value);
    }
    if (t === 'boolean') return value ? 'true' : 'false';
    if (t === 'string') return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
    if (t === 'object') {
      const keys = Object.keys(value).sort();
      return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
    }
    throw new Error('Unsupported type: ' + t);
  }

  function stableStringify(value) {
    return JSON.stringify(value, (_key, val) => {
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        return Object.keys(val).sort().reduce((acc, k) => { acc[k] = val[k]; return acc; }, {});
      }
      return val;
    });
  }

  try {
    const { payload } = req.body;
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return res.status(400).json({ error: 'payload object required' });
    }

    const answer_id = payload.answer_id || crypto.randomUUID();
    const seal_id = 'ans_' + Date.now() + '_' + Math.random().toString(36).slice(2, 10);
    const sealed_at = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
    const verify_url = 'https://verify.buildseal.io/a/' + seal_id;

    const proofPayload = { ...payload, answer_id, sealed_at };
    const canonical = canonicalize(proofPayload);
    const artifact_hash = 'sha256:' + crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');

    const tmpContent = path.join('/tmp', seal_id + '.content');
    const packPath = path.join('/tmp', seal_id + '_v5_pack.json');
    fs.writeFileSync(tmpContent, artifact_hash, 'utf8');

    const binPath = path.join(__dirname, 'isc_pack_v5_bin');
    let root_hash = null;
    let pack_json = null;
    let seal_status = 'sealed';
    let seal_error = null;

    try {
      const { execSync: execSyncLocal } = require('child_process');
      execSyncLocal(
        `cd /tmp && ${binPath} ${tmpContent} seal ${seal_id} --key ${KEY_PATH} --sealed-at "${sealed_at}"`,
        { encoding: 'utf8' }
      );
      if (fs.existsSync(packPath)) {
        const packData = JSON.parse(fs.readFileSync(packPath, 'utf8'));
        root_hash = packData.root || null;
        pack_json = JSON.stringify(packData);
        fs.unlinkSync(packPath);
      }
    } catch (e) {
      seal_status = 'degraded';
      seal_error = e.message || 'binary sealing failed';
    } finally {
      if (fs.existsSync(tmpContent)) fs.unlinkSync(tmpContent);
      if (fs.existsSync(packPath)) fs.unlinkSync(packPath);
    }

    await pool.query(
      `INSERT INTO seals (seal_id, artifact_hash, repo, commit_hash, verify_url, evidence_pack_url, status, pack_json, payload_json)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [seal_id, artifact_hash, 'answer-proof', answer_id, verify_url, verify_url, seal_status, pack_json, stableStringify(proofPayload)]
    );

    return res.json({ status: seal_status, seal_id, answer_id, verify_url, sealed_at, root_hash, artifact_hash, warning: seal_error });
  } catch (err) {
    return res.status(500).json({ error: 'seal-answer failed', detail: err.message });
  }
});


// GET /proof/:seal_id — Answer Proof verify endpoint
app.get('/proof/:seal_id', async (req, res) => {
  const { seal_id } = req.params;
  const { rows } = await pool.query("SELECT * FROM seals WHERE seal_id=$1", [seal_id]);
  if (!rows.length) return res.status(404).json({ error: 'not found' });

  const r = rows[0];
  let payload = null;
  let pack = null;

  try { payload = r.payload_json ? JSON.parse(r.payload_json) : null; } catch(e) {}
  try { pack = r.pack_json ? JSON.parse(r.pack_json) : null; } catch(e) {}

  res.json({
    seal_id: r.seal_id,
    status: r.status,
    sealed_at: r.created_at,
    artifact_hash: r.artifact_hash,
    root_hash: r.pack_hash || (pack && pack.root) || null,
    verify_url: r.verify_url,
    payload,
    pack
  });
});


// GET /seal/:id/evidence-package — Download .iscproof evidence package
app.get('/seal/:id/evidence-package', async (req, res) => {
  const seal_id = req.params.id;
  try {
    const r = await pool.query("SELECT * FROM seals WHERE seal_id=$1", [seal_id]);
    if (!r.rows.length) return res.status(404).json({ error: 'not_found' });
    const row = r.rows[0];

    const archiver = require('archiver');
    const pack_json = row.pack_json ? (typeof row.pack_json === 'string' ? (() => { try { return JSON.parse(row.pack_json); } catch(e) { return {}; } })() : row.pack_json) : {};
    const tsa_json  = row.tsa_json  ? (typeof row.tsa_json === 'string' ? (() => { try { return JSON.parse(row.tsa_json); } catch(e) { return {}; } })() : row.tsa_json) : {};
    const sealed_at = row.sealed_at || row.created_at || new Date().toISOString();

    // decision.json — from pack_json fields
    const decision_json = {
      seal_id,
      decision:    pack_json.decision    || null,
      reason_code: pack_json.reason_code || null,
      subject_ref: pack_json.subject_ref || null,
      subject_type: pack_json.subject_type || null,
      risk_score:  pack_json.risk_score  || null,
      model:       pack_json.model       || null,
      actor:       pack_json.actor       || null,
      sealed_at,
    };

    // canonical.json
    const canonical_json = row.artifact_hash || '';

    // verify.json
    const verify_output = row.verify_output_json ? (typeof row.verify_output_json === 'string' ? (() => { try { return JSON.parse(row.verify_output_json); } catch(e) { return {}; } })() : row.verify_output_json) : {};
    const verify_json = {
      seal_id,
      status: row.verdict || 'PENDING',
      signature_verified: verify_output.sig_valid || false,
      root_hash_match:    verify_output.root_match || false,
      tsa_verified:       verify_output.tsa_verified || false,
      offline_verifiable: true,
      verify_url: `https://buildseal.io/release/${seal_id}`,
      verified_at: row.verified_at || sealed_at,
    };

    // manifest.json
    const manifest = {
      package_version: '1.0',
      package_type: 'buildseal_decision_evidence',
      seal_id,
      sealed_at,
      primary_decision_file: 'decision.json',
      canonical_file: 'canonical.json',
      evidence_pack_file: 'evidence-pack.json',
      verify_file: 'verify.json',
      checksums_file: 'checksums.txt',
      human_summary: 'human/summary.txt',
      verify_url: `https://buildseal.io/release/${seal_id}`,
    };

    // checksums
    const crypto = require('crypto');
    const files = {
      'manifest.json':      JSON.stringify(manifest, null, 2),
      'decision.json':      JSON.stringify(decision_json, null, 2),
      'canonical.json':     canonical_json,
      'evidence-pack.json': JSON.stringify(pack_json, null, 2),
      'verify.json':        JSON.stringify(verify_json, null, 2),
    };
    const checksums = Object.entries(files)
      .map(([fname, content]) => {
        const hash = crypto.createHash('sha256').update(content).digest('hex');
        return `${hash}  ${fname}`;
      }).join('\n');
    files['checksums.txt'] = checksums;

    // human/summary.txt
    const summary = [
      'BuildSeal Decision Evidence Record',
      '===================================',
      `Seal ID:    ${seal_id}`,
      `Decision:   ${decision_json.decision || 'N/A'}`,
      `Reason:     ${decision_json.reason_code || 'N/A'}`,
      `Subject:    ${decision_json.subject_ref || 'N/A'}`,
      `Sealed At:  ${sealed_at}`,
      '',
      'Cryptographic Verification',
      '--------------------------',
      `Signature:  ${verify_json.signature_verified ? 'VERIFIED' : 'NOT VERIFIED'}`,
      `Root Hash:  ${verify_json.root_hash_match ? 'MATCHED' : 'MISMATCH'}`,
      `Timestamp:  ${verify_json.tsa_verified ? 'RFC 3161 VERIFIED' : 'NOT VERIFIED'}`,
      '',
      `Verify URL: https://buildseal.io/release/${seal_id}`,
      '',
      'This record is cryptographically sealed and tamper-evident.',
      'BuildSeal · ISCProof v5.1',
    ].join('\n');

    const filename = `buildseal_decision_${seal_id}.iscproof`;
    res.setHeader('Content-Type', 'application/vnd.buildseal.iscproof+zip');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);

    for (const [fname, content] of Object.entries(files)) {
      archive.append(content, { name: fname });
    }
    archive.append(summary, { name: 'human/summary.txt' });
    await archive.finalize();

  } catch (err) {
    log('error', 'evidence_package.error', { seal_id, error: err.message });
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

app.use(handleMulterError);


async function ensureProofSchema() {
  await pool.query(`ALTER TABLE seals ADD COLUMN IF NOT EXISTS payload_json TEXT`);
}

ensureProofSchema()
  .then(() => {
    console.log('[OK] proof schema ready');
    app.listen(process.env.PORT || 3000, () => log("info", "server.start", { port: process.env.PORT || 3000 }));
  })
  .catch(err => {
    console.error('[ERROR] proof schema migration failed:', err.message);
    process.exit(1);
  });
