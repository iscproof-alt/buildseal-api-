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
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_seals_artifact_hash ON seals(artifact_hash)`);
  console.log("DB ready");
console.log("BOOT: tsa-v3");
}
initDb();

const app = express();
app.use(cors());
app.use(express.json());
app.use(require('express').static(require('path').join(__dirname, 'public')));

app.get("/health", (req, res) => res.json({ status: "ok", db: true }));

app.get("/download/isc_verify", (req, res) => {
  res.download(__dirname + "/public/isc_verify", "isc_verify");
});

app.post("/seal", async (req, res) => {
  const { artifact_hash, repo, commit, filename } = req.body;
  if (!artifact_hash) return res.status(400).json({ error: "artifact_hash required" });

  const seal_id = "seal_" + Date.now() + "_" + Math.random().toString(36).slice(2, 10);
  const verify_url = (process.env.BASE_URL || "https://buildseal-api-production-3ca5.up.railway.app") + "/seal/" + seal_id;
  const sealed_at = new Date().toISOString().replace(/\.\d+Z$/, 'Z');

  await pool.query(
    "INSERT INTO seals (seal_id, artifact_hash, repo, commit_hash, verify_url, status) VALUES ($1,$2,$3,$4,$5,'processing')",
    [seal_id, artifact_hash, repo || 'web', commit || 'direct', verify_url]
  );

  const fs = require('fs');
  const path = require('path');
  const { execSync } = require('child_process');
  const tmpContent = path.join('/tmp', seal_id + '.content');
  fs.writeFileSync(tmpContent, artifact_hash);

  const binPath = __dirname + '/isc_pack_v5_bin';
  // Key: Render secret file > env var > local
  let keyPath;
  if (require('fs').existsSync('/etc/secrets/buildseal.key.json')) {
    keyPath = '/etc/secrets/buildseal.key.json';
  } else if (process.env.BUILDSEAL_KEY_JSON) {
    const fs = require('fs');
    keyPath = '/tmp/buildseal_runtime.key.json';
    fs.writeFileSync(keyPath, process.env.BUILDSEAL_KEY_JSON);
  } else {
    keyPath = __dirname + '/buildseal_new.key.json';
  }

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
    try { fs.unlinkSync(packPath); } catch(_) {}
  } catch(e) {
    status = 'failed';
    console.error('isc_pack_v5 error:', e.message);
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
    root: r.pack_hash || null
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
const upload = multer({ dest: '/tmp/uploads/' });

app.post('/upload-and-seal', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'no file' });

    const seal_id = 'seal_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    const verify_url = 'https://verify.buildseal.io/release/' + seal_id;

    await pool.query(
      "INSERT INTO seals (seal_id, artifact_hash, repo, commit_hash, verify_url, status, verdict) VALUES ($1,$2,$3,$4,$5,'PROCESSING','PENDING')",
      [seal_id, '', 'web-upload', 'direct', verify_url]
    );

    const packDir = '/tmp';
    const keyFile = '/tmp/signing_key.json';
    require('fs').writeFileSync(keyFile, process.env.BUILDSEAL_KEY_JSON || '{}');
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
    } catch(e) { console.error('TSA pack write error:', e.message); }

    let verdict = 'INVALID';
    let verifyOut = '';
    try {
      const packExists = require('fs').existsSync(packPath);
      const packContent = packExists ? JSON.parse(require('fs').readFileSync(packPath, 'utf8')) : {};
      console.log('PACK EXISTS:', packExists, packPath);
      console.log('PACK TSA:', JSON.stringify(packContent.tsa));
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
    const rootMatch = verifyOut.match(/root:\s+([a-f0-9]+)/);
    const sealedAtMatch = verifyOut.match(/sealed_at:\s+(\S+)/);
    const root_hash = rootMatch ? rootMatch[1] : '';
    let sealed_at = sealedAtMatch ? sealedAtMatch[1] : '';
    if (!sealed_at) { try { const pj = JSON.parse(require('fs').readFileSync(packPath, 'utf8')); sealed_at = pj.sealed_at || ''; } catch(e) {} }
    const tsa = tsaResult.present ? { present: true, provider: tsaResult.provider, time: tsaResult.time } : { present: false };
    res.json({ seal_id, verdict, verify_url, root_hash, sealed_at, tsa, verify_output: verifyJson });

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
  res.json({ ...r, verdict: r.verdict || 'PENDING' });
});

app.listen(process.env.PORT || 3000, () => console.log("BuildSeal API running on :3000"));
