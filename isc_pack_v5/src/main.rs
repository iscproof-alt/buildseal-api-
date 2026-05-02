use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use base64::Engine;
use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use serde_json::json;

fn b64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(s)
}
fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new(); h.update(data); hex::encode(h.finalize())
}
fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new(); h.update(data); h.finalize().to_vec()
}
fn der_length(len: usize) -> Vec<u8> {
    if len < 128 { vec![len as u8] }
    else if len < 256 { vec![0x81, len as u8] }
    else { vec![0x82, (len >> 8) as u8, (len & 0xff) as u8] }
}
fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag]; out.extend_from_slice(&der_length(content.len())); out.extend_from_slice(content); out
}
fn der_integer(val: u64) -> Vec<u8> {
    let mut bytes = Vec::new(); let mut v = val;
    loop { bytes.push((v & 0xff) as u8); v >>= 8; if v == 0 { break; } }
    bytes.reverse();
    if bytes[0] & 0x80 != 0 { bytes.insert(0, 0x00); }
    der_wrap(0x02, &bytes)
}
fn build_tsr_request(hash: &[u8; 32], nonce: u64) -> Vec<u8> {
    let sha256_oid: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    let alg_oid = der_wrap(0x06, sha256_oid);
    let null_val: &[u8] = &[0x05, 0x00];
    let mut alg_id_c = alg_oid; alg_id_c.extend_from_slice(null_val);
    let alg_id = der_wrap(0x30, &alg_id_c);
    let hashed_msg = der_wrap(0x04, hash);
    let mut mi_c = alg_id; mi_c.extend_from_slice(&hashed_msg);
    let mi = der_wrap(0x30, &mi_c);
    let cert_req: &[u8] = &[0x01, 0x01, 0xff];
    let mut req = der_integer(1);
    req.extend_from_slice(&mi);
    req.extend_from_slice(&der_integer(nonce));
    req.extend_from_slice(cert_req);
    der_wrap(0x30, &req)
}
fn parse_der_tag_len(data: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    if pos >= data.len() { return None; }
    let tag = data[pos];
    let b1 = *data.get(pos + 1)? as usize;
    if b1 < 128 { Some((tag, b1, 2)) }
    else if b1 == 0x81 { Some((tag, *data.get(pos+2)? as usize, 3)) }
    else if b1 == 0x82 { Some((tag, (*data.get(pos+2)? as usize) << 8 | *data.get(pos+3)? as usize, 4)) }
    else { None }
}
fn parse_time_at(data: &[u8], i: usize, tag: u8, len: usize, hdr: usize) -> Option<String> {
    if i + hdr + len > data.len() { return None; }
    let s = std::str::from_utf8(&data[i+hdr..i+hdr+len]).ok()?;
    if !s.ends_with('Z') { return None; }
    if tag == 0x18 && s.len() >= 14 && s[..8].chars().all(|c| c.is_ascii_digit()) {
        return Some(format!("{}-{}-{}T{}:{}:{}Z", &s[0..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12], &s[12..14]));
    }
    if tag == 0x17 && s.len() >= 12 && s[..6].chars().all(|c| c.is_ascii_digit()) {
        let yy: u32 = s[0..2].parse().ok()?;
        let yyyy = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        return Some(format!("{:04}-{}-{}T{}:{}:{}Z", yyyy, &s[2..4], &s[4..6], &s[6..8], &s[8..10], &s[10..12]));
    }
    None
}

fn find_generalized_time(data: &[u8]) -> Option<String> {
    // Scan every byte position — finds times inside nested SEQUENCEs too.
    // We collect all candidates and return the LAST one, which in a TSA token
    // is the TSTInfo.genTime (the actual timestamp, not cert validity dates).
    let mut last: Option<String> = None;
    let mut i = 0;
    while i + 2 < data.len() {
        let tag = data[i];
        if tag == 0x17 || tag == 0x18 {
            if let Some((_, len, hdr)) = parse_der_tag_len(data, i) {
                if len >= 12 && len <= 20 {
                    if let Some(t) = parse_time_at(data, i, tag, len, hdr) {
                        last = Some(t);
                    }
                }
            }
        }
        i += 1;
    }
    last
}
fn find_message_imprint_hash(data: &[u8]) -> Option<Vec<u8>> {
    // Look for SHA-256 AlgorithmIdentifier followed by OCTET STRING(32)
    // OID: 2.16.840.1.101.3.4.2.1
    let sha256_oid: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

    let mut i = 0usize;
    while i + sha256_oid.len() + 4 + 32 <= data.len() {
        if &data[i..i + sha256_oid.len()] == sha256_oid {
            let mut j = i + sha256_oid.len();

            // optional NULL
            if j + 2 <= data.len() && data[j] == 0x05 && data[j+1] == 0x00 {
                j += 2;
            }

            // OCTET STRING len 32
            if j + 2 + 32 <= data.len() && data[j] == 0x04 && data[j+1] == 0x20 {
                return Some(data[j+2..j+2+32].to_vec());
            }
        }
        i += 1;
    }

    None
}
fn extract_tst_token(resp: &[u8]) -> Option<Vec<u8>> {
    // TimeStampResp = SEQUENCE { PKIStatusInfo, TimeStampToken }
    // Outer SEQUENCE
    let (tag, _outer_len, outer_hdr) = parse_der_tag_len(resp, 0)?;
    if tag != 0x30 { return None; }

    // PKIStatusInfo = SEQUENCE { status INTEGER, ... }
    let (t1, l1, h1) = parse_der_tag_len(resp, outer_hdr)?;
    if t1 != 0x30 { return None; }

    // Check status (first child of PKIStatusInfo is INTEGER)
    let status_pos = outer_hdr + h1;
    if resp.get(status_pos) == Some(&0x02) {
        if let Some((_, sl, sh)) = parse_der_tag_len(resp, status_pos) {
            if let Some(sv) = resp.get(status_pos+sh..status_pos+sh+sl) {
                // status > 1 means rejection
                let status_val = sv.iter().fold(0u32, |a, &b| (a << 8) | b as u32);
                if status_val > 1 { return None; }
            }
        }
    }

    // TimeStampToken starts right after PKIStatusInfo
    let tst_start = outer_hdr + h1 + l1;
    if tst_start >= resp.len() { return None; }

    let (t2, l2, h2) = parse_der_tag_len(resp, tst_start)?;
    if t2 != 0x30 { return None; }

    Some(resp[tst_start..tst_start+h2+l2].to_vec())
}
struct TsaResponse { raw_token: Vec<u8>, gen_time: String, message_imprint: Vec<u8> }
fn parse_tsa_response(resp_bytes: &[u8]) -> Result<TsaResponse, String> {
    let token = extract_tst_token(resp_bytes).ok_or("cannot extract token")?;

    let gen_time = find_generalized_time(&token).ok_or("cannot find GeneralizedTime")?;
    let message_imprint = find_message_imprint_hash(&token).ok_or("cannot find imprint")?;
    Ok(TsaResponse { raw_token: token, gen_time, message_imprint })
}
const FREETSA_URL: &str = "https://freetsa.org/tsr";
fn request_tsa_token(root_hex: &str) -> Result<TsaResponse, String> {
    let root_bytes = hex::decode(root_hex).map_err(|e| format!("hex: {}", e))?;
    let hash: [u8; 32] = root_bytes.try_into().map_err(|_| "root must be 32 bytes".to_string())?;
    let ns = sha256_bytes(&SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes());
    let mut nb = [0u8; 8]; nb.copy_from_slice(&ns[..8]);
    let req_der = build_tsr_request(&hash, u64::from_le_bytes(nb));
    eprintln!("[tsa] sending request ({} bytes)", req_der.len());
    let resp = ureq::post(FREETSA_URL)
        .header("Content-Type", "application/timestamp-query")
        .send(req_der.as_slice())
        .map_err(|e| format!("HTTP: {}", e))?;
    if resp.status() != 200 { return Err(format!("HTTP {}", resp.status())); }
    let mut resp_bytes = Vec::new();
    use std::io::Read;
    resp.into_body().as_reader().read_to_end(&mut resp_bytes).map_err(|e| format!("read: {}", e))?;
    eprintln!("[tsa] response: {} bytes", resp_bytes.len());
    let r = parse_tsa_response(&resp_bytes)?;
    if r.message_imprint != hash { return Err(format!("imprint mismatch")); }
    eprintln!("[tsa] timestamp: {} OK", r.gen_time);
    Ok(r)
}
fn verify_tsa_token(tsa: &serde_json::Value, root_hex: &str) -> String {
    if !tsa["present"].as_bool().unwrap_or(false) { return "none".to_string(); }
    let token_b64 = match tsa["token_b64"].as_str() { Some(s) if !s.is_empty() => s, _ => return "present (no token)".to_string() };
    let token_bytes = match b64_decode(token_b64) { Ok(b) => b, Err(_) => return "token decode error".to_string() };
    let gen_time = match find_generalized_time(&token_bytes) { Some(t) => t, None => return "cannot parse time".to_string() };
    let imprint = match find_message_imprint_hash(&token_bytes) { Some(h) => h, None => return format!("no imprint | time: {}", gen_time) };
    let root_bytes = match hex::decode(root_hex) { Ok(b) => b, Err(_) => return "root hex error".to_string() };
    if imprint != root_bytes { return format!("IMPRINT MISMATCH | got: {}", hex::encode(&imprint[..8])); }
    let stored = tsa["time"].as_str().unwrap_or("");
    if !stored.is_empty() && stored != gen_time { return format!("TIME MISMATCH | stored:{} token:{}", stored, gen_time); }
    format!("VERIFIED | provider: {} | time: {}", tsa["provider"].as_str().unwrap_or("freetsa.org"), gen_time)
}
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 3 && args[1] == "--keygen" {
        let sk = SigningKey::generate(&mut OsRng);
        let pb = sk.verifying_key().to_bytes();
        let fp = &sha256_hex(&pb)[..16];
        let kd = json!({"private": hex::encode(sk.to_bytes()), "public": hex::encode(pb), "fingerprint": fp});
        fs::write(&args[2], serde_json::to_string_pretty(&kd).unwrap()).unwrap();
        println!("Key generated: {}\nFingerprint: {}", args[2], fp);
        return;
    }
    if args.len() >= 3 && args[1] == "--verify" {
        let ps = fs::read_to_string(&args[2]).unwrap_or_else(|e| { eprintln!("ERROR: {}", e); std::process::exit(1); });
        let pack: serde_json::Value = serde_json::from_str(&ps).unwrap_or_else(|e| { eprintln!("VERIFICATION FAILED\nCode: PACK_CORRUPT\nReason: {}", e); std::process::exit(1); });
        if pack["version"].as_u64().unwrap_or(0) < 5 { eprintln!("VERIFICATION FAILED\nCode: UNSUPPORTED_VERSION"); std::process::exit(1); }
        let mut rc = pack.clone();
        rc["root"] = json!(""); rc["signatures"][0]["signature"] = json!(""); rc.as_object_mut().map(|m| m.remove("tsa"));
        let root_check = sha256_hex(serde_json::to_string(&rc).unwrap().as_bytes());
        let stored_root = pack["root"].as_str().unwrap_or("");
        if root_check != stored_root { eprintln!("VERIFICATION FAILED\nCode: ROOT_MISMATCH\nstored:     {}\nrecomputed: {}", stored_root, root_check); std::process::exit(1); }
        let so = &pack["signatures"][0];
        let pb: [u8; 32] = hex::decode(so["public_key"].as_str().unwrap_or("")).unwrap().try_into().unwrap();
        let sb: [u8; 64] = hex::decode(so["signature"].as_str().unwrap_or("")).unwrap().try_into().unwrap();
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        let vk = VerifyingKey::from_bytes(&pb).unwrap();
        match vk.verify(&hex::decode(&root_check).unwrap(), &Signature::from_bytes(&sb)) {
            Ok(_) => {
                println!("PACK VERIFIED");
                println!("content_id:  {}", pack["content_id"].as_str().unwrap_or(""));
                println!("root:        {}", stored_root);
                println!("fingerprint: {}", so["fingerprint"].as_str().unwrap_or(""));
                println!("tsa:         {}", match pack.get("tsa") { Some(t) => verify_tsa_token(t, stored_root), None => "none".to_string() });
                std::process::exit(0);
            }
            Err(e) => { eprintln!("VERIFICATION FAILED\nCode: SIGNATURE_INVALID\nReason: {}", e); std::process::exit(1); }
        }
    }
    if args.len() < 4 { eprintln!("Usage: isc_pack_v5 <content> <profile> <content_id> [--key <f>] [--no-tsa]"); std::process::exit(2); }
    let no_tsa = args.contains(&"--no-tsa".to_string());
    let parent = args.iter().position(|a| a == "--parent").and_then(|p| args.get(p+1)).cloned().unwrap_or_default();
    let sk = if let Some(pos) = args.iter().position(|a| a == "--key") {
        let kd: serde_json::Value = serde_json::from_str(&fs::read_to_string(&args[pos+1]).unwrap()).unwrap();
        SigningKey::from_bytes(&hex::decode(kd["private"].as_str().unwrap()).unwrap().try_into().unwrap())
    } else { SigningKey::generate(&mut OsRng) };
    let pb = sk.verifying_key().to_bytes();
    let fp = &sha256_hex(&pb)[..16];
    let cb = fs::read(&args[1]).expect("cannot read content");
    let ch = sha256_hex(&cb);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let sealed_at = chrono::DateTime::from_timestamp(now as i64, 0).unwrap().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut fp_pack = json!({
        "pack_version": "5.1", "version": 5, "profile": &args[2], "content_id": &args[3],
        "content_hash": {"alg": "sha256", "digest": ch}, "parent": parent, "claims": [],
        "sealed_at": sealed_at, "root": "",
        "signatures": [{"alg": "ed25519", "public_key": hex::encode(pb), "fingerprint": fp, "signature": ""}]
    });
    let root = sha256_hex(serde_json::to_string(&fp_pack).unwrap().as_bytes());
    let sig = sk.sign(hex::decode(&root).unwrap().as_slice());
    fp_pack["root"] = json!(root);
    fp_pack["signatures"][0]["signature"] = json!(hex::encode(sig.to_bytes()));
    if no_tsa {
        fp_pack["tsa"] = json!({"present": false});
    } else {
        match request_tsa_token(&root) {
            Ok(r) => { fp_pack["tsa"] = json!({"present": true, "provider": "freetsa.org", "url": FREETSA_URL, "hash_algorithm": "sha256", "message_imprint": root, "token_b64": b64_encode(&r.raw_token), "time": r.gen_time}); }
            Err(e) => { eprintln!("[tsa] WARNING: {}", e); fp_pack["tsa"] = json!({"present": false, "error": e}); }
        }
    }
    let pack_name = format!("{}_v5_pack.json", args[3].replace("/", "_"));
    fs::write(&pack_name, serde_json::to_string_pretty(&fp_pack).unwrap()).unwrap();
    let tsa_time = if fp_pack["tsa"]["present"].as_bool().unwrap_or(false) { fp_pack["tsa"]["time"].as_str().unwrap_or("?").to_string() } else { "none".to_string() };
    println!("ISCProof Evidence Pack V5\nprofile:     {}\ncontent_id:  {}\nhash:        {}\nsealed_at:   {}\nroot:        {}\ntsa:         {}\nPACK CREATED: {}", args[2], args[3], ch, sealed_at, root, tsa_time, pack_name);
}

// cache-bust-tsa-rebuild-20260502
