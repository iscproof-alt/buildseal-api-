use std::env;
use std::fs;
use base64::Engine;
fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(s)
}
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use serde_json::json;

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() >= 3 && args[1] == "--keygen" {
        let keyfile = &args[2];
        let signing_key = SigningKey::generate(&mut OsRng);
        let secret_bytes = signing_key.to_bytes();
        let public_bytes = signing_key.verifying_key().to_bytes();
        let fingerprint = &sha256_hex(&public_bytes)[..16];
        let key_data = json!({
            "private": hex::encode(secret_bytes),
            "public": hex::encode(public_bytes),
            "fingerprint": fingerprint
        });
        fs::write(keyfile, serde_json::to_string_pretty(&key_data).unwrap()).unwrap();
        println!("Key generated: {}", keyfile);
        println!("Fingerprint: {}", fingerprint);
        return;
    }

    if args.len() >= 3 && args[1] == "--verify" {
        let pack_path = &args[2];
        let pack_str = fs::read_to_string(pack_path).unwrap_or_else(|e| {
            eprintln!("ERROR: cannot read file: {}", e); std::process::exit(1);
        });
        let pack: serde_json::Value = serde_json::from_str(&pack_str).unwrap_or_else(|e| {
            eprintln!("VERIFICATION FAILED");
            eprintln!("Code:   PACK_CORRUPT");
            eprintln!("Reason: {}", e);
            std::process::exit(1);
        });
        let mut recomputed = pack.clone();
        recomputed["root"] = json!("");
        recomputed["signatures"][0]["signature"] = json!("");
        recomputed.as_object_mut().map(|m| m.remove("tsa"));
        let root_input = serde_json::to_string(&recomputed).unwrap();
        let root_check = sha256_hex(root_input.as_bytes());
        // Version kontrolü
        let pack_ver = pack["version"].as_u64().unwrap_or(0);
        if pack_ver < 5 {
            eprintln!("VERIFICATION FAILED");
            eprintln!("Code:   UNSUPPORTED_VERSION");
            eprintln!("Reason: pack version {} is not supported (minimum: 5)", pack_ver);
            std::process::exit(1);
        }
        let stored_root = pack["root"].as_str().unwrap_or("");
        if root_check != stored_root {
            eprintln!("VERIFICATION FAILED");
            eprintln!("Code:   ROOT_MISMATCH");
            eprintln!("stored:     {}", stored_root);
            eprintln!("recomputed: {}", root_check);
            std::process::exit(1);
        }
        let sig_obj = &pack["signatures"][0];
        let pub_bytes: [u8; 32] = hex::decode(sig_obj["public_key"].as_str().unwrap_or(""))
            .expect("bad pubkey").try_into().expect("32 bytes");
        let sig_bytes: [u8; 64] = hex::decode(sig_obj["signature"].as_str().unwrap_or(""))
            .expect("bad sig").try_into().expect("64 bytes");
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        let vk = VerifyingKey::from_bytes(&pub_bytes).unwrap_or_else(|e| {
            eprintln!("ERROR: {}", e); std::process::exit(1);
        });
        let signature = Signature::from_bytes(&sig_bytes);
        let root_bytes = hex::decode(&root_check).unwrap();
        match vk.verify(&root_bytes, &signature) {
            Ok(_) => {
                println!("PACK VERIFIED");
                println!("content_id:  {}", pack["content_id"].as_str().unwrap_or(""));
                println!("root:        {}", stored_root);
                println!("fingerprint: {}", sig_obj["fingerprint"].as_str().unwrap_or(""));
                let tsa_status = if let Some(tsa) = pack.get("tsa") {
                    if tsa["present"].as_bool().unwrap_or(false) {
                        let token_b64 = tsa["token_b64"].as_str().unwrap_or("");
                        if !token_b64.is_empty() {
                            // RFC 3161 kriptografik verify
                            let tsr_path = format!("/tmp/isc_verify_{}.tsr", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
                            let root_bin_path = format!("/tmp/isc_root_{}.bin", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
                            let token_bytes = match base64_decode(token_b64) {
                                Ok(b) => b,
                                Err(_) => vec![]
                            };
                            let tsa_ok = if !token_bytes.is_empty() {
                                let _ = fs::write(&tsr_path, &token_bytes);
                                let root_bytes = match hex::decode(stored_root) { Ok(b) => b, Err(_) => vec![] };
                                let _ = fs::write(&root_bin_path, &root_bytes);
                                let verify_result = std::process::Command::new("openssl")
                                    .args(&["ts", "-verify", "-in", &tsr_path, "-data", &root_bin_path,
                                            "-CAfile", "/tmp/freetsa_ca.pem",
                                            "-untrusted", "/tmp/freetsa_tsa.crt"])
                                    .output();
                                let _ = fs::remove_file(&tsr_path);
                                let _ = fs::remove_file(&root_bin_path);
                                match verify_result {
                                    Ok(out) => out.status.success(),
                                    Err(_) => false
                                }
                            } else { false };
                            if tsa_ok {
                                format!("VERIFIED | provider: {} | time: {}", tsa["provider"].as_str().unwrap_or("unknown"), tsa["time"].as_str().unwrap_or("unknown"))
                            } else {
                                format!("present (unverified) | provider: {} | time: {}", tsa["provider"].as_str().unwrap_or("unknown"), tsa["time"].as_str().unwrap_or("unknown"))
                            }
                        } else {
                            format!("present (no token) | provider: {} | time: {}", tsa["provider"].as_str().unwrap_or("unknown"), tsa["time"].as_str().unwrap_or("unknown"))
                        }
                    } else {
                        "none".to_string()
                    }
                } else {
                    "none".to_string()
                };
                println!("tsa:         {}", tsa_status);
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("VERIFICATION FAILED");
                eprintln!("Code:   SIGNATURE_INVALID");
                eprintln!("Reason: {}", e);
                std::process::exit(1);
            }
        }
    }


    if args.len() < 4 {
        eprintln!("Usage: isc_pack_v5 <content> <profile> <content_id> [--parent <hash>] [--key <keyfile>]");
        std::process::exit(2);
    }

    let content_path = &args[1];
    let profile = &args[2];
    let content_id = &args[3];

    let parent_hash = if let Some(pos) = args.iter().position(|a| a == "--parent") {
        args.get(pos + 1).cloned().unwrap_or_default()
    } else {
        String::new()
    };

    let signing_key = if let Some(pos) = args.iter().position(|a| a == "--key") {
        let keyfile = &args[pos + 1];
        let key_data: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(keyfile).expect("cannot read key file")
        ).unwrap();
        let priv_hex = key_data["private"].as_str().unwrap();
        let priv_bytes = hex::decode(priv_hex).unwrap();
        let arr: [u8; 32] = priv_bytes.try_into().unwrap();
        SigningKey::from_bytes(&arr)
    } else {
        SigningKey::generate(&mut OsRng)
    };

    let public_bytes = signing_key.verifying_key().to_bytes();
    let fingerprint = &sha256_hex(&public_bytes)[..16];

    let content_bytes = fs::read(content_path).expect("cannot read content");
    let content_hash = sha256_hex(&content_bytes);

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let sealed_at = chrono::DateTime::from_timestamp(now as i64, 0)
        .unwrap().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let mut final_pack = json!({
        "pack_version": "5.1",
        "version": 5,
        "profile": profile,
        "content_id": content_id,
        "content_hash": { "alg": "sha256", "digest": content_hash },
        "parent": parent_hash,
        "claims": [],
        "sealed_at": sealed_at,
        "root": "",
        "signatures": [{ "alg": "ed25519", "public_key": hex::encode(public_bytes), "fingerprint": fingerprint, "signature": "" }]
    });

    let root_input = serde_json::to_string(&final_pack).unwrap();
    let root = sha256_hex(root_input.as_bytes());
    let sig = signing_key.sign(hex::decode(&root).unwrap().as_slice());

    final_pack["root"] = json!(root);
    final_pack["signatures"][0]["signature"] = json!(hex::encode(sig.to_bytes()));

    let pack_name = format!("{}_v5_pack.json", content_id.replace("/", "_"));
    fs::write(&pack_name, serde_json::to_string_pretty(&final_pack).unwrap()).unwrap();

    println!("ISCProof Evidence Pack V5");
    println!("profile:     {}", profile);
    println!("content_id:  {}", content_id);
    println!("hash:        {}", content_hash);
    println!("sealed_at:   {}", sealed_at);
    println!("root:        {}", root);
    println!("PACK CREATED: {}", pack_name);
}
