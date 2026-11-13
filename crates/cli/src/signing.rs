//! Detached Ed25519 signatures for exported audit records.
//!
//! A hash chain proves a file was not altered after it was written. It cannot
//! prove who wrote it: anyone can mint a fresh chain over fabricated events.
//! Signing closes that gap, but only if the verifier obtains the public key from
//! a channel it trusts rather than from the file being checked.

use outbound_witness_core::session::{AuditSignature, SessionRecord};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use std::fs;
use std::path::{Path, PathBuf};

/// File name of the private key inside the state directory.
const KEY_FILE: &str = "signing-key.pk8";

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if !value.is_ascii() {
        return Err("十六进制必须只包含 ASCII 字符".to_string());
    }
    if !value.len().is_multiple_of(2) {
        return Err("十六进制长度必须是偶数".to_string());
    }
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("无效的十六进制字符".to_string());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| format!("无效的十六进制字符: {}", &value[index..index + 2]))
        })
        .collect()
}

/// Loads the local signing key, creating one on first use. The key is written
/// owner-only and never leaves this machine by itself.
pub fn load_or_create_key(state_dir: &Path) -> Result<PathBuf, String> {
    let path = state_dir.join(KEY_FILE);
    if path.exists() {
        return Ok(path);
    }
    fs::create_dir_all(state_dir).map_err(|error| error.to_string())?;
    let rng = SystemRandom::new();
    let document =
        Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| "无法生成签名密钥".to_string())?;
    write_private(&path, document.as_ref())?;
    Ok(path)
}

fn key_pair(state_dir: &Path) -> Result<Ed25519KeyPair, String> {
    let path = load_or_create_key(state_dir)?;
    let document = fs::read(&path).map_err(|error| format!("无法读取签名密钥: {error}"))?;
    Ed25519KeyPair::from_pkcs8(&document).map_err(|_| "签名密钥格式无效".to_string())
}

/// Hex public key of this machine, for handing to whoever should verify.
pub fn public_key_hex(state_dir: &Path) -> Result<String, String> {
    Ok(hex_encode(key_pair(state_dir)?.public_key().as_ref()))
}

/// Bytes covered by the signature: the record with its own signature cleared, so
/// signing and verification agree byte for byte.
fn material(record: &SessionRecord) -> Result<Vec<u8>, String> {
    let mut bare = record.clone();
    bare.signature = None;
    serde_json::to_vec(&bare).map_err(|error| error.to_string())
}

/// Signs the record in place and returns the public key that signed it.
pub fn sign_record(state_dir: &Path, record: &mut SessionRecord) -> Result<String, String> {
    let pair = key_pair(state_dir)?;
    record.signature = None;
    let bytes = material(record)?;
    let signature = pair.sign(&bytes);
    let public_key = hex_encode(pair.public_key().as_ref());
    record.signature = Some(AuditSignature {
        algorithm: "ed25519".into(),
        public_key: public_key.clone(),
        value: hex_encode(signature.as_ref()),
        root_hash: None,
        signed_at: None,
        log_entry_id: None,
    });
    Ok(public_key)
}

/// Checks the detached signature using the public key embedded in the file.
/// This proves the sealed payload was produced by whoever holds that key; it
/// does not prove that key belongs to the party you expect. Use
/// `verify_record` with a key from a trusted channel for origin.
pub fn verify_embedded_signature(record: &SessionRecord) -> Result<(), String> {
    let signature = record
        .signature
        .as_ref()
        .ok_or_else(|| "该导出没有签名，无法验证完整性".to_string())?;
    let embedded = hex_decode(&signature.public_key)?;
    verify_with_key(record, &embedded)
}

fn verify_with_key(record: &SessionRecord, key: &[u8]) -> Result<(), String> {
    let Some(signature) = &record.signature else {
        return Err("该导出没有签名，无法验证来源".to_string());
    };
    if signature.algorithm != "ed25519" {
        return Err(format!("不支持的签名算法: {}", signature.algorithm));
    }
    let bytes = material(record)?;
    let signature_bytes = hex_decode(&signature.value)?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&bytes, &signature_bytes)
        .map_err(|_| "签名校验失败：内容与签名不匹配".to_string())
}

/// Checks the signature against a public key the caller trusts. Passing the key
/// embedded in the file would prove nothing.
pub fn verify_record(record: &SessionRecord, expected_public_key: &str) -> Result<(), String> {
    let Some(signature) = &record.signature else {
        return Err("该导出没有签名，无法验证来源".to_string());
    };
    let expected = hex_decode(expected_public_key)?;
    let embedded = hex_decode(&signature.public_key)?;
    if expected != embedded {
        return Err("文件内嵌公钥与你提供的公钥不一致".to_string());
    }
    verify_with_key(record, &expected)
}

/// Accepts a public key either as a path to a file or as a hex string.
pub fn read_public_key_argument(value: &str) -> Result<String, String> {
    let path = Path::new(value);
    if path.is_file() {
        let source = fs::read_to_string(path)
            .map_err(|error| format!("无法读取公钥文件 {}: {error}", path.display()))?;
        return Ok(source.trim().to_string());
    }
    Ok(value.trim().to_string())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("无法写入签名密钥 {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("无法写入签名密钥 {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|error| format!("无法写入签名密钥 {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use outbound_witness_core::session::{EnforcementMode, SessionSpec};

    fn record() -> SessionRecord {
        SessionRecord::new(SessionSpec::new(
            "/workspace".into(),
            vec!["example-agent".into()],
            EnforcementMode::Strict,
        ))
    }

    fn temp_state(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ow-signing-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn signs_a_record_and_verifies_it_with_the_same_key() {
        let dir = temp_state("roundtrip");
        let mut record = record();
        let public_key = sign_record(&dir, &mut record).unwrap();
        assert!(verify_record(&record, &public_key).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tampered_record_fails_signature_verification() {
        let dir = temp_state("tamper");
        let mut record = record();
        let public_key = sign_record(&dir, &mut record).unwrap();
        record.state = outbound_witness_core::session::SessionState::Failed;
        assert!(verify_record(&record, &public_key).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_foreign_public_key_is_rejected() {
        let dir = temp_state("foreign");
        let mut record = record();
        sign_record(&dir, &mut record).unwrap();
        let other = temp_state("foreign-other");
        let other_key = public_key_hex(&other).unwrap();
        assert!(verify_record(&record, &other_key).is_err());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&other);
    }

    #[test]
    fn an_unsigned_record_is_reported_as_unsigned() {
        let dir = temp_state("unsigned");
        let record = record();
        let error = verify_record(&record, "00").expect_err("no signature must be reported");
        assert!(error.contains("没有签名"), "unexpected error: {error}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_multibyte_hex_is_rejected_without_panicking() {
        assert!(hex_decode("€€").is_err());
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("0").is_err());
    }

    #[test]
    fn embedded_signature_verifies_without_claiming_origin() {
        let dir = temp_state("embedded");
        let mut record = record();
        sign_record(&dir, &mut record).unwrap();
        assert!(verify_embedded_signature(&record).is_ok());

        record.state = outbound_witness_core::session::SessionState::Failed;
        assert!(
            verify_embedded_signature(&record).is_err(),
            "tampering must break the embedded signature too"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
