use std::process::Command;

#[test]
fn demo_command_prints_strict_block_decision_to_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_outbound-witness"))
        .args(["demo", "--mode", "strict"])
        .output()
        .expect("binary should start");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("BLOCK 阻断"));
}

#[test]
fn demo_ledger_export_can_be_verified() {
    let dir = std::env::temp_dir().join(format!("ow-ledger-verify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger.json");

    let export = Command::new(env!("CARGO_BIN_EXE_outbound-witness"))
        .args([
            "demo",
            "--mode",
            "strict",
            "--export",
            path.to_str().unwrap(),
        ])
        .output()
        .expect("export should run");
    assert!(export.status.success());

    let verify = Command::new(env!("CARGO_BIN_EXE_outbound-witness"))
        .args(["verify", path.to_str().unwrap()])
        .output()
        .expect("verify should run");
    assert!(
        verify.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("基准事件链校验通过"));
    let _ = std::fs::remove_dir_all(&dir);
}
