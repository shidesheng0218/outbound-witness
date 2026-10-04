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
