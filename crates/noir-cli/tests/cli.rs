use std::{fs, path::PathBuf, process::Command};

use tempfile::TempDir;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("test-vectors")
        .join(name)
}

#[test]
fn witness_command_writes_outputs() {
    let artifact = fixture_path("fixture_artifact.json");
    let inputs = fixture_path("fixture_inputs.json");
    let out_dir = TempDir::new().expect("temp dir should be created");

    let output = Command::new(env!("CARGO_BIN_EXE_noir-groth16"))
        .arg("witness")
        .arg(&artifact)
        .arg(&inputs)
        .arg("--out")
        .arg(out_dir.path())
        .output()
        .expect("witness command should execute");

    assert!(
        output.status.success(),
        "witness command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let witness_map = out_dir.path().join("witness_map.json");
    let witness_bin = out_dir.path().join("witness.bin");
    let witness_wtns = out_dir.path().join("witness.wtns");

    assert!(witness_map.exists(), "witness_map.json should be emitted");
    assert!(witness_bin.exists(), "witness.bin should be emitted");
    assert!(witness_wtns.exists(), "witness.wtns should be emitted");
    assert!(
        fs::metadata(&witness_bin)
            .expect("witness.bin should have metadata")
            .len()
            > 0,
        "witness.bin should be non-empty"
    );
}

#[test]
fn r1cs_json_command_writes_json() {
    let artifact = fixture_path("fixture_artifact.json");
    let out_dir = TempDir::new().expect("temp dir should be created");
    let out_path = out_dir.path().join("circuit.r1cs.json");

    let output = Command::new(env!("CARGO_BIN_EXE_noir-groth16"))
        .arg("r1cs-json")
        .arg(&artifact)
        .arg("--out")
        .arg(&out_path)
        .output()
        .expect("r1cs-json command should execute");

    assert!(
        output.status.success(),
        "r1cs-json command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let raw = fs::read_to_string(&out_path).expect("r1cs json should be written");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("r1cs json should parse");
    assert!(parsed.get("n_wires").is_some());
    assert!(parsed.get("n_constraints").is_some());
}

#[test]
fn witness_command_fails_on_unexpected_input() {
    let artifact = fixture_path("fixture_artifact.json");
    let out_dir = TempDir::new().expect("temp dir should be created");
    let bad_inputs = out_dir.path().join("bad_inputs.json");
    fs::write(&bad_inputs, r#"{"x":"3","y":"12","unexpected":"999"}"#)
        .expect("bad input file should be written");

    let output = Command::new(env!("CARGO_BIN_EXE_noir-groth16"))
        .arg("witness")
        .arg(&artifact)
        .arg(&bad_inputs)
        .arg("--out")
        .arg(out_dir.path())
        .output()
        .expect("witness command should execute");

    assert!(
        !output.status.success(),
        "witness command should fail for unexpected input"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected input value `unexpected`"),
        "unexpected stderr: {stderr}"
    );
}
