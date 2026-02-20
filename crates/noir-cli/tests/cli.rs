use std::{fs, path::PathBuf, process::Command};

use tempfile::TempDir;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("test-vectors")
        .join(name)
}

fn parse_interop_counts(stdout: &[u8]) -> (u32, u32, usize) {
    let text = String::from_utf8_lossy(stdout);
    let line = text
        .lines()
        .find(|line| line.contains("n_wires="))
        .expect("interop output should include circuit summary");

    let mut n_wires = None;
    let mut n_constraints = None;
    let mut witness_len = None;
    for part in line.split_whitespace() {
        if let Some(value) = part.strip_prefix("n_wires=") {
            n_wires = Some(value.parse::<u32>().expect("n_wires should parse"));
        } else if let Some(value) = part.strip_prefix("n_constraints=") {
            n_constraints = Some(value.parse::<u32>().expect("n_constraints should parse"));
        } else if let Some(value) = part.strip_prefix("witness_len=") {
            witness_len = Some(value.parse::<usize>().expect("witness_len should parse"));
        }
    }

    (
        n_wires.expect("n_wires should be present"),
        n_constraints.expect("n_constraints should be present"),
        witness_len.expect("witness_len should be present"),
    )
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

#[test]
fn r1cs_json_command_supports_memory_mux_fixture() {
    let artifact = fixture_path("memory_mux_artifact.json");
    let out_dir = TempDir::new().expect("temp dir should be created");
    let out_path = out_dir.path().join("memory_mux.r1cs.json");

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
fn interop_command_is_deterministic_for_blackbox_fixture() {
    let artifact = fixture_path("blackbox_bool_artifact.json");
    let inputs = fixture_path("blackbox_bool_inputs.json");
    let first_out = TempDir::new().expect("first temp dir should be created");
    let second_out = TempDir::new().expect("second temp dir should be created");

    for out in [first_out.path(), second_out.path()] {
        let output = Command::new(env!("CARGO_BIN_EXE_noir-groth16"))
            .arg("interop")
            .arg(&artifact)
            .arg(&inputs)
            .arg("--out")
            .arg(out)
            .output()
            .expect("interop command should execute");

        assert!(
            output.status.success(),
            "interop command failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let (n_wires, _, witness_len) = parse_interop_counts(&output.stdout);
        assert_eq!(
            witness_len, n_wires as usize,
            "interop witness should be expanded to full wire count"
        );
    }

    let first_r1cs = fs::read(first_out.path().join("circuit.r1cs")).expect("first r1cs exists");
    let second_r1cs = fs::read(second_out.path().join("circuit.r1cs")).expect("second r1cs exists");
    let first_wtns = fs::read(first_out.path().join("witness.wtns")).expect("first wtns exists");
    let second_wtns = fs::read(second_out.path().join("witness.wtns")).expect("second wtns exists");

    assert_eq!(
        first_r1cs, second_r1cs,
        "r1cs bytes should be deterministic"
    );
    assert_eq!(
        first_wtns, second_wtns,
        "wtns bytes should be deterministic"
    );
}

#[test]
fn r1cs_json_command_compiles_supported_corpus_fixtures() {
    let fixtures = [
        "fixture_artifact.json",
        "memory_mux_artifact.json",
        "blackbox_bool_artifact.json",
    ];

    for fixture in fixtures {
        let artifact = fixture_path(fixture);
        let out_dir = TempDir::new().expect("temp dir should be created");
        let out_path = out_dir.path().join(format!("{fixture}.r1cs.json"));

        let output = Command::new(env!("CARGO_BIN_EXE_noir-groth16"))
            .arg("r1cs-json")
            .arg(&artifact)
            .arg("--out")
            .arg(&out_path)
            .output()
            .expect("r1cs-json command should execute");

        assert!(
            output.status.success(),
            "r1cs-json failed for fixture {fixture}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let raw = fs::read_to_string(&out_path).expect("r1cs json should be written");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("r1cs json should parse");
        assert!(
            parsed.get("n_wires").is_some(),
            "missing n_wires for {fixture}"
        );
        assert!(
            parsed.get("n_constraints").is_some(),
            "missing n_constraints for {fixture}"
        );
    }
}

#[test]
fn allow_unsupported_writes_diagnostics_and_still_fails() {
    let artifact = fixture_path("unsupported_brillig_artifact.json");
    let out_dir = TempDir::new().expect("temp dir should be created");
    let out_path = out_dir.path().join("unsupported.r1cs.json");

    let output = Command::new(env!("CARGO_BIN_EXE_noir-groth16"))
        .arg("r1cs-json")
        .arg(&artifact)
        .arg("--out")
        .arg(&out_path)
        .arg("--allow-unsupported")
        .output()
        .expect("r1cs-json command should execute");

    assert!(
        !output.status.success(),
        "r1cs-json should still fail with allow-unsupported"
    );
    assert!(
        !out_path.exists(),
        "r1cs output should not be written in diagnostics mode"
    );

    let report_path = out_dir.path().join("unsupported_opcodes.json");
    assert!(
        report_path.exists(),
        "diagnostic unsupported opcode report should be emitted"
    );

    let report = fs::read_to_string(&report_path).expect("unsupported report should be readable");
    assert!(
        report.contains("BrilligCall"),
        "report should mention unsupported opcode variant, report={report}"
    );
}
