#![cfg(feature = "interop-test")]

use std::process::Command;

use noir_acir::Artifact;
use noir_r1cs::{compile_r1cs, write_r1cs_binary};
use noir_witness::generate_witness_from_json_str;
use tempfile::TempDir;

#[test]
#[ignore]
fn snarkjs_interop_smoke() {
    if Command::new("snarkjs").arg("--version").output().is_err() {
        eprintln!("snarkjs is not installed; skipping interop smoke test");
        return;
    }

    let temp = TempDir::new().expect("temp dir should be created");
    let dir = temp.path();

    let artifact = Artifact::from_json_bytes(include_bytes!(
        "../../../test-vectors/fixture_artifact.json"
    ))
    .expect("fixture artifact should parse");
    let witness = generate_witness_from_json_str(
        &artifact,
        include_str!("../../../test-vectors/fixture_inputs.json"),
    )
    .expect("witness should be generated");
    let system = compile_r1cs(&artifact.program).expect("r1cs compilation should succeed");

    let r1cs_path = dir.join("circuit.r1cs");
    let wtns_path = dir.join("witness.wtns");
    write_r1cs_binary(&system, &r1cs_path).expect("r1cs should be written");
    witness
        .write_wtns(&wtns_path)
        .expect("wtns should be written");

    run(dir, &["wtns", "check", "circuit.r1cs", "witness.wtns"]);

    run(
        dir,
        &["powersoftau", "new", "bn128", "12", "pot12_0000.ptau", "-v"],
    );
    run(
        dir,
        &[
            "powersoftau",
            "prepare",
            "phase2",
            "pot12_0000.ptau",
            "pot12_final.ptau",
            "-v",
        ],
    );
    run(
        dir,
        &[
            "groth16",
            "setup",
            "circuit.r1cs",
            "pot12_final.ptau",
            "circuit_0000.zkey",
        ],
    );
    run(
        dir,
        &[
            "zkey",
            "contribute",
            "circuit_0000.zkey",
            "circuit_final.zkey",
            "--name=CI",
            "-v",
            "-e=deterministic entropy",
        ],
    );
    run(
        dir,
        &[
            "zkey",
            "export",
            "verificationkey",
            "circuit_final.zkey",
            "verification_key.json",
        ],
    );
    run(
        dir,
        &[
            "groth16",
            "prove",
            "circuit_final.zkey",
            "witness.wtns",
            "proof.json",
            "public.json",
        ],
    );

    let verify = Command::new("snarkjs")
        .args([
            "groth16",
            "verify",
            "verification_key.json",
            "public.json",
            "proof.json",
        ])
        .current_dir(dir)
        .output()
        .expect("snarkjs groth16 verify should execute");

    assert!(
        verify.status.success(),
        "verify command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );

    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(
        stdout.contains("OK") || stdout.contains("ok"),
        "unexpected verify output: {stdout}"
    );
}

fn run(dir: &std::path::Path, args: &[&str]) {
    let output = Command::new("snarkjs")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("snarkjs command should execute");

    assert!(
        output.status.success(),
        "snarkjs {} failed\nstdout:\n{}\nstderr:\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
