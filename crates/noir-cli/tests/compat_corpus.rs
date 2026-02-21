use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use noir_acir::Artifact;
use noir_r1cs::compile_r1cs_with_witness;
use noir_witness::{generate_witness_with_options, WitnessSolveOptions};
use tempfile::TempDir;

#[test]
#[ignore = "requires `nargo` and compiles real Noir projects in `examples/`"]
fn compatibility_corpus_differential_checks() {
    if Command::new("nargo").arg("--version").output().is_err() {
        if std::env::var("NOIR_CORPUS_REQUIRE_NARGO").is_ok() {
            panic!("nargo is required when NOIR_CORPUS_REQUIRE_NARGO is set");
        }
        eprintln!("nargo is not installed; skipping compatibility corpus test");
        return;
    }

    let projects = discover_corpus_projects();
    assert!(
        projects.len() >= 10,
        "compatibility corpus unexpectedly small: {}",
        projects.len()
    );

    for project_dir in projects {
        run_project_differential_check(&project_dir);
    }
}

fn discover_corpus_projects() -> Vec<PathBuf> {
    let examples_dir = workspace_root().join("examples");
    let mut projects = Vec::new();
    for entry in fs::read_dir(&examples_dir).expect("examples directory should be readable") {
        let path = entry.expect("directory entry should be readable").path();
        if !path.is_dir() {
            continue;
        }
        if !path.join("Nargo.toml").exists() || !path.join("inputs.json").exists() {
            continue;
        }
        projects.push(path);
    }
    projects.sort();
    projects
}

fn run_project_differential_check(project_dir: &Path) {
    let name = project_dir
        .file_name()
        .and_then(|value| value.to_str())
        .expect("project dir should have a UTF-8 name");
    eprintln!("compat-corpus: checking {name}");

    let temp = TempDir::new().expect("temp dir should be created");
    let copied_project = temp.path().join(name);
    copy_dir_recursive(project_dir, &copied_project);

    let compile = Command::new("nargo")
        .arg("compile")
        .current_dir(&copied_project)
        .output()
        .expect("nargo compile should execute");
    assert!(
        compile.status.success(),
        "nargo compile failed for {name}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&compile.stdout),
        String::from_utf8_lossy(&compile.stderr)
    );

    let artifact_path = find_artifact_json(&copied_project.join("target"), name);
    let artifact_bytes = fs::read(&artifact_path).expect("compiled artifact should be readable");
    let artifact = Artifact::from_json_bytes(&artifact_bytes).expect("artifact should parse");

    let inputs_raw = fs::read_to_string(project_dir.join("inputs.json"))
        .expect("inputs.json should be readable");
    let inputs_json: serde_json::Value =
        serde_json::from_str(&inputs_raw).expect("inputs.json should parse");

    let witness =
        generate_witness_with_options(&artifact, &inputs_json, WitnessSolveOptions::pedantic())
            .expect("ACVM witness generation should succeed");
    let system = compile_r1cs_with_witness(&artifact.program, &witness.witness_vector)
        .expect("R1CS lowering should succeed");
    let materialized = system
        .materialize_witness(&witness.witness_vector)
        .expect("witness should materialize to R1CS wire count");

    assert!(
        system.is_satisfied(&materialized),
        "R1CS system should be satisfied for {name}"
    );
    assert_tampered_witnesses_fail(&system, &materialized, name);
}

fn assert_tampered_witnesses_fail(
    system: &noir_r1cs::R1csSystem,
    witness: &[acir::FieldElement],
    case_name: &str,
) {
    let mut constrained_wires = BTreeSet::new();
    for row in system
        .a
        .iter()
        .chain(system.b.iter())
        .chain(system.c.iter())
    {
        for term in row {
            let wire = term.wire as usize;
            if wire > 0 && wire < witness.len() {
                constrained_wires.insert(wire);
            }
        }
    }
    let candidates: Vec<usize> = constrained_wires.into_iter().collect();
    assert!(
        !candidates.is_empty(),
        "no constrained wires found for case {case_name}"
    );

    let mut sample = Vec::new();
    if candidates.len() <= 64 {
        sample.extend(candidates.iter().copied());
    } else {
        sample.extend(candidates.iter().take(32).copied());
        sample.extend(candidates.iter().rev().take(32).copied());
        sample.sort_unstable();
        sample.dedup();
    }

    for wire_index in sample {
        let mut tampered = witness.to_vec();
        tampered[wire_index] += witness[0];
        assert!(
            !system.is_satisfied(&tampered),
            "tampered witness unexpectedly satisfied constraints for {case_name} at wire {wire_index}"
        );
    }
}

fn find_artifact_json(target_dir: &Path, fallback_name: &str) -> PathBuf {
    let mut artifacts = fs::read_dir(target_dir)
        .expect("target directory should be readable")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    artifacts.sort();

    if let Some(named) = artifacts
        .iter()
        .find(|path| path.file_stem().and_then(|value| value.to_str()) == Some(fallback_name))
    {
        return named.clone();
    }

    artifacts
        .into_iter()
        .next()
        .expect("nargo compile should emit at least one artifact json")
}

fn copy_dir_recursive(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("destination directory should be creatable");
    for entry in fs::read_dir(source).expect("source directory should be readable") {
        let entry = entry.expect("directory entry should be readable");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_dir_recursive(&source_path, &destination_path);
        } else {
            fs::copy(&source_path, &destination_path).expect("file copy should succeed");
        }
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should resolve")
}
