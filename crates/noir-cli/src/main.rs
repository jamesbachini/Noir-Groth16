use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use noir_acir::Artifact;
use noir_r1cs::{compile_r1cs, write_r1cs_binary, write_r1cs_json};
use noir_witness::{generate_witness, generate_witness_from_json_str, WitnessArtifacts};

#[derive(Debug, Parser)]
#[command(name = "noir-groth16")]
#[command(about = "Noir ACIR -> witness/R1CS utility CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Parse a Noir artifact and write deterministic parse summary JSON.
    CompileR1cs {
        artifact: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate witness outputs from artifact + ABI-shaped inputs.
    Witness {
        artifact: PathBuf,
        inputs: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Compile AssertZero ACIR into debug R1CS JSON.
    R1csJson {
        artifact: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Emit iden3 `.r1cs` and `.wtns` artifacts for snarkjs interop.
    Interop {
        artifact: PathBuf,
        inputs: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::CompileR1cs { artifact, out } => compile_r1cs_cmd(&artifact, &out),
        Commands::Witness {
            artifact,
            inputs,
            out,
        } => witness_cmd(&artifact, &inputs, &out),
        Commands::R1csJson { artifact, out } => r1cs_json_cmd(&artifact, &out),
        Commands::Interop {
            artifact,
            inputs,
            out,
        } => interop_cmd(&artifact, &inputs, &out),
    }
}

fn load_artifact(path: &PathBuf) -> Result<Artifact> {
    let bytes =
        fs::read(path).with_context(|| format!("failed reading artifact `{}`", path.display()))?;
    Artifact::from_json_bytes(&bytes)
        .with_context(|| format!("failed parsing `{}`", path.display()))
}

fn compile_r1cs_cmd(artifact_path: &PathBuf, out_dir: &PathBuf) -> Result<()> {
    let artifact = load_artifact(artifact_path)?;
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed creating output dir `{}`", out_dir.display()))?;

    let summary = artifact.opcode_summary();
    let summary_path = out_dir.join("parsed.json");
    fs::write(
        &summary_path,
        serde_json::to_vec_pretty(&summary).context("failed serializing parsed summary")?,
    )
    .with_context(|| format!("failed writing `{}`", summary_path.display()))?;

    println!(
        "opcode_count={} witness_count={} opcode_variants={}",
        summary.opcode_count,
        summary.witness_count,
        summary.opcode_variants.join(",")
    );
    Ok(())
}

fn witness_cmd(artifact_path: &PathBuf, inputs_path: &PathBuf, out_dir: &PathBuf) -> Result<()> {
    let artifact = load_artifact(artifact_path)?;
    let inputs = fs::read_to_string(inputs_path)
        .with_context(|| format!("failed reading inputs `{}`", inputs_path.display()))?;

    let witness = generate_witness_from_json_str(&artifact, &inputs)
        .context("failed generating witness from inputs")?;

    write_witness_outputs(&witness, out_dir)?;

    println!(
        "witness_count={} witness_map_entries={}",
        witness.witness_vector.len(),
        witness.witness_map_hex().len()
    );
    Ok(())
}

fn r1cs_json_cmd(artifact_path: &PathBuf, out_path: &PathBuf) -> Result<()> {
    let artifact = load_artifact(artifact_path)?;
    let system = compile_r1cs(&artifact.program).context("failed compiling R1CS")?;

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating output dir `{}`", parent.display()))?;
        }
    }

    write_r1cs_json(&system, out_path)
        .with_context(|| format!("failed writing `{}`", out_path.display()))?;

    println!(
        "n_wires={} n_constraints={}",
        system.n_wires, system.n_constraints
    );
    Ok(())
}

fn interop_cmd(artifact_path: &PathBuf, inputs_path: &PathBuf, out_dir: &PathBuf) -> Result<()> {
    let artifact = load_artifact(artifact_path)?;
    let inputs = fs::read_to_string(inputs_path)
        .with_context(|| format!("failed reading inputs `{}`", inputs_path.display()))?;
    let inputs_json: serde_json::Value =
        serde_json::from_str(&inputs).context("invalid inputs json")?;

    let witness = generate_witness(&artifact, &inputs_json).context("failed generating witness")?;
    let system = compile_r1cs(&artifact.program).context("failed compiling R1CS")?;

    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed creating output dir `{}`", out_dir.display()))?;

    let r1cs_path = out_dir.join("circuit.r1cs");
    let wtns_path = out_dir.join("witness.wtns");
    write_r1cs_binary(&system, &r1cs_path)
        .with_context(|| format!("failed writing `{}`", r1cs_path.display()))?;
    witness
        .write_wtns(&wtns_path)
        .with_context(|| format!("failed writing `{}`", wtns_path.display()))?;

    println!(
        "n_wires={} n_constraints={} witness_len={}",
        system.n_wires,
        system.n_constraints,
        witness.witness_vector.len()
    );
    Ok(())
}

fn write_witness_outputs(witness: &WitnessArtifacts, out_dir: &PathBuf) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed creating output dir `{}`", out_dir.display()))?;

    let witness_map_path = out_dir.join("witness_map.json");
    let witness_bin_path = out_dir.join("witness.bin");
    let witness_wtns_path = out_dir.join("witness.wtns");

    witness
        .write_witness_map_json(&witness_map_path)
        .with_context(|| format!("failed writing `{}`", witness_map_path.display()))?;
    witness
        .write_witness_bin(&witness_bin_path)
        .with_context(|| format!("failed writing `{}`", witness_bin_path.display()))?;
    witness
        .write_wtns(&witness_wtns_path)
        .with_context(|| format!("failed writing `{}`", witness_wtns_path.display()))?;

    Ok(())
}
