use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use noir_acir::Artifact;
use noir_r1cs::{
    compile_r1cs, compile_r1cs_with_options, write_r1cs_binary, write_r1cs_json, LoweringOptions,
    R1csError, UnsupportedOpcodeInfo,
};
use noir_witness::{
    generate_witness_from_json_str_with_options, generate_witness_with_options, WitnessArtifacts,
    WitnessSolveOptions,
};

#[derive(Debug, Parser)]
#[command(name = "noir-cli")]
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
        #[arg(long, default_value_t = false)]
        no_pedantic: bool,
    },
    /// Compile AssertZero ACIR into debug R1CS JSON.
    R1csJson {
        artifact: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_unsupported: bool,
    },
    /// Emit iden3 `.r1cs` and `.wtns` artifacts for snarkjs interop.
    Interop {
        artifact: PathBuf,
        inputs: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_unsupported: bool,
        #[arg(long, default_value_t = false)]
        no_pedantic: bool,
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
            no_pedantic,
        } => witness_cmd(&artifact, &inputs, &out, !no_pedantic),
        Commands::R1csJson {
            artifact,
            out,
            allow_unsupported,
        } => r1cs_json_cmd(&artifact, &out, allow_unsupported),
        Commands::Interop {
            artifact,
            inputs,
            out,
            allow_unsupported,
            no_pedantic,
        } => interop_cmd(&artifact, &inputs, &out, allow_unsupported, !no_pedantic),
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

fn witness_cmd(
    artifact_path: &PathBuf,
    inputs_path: &PathBuf,
    out_dir: &PathBuf,
    pedantic_solving: bool,
) -> Result<()> {
    let artifact = load_artifact(artifact_path)?;
    let inputs = fs::read_to_string(inputs_path)
        .with_context(|| format!("failed reading inputs `{}`", inputs_path.display()))?;

    let witness = generate_witness_from_json_str_with_options(
        &artifact,
        &inputs,
        WitnessSolveOptions { pedantic_solving },
    )
    .context("failed generating witness from inputs")?;

    write_witness_outputs(&witness, out_dir)?;

    println!(
        "witness_count={} witness_map_entries={}",
        witness.witness_vector.len(),
        witness.witness_map_hex().len()
    );
    Ok(())
}

fn r1cs_json_cmd(
    artifact_path: &PathBuf,
    out_path: &PathBuf,
    allow_unsupported: bool,
) -> Result<()> {
    let artifact = load_artifact(artifact_path)?;

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed creating output dir `{}`", parent.display()))?;
        }
    }

    let diagnostics_path = unsupported_report_path_for_r1cs_json(out_path);
    let system = compile_r1cs_for_command(&artifact, allow_unsupported, Some(&diagnostics_path))
        .context("failed compiling R1CS")?;

    write_r1cs_json(&system, out_path)
        .with_context(|| format!("failed writing `{}`", out_path.display()))?;

    println!(
        "n_wires={} n_constraints={}",
        system.n_wires, system.n_constraints
    );
    Ok(())
}

fn interop_cmd(
    artifact_path: &PathBuf,
    inputs_path: &PathBuf,
    out_dir: &PathBuf,
    allow_unsupported: bool,
    pedantic_solving: bool,
) -> Result<()> {
    let artifact = load_artifact(artifact_path)?;
    let inputs = fs::read_to_string(inputs_path)
        .with_context(|| format!("failed reading inputs `{}`", inputs_path.display()))?;
    let inputs_json: serde_json::Value =
        serde_json::from_str(&inputs).context("invalid inputs json")?;

    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed creating output dir `{}`", out_dir.display()))?;
    let mut witness = generate_witness_with_options(
        &artifact,
        &inputs_json,
        WitnessSolveOptions { pedantic_solving },
    )
    .context("failed generating witness")?;
    let diagnostics_path = out_dir.join("unsupported_opcodes.json");
    let system = compile_r1cs_for_command(&artifact, allow_unsupported, Some(&diagnostics_path))
        .context("failed compiling R1CS")?;
    witness.witness_vector = system
        .materialize_witness(&witness.witness_vector)
        .ok_or_else(|| anyhow!("failed materializing witness for {} wires", system.n_wires))?;

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

fn compile_r1cs_for_command(
    artifact: &Artifact,
    allow_unsupported: bool,
    diagnostics_path: Option<&PathBuf>,
) -> Result<noir_r1cs::R1csSystem> {
    if !allow_unsupported {
        return match compile_r1cs(&artifact.program) {
            Ok(system) => Ok(system),
            Err(R1csError::UnsupportedOpcode { info }) => anyhow::bail!(
                "strict lowering failed: unsupported opcode `{}` at index {} in function {}\n  predicate_state: {}\n  exact_opcode: {}\n  details: {}\n  workaround: {}",
                info.opcode,
                info.index,
                info.function_id,
                info.predicate_state,
                info.exact_opcode,
                info.details,
                info.workaround
            ),
            Err(err) => Err(err).context("strict lowering failed"),
        };
    }

    match compile_r1cs_with_options(&artifact.program, LoweringOptions::allow_unsupported()) {
        Ok(system) => Ok(system),
        Err(R1csError::UnsupportedOpcodes { opcodes }) => {
            if let Some(path) = diagnostics_path {
                write_unsupported_report(path, &opcodes)?;
                eprintln!("unsupported opcode report written to `{}`", path.display());
            }
            eprintln!("unsupported opcode count={}", opcodes.len());
            eprintln!("{}", format_unsupported_summary(&opcodes));
            if let Some(first) = opcodes.first() {
                eprintln!("{}", format_unsupported_opcode(first));
            }
            anyhow::bail!(
                "unsupported opcodes encountered; no R1CS/WTNS emitted (use diagnostics report for details)"
            )
        }
        Err(err) => Err(err).context("failed compiling R1CS"),
    }
}

fn write_unsupported_report(path: &PathBuf, opcodes: &[UnsupportedOpcodeInfo]) -> Result<()> {
    let payload = serde_json::json!({
        "unsupported_opcode_count": opcodes.len(),
        "unsupported_opcodes": opcodes,
    });
    fs::write(path, serde_json::to_vec_pretty(&payload)?)
        .with_context(|| format!("failed writing `{}`", path.display()))?;
    Ok(())
}

fn format_unsupported_opcode(info: &UnsupportedOpcodeInfo) -> String {
    format!(
        "unsupported opcode `{}` at index {} in function {} (predicate={})\n  exact_opcode: {}\n  details: {}\n  workaround: {}",
        info.opcode,
        info.index,
        info.function_id,
        info.predicate_state,
        info.exact_opcode,
        info.details,
        info.workaround
    )
}

fn format_unsupported_summary(opcodes: &[UnsupportedOpcodeInfo]) -> String {
    let mut by_variant = BTreeMap::<String, usize>::new();
    let mut by_blackbox = BTreeMap::<String, usize>::new();

    for info in opcodes {
        *by_variant.entry(info.opcode_variant.clone()).or_default() += 1;
        if let Some(name) = parse_blackbox_name(&info.exact_opcode) {
            *by_blackbox.entry(name).or_default() += 1;
        }
    }

    let variants = by_variant
        .into_iter()
        .map(|(name, count)| format!("{name}:{count}"))
        .collect::<Vec<_>>()
        .join(", ");

    if by_blackbox.is_empty() {
        return format!("unsupported summary by variant: {variants}");
    }

    let blackboxes = by_blackbox
        .into_iter()
        .map(|(name, count)| format!("{name}:{count}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("unsupported summary by variant: {variants}; blackboxes: {blackboxes}")
}

fn parse_blackbox_name(exact_opcode: &str) -> Option<String> {
    let suffix = exact_opcode.strip_prefix("BLACKBOX::")?;
    let end = suffix.find(' ').unwrap_or(suffix.len());
    let mut name = suffix[..end].to_string();
    if let Some(stripped) = name.strip_suffix(':') {
        name = stripped.to_string();
    }
    Some(name)
}

fn unsupported_report_path_for_r1cs_json(out_path: &Path) -> PathBuf {
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            return parent.join("unsupported_opcodes.json");
        }
    }
    PathBuf::from("unsupported_opcodes.json")
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
