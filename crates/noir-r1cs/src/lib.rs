use std::{collections::BTreeMap, io::Write, path::Path};

use acir::{
    circuit::{Circuit, Opcode, Program},
    native_types::{Expression, Witness},
    FieldElement,
};
use r1cs_file::{
    Constraint, Constraints, FieldElement as R1csFieldElement, Header, R1csFile, WireMap,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum R1csError {
    #[error("program has no functions")]
    EmptyProgram,
    #[error("unsupported opcode for MVP compiler: {0}")]
    UnsupportedOpcode(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseTerm {
    pub wire: u32,
    pub coeff: FieldElement,
}

pub type SparseRow = Vec<SparseTerm>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct R1csSystem {
    pub n_wires: u32,
    pub n_constraints: u32,
    pub n_public_outputs: u32,
    pub n_public_inputs: u32,
    pub n_private_inputs: u32,
    pub a: Vec<SparseRow>,
    pub b: Vec<SparseRow>,
    pub c: Vec<SparseRow>,
}

pub fn compile_r1cs(program: &Program) -> Result<R1csSystem, R1csError> {
    let circuit = program.functions.first().ok_or(R1csError::EmptyProgram)?;
    compile_r1cs_circuit(circuit)
}

pub fn compile_r1cs_circuit(circuit: &Circuit) -> Result<R1csSystem, R1csError> {
    let mut next_wire = circuit.current_witness_index + 1;
    let mut a_rows = Vec::new();
    let mut b_rows = Vec::new();
    let mut c_rows = Vec::new();

    for opcode in &circuit.opcodes {
        match opcode {
            Opcode::AssertZero(expr) => {
                lower_assert_zero(expr, &mut next_wire, &mut a_rows, &mut b_rows, &mut c_rows);
            }
            other => {
                return Err(R1csError::UnsupportedOpcode(
                    opcode_variant(other).to_string(),
                ))
            }
        }
    }

    let n_constraints = a_rows.len() as u32;
    Ok(R1csSystem {
        n_wires: next_wire,
        n_constraints,
        n_public_outputs: circuit.return_values.indices().len() as u32,
        n_public_inputs: circuit.public_parameters.indices().len() as u32,
        n_private_inputs: circuit.private_parameters.len() as u32,
        a: a_rows,
        b: b_rows,
        c: c_rows,
    })
}

pub fn write_r1cs_json(system: &R1csSystem, path: impl AsRef<Path>) -> Result<(), R1csError> {
    let json = serde_json::to_vec_pretty(system)?;
    std::fs::write(path, json)?;
    Ok(())
}

pub fn write_r1cs_binary(system: &R1csSystem, path: impl AsRef<Path>) -> Result<(), R1csError> {
    let mut constraints = Vec::with_capacity(system.n_constraints as usize);
    for i in 0..system.n_constraints as usize {
        constraints.push(Constraint(
            to_r1cs_terms(&system.a[i]),
            to_r1cs_terms(&system.b[i]),
            to_r1cs_terms(&system.c[i]),
        ));
    }

    let file = R1csFile::<32> {
        header: Header {
            prime: R1csFieldElement::from(bn254_modulus_le_bytes()),
            n_wires: system.n_wires,
            n_pub_out: system.n_public_outputs,
            n_pub_in: system.n_public_inputs,
            n_prvt_in: system.n_private_inputs,
            n_labels: system.n_wires as u64,
            n_constraints: system.n_constraints,
        },
        constraints: Constraints(constraints),
        map: WireMap((0..system.n_wires as u64).collect()),
    };

    let mut out = std::fs::File::create(path)?;
    file.write(&mut out)?;
    out.flush()?;
    Ok(())
}

impl R1csSystem {
    pub fn is_satisfied(&self, witness: &[FieldElement]) -> bool {
        let Some(full_witness) = self.materialize_witness(witness) else {
            return false;
        };

        for i in 0..self.n_constraints as usize {
            let Some(left) = dot(&self.a[i], &full_witness) else {
                return false;
            };
            let Some(right) = dot(&self.b[i], &full_witness) else {
                return false;
            };
            let Some(out) = dot(&self.c[i], &full_witness) else {
                return false;
            };
            if left * right != out {
                return false;
            }
        }
        true
    }

    fn materialize_witness(&self, witness: &[FieldElement]) -> Option<Vec<FieldElement>> {
        let mut full = vec![FieldElement::zero(); self.n_wires as usize];
        let copy_len = std::cmp::min(witness.len(), full.len());
        full[..copy_len].copy_from_slice(&witness[..copy_len]);

        // ACIR witnesses don't include compiler-introduced intermediate wires.
        // For MVP lowering, those wires are only introduced by rows of form lhs * rhs = t.
        for i in 0..self.n_constraints as usize {
            let a = &self.a[i];
            let b = &self.b[i];
            let c = &self.c[i];
            if a.len() == 1
                && b.len() == 1
                && c.len() == 1
                && a[0].coeff.is_one()
                && b[0].coeff.is_one()
                && c[0].coeff.is_one()
            {
                let lhs_index = a[0].wire as usize;
                let rhs_index = b[0].wire as usize;
                let target = c[0].wire as usize;
                if target >= full.len() || lhs_index >= full.len() || rhs_index >= full.len() {
                    return None;
                }
                if target >= copy_len {
                    let lhs = full[lhs_index];
                    let rhs = full[rhs_index];
                    full[target] = lhs * rhs;
                }
            }
        }

        Some(full)
    }
}

fn dot(row: &SparseRow, witness: &[FieldElement]) -> Option<FieldElement> {
    row.iter().try_fold(FieldElement::zero(), |acc, term| {
        witness
            .get(term.wire as usize)
            .map(|value| acc + term.coeff * *value)
    })
}

fn lower_assert_zero(
    expr: &Expression,
    next_wire: &mut u32,
    a_rows: &mut Vec<SparseRow>,
    b_rows: &mut Vec<SparseRow>,
    c_rows: &mut Vec<SparseRow>,
) {
    let mut linear_terms: BTreeMap<u32, FieldElement> = BTreeMap::new();

    for (coeff, lhs, rhs) in &expr.mul_terms {
        let t = Witness(*next_wire);
        *next_wire += 1;

        a_rows.push(vec![SparseTerm {
            wire: lhs.witness_index(),
            coeff: FieldElement::one(),
        }]);
        b_rows.push(vec![SparseTerm {
            wire: rhs.witness_index(),
            coeff: FieldElement::one(),
        }]);
        c_rows.push(vec![SparseTerm {
            wire: t.witness_index(),
            coeff: FieldElement::one(),
        }]);

        add_linear(&mut linear_terms, t.witness_index(), *coeff);
    }

    for (coeff, witness) in &expr.linear_combinations {
        add_linear(&mut linear_terms, witness.witness_index(), *coeff);
    }

    if !expr.q_c.is_zero() {
        add_linear(&mut linear_terms, 0, expr.q_c);
    }

    let a_row = vec![SparseTerm {
        wire: 0,
        coeff: FieldElement::one(),
    }];
    let b_row = linear_terms
        .into_iter()
        .map(|(wire, coeff)| SparseTerm { wire, coeff })
        .collect::<Vec<_>>();
    let c_row = Vec::new();

    a_rows.push(a_row);
    b_rows.push(b_row);
    c_rows.push(c_row);
}

fn add_linear(map: &mut BTreeMap<u32, FieldElement>, wire: u32, coeff: FieldElement) {
    let entry = map.entry(wire).or_insert(FieldElement::zero());
    *entry += coeff;
    if entry.is_zero() {
        map.remove(&wire);
    }
}

fn to_r1cs_terms(row: &SparseRow) -> Vec<(R1csFieldElement<32>, u32)> {
    row.iter()
        .map(|term| {
            (
                R1csFieldElement::from(field_to_le_bytes_32(term.coeff)),
                term.wire,
            )
        })
        .collect()
}

fn field_to_le_bytes_32(value: FieldElement) -> [u8; 32] {
    let mut be = value.to_be_bytes();
    if be.len() < 32 {
        let mut padded = vec![0u8; 32 - be.len()];
        padded.extend(be);
        be = padded;
    }

    let mut le = [0u8; 32];
    for (i, byte) in be.into_iter().rev().take(32).enumerate() {
        le[i] = byte;
    }
    le
}

fn bn254_modulus_le_bytes() -> [u8; 32] {
    let mut be = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c,
        0xfd, 0x47,
    ];
    be.reverse();
    be
}

fn opcode_variant(opcode: &Opcode) -> &'static str {
    match opcode {
        Opcode::AssertZero(_) => "AssertZero",
        Opcode::BlackBoxFuncCall(_) => "BlackBoxFuncCall",
        Opcode::Directive(_) => "Directive",
        Opcode::MemoryOp { .. } => "MemoryOp",
        Opcode::MemoryInit { .. } => "MemoryInit",
        Opcode::BrilligCall { .. } => "BrilligCall",
        Opcode::Call { .. } => "Call",
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Cursor};

    use noir_acir::Artifact;
    use noir_witness::generate_witness_from_json_str;
    use r1cs_file::R1csFile;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn constraint_count_matches_mul_terms_plus_one() {
        let artifact = Artifact::from_json_bytes(include_bytes!(
            "../../../test-vectors/fixture_artifact.json"
        ))
        .expect("fixture should parse");
        let circuit = artifact.main_circuit();

        let mul_terms = match &circuit.opcodes[0] {
            Opcode::AssertZero(expr) => expr.mul_terms.len(),
            _ => panic!("expected assert-zero opcode"),
        };

        let system = compile_r1cs(&artifact.program).expect("compile should succeed");
        assert_eq!(system.n_constraints, (mul_terms + 1) as u32);
    }

    #[test]
    fn fixture_witness_satisfies_compiled_r1cs() {
        let artifact = Artifact::from_json_bytes(include_bytes!(
            "../../../test-vectors/fixture_artifact.json"
        ))
        .expect("fixture should parse");
        let witness = generate_witness_from_json_str(
            &artifact,
            include_str!("../../../test-vectors/fixture_inputs.json"),
        )
        .expect("witness generation should succeed");

        let system = compile_r1cs(&artifact.program).expect("compile should succeed");
        assert!(system.is_satisfied(&witness.witness_vector));
    }

    #[test]
    fn tampered_fixture_witness_fails_compiled_r1cs() {
        let artifact = Artifact::from_json_bytes(include_bytes!(
            "../../../test-vectors/fixture_artifact.json"
        ))
        .expect("fixture should parse");
        let witness = generate_witness_from_json_str(
            &artifact,
            include_str!("../../../test-vectors/fixture_inputs.json"),
        )
        .expect("witness generation should succeed");
        let mut tampered = witness.witness_vector.clone();
        tampered[1] += FieldElement::one();

        let system = compile_r1cs(&artifact.program).expect("compile should succeed");
        assert!(!system.is_satisfied(&tampered));
    }

    #[test]
    fn malformed_rows_do_not_panic_and_fail_satisfaction() {
        let system = R1csSystem {
            n_wires: 2,
            n_constraints: 1,
            n_public_outputs: 0,
            n_public_inputs: 0,
            n_private_inputs: 1,
            a: vec![vec![SparseTerm {
                wire: 0,
                coeff: FieldElement::one(),
            }]],
            b: vec![vec![SparseTerm {
                wire: 9,
                coeff: FieldElement::one(),
            }]],
            c: vec![Vec::new()],
        };

        assert!(!system.is_satisfied(&[FieldElement::one(), FieldElement::one()]));
    }

    #[test]
    fn empty_program_is_rejected() {
        let program = Program {
            functions: Vec::new(),
            unconstrained_functions: Vec::new(),
        };

        let err = compile_r1cs(&program).expect_err("empty program should fail");
        assert!(matches!(err, R1csError::EmptyProgram));
    }

    #[test]
    fn unsupported_opcode_is_rejected() {
        let circuit = Circuit {
            current_witness_index: 0,
            opcodes: vec![Opcode::BrilligCall {
                id: 0,
                inputs: Vec::new(),
                outputs: Vec::new(),
                predicate: None,
            }],
            ..Circuit::default()
        };

        let err = compile_r1cs_circuit(&circuit).expect_err("unsupported opcode should fail");
        assert!(matches!(err, R1csError::UnsupportedOpcode(name) if name == "BrilligCall"));
    }

    #[test]
    fn writes_and_roundtrips_r1cs_binary() {
        let artifact = Artifact::from_json_bytes(include_bytes!(
            "../../../test-vectors/fixture_artifact.json"
        ))
        .expect("fixture should parse");
        let system = compile_r1cs(&artifact.program).expect("compile should succeed");

        let dir = TempDir::new().expect("temp dir should be creatable");
        let path = dir.path().join("circuit.r1cs");
        write_r1cs_binary(&system, &path).expect("r1cs write should succeed");

        let bytes = fs::read(path).expect("r1cs file should exist");
        let parsed = R1csFile::<32>::read(Cursor::new(bytes)).expect("r1cs should parse");

        assert_eq!(parsed.header.n_constraints, system.n_constraints);
        assert_eq!(parsed.header.n_wires, system.n_wires);
    }
}
