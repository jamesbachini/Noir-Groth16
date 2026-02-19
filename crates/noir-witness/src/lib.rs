use std::{collections::BTreeMap, io::Write, path::Path};

use acir::{
    native_types::{Witness, WitnessMap},
    BlackBoxFunc, FieldElement,
};
use acvm::pwg::{ACVMStatus, ACVM};
use noir_acir::{AbiParameter, AbiType, Artifact, ArtifactError};
use serde_json::Value;
use thiserror::Error;
use wtns_file::{FieldElement as WtnsFieldElement, WtnsFile};

mod poseidon2;
pub use poseidon2::poseidon2_permutation;

#[derive(Debug, Error)]
pub enum WitnessError {
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    #[error("failed to parse inputs json: {0}")]
    InputsJson(#[from] serde_json::Error),
    #[error("inputs json must be a JSON object")]
    InputsMustBeObject,
    #[error("missing input value for parameter `{0}`")]
    MissingInput(String),
    #[error("input `{name}` flattened to {actual} field elements, expected {expected}")]
    InputArityMismatch {
        name: String,
        expected: usize,
        actual: usize,
    },
    #[error("failed to parse field value for `{0}`")]
    InvalidFieldValue(String),
    #[error("unsupported ABI type kind `{0}`")]
    UnsupportedAbiType(String),
    #[error("ACVM failed to solve: {0}")]
    SolverFailed(String),
    #[error("unsupported ACVM status while solving: {0}")]
    UnsupportedAcvmStatus(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Debug)]
pub struct WitnessArtifacts {
    pub witness_map: WitnessMap,
    pub witness_vector: Vec<FieldElement>,
}

#[derive(Clone, Copy, Debug)]
struct NoirBn254BlackBoxSolver;

impl NoirBn254BlackBoxSolver {
    fn unsupported(function: BlackBoxFunc) -> acvm::BlackBoxResolutionError {
        acvm::BlackBoxResolutionError::Failed(
            function,
            format!("{} is not supported", function.name()),
        )
    }
}

impl acvm::BlackBoxFunctionSolver for NoirBn254BlackBoxSolver {
    fn schnorr_verify(
        &self,
        _public_key_x: &FieldElement,
        _public_key_y: &FieldElement,
        _signature: &[u8; 64],
        _message: &[u8],
    ) -> Result<bool, acvm::BlackBoxResolutionError> {
        Err(Self::unsupported(BlackBoxFunc::SchnorrVerify))
    }

    fn pedersen_commitment(
        &self,
        _inputs: &[FieldElement],
        _domain_separator: u32,
    ) -> Result<(FieldElement, FieldElement), acvm::BlackBoxResolutionError> {
        Err(Self::unsupported(BlackBoxFunc::PedersenCommitment))
    }

    fn pedersen_hash(
        &self,
        _inputs: &[FieldElement],
        _domain_separator: u32,
    ) -> Result<FieldElement, acvm::BlackBoxResolutionError> {
        Err(Self::unsupported(BlackBoxFunc::PedersenHash))
    }

    fn multi_scalar_mul(
        &self,
        _points: &[FieldElement],
        _scalars: &[FieldElement],
    ) -> Result<(FieldElement, FieldElement), acvm::BlackBoxResolutionError> {
        Err(Self::unsupported(BlackBoxFunc::MultiScalarMul))
    }

    fn ec_add(
        &self,
        _input1_x: &FieldElement,
        _input1_y: &FieldElement,
        _input2_x: &FieldElement,
        _input2_y: &FieldElement,
    ) -> Result<(FieldElement, FieldElement), acvm::BlackBoxResolutionError> {
        Err(Self::unsupported(BlackBoxFunc::EmbeddedCurveAdd))
    }

    fn poseidon2_permutation(
        &self,
        inputs: &[FieldElement],
        len: u32,
    ) -> Result<Vec<FieldElement>, acvm::BlackBoxResolutionError> {
        poseidon2_permutation(inputs, len)
    }
}

impl WitnessArtifacts {
    pub fn witness_map_hex(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for (index, value) in self
            .witness_map
            .clone()
            .into_iter()
            .map(|(witness, value)| (witness.witness_index(), value))
        {
            out.insert(index.to_string(), format!("0x{}", value.to_hex()));
        }
        out
    }

    pub fn witness_bin(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.witness_vector.len() * 32);
        for value in &self.witness_vector {
            out.extend_from_slice(&field_to_le_bytes_32(*value));
        }
        out
    }

    pub fn write_witness_map_json(&self, path: impl AsRef<Path>) -> Result<(), WitnessError> {
        let json = serde_json::to_vec_pretty(&self.witness_map_hex())
            .map_err(|err| WitnessError::SolverFailed(err.to_string()))?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn write_witness_bin(&self, path: impl AsRef<Path>) -> Result<(), WitnessError> {
        std::fs::write(path, self.witness_bin())?;
        Ok(())
    }

    pub fn write_wtns(&self, path: impl AsRef<Path>) -> Result<(), WitnessError> {
        let witness = self
            .witness_vector
            .iter()
            .map(|value| WtnsFieldElement::from(field_to_le_bytes_32(*value)))
            .collect::<Vec<_>>();

        let file =
            WtnsFile::<32>::from_vec(witness, WtnsFieldElement::from(bn254_modulus_le_bytes()));
        let mut output = std::fs::File::create(path)?;
        file.write(&mut output)?;
        output.flush()?;
        Ok(())
    }
}

pub fn generate_witness_from_json_str(
    artifact: &Artifact,
    inputs_json: &str,
) -> Result<WitnessArtifacts, WitnessError> {
    let inputs: Value = serde_json::from_str(inputs_json)?;
    generate_witness(artifact, &inputs)
}

pub fn generate_witness(
    artifact: &Artifact,
    inputs: &Value,
) -> Result<WitnessArtifacts, WitnessError> {
    let input_obj = inputs.as_object().ok_or(WitnessError::InputsMustBeObject)?;
    let layout = artifact.witness_layout()?;

    let mut initial_witness = WitnessMap::new();
    for (param, assigned) in artifact.abi.parameters.iter().zip(layout.parameters.iter()) {
        let value = input_obj
            .get(&param.name)
            .ok_or_else(|| WitnessError::MissingInput(param.name.clone()))?;

        let flattened = flatten_value_for_param(param, value)?;
        if flattened.len() != assigned.witnesses.len() {
            return Err(WitnessError::InputArityMismatch {
                name: param.name.clone(),
                expected: assigned.witnesses.len(),
                actual: flattened.len(),
            });
        }

        for (witness_index, field) in assigned.witnesses.iter().zip(flattened.into_iter()) {
            initial_witness.insert(Witness(*witness_index), field);
        }
    }

    let solver = NoirBn254BlackBoxSolver;
    let circuit = artifact.main_circuit();
    let mut acvm = ACVM::new(
        &solver,
        &circuit.opcodes,
        initial_witness,
        &artifact.program.unconstrained_functions,
        &circuit.assert_messages,
    );

    match acvm.solve() {
        ACVMStatus::Solved => {}
        ACVMStatus::Failure(err) => {
            return Err(WitnessError::SolverFailed(err.to_string()));
        }
        other => {
            return Err(WitnessError::UnsupportedAcvmStatus(other.to_string()));
        }
    }

    let witness_map = acvm.finalize();
    let witness_vector = witness_map_to_vector(&witness_map, circuit.current_witness_index);

    Ok(WitnessArtifacts {
        witness_map,
        witness_vector,
    })
}

fn flatten_value_for_param(
    param: &AbiParameter,
    value: &Value,
) -> Result<Vec<FieldElement>, WitnessError> {
    flatten_value_for_type(&param.typ, value).map_err(|err| match err {
        WitnessError::InvalidFieldValue(_) => WitnessError::InvalidFieldValue(param.name.clone()),
        other => other,
    })
}

fn flatten_value_for_type(typ: &AbiType, value: &Value) -> Result<Vec<FieldElement>, WitnessError> {
    match typ.kind.as_str() {
        "field" | "integer" => Ok(vec![parse_field(value)?]),
        "boolean" => {
            let b = value.as_bool().ok_or_else(|| {
                WitnessError::InvalidFieldValue(format!("expected bool, got {value}"))
            })?;
            Ok(vec![FieldElement::from(b)])
        }
        "array" => {
            let len = typ
                .extra
                .get("length")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    WitnessError::UnsupportedAbiType("array missing length".to_string())
                })? as usize;

            let inner_value = typ.extra.get("type").ok_or_else(|| {
                WitnessError::UnsupportedAbiType("array missing type".to_string())
            })?;
            let inner: AbiType = serde_json::from_value(inner_value.clone()).map_err(|_| {
                WitnessError::UnsupportedAbiType("invalid array inner type".to_string())
            })?;

            let arr = value.as_array().ok_or_else(|| {
                WitnessError::InvalidFieldValue(format!("expected array, got {value}"))
            })?;
            if arr.len() != len {
                return Err(WitnessError::InvalidFieldValue(format!(
                    "array length mismatch: expected {len}, got {}",
                    arr.len()
                )));
            }

            let mut flattened = Vec::new();
            for item in arr {
                flattened.extend(flatten_value_for_type(&inner, item)?);
            }
            Ok(flattened)
        }
        "tuple" => {
            let fields_value = typ.extra.get("fields").ok_or_else(|| {
                WitnessError::UnsupportedAbiType("tuple missing fields".to_string())
            })?;
            let fields: Vec<AbiType> =
                serde_json::from_value(fields_value.clone()).map_err(|_| {
                    WitnessError::UnsupportedAbiType("invalid tuple fields".to_string())
                })?;

            let arr = value.as_array().ok_or_else(|| {
                WitnessError::InvalidFieldValue(format!("expected tuple array, got {value}"))
            })?;
            if arr.len() != fields.len() {
                return Err(WitnessError::InvalidFieldValue(format!(
                    "tuple arity mismatch: expected {}, got {}",
                    fields.len(),
                    arr.len()
                )));
            }

            let mut flattened = Vec::new();
            for (field_typ, field_val) in fields.iter().zip(arr.iter()) {
                flattened.extend(flatten_value_for_type(field_typ, field_val)?);
            }
            Ok(flattened)
        }
        "struct" => {
            let fields_value = typ.extra.get("fields").ok_or_else(|| {
                WitnessError::UnsupportedAbiType("struct missing fields".to_string())
            })?;
            let fields: Vec<serde_json::Value> = serde_json::from_value(fields_value.clone())
                .map_err(|_| {
                    WitnessError::UnsupportedAbiType("invalid struct fields".to_string())
                })?;

            let obj = value.as_object().ok_or_else(|| {
                WitnessError::InvalidFieldValue(format!("expected struct object, got {value}"))
            })?;

            let mut flattened = Vec::new();
            for field in fields {
                let name = field.get("name").and_then(Value::as_str).ok_or_else(|| {
                    WitnessError::UnsupportedAbiType("struct field missing name".to_string())
                })?;
                let typ_value = field.get("type").ok_or_else(|| {
                    WitnessError::UnsupportedAbiType("struct field missing type".to_string())
                })?;
                let field_typ: AbiType =
                    serde_json::from_value(typ_value.clone()).map_err(|_| {
                        WitnessError::UnsupportedAbiType("invalid struct field type".to_string())
                    })?;
                let field_value = obj.get(name).ok_or_else(|| {
                    WitnessError::InvalidFieldValue(format!("missing struct field `{name}`"))
                })?;
                flattened.extend(flatten_value_for_type(&field_typ, field_value)?);
            }
            Ok(flattened)
        }
        other => Err(WitnessError::UnsupportedAbiType(other.to_string())),
    }
}

fn parse_field(value: &Value) -> Result<FieldElement, WitnessError> {
    if let Some(v) = value.as_u64() {
        return Ok(FieldElement::from(v as u128));
    }
    if let Some(v) = value.as_i64() {
        return FieldElement::try_from_str(&v.to_string())
            .ok_or_else(|| WitnessError::InvalidFieldValue(value.to_string()));
    }
    if let Some(v) = value.as_bool() {
        return Ok(FieldElement::from(v));
    }
    if let Some(s) = value.as_str() {
        return FieldElement::try_from_str(s)
            .or_else(|| FieldElement::from_hex(s))
            .ok_or_else(|| WitnessError::InvalidFieldValue(s.to_string()));
    }

    Err(WitnessError::InvalidFieldValue(value.to_string()))
}

fn witness_map_to_vector(
    witness_map: &WitnessMap,
    current_witness_index: u32,
) -> Vec<FieldElement> {
    let mut witness_vector = vec![FieldElement::zero(); (current_witness_index + 1) as usize];
    witness_vector[0] = FieldElement::one();
    for index in 1..=current_witness_index {
        if let Some(value) = witness_map.get_index(index) {
            witness_vector[index as usize] = *value;
        }
    }
    witness_vector
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, io::Cursor};

    use acir::{
        circuit::{
            opcodes::{BlackBoxFuncCall, FunctionInput},
            Circuit, Opcode, Program,
        },
        native_types::{Expression, Witness},
        FieldElement,
    };
    use tempfile::TempDir;

    use super::*;

    fn field_typ() -> noir_acir::AbiType {
        noir_acir::AbiType {
            kind: "field".to_string(),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn witness_bin_is_deterministic_for_fixture() {
        let artifact_bytes = include_bytes!("../../../test-vectors/fixture_artifact.json");
        let inputs = include_str!("../../../test-vectors/fixture_inputs.json");

        let artifact = Artifact::from_json_bytes(artifact_bytes).expect("fixture should parse");

        let first = generate_witness_from_json_str(&artifact, inputs)
            .expect("witness generation should succeed");
        let second = generate_witness_from_json_str(&artifact, inputs)
            .expect("witness generation should succeed");

        assert_eq!(first.witness_bin(), second.witness_bin());
    }

    #[test]
    fn poseidon2_smoke_matches_expected_output() {
        let inputs = vec![
            FieldElement::from(1u128),
            FieldElement::from(2u128),
            FieldElement::from(3u128),
            FieldElement::from(4u128),
        ];
        let expected = poseidon2_permutation(&inputs, 4).expect("poseidon2 reference should run");

        let poseidon = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Poseidon2Permutation {
            inputs: vec![
                FunctionInput {
                    witness: Witness(1),
                    num_bits: FieldElement::max_num_bits(),
                },
                FunctionInput {
                    witness: Witness(2),
                    num_bits: FieldElement::max_num_bits(),
                },
                FunctionInput {
                    witness: Witness(3),
                    num_bits: FieldElement::max_num_bits(),
                },
                FunctionInput {
                    witness: Witness(4),
                    num_bits: FieldElement::max_num_bits(),
                },
            ],
            outputs: vec![Witness(5), Witness(6), Witness(7), Witness(8)],
            len: 4,
        });

        // Add one arithmetic constraint so this fixture also exercises AssertZero solving.
        let bind = Opcode::AssertZero(Expression {
            mul_terms: Vec::new(),
            linear_combinations: vec![
                (FieldElement::one(), Witness(5)),
                (-FieldElement::one(), Witness(9)),
            ],
            q_c: FieldElement::zero(),
        });

        let circuit = Circuit {
            current_witness_index: 9,
            opcodes: vec![poseidon, bind],
            private_parameters: BTreeSet::from([Witness(1), Witness(2), Witness(3), Witness(4)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: vec![],
        };

        let artifact = Artifact {
            noir_version: None,
            abi: noir_acir::Abi {
                parameters: vec![
                    noir_acir::AbiParameter {
                        name: "a".to_string(),
                        typ: field_typ(),
                        visibility: noir_acir::AbiVisibility::Private,
                    },
                    noir_acir::AbiParameter {
                        name: "b".to_string(),
                        typ: field_typ(),
                        visibility: noir_acir::AbiVisibility::Private,
                    },
                    noir_acir::AbiParameter {
                        name: "c".to_string(),
                        typ: field_typ(),
                        visibility: noir_acir::AbiVisibility::Private,
                    },
                    noir_acir::AbiParameter {
                        name: "d".to_string(),
                        typ: field_typ(),
                        visibility: noir_acir::AbiVisibility::Private,
                    },
                ],
                return_type: None,
                error_types: BTreeMap::new(),
            },
            program_bytes: Program::serialize_program(&program),
            program,
        };

        let inputs = serde_json::json!({
            "a": "1",
            "b": "2",
            "c": "3",
            "d": "4"
        });

        let witness = generate_witness(&artifact, &inputs).expect("poseidon witness should solve");

        assert_eq!(witness.witness_map.get_index(5), Some(&expected[0]));
        assert_eq!(witness.witness_map.get_index(6), Some(&expected[1]));
        assert_eq!(witness.witness_map.get_index(7), Some(&expected[2]));
        assert_eq!(witness.witness_map.get_index(8), Some(&expected[3]));
    }

    #[test]
    fn writes_wtns_file() {
        let artifact_bytes = include_bytes!("../../../test-vectors/fixture_artifact.json");
        let inputs = include_str!("../../../test-vectors/fixture_inputs.json");
        let artifact = Artifact::from_json_bytes(artifact_bytes).expect("fixture should parse");
        let witness = generate_witness_from_json_str(&artifact, inputs)
            .expect("witness generation should succeed");

        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("witness.wtns");
        witness
            .write_wtns(&path)
            .expect("wtns write should succeed");

        let bytes = fs::read(path).expect("read written wtns");
        let parsed = WtnsFile::<32>::read(Cursor::new(bytes)).expect("wtns should parse");
        assert_eq!(parsed.witness.0.len(), witness.witness_vector.len());
    }
}
