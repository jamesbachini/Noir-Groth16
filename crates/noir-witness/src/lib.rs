use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::Path,
};

use acir::{
    native_types::{Witness, WitnessMap},
    AcirField, FieldElement,
};
use acvm::pwg::{ACVMStatus, ACVM};
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use noir_acir::{AbiParameter, AbiType, Artifact, ArtifactError};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use wtns_file::{FieldElement as WtnsFieldElement, WtnsFile};

pub use bn254_blackbox_solver::poseidon2_permutation;

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
    #[error("unexpected input value `{0}` that is not present in ABI")]
    UnexpectedInput(String),
    #[error("input `{name}` flattened to {actual} field elements, expected {expected}")]
    InputArityMismatch {
        name: String,
        expected: usize,
        actual: usize,
    },
    #[error("unexpected struct field `{0}`")]
    UnexpectedStructField(String),
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
    pub witness_map: WitnessMap<FieldElement>,
    pub witness_vector: Vec<FieldElement>,
}

#[derive(Clone, Debug, Deserialize)]
struct StructField {
    name: String,
    #[serde(rename = "type")]
    typ: AbiType,
}

impl WitnessArtifacts {
    pub fn witness_map_hex(&self) -> BTreeMap<u32, String> {
        let mut out = BTreeMap::new();
        for (index, value) in self
            .witness_map
            .clone()
            .into_iter()
            .map(|(witness, value): (Witness, FieldElement)| (witness.witness_index(), value))
        {
            out.insert(index, format!("0x{}", value.to_hex()));
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
    let expected_inputs = artifact
        .abi
        .parameters
        .iter()
        .map(|param| param.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut unexpected = input_obj
        .keys()
        .filter(|name| !expected_inputs.contains(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    unexpected.sort_unstable();
    if let Some(name) = unexpected.into_iter().next() {
        return Err(WitnessError::UnexpectedInput(name));
    }

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

    let solver = Bn254BlackBoxSolver;
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
        "string" => {
            let len_u64 = typ
                .extra
                .get("length")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    WitnessError::UnsupportedAbiType("string missing length".to_string())
                })?;
            let len = usize::try_from(len_u64).map_err(|_| {
                WitnessError::UnsupportedAbiType("string length does not fit usize".to_string())
            })?;

            let string = value.as_str().ok_or_else(|| {
                WitnessError::InvalidFieldValue(format!("expected string, got {value}"))
            })?;
            let bytes = string.as_bytes();
            if bytes.len() != len {
                return Err(WitnessError::InvalidFieldValue(format!(
                    "string length mismatch: expected {len}, got {}",
                    bytes.len()
                )));
            }

            Ok(bytes
                .iter()
                .map(|byte| FieldElement::from(u128::from(*byte)))
                .collect())
        }
        "array" => {
            let len_u64 = typ
                .extra
                .get("length")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    WitnessError::UnsupportedAbiType("array missing length".to_string())
                })?;
            let len = usize::try_from(len_u64).map_err(|_| {
                WitnessError::UnsupportedAbiType("array length does not fit usize".to_string())
            })?;

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
            let fields: Vec<StructField> =
                serde_json::from_value(fields_value.clone()).map_err(|_| {
                    WitnessError::UnsupportedAbiType("invalid struct fields".to_string())
                })?;

            let obj = value.as_object().ok_or_else(|| {
                WitnessError::InvalidFieldValue(format!("expected struct object, got {value}"))
            })?;
            let expected_fields = fields
                .iter()
                .map(|field| field.name.as_str())
                .collect::<BTreeSet<_>>();
            let mut unexpected = obj
                .keys()
                .filter(|field| !expected_fields.contains(field.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            unexpected.sort_unstable();
            if let Some(field) = unexpected.into_iter().next() {
                return Err(WitnessError::UnexpectedStructField(field));
            }

            let mut flattened = Vec::new();
            for field in fields {
                let field_value = obj.get(&field.name).ok_or_else(|| {
                    WitnessError::InvalidFieldValue(format!(
                        "missing struct field `{}`",
                        field.name
                    ))
                })?;
                flattened.extend(flatten_value_for_type(&field.typ, field_value)?);
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
    witness_map: &WitnessMap<FieldElement>,
    current_witness_index: u32,
) -> Vec<FieldElement> {
    let mut witness_vector = vec![FieldElement::zero(); (current_witness_index + 2) as usize];
    witness_vector[0] = FieldElement::one();
    for index in 0..=current_witness_index {
        if let Some(value) = witness_map.get_index(index) {
            witness_vector[(index + 1) as usize] = *value;
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
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
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
        let expected = poseidon2_permutation(&inputs).expect("poseidon2 reference should run");

        let poseidon = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Poseidon2Permutation {
            inputs: vec![
                FunctionInput::Witness(Witness(1)),
                FunctionInput::Witness(Witness(2)),
                FunctionInput::Witness(Witness(3)),
                FunctionInput::Witness(Witness(4)),
            ],
            outputs: vec![Witness(5), Witness(6), Witness(7), Witness(8)],
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
        assert_eq!(
            parsed.header.prime,
            WtnsFieldElement::from(bn254_modulus_le_bytes())
        );
    }

    #[test]
    fn rejects_unexpected_top_level_input() {
        let artifact = Artifact::from_json_bytes(include_bytes!(
            "../../../test-vectors/fixture_artifact.json"
        ))
        .expect("fixture should parse");
        let inputs = serde_json::json!({
            "x": "3",
            "y": "12",
            "z": "999"
        });

        let err = generate_witness(&artifact, &inputs).expect_err("unexpected input should fail");
        assert!(matches!(err, WitnessError::UnexpectedInput(name) if name == "z"));
    }

    #[test]
    fn rejects_unexpected_struct_field() {
        let struct_type: AbiType = serde_json::from_value(serde_json::json!({
            "kind": "struct",
            "fields": [
                {
                    "name": "a",
                    "type": { "kind": "field" }
                }
            ]
        }))
        .expect("struct type should parse");

        let circuit = Circuit {
            current_witness_index: 1,
            private_parameters: BTreeSet::from([Witness(1)]),
            ..Circuit::default()
        };
        let artifact = Artifact {
            noir_version: None,
            abi: noir_acir::Abi {
                parameters: vec![noir_acir::AbiParameter {
                    name: "obj".to_string(),
                    typ: struct_type,
                    visibility: noir_acir::AbiVisibility::Private,
                }],
                return_type: None,
                error_types: BTreeMap::new(),
            },
            program: Program {
                functions: vec![circuit],
                unconstrained_functions: vec![],
            },
            program_bytes: Vec::new(),
        };

        let inputs = serde_json::json!({
            "obj": {
                "a": "1",
                "extra": "2"
            }
        });
        let err = generate_witness(&artifact, &inputs)
            .expect_err("unexpected struct field should fail witness generation");
        assert!(matches!(err, WitnessError::UnexpectedStructField(field) if field == "extra"));
    }

    #[test]
    fn supports_string_abi_inputs() {
        let string_type: AbiType = serde_json::from_value(serde_json::json!({
            "kind": "string",
            "length": 3
        }))
        .expect("string ABI type should parse");

        let circuit = Circuit {
            current_witness_index: 3,
            private_parameters: BTreeSet::from([Witness(1), Witness(2), Witness(3)]),
            ..Circuit::default()
        };
        let artifact = Artifact {
            noir_version: None,
            abi: noir_acir::Abi {
                parameters: vec![noir_acir::AbiParameter {
                    name: "msg".to_string(),
                    typ: string_type,
                    visibility: noir_acir::AbiVisibility::Private,
                }],
                return_type: None,
                error_types: BTreeMap::new(),
            },
            program: Program {
                functions: vec![circuit],
                unconstrained_functions: vec![],
            },
            program_bytes: Vec::new(),
        };

        let inputs = serde_json::json!({ "msg": "cat" });
        let witness = generate_witness(&artifact, &inputs).expect("string ABI should flatten");
        assert_eq!(
            witness.witness_map.get_index(1),
            Some(&FieldElement::from(u128::from(b'c')))
        );
        assert_eq!(
            witness.witness_map.get_index(2),
            Some(&FieldElement::from(u128::from(b'a')))
        );
        assert_eq!(
            witness.witness_map.get_index(3),
            Some(&FieldElement::from(u128::from(b't')))
        );
    }

    #[test]
    fn rejects_string_abi_length_mismatch() {
        let string_type: AbiType = serde_json::from_value(serde_json::json!({
            "kind": "string",
            "length": 4
        }))
        .expect("string ABI type should parse");

        let circuit = Circuit {
            current_witness_index: 4,
            private_parameters: BTreeSet::from([Witness(1), Witness(2), Witness(3), Witness(4)]),
            ..Circuit::default()
        };
        let artifact = Artifact {
            noir_version: None,
            abi: noir_acir::Abi {
                parameters: vec![noir_acir::AbiParameter {
                    name: "msg".to_string(),
                    typ: string_type,
                    visibility: noir_acir::AbiVisibility::Private,
                }],
                return_type: None,
                error_types: BTreeMap::new(),
            },
            program: Program {
                functions: vec![circuit],
                unconstrained_functions: vec![],
            },
            program_bytes: Vec::new(),
        };

        let inputs = serde_json::json!({ "msg": "cat" });
        let err =
            generate_witness(&artifact, &inputs).expect_err("string length mismatch should fail");
        assert!(matches!(err, WitnessError::InvalidFieldValue(name) if name == "msg"));
    }

    #[test]
    fn witness_map_hex_uses_numeric_key_ordering() {
        let mut witness_map = WitnessMap::new();
        witness_map.insert(Witness(10), FieldElement::from(10u128));
        witness_map.insert(Witness(2), FieldElement::from(2u128));
        witness_map.insert(Witness(1), FieldElement::from(1u128));

        let witness = WitnessArtifacts {
            witness_map,
            witness_vector: Vec::new(),
        };
        let keys = witness
            .witness_map_hex()
            .keys()
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(keys, vec![1, 2, 10]);
    }
}
