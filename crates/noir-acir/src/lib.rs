use std::collections::BTreeMap;

use acir::circuit::{Circuit, Opcode, Program};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("failed to parse artifact json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("artifact bytecode has no functions")]
    EmptyProgram,
    #[error("abi parameter `{name}` could not be assigned witnesses: needed {needed}, remaining {remaining}")]
    WitnessAllocation {
        name: String,
        needed: usize,
        remaining: usize,
    },
    #[error("unsupported ABI type kind `{0}`")]
    UnsupportedAbiType(String),
    #[error("ABI type kind `{kind}` is missing required key `{key}`")]
    MissingAbiTypeKey { kind: String, key: &'static str },
    #[error("invalid ABI shape: {0}")]
    InvalidAbiShape(String),
}

#[derive(Clone, Debug)]
pub struct Artifact {
    pub noir_version: Option<String>,
    pub abi: Abi,
    pub program: Program,
    pub program_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ParsedSummary {
    pub opcode_count: usize,
    pub witness_count: u32,
    pub opcode_variants: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WitnessLayout {
    pub parameters: Vec<ParameterWitnesses>,
    pub return_witnesses: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ParameterWitnesses {
    pub name: String,
    pub visibility: AbiVisibility,
    pub witnesses: Vec<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Abi {
    pub parameters: Vec<AbiParameter>,
    pub return_type: Option<AbiType>,
    #[serde(default)]
    pub error_types: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiParameter {
    pub name: String,
    #[serde(rename = "type")]
    pub typ: AbiType,
    pub visibility: AbiVisibility,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AbiVisibility {
    Public,
    Private,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiType {
    pub kind: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
struct ArtifactFile {
    #[serde(default)]
    noir_version: Option<String>,
    abi: Abi,
    #[serde(deserialize_with = "Program::deserialize_program_base64")]
    bytecode: Program,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct AbiStructField {
    name: String,
    #[serde(rename = "type")]
    typ: AbiType,
}

impl Artifact {
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ArtifactError> {
        let artifact: ArtifactFile = serde_json::from_slice(bytes)?;
        if artifact.bytecode.functions.is_empty() {
            return Err(ArtifactError::EmptyProgram);
        }

        Ok(Self {
            noir_version: artifact.noir_version,
            abi: artifact.abi,
            program_bytes: Program::serialize_program(&artifact.bytecode),
            program: artifact.bytecode,
        })
    }

    pub fn from_json_str(json: &str) -> Result<Self, ArtifactError> {
        Self::from_json_bytes(json.as_bytes())
    }

    pub fn main_circuit(&self) -> &Circuit {
        &self.program.functions[0]
    }

    pub fn opcode_summary(&self) -> ParsedSummary {
        let circuit = self.main_circuit();
        let mut variants = std::collections::BTreeSet::new();
        for opcode in &circuit.opcodes {
            variants.insert(opcode_variant_name(opcode).to_string());
        }

        ParsedSummary {
            opcode_count: circuit.opcodes.len(),
            witness_count: circuit.current_witness_index + 1,
            opcode_variants: variants.into_iter().collect(),
        }
    }

    pub fn witness_layout(&self) -> Result<WitnessLayout, ArtifactError> {
        let circuit = self.main_circuit();
        let mut private = circuit
            .private_parameters
            .iter()
            .map(|w| w.witness_index())
            .collect::<Vec<_>>();
        private.sort_unstable();

        let mut public = circuit.public_parameters.indices();
        public.sort_unstable();

        let mut private_cursor = 0usize;
        let mut public_cursor = 0usize;
        let mut parameters = Vec::with_capacity(self.abi.parameters.len());

        for parameter in &self.abi.parameters {
            let count = parameter.typ.field_count()?;
            let (source, cursor) = match parameter.visibility {
                AbiVisibility::Private => (&private, &mut private_cursor),
                AbiVisibility::Public => (&public, &mut public_cursor),
            };

            if source.len() < *cursor + count {
                return Err(ArtifactError::WitnessAllocation {
                    name: parameter.name.clone(),
                    needed: count,
                    remaining: source.len().saturating_sub(*cursor),
                });
            }

            let witnesses = source[*cursor..*cursor + count].to_vec();
            *cursor += count;

            parameters.push(ParameterWitnesses {
                name: parameter.name.clone(),
                visibility: parameter.visibility.clone(),
                witnesses,
            });
        }

        let mut return_witnesses = self.main_circuit().return_values.indices();
        return_witnesses.sort_unstable();

        Ok(WitnessLayout {
            parameters,
            return_witnesses,
        })
    }
}

impl AbiType {
    pub fn field_count(&self) -> Result<usize, ArtifactError> {
        match self.kind.as_str() {
            "field" | "boolean" | "integer" => Ok(1),
            "array" => {
                let len = self.require_u64("length")? as usize;
                let inner = self.require_type("type")?;
                Ok(len * inner.field_count()?)
            }
            "tuple" => {
                let fields = self.require_types("fields")?;
                let mut total = 0usize;
                for field in fields {
                    total += field.field_count()?;
                }
                Ok(total)
            }
            "struct" => {
                let fields_val = self.require_value("fields")?;
                let fields: Vec<AbiStructField> = serde_json::from_value(fields_val.clone())
                    .map_err(|err| ArtifactError::InvalidAbiShape(err.to_string()))?;
                let mut total = 0usize;
                for field in fields {
                    total += field.typ.field_count()?;
                }
                Ok(total)
            }
            other => Err(ArtifactError::UnsupportedAbiType(other.to_string())),
        }
    }

    fn require_value(&self, key: &'static str) -> Result<&Value, ArtifactError> {
        self.extra
            .get(key)
            .ok_or_else(|| ArtifactError::MissingAbiTypeKey {
                kind: self.kind.clone(),
                key,
            })
    }

    fn require_type(&self, key: &'static str) -> Result<AbiType, ArtifactError> {
        let value = self.require_value(key)?;
        serde_json::from_value(value.clone())
            .map_err(|err| ArtifactError::InvalidAbiShape(err.to_string()))
    }

    fn require_types(&self, key: &'static str) -> Result<Vec<AbiType>, ArtifactError> {
        let value = self.require_value(key)?;
        serde_json::from_value(value.clone())
            .map_err(|err| ArtifactError::InvalidAbiShape(err.to_string()))
    }

    fn require_u64(&self, key: &'static str) -> Result<u64, ArtifactError> {
        self.require_value(key)?.as_u64().ok_or_else(|| {
            ArtifactError::InvalidAbiShape(format!(
                "ABI type `{}` key `{}` must be an unsigned integer",
                self.kind, key
            ))
        })
    }
}

pub fn opcode_variant_name(opcode: &Opcode) -> &'static str {
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
    use super::*;

    #[test]
    fn parse_fixture_contains_assert_zero() {
        let bytes = include_bytes!("../../../test-vectors/fixture_artifact.json");
        let artifact = Artifact::from_json_bytes(bytes).expect("fixture should parse");
        let summary = artifact.opcode_summary();
        assert!(summary
            .opcode_variants
            .iter()
            .any(|name| name == "AssertZero"));
    }

    #[test]
    fn parsed_summary_snapshot_is_stable() {
        let bytes = include_bytes!("../../../test-vectors/fixture_artifact.json");
        let artifact = Artifact::from_json_bytes(bytes).expect("fixture should parse");
        let json = serde_json::to_string_pretty(&artifact.opcode_summary())
            .expect("summary serialization should succeed");

        let expected = r#"{
  "opcode_count": 1,
  "witness_count": 4,
  "opcode_variants": [
    "AssertZero"
  ]
}"#;
        assert_eq!(json, expected);
    }
}
