use std::collections::BTreeMap;

use acir::{
    circuit::{Circuit, Opcode, Program},
    FieldElement,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("failed to parse artifact json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed decoding artifact bytecode: {0}")]
    BytecodeDecode(String),
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
    pub program: Program<FieldElement>,
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
    bytecode: String,
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
        let bytecode = deserialize_program_base64_compatible(&artifact.bytecode)?;
        if bytecode.functions.is_empty() {
            return Err(ArtifactError::EmptyProgram);
        }

        Ok(Self {
            noir_version: artifact.noir_version,
            abi: artifact.abi,
            program_bytes: Program::serialize_program(&bytecode),
            program: bytecode,
        })
    }

    pub fn from_json_str(json: &str) -> Result<Self, ArtifactError> {
        Self::from_json_bytes(json.as_bytes())
    }

    pub fn main_circuit(&self) -> &Circuit<FieldElement> {
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

fn deserialize_program_base64_compatible(
    encoded_b64: &str,
) -> Result<Program<FieldElement>, ArtifactError> {
    let program_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded_b64)
        .map_err(|err| ArtifactError::BytecodeDecode(err.to_string()))?;

    if let Ok(program) = Program::deserialize_program(&program_bytes) {
        return Ok(program);
    }

    let legacy_program =
        acir_legacy::circuit::Program::<acir_legacy::FieldElement>::deserialize_program(
            &program_bytes,
        )
        .ok();
    let mut value = if let Some(legacy_program) = legacy_program {
        serde_json::to_value(legacy_program)
            .map_err(|err| ArtifactError::BytecodeDecode(err.to_string()))?
    } else {
        let legacy_046 = acir_046::circuit::Program::deserialize_program(&program_bytes)
            .map_err(|err| ArtifactError::BytecodeDecode(err.to_string()))?;
        let mut value = serde_json::to_value(legacy_046)
            .map_err(|err| ArtifactError::BytecodeDecode(err.to_string()))?;
        upgrade_046_program_json(&mut value);
        value
    };
    upgrade_legacy_program_json(&mut value)?;
    serde_json::from_value(value).map_err(|err| ArtifactError::BytecodeDecode(err.to_string()))
}

fn upgrade_legacy_program_json(value: &mut Value) -> Result<(), ArtifactError> {
    let predicate_true =
        serde_json::to_value(acir::native_types::Expression::<FieldElement>::one())
            .map_err(|err| ArtifactError::BytecodeDecode(err.to_string()))?;

    let Some(functions) = value.get_mut("functions").and_then(Value::as_array_mut) else {
        return Ok(());
    };

    for function in functions {
        let Some(opcodes) = function.get_mut("opcodes").and_then(Value::as_array_mut) else {
            continue;
        };

        for opcode in opcodes {
            let Some(opcode_obj) = opcode.as_object_mut() else {
                continue;
            };

            for call_variant in ["BrilligCall", "Call"] {
                let Some(call) = opcode_obj
                    .get_mut(call_variant)
                    .and_then(Value::as_object_mut)
                else {
                    continue;
                };

                let needs_predicate = call.get("predicate").is_none_or(Value::is_null);

                if needs_predicate {
                    call.insert("predicate".to_string(), predicate_true.clone());
                }
            }
        }
    }

    Ok(())
}

fn upgrade_046_program_json(value: &mut Value) {
    let Some(functions) = value.get_mut("functions").and_then(Value::as_array_mut) else {
        return;
    };

    for function in functions {
        let Some(function_obj) = function.as_object_mut() else {
            continue;
        };

        function_obj.remove("expression_width");
        function_obj.remove("recursive");

        if let Some(assert_messages) = function_obj
            .get_mut("assert_messages")
            .and_then(Value::as_array_mut)
        {
            for entry in assert_messages {
                let Some(parts) = entry.as_array_mut() else {
                    continue;
                };
                if parts.len() != 2 {
                    continue;
                }
                let payload = &parts[1];
                let replacement = payload.as_object().and_then(|obj| {
                    obj.get("StaticString")
                        .map(|_| serde_json::json!({"error_selector": 0u64, "payload": []}))
                        .or_else(|| {
                            obj.get("Dynamic").and_then(|v| {
                                let parts = v.as_array()?;
                                if parts.len() != 2 {
                                    return None;
                                }
                                Some(serde_json::json!({
                                    "error_selector": parts[0],
                                    "payload": parts[1],
                                }))
                            })
                        })
                });
                if let Some(new_payload) = replacement {
                    parts[1] = new_payload;
                }
            }
        }

        if let Some(opcodes) = function_obj
            .get_mut("opcodes")
            .and_then(Value::as_array_mut)
        {
            for opcode in opcodes {
                let Some(op_obj) = opcode.as_object_mut() else {
                    continue;
                };
                if let Some(mem_init) = op_obj.get_mut("MemoryInit").and_then(Value::as_object_mut)
                {
                    mem_init
                        .entry("block_type".to_string())
                        .or_insert_with(|| Value::String("Memory".to_string()));
                }
                if let Some(mem_op) = op_obj.get_mut("MemoryOp").and_then(Value::as_object_mut) {
                    mem_op.remove("predicate");
                }
                if let Some(bb) = op_obj
                    .get_mut("BlackBoxFuncCall")
                    .and_then(Value::as_object_mut)
                {
                    upgrade_046_blackbox_call(bb);
                }
            }
        }
    }

    normalize_046_field_hex_strings(value);
}

fn normalize_046_field_hex_strings(value: &mut Value) {
    match value {
        Value::String(s) => {
            if let Some(bytes) = parse_hex_bytes(s) {
                *value = Value::Array(
                    bytes
                        .into_iter()
                        .map(|b| Value::Number(serde_json::Number::from(b)))
                        .collect(),
                );
            }
        }
        Value::Array(values) => {
            for item in values {
                normalize_046_field_hex_strings(item);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                normalize_046_field_hex_strings(item);
            }
        }
        _ => {}
    }
}

fn parse_hex_bytes(input: &str) -> Option<Vec<u8>> {
    if input.len() != 64 || !input.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    let mut out = Vec::with_capacity(32);
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = decode_hex_nibble(bytes[i])?;
        let lo = decode_hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

fn upgrade_046_blackbox_call(call: &mut serde_json::Map<String, Value>) {
    // Old 0.46 encoding used FunctionInput { witness, num_bits }.
    // New ACIR uses FunctionInput::{Witness, Constant} and keeps num_bits on AND/XOR/RANGE.
    if let Some(and_call) = call.get_mut("AND").and_then(Value::as_object_mut) {
        let bits = and_call
            .get("lhs")
            .and_then(extract_046_num_bits)
            .or_else(|| and_call.get("rhs").and_then(extract_046_num_bits))
            .unwrap_or(1);
        if let Some(lhs) = and_call.get_mut("lhs") {
            convert_046_function_input(lhs);
        }
        if let Some(rhs) = and_call.get_mut("rhs") {
            convert_046_function_input(rhs);
        }
        and_call.insert("num_bits".to_string(), Value::Number(bits.into()));
        return;
    }

    if let Some(xor_call) = call.get_mut("XOR").and_then(Value::as_object_mut) {
        let bits = xor_call
            .get("lhs")
            .and_then(extract_046_num_bits)
            .or_else(|| xor_call.get("rhs").and_then(extract_046_num_bits))
            .unwrap_or(1);
        if let Some(lhs) = xor_call.get_mut("lhs") {
            convert_046_function_input(lhs);
        }
        if let Some(rhs) = xor_call.get_mut("rhs") {
            convert_046_function_input(rhs);
        }
        xor_call.insert("num_bits".to_string(), Value::Number(bits.into()));
        return;
    }

    if let Some(range_call) = call.get_mut("RANGE").and_then(Value::as_object_mut) {
        let bits = range_call
            .get("input")
            .and_then(extract_046_num_bits)
            .unwrap_or(1);
        if let Some(input) = range_call.get_mut("input") {
            convert_046_function_input(input);
        }
        range_call.insert("num_bits".to_string(), Value::Number(bits.into()));
        return;
    }

    for value in call.values_mut() {
        convert_046_function_input_deep(value);
    }
}

fn extract_046_num_bits(value: &Value) -> Option<u64> {
    value
        .as_object()
        .and_then(|obj| obj.get("num_bits"))
        .and_then(Value::as_u64)
}

fn convert_046_function_input(value: &mut Value) {
    let Some(input_obj) = value.as_object() else {
        return;
    };
    let Some(witness) = input_obj.get("witness").cloned() else {
        return;
    };
    *value = serde_json::json!({"Witness": witness});
}

fn convert_046_function_input_deep(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for item in values {
                convert_046_function_input_deep(item);
            }
        }
        Value::Object(map) => {
            if map.contains_key("witness") && map.contains_key("num_bits") {
                let witness = map.get("witness").cloned().unwrap_or(Value::Null);
                *value = serde_json::json!({"Witness": witness});
                return;
            }
            for item in map.values_mut() {
                convert_046_function_input_deep(item);
            }
        }
        _ => {}
    }
}

impl AbiType {
    pub fn field_count(&self) -> Result<usize, ArtifactError> {
        match self.kind.as_str() {
            "field" | "boolean" | "integer" => Ok(1),
            "array" => {
                let len_u64 = self.require_u64("length")?;
                let len = usize::try_from(len_u64).map_err(|_| {
                    ArtifactError::InvalidAbiShape(format!(
                        "ABI type `{}` key `length` does not fit usize",
                        self.kind
                    ))
                })?;
                let inner = self.require_type("type")?;
                let inner_fields = inner.field_count()?;
                len.checked_mul(inner_fields).ok_or_else(|| {
                    ArtifactError::InvalidAbiShape(format!(
                        "ABI type `{}` field count overflow",
                        self.kind
                    ))
                })
            }
            "tuple" => {
                let fields = self.require_types("fields")?;
                let mut total = 0usize;
                for field in fields {
                    total = total.checked_add(field.field_count()?).ok_or_else(|| {
                        ArtifactError::InvalidAbiShape(format!(
                            "ABI type `{}` field count overflow",
                            self.kind
                        ))
                    })?;
                }
                Ok(total)
            }
            "struct" => {
                let fields_val = self.require_value("fields")?;
                let fields: Vec<AbiStructField> = serde_json::from_value(fields_val.clone())
                    .map_err(|err| ArtifactError::InvalidAbiShape(err.to_string()))?;
                let mut total = 0usize;
                for field in fields {
                    total = total.checked_add(field.typ.field_count()?).ok_or_else(|| {
                        ArtifactError::InvalidAbiShape(format!(
                            "ABI type `{}` field count overflow",
                            self.kind
                        ))
                    })?;
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

pub fn opcode_variant_name(opcode: &Opcode<FieldElement>) -> &'static str {
    match opcode {
        Opcode::AssertZero(_) => "AssertZero",
        Opcode::BlackBoxFuncCall(_) => "BlackBoxFuncCall",
        Opcode::MemoryOp { .. } => "MemoryOp",
        Opcode::MemoryInit { .. } => "MemoryInit",
        Opcode::BrilligCall { .. } => "BrilligCall",
        Opcode::Call { .. } => "Call",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

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

    #[test]
    fn witness_layout_errors_when_abi_needs_more_witnesses() {
        let bytes = include_bytes!("../../../test-vectors/fixture_artifact.json");
        let mut artifact = Artifact::from_json_bytes(bytes).expect("fixture should parse");
        artifact.abi.parameters.push(AbiParameter {
            name: "z".to_string(),
            typ: AbiType {
                kind: "field".to_string(),
                extra: BTreeMap::new(),
            },
            visibility: AbiVisibility::Private,
        });

        let err = artifact
            .witness_layout()
            .expect_err("layout should fail when ABI needs more witnesses");
        match err {
            ArtifactError::WitnessAllocation {
                name,
                needed,
                remaining,
            } => {
                assert_eq!(name, "z");
                assert_eq!(needed, 1);
                assert_eq!(remaining, 0);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn abi_field_count_detects_overflow() {
        let typ: AbiType = serde_json::from_value(serde_json::json!({
            "kind": "array",
            "length": u64::MAX,
            "type": {
                "kind": "tuple",
                "fields": [
                    {"kind": "field"},
                    {"kind": "field"}
                ]
            }
        }))
        .expect("abi type should deserialize");

        let err = typ
            .field_count()
            .expect_err("overflowing field count should fail");
        assert!(
            matches!(err, ArtifactError::InvalidAbiShape(_)),
            "expected invalid ABI shape error, got {err}"
        );
    }

    #[test]
    fn abi_field_count_rejects_unsupported_kind() {
        let typ = AbiType {
            kind: "string".to_string(),
            extra: BTreeMap::new(),
        };

        let err = typ
            .field_count()
            .expect_err("unsupported type should fail field count");
        assert!(matches!(err, ArtifactError::UnsupportedAbiType(kind) if kind == "string"));
    }
}
