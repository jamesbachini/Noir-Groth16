use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::Path,
};

use acir::{
    circuit::{
        brillig::{BrilligInputs, BrilligOutputs},
        opcodes::{AcirFunctionId, BlackBoxFuncCall, BlockId, FunctionInput, MemOp},
        Circuit, Opcode, OpcodeLocation, Program,
    },
    native_types::{Expression, Witness},
    AcirField, FieldElement,
};
use acvm::blackbox_solver::{
    blake2s, blake3, ecdsa_secp256k1_verify, ecdsa_secp256r1_verify, sha256_compression,
};
use bn254_blackbox_solver::multi_scalar_mul as bn254_multi_scalar_mul;
use r1cs_file::{
    Constraint, Constraints, FieldElement as R1csFieldElement, Header, R1csFile, WireMap,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod poseidon2_constants;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoweringMode {
    Strict,
    AllowUnsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringOptions {
    pub mode: LoweringMode,
}

impl LoweringOptions {
    pub const fn strict() -> Self {
        Self {
            mode: LoweringMode::Strict,
        }
    }

    pub const fn allow_unsupported() -> Self {
        Self {
            mode: LoweringMode::AllowUnsupported,
        }
    }
}

impl Default for LoweringOptions {
    fn default() -> Self {
        Self::strict()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedOpcodeInfo {
    pub opcode: String,
    pub index: usize,
    pub function_id: usize,
    pub opcode_variant: String,
    pub predicate_state: String,
    pub exact_opcode: String,
    pub details: String,
    pub workaround: String,
}

#[derive(Debug, Error)]
pub enum R1csError {
    #[error("program has no functions")]
    EmptyProgram,
    #[error(
        "unsupported opcode `{}` at index {} in function {} (predicate={}): {}; exact_opcode={}; workaround={}",
        info.opcode,
        info.index,
        info.function_id,
        info.predicate_state,
        info.details,
        info.exact_opcode,
        info.workaround
    )]
    UnsupportedOpcode { info: Box<UnsupportedOpcodeInfo> },
    #[error("unsupported opcodes encountered during lowering")]
    UnsupportedOpcodes { opcodes: Vec<UnsupportedOpcodeInfo> },
    #[error("underconstrained wire {wire}: {reason}")]
    Underconstrained { wire: u32, reason: String },
    #[error("non-deterministic ordering detected: {context}")]
    NonDeterministicOrdering { context: String },
    #[error("invalid program invariant: {details}")]
    InvalidProgramInvariant { details: String },
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

type AcirProgram = Program<FieldElement>;
type AcirCircuit = Circuit<FieldElement>;
type AcirOpcode = Opcode<FieldElement>;
type AcirExpression = Expression<FieldElement>;
type AcirFunctionInput = FunctionInput<FieldElement>;
type AcirBlackBoxFuncCall = BlackBoxFuncCall<FieldElement>;
type AcirMemOp = MemOp<FieldElement>;

pub fn lower_program(program: &AcirProgram) -> Result<R1csSystem, R1csError> {
    compile_r1cs(program)
}

pub fn compile_r1cs(program: &AcirProgram) -> Result<R1csSystem, R1csError> {
    compile_r1cs_with_options(program, LoweringOptions::strict())
}

pub fn compile_r1cs_with_options(
    program: &AcirProgram,
    options: LoweringOptions,
) -> Result<R1csSystem, R1csError> {
    let circuit = program.functions.first().ok_or(R1csError::EmptyProgram)?;
    LoweringContext::new_for_program(program, 0, circuit, options).lower()
}

pub fn compile_r1cs_circuit(circuit: &AcirCircuit) -> Result<R1csSystem, R1csError> {
    compile_r1cs_circuit_with_options(circuit, LoweringOptions::strict())
}

pub fn compile_r1cs_circuit_with_options(
    circuit: &AcirCircuit,
    options: LoweringOptions,
) -> Result<R1csSystem, R1csError> {
    LoweringContext::new_for_circuit(circuit, options).lower()
}

pub fn collect_unsupported_opcodes(
    program: &AcirProgram,
) -> Result<Vec<UnsupportedOpcodeInfo>, R1csError> {
    match compile_r1cs_with_options(program, LoweringOptions::allow_unsupported()) {
        Ok(_) => Ok(Vec::new()),
        Err(R1csError::UnsupportedOpcodes { opcodes }) => Ok(opcodes),
        Err(err) => Err(err),
    }
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

struct LoweringContext<'a> {
    program: Option<&'a AcirProgram>,
    current_function_index: usize,
    call_stack: Vec<usize>,
    circuit: &'a AcirCircuit,
    options: LoweringOptions,
    field_modulus_le_bytes: [u8; 32],
    wire_map: BTreeMap<u32, u32>,
    next_virtual_witness_index: u32,
    next_wire: u32,
    next_memory_block_id: u32,
    allocated_intermediate_wires: BTreeSet<u32>,
    constrained_wires: BTreeSet<u32>,
    hint_plumbing_rows: BTreeSet<usize>,
    a_rows: Vec<SparseRow>,
    b_rows: Vec<SparseRow>,
    c_rows: Vec<SparseRow>,
    memory_blocks: BTreeMap<u32, Vec<u32>>,
    pending_hint_outputs: Vec<PendingHintOutputConstraint>,
    unsupported: Vec<UnsupportedOpcodeInfo>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingHintOutputConstraint {
    source: &'static str,
    opcode_index: usize,
    witness: Witness,
    wire: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolvedBlackBoxPredicate {
    Constant(bool),
    Wire(u32),
}

#[derive(Clone, Debug)]
struct Sha256Word {
    wire: u32,
    bits: Vec<u32>,
}

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl<'a> LoweringContext<'a> {
    fn new_for_program(
        program: &'a AcirProgram,
        function_index: usize,
        circuit: &'a AcirCircuit,
        options: LoweringOptions,
    ) -> Self {
        let mut this = Self::new_for_circuit(circuit, options);
        this.program = Some(program);
        this.current_function_index = function_index;
        this.call_stack.push(function_index);
        this.next_memory_block_id = program
            .functions
            .iter()
            .map(next_memory_block_id)
            .max()
            .unwrap_or(0);
        this
    }

    fn new_for_circuit(circuit: &'a AcirCircuit, options: LoweringOptions) -> Self {
        let mut wire_map = BTreeMap::new();
        for witness in 0..=circuit.current_witness_index {
            wire_map.insert(witness, witness + 1);
        }

        Self {
            program: None,
            current_function_index: 0,
            call_stack: Vec::new(),
            circuit,
            options,
            field_modulus_le_bytes: bn254_modulus_le_bytes(),
            wire_map,
            next_virtual_witness_index: circuit.current_witness_index + 1,
            next_wire: circuit.current_witness_index + 2,
            next_memory_block_id: next_memory_block_id(circuit),
            allocated_intermediate_wires: BTreeSet::new(),
            constrained_wires: BTreeSet::new(),
            hint_plumbing_rows: BTreeSet::new(),
            a_rows: Vec::new(),
            b_rows: Vec::new(),
            c_rows: Vec::new(),
            memory_blocks: BTreeMap::new(),
            pending_hint_outputs: Vec::new(),
            unsupported: Vec::new(),
        }
    }

    fn lower(mut self) -> Result<R1csSystem, R1csError> {
        self.validate_program_invariants()?;

        for (index, opcode) in self.circuit.opcodes.iter().enumerate() {
            self.lower_opcode(index, opcode)?;
        }

        self.validate_hint_output_constraints()?;

        if !self.unsupported.is_empty() {
            return Err(R1csError::UnsupportedOpcodes {
                opcodes: self.unsupported,
            });
        }

        self.validate_post_invariants()?;

        Ok(R1csSystem {
            n_wires: self.next_wire,
            n_constraints: self.a_rows.len() as u32,
            n_public_outputs: self.circuit.return_values.indices().len() as u32,
            n_public_inputs: self.circuit.public_parameters.indices().len() as u32,
            n_private_inputs: self.circuit.private_parameters.len() as u32,
            a: self.a_rows,
            b: self.b_rows,
            c: self.c_rows,
        })
    }

    fn validate_program_invariants(&self) -> Result<(), R1csError> {
        if !is_strictly_sorted(&self.circuit.public_parameters.indices()) {
            return Err(R1csError::NonDeterministicOrdering {
                context: "public input ordering is not stable".to_string(),
            });
        }
        if !is_strictly_sorted(&self.circuit.return_values.indices()) {
            return Err(R1csError::NonDeterministicOrdering {
                context: "public output ordering is not stable".to_string(),
            });
        }

        for witness in self
            .circuit
            .private_parameters
            .iter()
            .chain(self.circuit.public_parameters.0.iter())
            .chain(self.circuit.return_values.0.iter())
        {
            self.ensure_witness_in_range(*witness, "program parameters")?;
        }
        Ok(())
    }

    fn validate_post_invariants(&self) -> Result<(), R1csError> {
        if self.a_rows.len() != self.b_rows.len() || self.a_rows.len() != self.c_rows.len() {
            return Err(R1csError::InvalidProgramInvariant {
                details: "A/B/C matrix row count mismatch".to_string(),
            });
        }

        for wire in &self.allocated_intermediate_wires {
            if !self.constrained_wires.contains(wire) {
                return Err(R1csError::Underconstrained {
                    wire: *wire,
                    reason: "allocated intermediate wire does not appear in any constraint row"
                        .to_string(),
                });
            }
        }

        for row in self
            .a_rows
            .iter()
            .chain(self.b_rows.iter())
            .chain(self.c_rows.iter())
        {
            ensure_row_is_canonical(row)?;
            for term in row {
                if term.wire >= self.next_wire {
                    return Err(R1csError::InvalidProgramInvariant {
                        details: format!(
                            "term references wire {} but n_wires is {}",
                            term.wire, self.next_wire
                        ),
                    });
                }
            }
        }

        if self.field_modulus_le_bytes != bn254_modulus_le_bytes() {
            return Err(R1csError::InvalidProgramInvariant {
                details: "field modulus mismatch in lowering context".to_string(),
            });
        }

        Ok(())
    }

    fn lower_opcode(&mut self, index: usize, opcode: &AcirOpcode) -> Result<(), R1csError> {
        match opcode {
            Opcode::AssertZero(expr) => self.lower_assert_zero(expr, index, "AssertZero"),
            Opcode::MemoryInit { block_id, init, .. } => {
                self.lower_memory_init(*block_id, init, index)
            }
            Opcode::MemoryOp { block_id, op } => self.lower_memory_op(*block_id, op, index),
            Opcode::BlackBoxFuncCall(call) => self.lower_blackbox(call, index),
            Opcode::BrilligCall {
                id: _,
                inputs,
                outputs,
                predicate,
            } => self.lower_brillig_call(inputs, outputs, predicate, index),
            Opcode::Call {
                id,
                inputs,
                outputs,
                predicate,
            } => self.lower_call(*id, inputs, outputs, predicate, index),
        }
    }

    fn lower_call(
        &mut self,
        id: AcirFunctionId,
        inputs: &[Witness],
        outputs: &[Witness],
        predicate: &AcirExpression,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        for input in inputs {
            self.ensure_witness_in_range(*input, "Call input")?;
        }
        for output in outputs {
            self.ensure_witness_in_range(*output, "Call output")?;
        }

        let predicate = canonicalize_expression(predicate);
        self.ensure_expression_witnesses_in_range(&predicate, "Call predicate")?;

        let pred_const = match predicate.to_const().copied() {
            Some(value) if value.is_zero() => {
                for output in outputs {
                    let output_wire = self.wire_for_witness(*output)?;
                    self.emit_constraint(
                        vec![SparseTerm {
                            wire: 0,
                            coeff: FieldElement::one(),
                        }],
                        vec![SparseTerm {
                            wire: output_wire,
                            coeff: FieldElement::one(),
                        }],
                        Vec::new(),
                    )?;
                }
                return Ok(());
            }
            Some(value) if value.is_one() => Some(value),
            Some(value) => {
                return self.unsupported_opcode(
                    "Call",
                    opcode_index,
                    format!("Call predicate must evaluate to 0 or 1, found {value}"),
                );
            }
            None => None,
        };

        let Some(program) = self.program else {
            return self.unsupported_opcode(
                "Call",
                opcode_index,
                "nested Call lowering requires lowering from a full Program".to_string(),
            );
        };

        if id.as_usize() == 0 {
            return self.unsupported_opcode(
                "Call",
                opcode_index,
                "Call to function id 0 (main) is invalid".to_string(),
            );
        }

        let callee_index = id.as_usize();
        let Some(callee) = program.functions.get(callee_index) else {
            return self.unsupported_opcode(
                "Call",
                opcode_index,
                format!(
                    "Call references function id {} but program has only {} functions",
                    id,
                    program.functions.len()
                ),
            );
        };

        if self.call_stack.contains(&callee_index) {
            return self.unsupported_opcode(
                "Call",
                opcode_index,
                format!("recursive Call to function id {} is unsupported", id.0),
            );
        }

        let callee_returns = callee.return_values.indices();
        if callee_returns.len() != outputs.len() {
            return Err(R1csError::InvalidProgramInvariant {
                details: format!(
                    "Call output arity mismatch for function {}: call outputs={}, callee return_values={}",
                    id.0,
                    outputs.len(),
                    callee_returns.len()
                ),
            });
        }

        let dynamic_pred_wire = if pred_const.is_none() {
            let pred_wire =
                self.bind_expression_to_new_wire(&predicate, opcode_index, "Call predicate")?;
            self.enforce_boolean_wire(pred_wire)?;
            Some(pred_wire)
        } else {
            None
        };

        let mut witness_map: BTreeMap<u32, Witness> = BTreeMap::new();
        if dynamic_pred_wire.is_some() {
            for i in 0..inputs.len() {
                witness_map.insert(i as u32, self.allocate_virtual_witness());
            }
            for callee_return in &callee_returns {
                witness_map
                    .entry(*callee_return)
                    .or_insert_with(|| self.allocate_virtual_witness());
            }
        } else {
            for (i, input) in inputs.iter().enumerate() {
                witness_map.insert(i as u32, *input);
            }
            for (callee_return, output) in callee_returns.iter().zip(outputs.iter()) {
                let prev = witness_map.insert(*callee_return, *output);
                if let Some(prev) = prev {
                    if prev != *output {
                        return Err(R1csError::InvalidProgramInvariant {
                            details: format!(
                                "callee witness {} is mapped to conflicting call outputs",
                                callee_return
                            ),
                        });
                    }
                }
            }
        }

        for witness_index in 0..=callee.current_witness_index {
            witness_map
                .entry(witness_index)
                .or_insert_with(|| self.allocate_virtual_witness());
        }

        let mut block_map: BTreeMap<u32, u32> = BTreeMap::new();
        for opcode in &callee.opcodes {
            if let Opcode::MemoryInit { block_id, .. } | Opcode::MemoryOp { block_id, .. } = opcode
            {
                block_map
                    .entry(block_id.0)
                    .or_insert_with(|| self.allocate_memory_block_id());
            }
        }

        let dynamic_input_bindings = if dynamic_pred_wire.is_some() {
            let mut bindings = Vec::with_capacity(inputs.len());
            for i in 0..inputs.len() {
                let Some(mapped) = witness_map.get(&(i as u32)).copied() else {
                    return Err(R1csError::InvalidProgramInvariant {
                        details: format!(
                            "missing dynamic input witness mapping for callee input {}",
                            i
                        ),
                    });
                };
                bindings.push(mapped);
            }
            Some(bindings)
        } else {
            None
        };

        let dynamic_output_bindings = if dynamic_pred_wire.is_some() {
            let mut bindings = Vec::with_capacity(callee_returns.len());
            for callee_return in &callee_returns {
                let Some(mapped) = witness_map.get(callee_return).copied() else {
                    return Err(R1csError::InvalidProgramInvariant {
                        details: format!(
                            "missing dynamic output witness mapping for callee return {}",
                            callee_return
                        ),
                    });
                };
                bindings.push(mapped);
            }
            Some(bindings)
        } else {
            None
        };

        let first_row = self.a_rows.len();
        self.call_stack.push(callee_index);
        for (inner_index, opcode) in callee.opcodes.iter().enumerate() {
            let remapped = remap_opcode(opcode, &witness_map, &block_map);
            if let Err(err) = self.lower_opcode(inner_index, &remapped) {
                self.call_stack.pop();
                return Err(err);
            }
        }
        self.call_stack.pop();

        if let Some(pred_wire) = dynamic_pred_wire {
            let original_end = self.a_rows.len();
            self.gate_constraint_rows_with_predicate(first_row, original_end, pred_wire)?;

            let input_bindings = dynamic_input_bindings
                .expect("dynamic predicate call input bindings must be collected");
            for (input, virtual_input) in inputs.iter().zip(input_bindings.iter()) {
                self.emit_predicated_witness_equality(pred_wire, *virtual_input, *input)?;
            }

            let output_bindings = dynamic_output_bindings
                .expect("dynamic predicate call output bindings must be collected");
            for (output, virtual_output) in outputs.iter().zip(output_bindings.iter()) {
                self.emit_predicated_output_binding(pred_wire, *virtual_output, *output)?;
            }
        }

        Ok(())
    }

    fn gate_constraint_rows_with_predicate(
        &mut self,
        start_row: usize,
        end_row: usize,
        predicate_wire: u32,
    ) -> Result<(), R1csError> {
        for row_index in start_row..end_row {
            let original_c = self.c_rows[row_index].clone();
            let lifted_product_wire = self.allocate_intermediate_wire();
            self.c_rows[row_index] = vec![SparseTerm {
                wire: lifted_product_wire,
                coeff: FieldElement::one(),
            }];
            self.constrained_wires.insert(lifted_product_wire);

            let mut mismatch_terms = Vec::with_capacity(original_c.len() + 1);
            mismatch_terms.push(SparseTerm {
                wire: lifted_product_wire,
                coeff: FieldElement::one(),
            });
            for term in original_c {
                mismatch_terms.push(SparseTerm {
                    wire: term.wire,
                    coeff: -term.coeff,
                });
            }

            let was_hint_plumbing = self.hint_plumbing_rows.contains(&row_index);
            let gated_row_index = self.a_rows.len();
            self.emit_constraint(
                vec![SparseTerm {
                    wire: predicate_wire,
                    coeff: FieldElement::one(),
                }],
                mismatch_terms,
                Vec::new(),
            )?;
            if was_hint_plumbing {
                self.hint_plumbing_rows.insert(gated_row_index);
            }
        }

        Ok(())
    }

    fn emit_predicated_witness_equality(
        &mut self,
        predicate_wire: u32,
        lhs: Witness,
        rhs: Witness,
    ) -> Result<(), R1csError> {
        let lhs_wire = self.wire_for_witness(lhs)?;
        let rhs_wire = self.wire_for_witness(rhs)?;
        self.emit_constraint(
            vec![SparseTerm {
                wire: predicate_wire,
                coeff: FieldElement::one(),
            }],
            vec![
                SparseTerm {
                    wire: lhs_wire,
                    coeff: FieldElement::one(),
                },
                SparseTerm {
                    wire: rhs_wire,
                    coeff: -FieldElement::one(),
                },
            ],
            Vec::new(),
        )
    }

    fn emit_predicated_output_binding(
        &mut self,
        predicate_wire: u32,
        virtual_output: Witness,
        output: Witness,
    ) -> Result<(), R1csError> {
        let virtual_output_wire = self.wire_for_witness(virtual_output)?;
        let output_wire = self.wire_for_witness(output)?;
        self.emit_constraint(
            vec![SparseTerm {
                wire: predicate_wire,
                coeff: FieldElement::one(),
            }],
            vec![SparseTerm {
                wire: virtual_output_wire,
                coeff: FieldElement::one(),
            }],
            vec![SparseTerm {
                wire: output_wire,
                coeff: FieldElement::one(),
            }],
        )
    }

    fn lower_assert_zero(
        &mut self,
        expr: &AcirExpression,
        opcode_index: usize,
        context: &str,
    ) -> Result<(), R1csError> {
        let expr = canonicalize_expression(expr);
        self.ensure_expression_witnesses_in_range(&expr, context)?;

        let mut linear_terms: BTreeMap<u32, FieldElement> = BTreeMap::new();

        for (coeff, lhs, rhs) in &expr.mul_terms {
            if coeff.is_zero() {
                continue;
            }
            let lhs_wire = self.wire_for_witness(*lhs)?;
            let rhs_wire = self.wire_for_witness(*rhs)?;
            let tmp_wire = self.allocate_intermediate_wire();

            self.emit_constraint(
                vec![SparseTerm {
                    wire: lhs_wire,
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: rhs_wire,
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: tmp_wire,
                    coeff: FieldElement::one(),
                }],
            )?;

            add_linear(&mut linear_terms, tmp_wire, *coeff);
        }

        for (coeff, witness) in &expr.linear_combinations {
            if coeff.is_zero() {
                continue;
            }
            let wire = self.wire_for_witness(*witness)?;
            add_linear(&mut linear_terms, wire, *coeff);
        }

        if !expr.q_c.is_zero() {
            add_linear(&mut linear_terms, 0, expr.q_c);
        }

        self.emit_constraint(
            vec![SparseTerm {
                wire: 0,
                coeff: FieldElement::one(),
            }],
            linear_terms
                .into_iter()
                .map(|(wire, coeff)| SparseTerm { wire, coeff })
                .collect(),
            Vec::new(),
        )
        .map_err(|err| match err {
            R1csError::InvalidProgramInvariant { details } => R1csError::InvalidProgramInvariant {
                details: format!(
                    "failed lowering {context} at opcode index {opcode_index}: {details}"
                ),
            },
            other => other,
        })
    }

    fn lower_brillig_call(
        &mut self,
        inputs: &[BrilligInputs<FieldElement>],
        outputs: &[BrilligOutputs],
        predicate: &AcirExpression,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        for input in inputs {
            match input {
                BrilligInputs::Single(expr) => {
                    self.ensure_expression_witnesses_in_range(expr, "BrilligCall input")?;
                }
                BrilligInputs::Array(exprs) => {
                    for expr in exprs {
                        self.ensure_expression_witnesses_in_range(expr, "BrilligCall array input")?;
                    }
                }
                BrilligInputs::MemoryArray(_) => {}
            }
        }

        let predicate = canonicalize_expression(predicate);
        self.ensure_expression_witnesses_in_range(&predicate, "BrilligCall predicate")?;

        if let Some(value) = predicate.to_const() {
            if !value.is_zero() && !value.is_one() {
                return self.unsupported_opcode(
                    "BrilligCall",
                    opcode_index,
                    format!("BrilligCall predicate must evaluate to 0 or 1, found {value}"),
                );
            }
        }

        let pred_const = predicate.to_const().copied();
        if outputs.is_empty() {
            if pred_const.is_some_and(|value| value.is_zero()) {
                return Ok(());
            }
            return self.unsupported_opcode(
                "BrilligCall",
                opcode_index,
                "BrilligCall must expose at least one output witness unless predicate is constant 0"
                    .to_string(),
            );
        }

        let pred_wire = match pred_const {
            Some(value) if value.is_zero() || value.is_one() => None,
            _ => Some(self.bind_expression_to_new_wire(
                &predicate,
                opcode_index,
                "BrilligCall predicate",
            )?),
        };
        if let Some(pred_wire) = pred_wire {
            self.enforce_boolean_wire(pred_wire)?;
        }

        for output in outputs {
            match output {
                BrilligOutputs::Simple(witness) => {
                    self.handle_brillig_output(*witness, pred_const, pred_wire, opcode_index)?;
                }
                BrilligOutputs::Array(witnesses) => {
                    if witnesses.is_empty() {
                        return self.unsupported_opcode(
                            "BrilligCall",
                            opcode_index,
                            "BrilligCall output arrays must not be empty".to_string(),
                        );
                    }
                    for witness in witnesses {
                        self.handle_brillig_output(*witness, pred_const, pred_wire, opcode_index)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_brillig_output(
        &mut self,
        output: Witness,
        pred_const: Option<FieldElement>,
        pred_wire: Option<u32>,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        self.ensure_witness_in_range(output, "BrilligCall output")?;
        let output_wire = self.wire_for_witness(output)?;

        match pred_const {
            Some(value) if value.is_zero() => self.emit_constraint(
                vec![SparseTerm {
                    wire: 0,
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: output_wire,
                    coeff: FieldElement::one(),
                }],
                Vec::new(),
            )?,
            Some(value) if value.is_one() => {
                self.register_hint_output("BrilligCall", output, opcode_index)?;
            }
            _ => {
                let pred_wire = pred_wire.expect("dynamic predicate wire must be allocated");
                let hinted_wire = self.allocate_intermediate_wire();
                self.emit_hint_plumbing_constraint(
                    vec![SparseTerm {
                        wire: pred_wire,
                        coeff: FieldElement::one(),
                    }],
                    vec![SparseTerm {
                        wire: hinted_wire,
                        coeff: FieldElement::one(),
                    }],
                    vec![SparseTerm {
                        wire: output_wire,
                        coeff: FieldElement::one(),
                    }],
                )?;
                self.register_hint_output("BrilligCall", output, opcode_index)?;
            }
        }

        Ok(())
    }

    fn lower_memory_init(
        &mut self,
        block_id: BlockId,
        init: &[Witness],
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        if self.memory_blocks.contains_key(&block_id.0) {
            return Err(R1csError::InvalidProgramInvariant {
                details: format!(
                    "memory block {} initialized more than once (opcode index {})",
                    block_id.0, opcode_index
                ),
            });
        }

        let mut entries = Vec::with_capacity(init.len());
        for witness in init {
            self.ensure_witness_in_range(*witness, "MemoryInit")?;
            entries.push(self.wire_for_witness(*witness)?);
        }
        self.memory_blocks.insert(block_id.0, entries);
        Ok(())
    }

    fn lower_memory_op(
        &mut self,
        block_id: BlockId,
        op: &AcirMemOp,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        let entries = self
            .memory_blocks
            .get(&block_id.0)
            .cloned()
            .ok_or_else(|| R1csError::InvalidProgramInvariant {
                details: format!(
                    "memory block {} used before initialization at opcode index {}",
                    block_id.0, opcode_index
                ),
            })?;

        if entries.is_empty() {
            return self.unsupported_opcode(
                "MemoryOp",
                opcode_index,
                "dynamic MemoryOp over empty memory blocks is unsupported".to_string(),
            );
        }

        let operation = canonicalize_expression(&op.operation);
        self.ensure_expression_witnesses_in_range(&operation, "MemoryOp operation")?;
        let op_wire =
            self.bind_expression_to_new_wire(&operation, opcode_index, "MemoryOp operation")?;
        self.enforce_boolean_wire(op_wire)?;

        let index_expr = canonicalize_expression(&op.index);
        self.ensure_expression_witnesses_in_range(&index_expr, "MemoryOp index")?;
        let index_wire =
            self.bind_expression_to_new_wire(&index_expr, opcode_index, "MemoryOp index")?;

        let value_expr = canonicalize_expression(&op.value);
        self.ensure_expression_witnesses_in_range(&value_expr, "MemoryOp value")?;
        let value_wire =
            self.bind_expression_to_new_wire(&value_expr, opcode_index, "MemoryOp value")?;

        let mut selector_wires = Vec::with_capacity(entries.len());
        for _ in &entries {
            let selector = self.allocate_intermediate_wire();
            self.enforce_boolean_wire(selector)?;
            selector_wires.push(selector);
        }

        let mut selector_sum = Vec::with_capacity(selector_wires.len());
        for selector_wire in &selector_wires {
            selector_sum.push(SparseTerm {
                wire: *selector_wire,
                coeff: FieldElement::one(),
            });
        }
        self.emit_constraint(
            vec![SparseTerm {
                wire: 0,
                coeff: FieldElement::one(),
            }],
            selector_sum,
            vec![SparseTerm {
                wire: 0,
                coeff: FieldElement::one(),
            }],
        )?;

        let mut index_eq_terms = Vec::with_capacity(selector_wires.len());
        for (i, selector_wire) in selector_wires.iter().enumerate() {
            index_eq_terms.push(SparseTerm {
                wire: *selector_wire,
                coeff: FieldElement::from(i as u128),
            });
        }
        self.emit_constraint(
            vec![SparseTerm {
                wire: 0,
                coeff: FieldElement::one(),
            }],
            index_eq_terms,
            vec![SparseTerm {
                wire: index_wire,
                coeff: FieldElement::one(),
            }],
        )?;

        let mut weighted_old_entries = Vec::with_capacity(entries.len());
        for (entry_wire, selector_wire) in entries.iter().zip(selector_wires.iter()) {
            let weighted_entry = self.allocate_intermediate_wire();
            self.emit_constraint(
                vec![SparseTerm {
                    wire: *entry_wire,
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: *selector_wire,
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: weighted_entry,
                    coeff: FieldElement::one(),
                }],
            )?;
            weighted_old_entries.push(weighted_entry);
        }

        let selected_old_wire = self.allocate_intermediate_wire();
        let mut selected_terms = Vec::with_capacity(weighted_old_entries.len());
        for weighted in &weighted_old_entries {
            selected_terms.push(SparseTerm {
                wire: *weighted,
                coeff: FieldElement::one(),
            });
        }
        self.emit_constraint(
            vec![SparseTerm {
                wire: 0,
                coeff: FieldElement::one(),
            }],
            selected_terms,
            vec![SparseTerm {
                wire: selected_old_wire,
                coeff: FieldElement::one(),
            }],
        )?;

        // Enforce read semantics only when operation = 0:
        // (value - selected_old) * (1 - operation) = 0
        self.emit_constraint(
            vec![
                SparseTerm {
                    wire: value_wire,
                    coeff: FieldElement::one(),
                },
                SparseTerm {
                    wire: selected_old_wire,
                    coeff: -FieldElement::one(),
                },
            ],
            vec![
                SparseTerm {
                    wire: 0,
                    coeff: FieldElement::one(),
                },
                SparseTerm {
                    wire: op_wire,
                    coeff: -FieldElement::one(),
                },
            ],
            Vec::new(),
        )?;

        let mut new_entries = Vec::with_capacity(entries.len());
        for (entry_wire, selector_wire) in entries.iter().zip(selector_wires.iter()) {
            let active_write = self.allocate_intermediate_wire();
            self.emit_constraint(
                vec![SparseTerm {
                    wire: op_wire,
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: *selector_wire,
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: active_write,
                    coeff: FieldElement::one(),
                }],
            )?;

            let delta_wire = self.allocate_intermediate_wire();
            let updated_entry = self.allocate_intermediate_wire();
            self.emit_constraint(
                vec![SparseTerm {
                    wire: active_write,
                    coeff: FieldElement::one(),
                }],
                vec![
                    SparseTerm {
                        wire: value_wire,
                        coeff: FieldElement::one(),
                    },
                    SparseTerm {
                        wire: *entry_wire,
                        coeff: -FieldElement::one(),
                    },
                ],
                vec![SparseTerm {
                    wire: delta_wire,
                    coeff: FieldElement::one(),
                }],
            )?;
            self.emit_constraint(
                vec![SparseTerm {
                    wire: 0,
                    coeff: FieldElement::one(),
                }],
                vec![
                    SparseTerm {
                        wire: *entry_wire,
                        coeff: FieldElement::one(),
                    },
                    SparseTerm {
                        wire: delta_wire,
                        coeff: FieldElement::one(),
                    },
                ],
                vec![SparseTerm {
                    wire: updated_entry,
                    coeff: FieldElement::one(),
                }],
            )?;

            new_entries.push(updated_entry);
        }

        self.memory_blocks.insert(block_id.0, new_entries);
        Ok(())
    }

    fn bind_expression_to_new_wire(
        &mut self,
        expr: &AcirExpression,
        opcode_index: usize,
        context: &str,
    ) -> Result<u32, R1csError> {
        let wire = self.allocate_intermediate_wire();
        self.constrain_expression_to_wire(expr, wire, opcode_index, context)?;
        Ok(wire)
    }

    fn constrain_expression_to_wire(
        &mut self,
        expr: &AcirExpression,
        target_wire: u32,
        opcode_index: usize,
        context: &str,
    ) -> Result<(), R1csError> {
        let expr = canonicalize_expression(expr);
        self.ensure_expression_witnesses_in_range(&expr, context)?;

        let mut linear_terms: BTreeMap<u32, FieldElement> = BTreeMap::new();
        for (coeff, lhs, rhs) in &expr.mul_terms {
            if coeff.is_zero() {
                continue;
            }
            let lhs_wire = self.wire_for_witness(*lhs)?;
            let rhs_wire = self.wire_for_witness(*rhs)?;
            let tmp_wire = self.allocate_intermediate_wire();

            self.emit_constraint(
                vec![SparseTerm {
                    wire: lhs_wire,
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: rhs_wire,
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: tmp_wire,
                    coeff: FieldElement::one(),
                }],
            )?;

            add_linear(&mut linear_terms, tmp_wire, *coeff);
        }

        for (coeff, witness) in &expr.linear_combinations {
            if coeff.is_zero() {
                continue;
            }
            add_linear(&mut linear_terms, self.wire_for_witness(*witness)?, *coeff);
        }
        if !expr.q_c.is_zero() {
            add_linear(&mut linear_terms, 0, expr.q_c);
        }

        self.emit_constraint(
            vec![SparseTerm {
                wire: 0,
                coeff: FieldElement::one(),
            }],
            linear_terms
                .into_iter()
                .map(|(wire, coeff)| SparseTerm { wire, coeff })
                .collect(),
            vec![SparseTerm {
                wire: target_wire,
                coeff: FieldElement::one(),
            }],
        )
        .map_err(|err| match err {
            R1csError::InvalidProgramInvariant { details } => R1csError::InvalidProgramInvariant {
                details: format!(
                    "failed binding expression for {context} at opcode index {opcode_index}: {details}"
                ),
            },
            other => other,
        })
    }

    fn enforce_boolean_wire(&mut self, wire: u32) -> Result<(), R1csError> {
        self.emit_constraint(
            vec![SparseTerm {
                wire,
                coeff: FieldElement::one(),
            }],
            vec![
                SparseTerm {
                    wire,
                    coeff: FieldElement::one(),
                },
                SparseTerm {
                    wire: 0,
                    coeff: -FieldElement::one(),
                },
            ],
            Vec::new(),
        )
    }

    fn lower_blackbox(
        &mut self,
        call: &AcirBlackBoxFuncCall,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        match call {
            BlackBoxFuncCall::AND {
                lhs,
                rhs,
                num_bits,
                output,
            } => self.lower_bitwise_and(lhs, rhs, *num_bits, *output, opcode_index),
            BlackBoxFuncCall::XOR {
                lhs,
                rhs,
                num_bits,
                output,
            } => self.lower_bitwise_xor(lhs, rhs, *num_bits, *output, opcode_index),
            BlackBoxFuncCall::RANGE { input, num_bits } => {
                self.lower_range(input, *num_bits, opcode_index)
            }
            call @ BlackBoxFuncCall::Blake2s { .. } => {
                self.lower_blake2s_with_constant_folding(call, opcode_index)
            }
            call @ BlackBoxFuncCall::Blake3 { .. } => {
                self.lower_blake3_with_constant_folding(call, opcode_index)
            }
            call @ BlackBoxFuncCall::EcdsaSecp256k1 { .. } => {
                self.lower_ecdsa_with_constant_folding(call, opcode_index, true)
            }
            call @ BlackBoxFuncCall::EcdsaSecp256r1 { .. } => {
                self.lower_ecdsa_with_constant_folding(call, opcode_index, false)
            }
            BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs } => {
                self.lower_poseidon2_permutation(inputs, outputs, opcode_index)
            }
            call @ BlackBoxFuncCall::Sha256Compression { .. } => {
                self.lower_sha256_compression_with_constant_folding(call, opcode_index)
            }
            call @ BlackBoxFuncCall::MultiScalarMul { .. } => {
                self.lower_multi_scalar_mul_with_constant_folding(call, opcode_index)
            }
            BlackBoxFuncCall::EmbeddedCurveAdd {
                input1,
                input2,
                predicate,
                outputs,
            } => self.lower_embedded_curve_add(input1, input2, predicate, *outputs, opcode_index),
            other => self.lower_blackbox_as_hint(other, opcode_index),
        }
    }

    fn lower_bitwise_and(
        &mut self,
        lhs: &AcirFunctionInput,
        rhs: &AcirFunctionInput,
        num_bits: u32,
        output: Witness,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        let lhs_bits = self.decompose_function_input_to_bits(
            lhs,
            num_bits,
            opcode_index,
            "BlackBoxFuncCall::AND lhs",
        )?;
        let rhs_bits = self.decompose_function_input_to_bits(
            rhs,
            num_bits,
            opcode_index,
            "BlackBoxFuncCall::AND rhs",
        )?;

        self.ensure_witness_in_range(output, "BlackBoxFuncCall::AND output")?;
        let output_wire = self.wire_for_witness(output)?;
        let output_bits = self.decompose_wire_to_bits(
            output_wire,
            num_bits,
            opcode_index,
            "BlackBoxFuncCall::AND output",
        )?;

        for i in 0..num_bits as usize {
            self.emit_constraint(
                vec![SparseTerm {
                    wire: lhs_bits[i],
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: rhs_bits[i],
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: output_bits[i],
                    coeff: FieldElement::one(),
                }],
            )?;
        }

        Ok(())
    }

    fn lower_bitwise_xor(
        &mut self,
        lhs: &AcirFunctionInput,
        rhs: &AcirFunctionInput,
        num_bits: u32,
        output: Witness,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        let lhs_bits = self.decompose_function_input_to_bits(
            lhs,
            num_bits,
            opcode_index,
            "BlackBoxFuncCall::XOR lhs",
        )?;
        let rhs_bits = self.decompose_function_input_to_bits(
            rhs,
            num_bits,
            opcode_index,
            "BlackBoxFuncCall::XOR rhs",
        )?;

        self.ensure_witness_in_range(output, "BlackBoxFuncCall::XOR output")?;
        let output_wire = self.wire_for_witness(output)?;
        let output_bits = self.decompose_wire_to_bits(
            output_wire,
            num_bits,
            opcode_index,
            "BlackBoxFuncCall::XOR output",
        )?;

        for i in 0..num_bits as usize {
            let product_wire = self.allocate_intermediate_wire();
            self.emit_constraint(
                vec![SparseTerm {
                    wire: lhs_bits[i],
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: rhs_bits[i],
                    coeff: FieldElement::one(),
                }],
                vec![SparseTerm {
                    wire: product_wire,
                    coeff: FieldElement::one(),
                }],
            )?;

            self.emit_constraint(
                vec![SparseTerm {
                    wire: 0,
                    coeff: FieldElement::one(),
                }],
                vec![
                    SparseTerm {
                        wire: product_wire,
                        coeff: FieldElement::from(2u128),
                    },
                    SparseTerm {
                        wire: output_bits[i],
                        coeff: FieldElement::one(),
                    },
                    SparseTerm {
                        wire: lhs_bits[i],
                        coeff: -FieldElement::one(),
                    },
                    SparseTerm {
                        wire: rhs_bits[i],
                        coeff: -FieldElement::one(),
                    },
                ],
                Vec::new(),
            )?;
        }

        Ok(())
    }

    fn lower_range(
        &mut self,
        input: &AcirFunctionInput,
        num_bits: u32,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        let exact_range_bits = FieldElement::max_num_bits().saturating_sub(1);

        if num_bits > exact_range_bits {
            // Over a prime field, values are already canonical field elements.
            // RANGE checks at/above field bit width are tautological in ACVM semantics.
            if let FunctionInput::Witness(witness) = input {
                self.ensure_witness_in_range(*witness, "BlackBoxFuncCall::RANGE input")?;
            }
            return Ok(());
        }

        let _ = self.decompose_function_input_to_bits(
            input,
            num_bits,
            opcode_index,
            "BlackBoxFuncCall::RANGE input",
        )?;
        Ok(())
    }

    fn lower_blake2s_with_constant_folding(
        &mut self,
        call: &AcirBlackBoxFuncCall,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        let (inputs, outputs) = match call {
            BlackBoxFuncCall::Blake2s { inputs, outputs } => (inputs.as_slice(), outputs.as_ref()),
            _ => unreachable!("caller must pass Blake2s"),
        };

        for input in inputs {
            self.lower_range(input, 8, opcode_index)?;
        }

        let mut bytes = Vec::with_capacity(inputs.len());
        for input in inputs {
            match input {
                FunctionInput::Constant(value) => {
                    let Some(word) = value.try_to_u32() else {
                        return self.unsupported_opcode(
                            "BlackBoxFuncCall",
                            opcode_index,
                            format!("Blake2s constant input must fit into 8 bits, found {value}"),
                        );
                    };
                    if word > u32::from(u8::MAX) {
                        return self.unsupported_opcode(
                            "BlackBoxFuncCall",
                            opcode_index,
                            format!("Blake2s constant input must fit into 8 bits, found {value}"),
                        );
                    }
                    bytes.push(word as u8);
                }
                FunctionInput::Witness(_) => {
                    return self.lower_blackbox_with_mode(
                        call,
                        opcode_index,
                        "Blake2s witness-driven native lowering is not implemented".to_string(),
                    )
                }
            }
        }

        let digest = match blake2s(&bytes) {
            Ok(digest) => digest,
            Err(err) => {
                return self.unsupported_opcode(
                    "BlackBoxFuncCall",
                    opcode_index,
                    format!("failed evaluating constant Blake2s inputs: {err}"),
                );
            }
        };

        for (output, byte) in outputs.iter().zip(digest.into_iter()) {
            self.ensure_witness_in_range(*output, "BlackBoxFuncCall::Blake2s output")?;
            let output_wire = self.wire_for_witness(*output)?;
            self.enforce_wire_equals_constant(output_wire, FieldElement::from(u128::from(byte)))?;
        }

        Ok(())
    }

    fn lower_blake3_with_constant_folding(
        &mut self,
        call: &AcirBlackBoxFuncCall,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        let (inputs, outputs) = match call {
            BlackBoxFuncCall::Blake3 { inputs, outputs } => (inputs.as_slice(), outputs.as_ref()),
            _ => unreachable!("caller must pass Blake3"),
        };

        for input in inputs {
            self.lower_range(input, 8, opcode_index)?;
        }

        let mut bytes = Vec::with_capacity(inputs.len());
        for input in inputs {
            match input {
                FunctionInput::Constant(value) => {
                    let Some(word) = value.try_to_u32() else {
                        return self.unsupported_opcode(
                            "BlackBoxFuncCall",
                            opcode_index,
                            format!("Blake3 constant input must fit into 8 bits, found {value}"),
                        );
                    };
                    if word > u32::from(u8::MAX) {
                        return self.unsupported_opcode(
                            "BlackBoxFuncCall",
                            opcode_index,
                            format!("Blake3 constant input must fit into 8 bits, found {value}"),
                        );
                    }
                    bytes.push(word as u8);
                }
                FunctionInput::Witness(_) => {
                    return self.lower_blackbox_with_mode(
                        call,
                        opcode_index,
                        "Blake3 witness-driven native lowering is not implemented".to_string(),
                    )
                }
            }
        }

        let digest = match blake3(&bytes) {
            Ok(digest) => digest,
            Err(err) => {
                return self.unsupported_opcode(
                    "BlackBoxFuncCall",
                    opcode_index,
                    format!("failed evaluating constant Blake3 inputs: {err}"),
                );
            }
        };

        for (output, byte) in outputs.iter().zip(digest.into_iter()) {
            self.ensure_witness_in_range(*output, "BlackBoxFuncCall::Blake3 output")?;
            let output_wire = self.wire_for_witness(*output)?;
            self.enforce_wire_equals_constant(output_wire, FieldElement::from(u128::from(byte)))?;
        }

        Ok(())
    }

    fn lower_sha256_compression_with_constant_folding(
        &mut self,
        call: &AcirBlackBoxFuncCall,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        let (inputs, hash_values, outputs) = match call {
            BlackBoxFuncCall::Sha256Compression {
                inputs,
                hash_values,
                outputs,
            } => (inputs.as_ref(), hash_values.as_ref(), outputs.as_ref()),
            _ => unreachable!("caller must pass Sha256Compression"),
        };

        for input in inputs {
            self.lower_range(input, 32, opcode_index)?;
        }
        for hash_value in hash_values {
            self.lower_range(hash_value, 32, opcode_index)?;
        }

        let all_inputs_constant = inputs
            .iter()
            .all(|input| matches!(input, FunctionInput::Constant(_)));
        let all_hash_values_constant = hash_values
            .iter()
            .all(|hash_value| matches!(hash_value, FunctionInput::Constant(_)));

        if !(all_inputs_constant && all_hash_values_constant) {
            return self.lower_sha256_compression_relation(
                inputs,
                hash_values,
                outputs,
                opcode_index,
            );
        }

        let mut message = [0u32; 16];
        for (index, input) in inputs.iter().enumerate() {
            let FunctionInput::Constant(value) = input else {
                unreachable!("all inputs are constants")
            };
            let Some(word) = value.try_to_u32() else {
                return self.unsupported_opcode(
                    "BlackBoxFuncCall",
                    opcode_index,
                    format!(
                        "Sha256Compression constant input word must fit into 32 bits, found {value}"
                    ),
                );
            };
            message[index] = word;
        }

        let mut state = [0u32; 8];
        for (index, hash_value) in hash_values.iter().enumerate() {
            let FunctionInput::Constant(value) = hash_value else {
                unreachable!("all hash values are constants")
            };
            let Some(word) = value.try_to_u32() else {
                return self.unsupported_opcode(
                    "BlackBoxFuncCall",
                    opcode_index,
                    format!(
                        "Sha256Compression constant hash value must fit into 32 bits, found {value}"
                    ),
                );
            };
            state[index] = word;
        }

        sha256_compression(&mut state, &message);
        for (output, value) in outputs.iter().zip(state.into_iter()) {
            self.ensure_witness_in_range(*output, "BlackBoxFuncCall::Sha256Compression output")?;
            let output_wire = self.wire_for_witness(*output)?;
            self.enforce_wire_equals_constant(output_wire, FieldElement::from(u128::from(value)))?;
        }

        Ok(())
    }

    fn lower_sha256_compression_relation(
        &mut self,
        inputs: &[AcirFunctionInput; 16],
        hash_values: &[AcirFunctionInput; 8],
        outputs: &[Witness; 8],
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        let zero_wire = self.constrain_linear_combination_to_new_wire(&[], FieldElement::zero())?;

        let mut schedule = Vec::with_capacity(64);
        for (index, input) in inputs.iter().enumerate() {
            let context = format!("BlackBoxFuncCall::Sha256Compression input[{index}]");
            schedule.push(self.sha256_word_from_input(input, opcode_index, &context)?);
        }
        for index in 16..64 {
            let sigma0_bits = self.sha256_xor3_bits(
                &Self::sha256_right_rotate_bits(&schedule[index - 15].bits, 7),
                &Self::sha256_right_rotate_bits(&schedule[index - 15].bits, 18),
                &Self::sha256_right_shift_bits(&schedule[index - 15].bits, 3, zero_wire),
            )?;
            let sigma0 = self.sha256_word_from_bits(sigma0_bits)?;

            let sigma1_bits = self.sha256_xor3_bits(
                &Self::sha256_right_rotate_bits(&schedule[index - 2].bits, 17),
                &Self::sha256_right_rotate_bits(&schedule[index - 2].bits, 19),
                &Self::sha256_right_shift_bits(&schedule[index - 2].bits, 10, zero_wire),
            )?;
            let sigma1 = self.sha256_word_from_bits(sigma1_bits)?;

            let word = self.sha256_add_mod_u32(
                &[
                    schedule[index - 16].wire,
                    sigma0.wire,
                    schedule[index - 7].wire,
                    sigma1.wire,
                ],
                0,
                opcode_index,
                "BlackBoxFuncCall::Sha256Compression schedule word",
            )?;
            schedule.push(word);
        }

        let mut initial_state = Vec::with_capacity(8);
        for (index, hash_value) in hash_values.iter().enumerate() {
            let context = format!("BlackBoxFuncCall::Sha256Compression hash value[{index}]");
            initial_state.push(self.sha256_word_from_input(hash_value, opcode_index, &context)?);
        }

        let mut a = initial_state[0].clone();
        let mut b = initial_state[1].clone();
        let mut c = initial_state[2].clone();
        let mut d = initial_state[3].clone();
        let mut e = initial_state[4].clone();
        let mut f = initial_state[5].clone();
        let mut g = initial_state[6].clone();
        let mut h = initial_state[7].clone();

        for round in 0..64 {
            let big_sigma1_bits = self.sha256_xor3_bits(
                &Self::sha256_right_rotate_bits(&e.bits, 6),
                &Self::sha256_right_rotate_bits(&e.bits, 11),
                &Self::sha256_right_rotate_bits(&e.bits, 25),
            )?;
            let big_sigma1 = self.sha256_word_from_bits(big_sigma1_bits)?;

            let e_and_f = self.sha256_and_bits(&e.bits, &f.bits)?;
            let not_e = self.sha256_not_bits(&e.bits)?;
            let not_e_and_g = self.sha256_and_bits(&not_e, &g.bits)?;
            let ch_bits = self.sha256_xor_bits(&e_and_f, &not_e_and_g)?;
            let ch = self.sha256_word_from_bits(ch_bits)?;

            let temp1 = self.sha256_add_mod_u32(
                &[h.wire, big_sigma1.wire, ch.wire, schedule[round].wire],
                SHA256_ROUND_CONSTANTS[round],
                opcode_index,
                "BlackBoxFuncCall::Sha256Compression temp1",
            )?;

            let big_sigma0_bits = self.sha256_xor3_bits(
                &Self::sha256_right_rotate_bits(&a.bits, 2),
                &Self::sha256_right_rotate_bits(&a.bits, 13),
                &Self::sha256_right_rotate_bits(&a.bits, 22),
            )?;
            let big_sigma0 = self.sha256_word_from_bits(big_sigma0_bits)?;

            let a_and_b = self.sha256_and_bits(&a.bits, &b.bits)?;
            let a_and_c = self.sha256_and_bits(&a.bits, &c.bits)?;
            let b_and_c = self.sha256_and_bits(&b.bits, &c.bits)?;
            let maj_bits = self.sha256_xor3_bits(&a_and_b, &a_and_c, &b_and_c)?;
            let maj = self.sha256_word_from_bits(maj_bits)?;

            let temp2 = self.sha256_add_mod_u32(
                &[big_sigma0.wire, maj.wire],
                0,
                opcode_index,
                "BlackBoxFuncCall::Sha256Compression temp2",
            )?;

            let next_e = self.sha256_add_mod_u32(
                &[d.wire, temp1.wire],
                0,
                opcode_index,
                "BlackBoxFuncCall::Sha256Compression next e",
            )?;
            let next_a = self.sha256_add_mod_u32(
                &[temp1.wire, temp2.wire],
                0,
                opcode_index,
                "BlackBoxFuncCall::Sha256Compression next a",
            )?;

            h = g;
            g = f;
            f = e;
            e = next_e;
            d = c;
            c = b;
            b = a;
            a = next_a;
        }

        let state_words = [a, b, c, d, e, f, g, h];
        let mut final_state = Vec::with_capacity(8);
        for (index, value) in state_words.iter().enumerate() {
            final_state.push(self.sha256_add_mod_u32(
                &[initial_state[index].wire, value.wire],
                0,
                opcode_index,
                "BlackBoxFuncCall::Sha256Compression final state word",
            )?);
        }

        for (index, output) in outputs.iter().enumerate() {
            self.ensure_witness_in_range(*output, "BlackBoxFuncCall::Sha256Compression output")?;
            let output_wire = self.wire_for_witness(*output)?;
            self.enforce_wire_equality(output_wire, final_state[index].wire)?;
        }

        Ok(())
    }

    fn sha256_word_from_input(
        &mut self,
        input: &AcirFunctionInput,
        opcode_index: usize,
        context: &str,
    ) -> Result<Sha256Word, R1csError> {
        let wire = self.resolve_blackbox_function_input_wire(input, context)?;
        let bits = self.decompose_wire_to_bits(wire, 32, opcode_index, context)?;
        Ok(Sha256Word { wire, bits })
    }

    fn sha256_word_from_bits(&mut self, bits: Vec<u32>) -> Result<Sha256Word, R1csError> {
        let mut terms = Vec::with_capacity(bits.len());
        let mut coeff = FieldElement::one();
        for bit in &bits {
            terms.push((*bit, coeff));
            coeff += coeff;
        }
        let wire = self.constrain_linear_combination_to_new_wire(&terms, FieldElement::zero())?;
        Ok(Sha256Word { wire, bits })
    }

    fn sha256_add_mod_u32(
        &mut self,
        operands: &[u32],
        constant: u32,
        opcode_index: usize,
        context: &str,
    ) -> Result<Sha256Word, R1csError> {
        let result_wire = self.allocate_intermediate_wire();
        let result_bits = self.decompose_wire_to_bits(result_wire, 32, opcode_index, context)?;

        let mut carry_bound = operands.len();
        if constant != 0 {
            carry_bound += 1;
        }
        let mut carry_bits = 1u32;
        let mut max_carry = carry_bound.saturating_sub(1);
        while max_carry > 1 {
            carry_bits += 1;
            max_carry >>= 1;
        }

        let carry_wire = self.allocate_intermediate_wire();
        let _ = self.decompose_wire_to_bits(carry_wire, carry_bits, opcode_index, context)?;

        let two_to_32 = FieldElement::from(1u128 << 32);
        let mut linear_terms: BTreeMap<u32, FieldElement> = BTreeMap::new();
        for operand in operands {
            add_linear(&mut linear_terms, *operand, FieldElement::one());
        }
        add_linear(&mut linear_terms, result_wire, -FieldElement::one());
        add_linear(&mut linear_terms, carry_wire, -two_to_32);
        if constant != 0 {
            add_linear(
                &mut linear_terms,
                0,
                FieldElement::from(u128::from(constant)),
            );
        }

        self.emit_constraint(
            vec![SparseTerm {
                wire: 0,
                coeff: FieldElement::one(),
            }],
            linear_terms
                .into_iter()
                .map(|(wire, coeff)| SparseTerm { wire, coeff })
                .collect(),
            Vec::new(),
        )?;

        Ok(Sha256Word {
            wire: result_wire,
            bits: result_bits,
        })
    }

    fn sha256_right_rotate_bits(bits: &[u32], amount: usize) -> Vec<u32> {
        let width = bits.len();
        (0..width)
            .map(|index| bits[(index + amount) % width])
            .collect()
    }

    fn sha256_right_shift_bits(bits: &[u32], amount: usize, zero_wire: u32) -> Vec<u32> {
        let width = bits.len();
        (0..width)
            .map(|index| {
                if index + amount < width {
                    bits[index + amount]
                } else {
                    zero_wire
                }
            })
            .collect()
    }

    fn sha256_xor_bits(&mut self, lhs: &[u32], rhs: &[u32]) -> Result<Vec<u32>, R1csError> {
        let mut out = Vec::with_capacity(lhs.len());
        for (lhs_bit, rhs_bit) in lhs.iter().zip(rhs.iter()) {
            let product = self.multiply_wires(*lhs_bit, *rhs_bit)?;
            let output = self.allocate_intermediate_wire();
            self.emit_constraint(
                vec![SparseTerm {
                    wire: 0,
                    coeff: FieldElement::one(),
                }],
                vec![
                    SparseTerm {
                        wire: *lhs_bit,
                        coeff: FieldElement::one(),
                    },
                    SparseTerm {
                        wire: *rhs_bit,
                        coeff: FieldElement::one(),
                    },
                    SparseTerm {
                        wire: product,
                        coeff: -FieldElement::from(2u128),
                    },
                    SparseTerm {
                        wire: output,
                        coeff: -FieldElement::one(),
                    },
                ],
                Vec::new(),
            )?;
            self.enforce_boolean_wire(output)?;
            out.push(output);
        }
        Ok(out)
    }

    fn sha256_xor3_bits(
        &mut self,
        first: &[u32],
        second: &[u32],
        third: &[u32],
    ) -> Result<Vec<u32>, R1csError> {
        let partial = self.sha256_xor_bits(first, second)?;
        self.sha256_xor_bits(&partial, third)
    }

    fn sha256_and_bits(&mut self, lhs: &[u32], rhs: &[u32]) -> Result<Vec<u32>, R1csError> {
        let mut out = Vec::with_capacity(lhs.len());
        for (lhs_bit, rhs_bit) in lhs.iter().zip(rhs.iter()) {
            out.push(self.boolean_and_wires(*lhs_bit, *rhs_bit)?);
        }
        Ok(out)
    }

    fn sha256_not_bits(&mut self, bits: &[u32]) -> Result<Vec<u32>, R1csError> {
        let mut out = Vec::with_capacity(bits.len());
        for bit in bits {
            out.push(self.boolean_not_wire(*bit)?);
        }
        Ok(out)
    }

    fn lower_ecdsa_with_constant_folding(
        &mut self,
        call: &AcirBlackBoxFuncCall,
        opcode_index: usize,
        secp256k1: bool,
    ) -> Result<(), R1csError> {
        let (public_key_x, public_key_y, signature, hashed_message, predicate, output) =
            if secp256k1 {
                match call {
                    BlackBoxFuncCall::EcdsaSecp256k1 {
                        public_key_x,
                        public_key_y,
                        signature,
                        hashed_message,
                        predicate,
                        output,
                    } => (
                        public_key_x.as_ref(),
                        public_key_y.as_ref(),
                        signature.as_ref(),
                        hashed_message.as_ref(),
                        predicate,
                        *output,
                    ),
                    _ => unreachable!("caller must pass EcdsaSecp256k1"),
                }
            } else {
                match call {
                    BlackBoxFuncCall::EcdsaSecp256r1 {
                        public_key_x,
                        public_key_y,
                        signature,
                        hashed_message,
                        predicate,
                        output,
                    } => (
                        public_key_x.as_ref(),
                        public_key_y.as_ref(),
                        signature.as_ref(),
                        hashed_message.as_ref(),
                        predicate,
                        *output,
                    ),
                    _ => unreachable!("caller must pass EcdsaSecp256r1"),
                }
            };

        for input in public_key_x
            .iter()
            .chain(public_key_y.iter())
            .chain(signature.iter())
            .chain(hashed_message.iter())
        {
            self.lower_range(input, 8, opcode_index)?;
        }

        self.ensure_witness_in_range(output, "BlackBoxFuncCall::Ecdsa output")?;
        let output_wire = self.wire_for_witness(output)?;

        match predicate {
            FunctionInput::Constant(value) if value.is_zero() => {
                // ACVM writes `true` for disabled ECDSA calls.
                self.enforce_wire_equals_constant(output_wire, FieldElement::one())?;
                return Ok(());
            }
            FunctionInput::Constant(value) if value.is_one() => {}
            FunctionInput::Constant(value) => {
                return self.unsupported_opcode(
                    "BlackBoxFuncCall",
                    opcode_index,
                    format!("ECDSA predicate must be 0 or 1, found {value}"),
                );
            }
            FunctionInput::Witness(_) => {
                return self.lower_blackbox_with_mode(
                    call,
                    opcode_index,
                    "ECDSA witness-driven native lowering is not implemented".to_string(),
                )
            }
        }

        let mut pub_key_x = [0u8; 32];
        for (index, input) in public_key_x.iter().enumerate() {
            match input {
                FunctionInput::Constant(value) => {
                    let Some(word) = value.try_to_u32() else {
                        return self.unsupported_opcode(
                            "BlackBoxFuncCall",
                            opcode_index,
                            format!(
                                "ECDSA public key x constant input must fit into 8 bits, found {value}"
                            ),
                        );
                    };
                    if word > u32::from(u8::MAX) {
                        return self.unsupported_opcode(
                            "BlackBoxFuncCall",
                            opcode_index,
                            format!(
                                "ECDSA public key x constant input must fit into 8 bits, found {value}"
                            ),
                        );
                    }
                    pub_key_x[index] = word as u8;
                }
                FunctionInput::Witness(_) => {
                    return self.lower_blackbox_with_mode(
                        call,
                        opcode_index,
                        "ECDSA witness-driven native lowering is not implemented".to_string(),
                    )
                }
            }
        }

        let mut pub_key_y = [0u8; 32];
        for (index, input) in public_key_y.iter().enumerate() {
            match input {
                FunctionInput::Constant(value) => {
                    let Some(word) = value.try_to_u32() else {
                        return self.unsupported_opcode(
                            "BlackBoxFuncCall",
                            opcode_index,
                            format!(
                                "ECDSA public key y constant input must fit into 8 bits, found {value}"
                            ),
                        );
                    };
                    if word > u32::from(u8::MAX) {
                        return self.unsupported_opcode(
                            "BlackBoxFuncCall",
                            opcode_index,
                            format!(
                                "ECDSA public key y constant input must fit into 8 bits, found {value}"
                            ),
                        );
                    }
                    pub_key_y[index] = word as u8;
                }
                FunctionInput::Witness(_) => {
                    return self.lower_blackbox_with_mode(
                        call,
                        opcode_index,
                        "ECDSA witness-driven native lowering is not implemented".to_string(),
                    )
                }
            }
        }

        let mut signature_bytes = [0u8; 64];
        for (index, input) in signature.iter().enumerate() {
            match input {
                FunctionInput::Constant(value) => {
                    let Some(word) = value.try_to_u32() else {
                        return self.unsupported_opcode(
                            "BlackBoxFuncCall",
                            opcode_index,
                            format!(
                                "ECDSA signature constant input must fit into 8 bits, found {value}"
                            ),
                        );
                    };
                    if word > u32::from(u8::MAX) {
                        return self.unsupported_opcode(
                            "BlackBoxFuncCall",
                            opcode_index,
                            format!(
                                "ECDSA signature constant input must fit into 8 bits, found {value}"
                            ),
                        );
                    }
                    signature_bytes[index] = word as u8;
                }
                FunctionInput::Witness(_) => {
                    return self.lower_blackbox_with_mode(
                        call,
                        opcode_index,
                        "ECDSA witness-driven native lowering is not implemented".to_string(),
                    )
                }
            }
        }

        let mut hashed_message_bytes = [0u8; 32];
        for (index, input) in hashed_message.iter().enumerate() {
            match input {
                FunctionInput::Constant(value) => {
                    let Some(word) = value.try_to_u32() else {
                        return self.unsupported_opcode(
                            "BlackBoxFuncCall",
                            opcode_index,
                            format!(
                                "ECDSA hashed message constant input must fit into 8 bits, found {value}"
                            ),
                        );
                    };
                    if word > u32::from(u8::MAX) {
                        return self.unsupported_opcode(
                            "BlackBoxFuncCall",
                            opcode_index,
                            format!(
                                "ECDSA hashed message constant input must fit into 8 bits, found {value}"
                            ),
                        );
                    }
                    hashed_message_bytes[index] = word as u8;
                }
                FunctionInput::Witness(_) => {
                    return self.lower_blackbox_with_mode(
                        call,
                        opcode_index,
                        "ECDSA witness-driven native lowering is not implemented".to_string(),
                    )
                }
            }
        }

        let is_valid = if secp256k1 {
            match ecdsa_secp256k1_verify(
                &hashed_message_bytes,
                &pub_key_x,
                &pub_key_y,
                &signature_bytes,
            ) {
                Ok(is_valid) => is_valid,
                Err(err) => {
                    return self.unsupported_opcode(
                        "BlackBoxFuncCall",
                        opcode_index,
                        format!("failed evaluating constant EcdsaSecp256k1 inputs: {err}"),
                    );
                }
            }
        } else {
            match ecdsa_secp256r1_verify(
                &hashed_message_bytes,
                &pub_key_x,
                &pub_key_y,
                &signature_bytes,
            ) {
                Ok(is_valid) => is_valid,
                Err(err) => {
                    return self.unsupported_opcode(
                        "BlackBoxFuncCall",
                        opcode_index,
                        format!("failed evaluating constant EcdsaSecp256r1 inputs: {err}"),
                    );
                }
            }
        };
        let output_value = if is_valid {
            FieldElement::one()
        } else {
            FieldElement::zero()
        };
        self.enforce_wire_equals_constant(output_wire, output_value)?;

        Ok(())
    }

    fn lower_multi_scalar_mul_with_constant_folding(
        &mut self,
        call: &AcirBlackBoxFuncCall,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        let (points, scalars, predicate, outputs) = match call {
            BlackBoxFuncCall::MultiScalarMul {
                points,
                scalars,
                predicate,
                outputs,
            } => (points.as_slice(), scalars.as_slice(), predicate, *outputs),
            _ => unreachable!("caller must pass MultiScalarMul"),
        };

        if !points.len().is_multiple_of(3) {
            return self.unsupported_opcode(
                "BlackBoxFuncCall",
                opcode_index,
                format!(
                    "MultiScalarMul expects points length to be a multiple of 3, found {}",
                    points.len()
                ),
            );
        }
        if !scalars.len().is_multiple_of(2) {
            return self.unsupported_opcode(
                "BlackBoxFuncCall",
                opcode_index,
                format!(
                    "MultiScalarMul expects scalars length to be a multiple of 2, found {}",
                    scalars.len()
                ),
            );
        }
        if points.len() / 3 != scalars.len() / 2 {
            return self.unsupported_opcode(
                "BlackBoxFuncCall",
                opcode_index,
                format!(
                    "MultiScalarMul points/scalars arity mismatch: {} points vs {} scalars",
                    points.len(),
                    scalars.len()
                ),
            );
        }

        let output_witnesses = [outputs.0, outputs.1, outputs.2];
        let mut output_wires = [0u32; 3];
        for (index, output) in output_witnesses.iter().enumerate() {
            self.ensure_witness_in_range(*output, "BlackBoxFuncCall::MultiScalarMul output")?;
            output_wires[index] = self.wire_for_witness(*output)?;
        }
        let output_x_wire = output_wires[0];
        let output_y_wire = output_wires[1];
        let output_infinite_wire = output_wires[2];
        self.enforce_boolean_wire(output_infinite_wire)?;

        let predicate = self.resolve_blackbox_predicate(
            predicate,
            opcode_index,
            "BlackBoxFuncCall::MultiScalarMul predicate",
        )?;
        if matches!(predicate, ResolvedBlackBoxPredicate::Constant(false)) {
            self.enforce_wire_equals_constant(output_x_wire, FieldElement::zero())?;
            self.enforce_wire_equals_constant(output_y_wire, FieldElement::zero())?;
            self.enforce_wire_equals_constant(output_infinite_wire, FieldElement::one())?;
            return Ok(());
        }

        let predicate_wire = match predicate {
            ResolvedBlackBoxPredicate::Constant(true) => 0,
            ResolvedBlackBoxPredicate::Wire(wire) => wire,
            ResolvedBlackBoxPredicate::Constant(false) => unreachable!(),
        };
        if let ResolvedBlackBoxPredicate::Wire(wire) = predicate {
            let one_minus_predicate = self.boolean_not_wire(wire)?;
            self.enforce_selector_times_linear_zero(
                one_minus_predicate,
                &[(output_x_wire, FieldElement::one())],
                FieldElement::zero(),
            )?;
            self.enforce_selector_times_linear_zero(
                one_minus_predicate,
                &[(output_y_wire, FieldElement::one())],
                FieldElement::zero(),
            )?;
            self.enforce_selector_times_linear_zero(
                one_minus_predicate,
                &[(output_infinite_wire, FieldElement::one())],
                -FieldElement::one(),
            )?;
        }

        let mut point_values = Vec::with_capacity(points.len());
        for point in points {
            match point {
                FunctionInput::Constant(value) => point_values.push(*value),
                FunctionInput::Witness(_) => {
                    return self.lower_blackbox_with_mode(
                        call,
                        opcode_index,
                        "MultiScalarMul witness-driven native lowering is not implemented"
                            .to_string(),
                    )
                }
            }
        }

        let mut scalar_lo = Vec::with_capacity(scalars.len() / 2);
        let mut scalar_hi = Vec::with_capacity(scalars.len() / 2);
        for (index, scalar) in scalars.iter().enumerate() {
            match scalar {
                FunctionInput::Constant(value) => {
                    if index.is_multiple_of(2) {
                        scalar_lo.push(*value);
                    } else {
                        scalar_hi.push(*value);
                    }
                }
                FunctionInput::Witness(_) => {
                    return self.lower_blackbox_with_mode(
                        call,
                        opcode_index,
                        "MultiScalarMul witness-driven native lowering is not implemented"
                            .to_string(),
                    )
                }
            }
        }

        let (result_x, result_y, result_infinite) =
            match bn254_multi_scalar_mul(&point_values, &scalar_lo, &scalar_hi) {
                Ok(result) => result,
                Err(err) => {
                    return self.unsupported_opcode(
                        "BlackBoxFuncCall",
                        opcode_index,
                        format!("failed evaluating constant MultiScalarMul inputs: {err}"),
                    );
                }
            };

        self.enforce_selector_times_linear_zero(
            predicate_wire,
            &[(output_x_wire, FieldElement::one())],
            -result_x,
        )?;
        self.enforce_selector_times_linear_zero(
            predicate_wire,
            &[(output_y_wire, FieldElement::one())],
            -result_y,
        )?;
        self.enforce_selector_times_linear_zero(
            predicate_wire,
            &[(output_infinite_wire, FieldElement::one())],
            -result_infinite,
        )?;

        Ok(())
    }

    fn lower_poseidon2_permutation(
        &mut self,
        inputs: &[AcirFunctionInput],
        outputs: &[Witness],
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        if inputs.len() != outputs.len() {
            return self.unsupported_opcode(
                "BlackBoxFuncCall",
                opcode_index,
                format!(
                    "Poseidon2Permutation input/output arity mismatch: {} inputs vs {} outputs",
                    inputs.len(),
                    outputs.len()
                ),
            );
        }

        let config = &*poseidon2_constants::POSEIDON2_CONFIG;
        let expected_width = config.t as usize;
        if inputs.len() != expected_width {
            return self.unsupported_opcode(
                "BlackBoxFuncCall",
                opcode_index,
                format!(
                    "Poseidon2Permutation expects exactly {expected_width} state elements, found {}",
                    inputs.len()
                ),
            );
        }

        let mut state = [0u32; 4];
        for (index, input) in inputs.iter().enumerate() {
            state[index] = self.resolve_blackbox_function_input_wire(
                input,
                "BlackBoxFuncCall::Poseidon2Permutation input",
            )?;
        }

        let mut output_wires = [0u32; 4];
        for (index, output) in outputs.iter().enumerate() {
            self.ensure_witness_in_range(*output, "BlackBoxFuncCall::Poseidon2Permutation output")?;
            output_wires[index] = self.wire_for_witness(*output)?;
        }

        state = self.poseidon2_matrix_multiplication_4x4(state)?;

        let full_round_half = (config.rounds_f / 2) as usize;
        for round in 0..full_round_half {
            self.poseidon2_add_round_constants(&mut state, &config.round_constant[round])?;
            self.poseidon2_sbox(&mut state)?;
            state = self.poseidon2_matrix_multiplication_4x4(state)?;
        }

        let partial_round_end = full_round_half + config.rounds_p as usize;
        for round in full_round_half..partial_round_end {
            state[0] = self.add_constant_to_wire(state[0], config.round_constant[round][0])?;
            state[0] = self.poseidon2_single_box(state[0])?;
            state = self.poseidon2_internal_m_multiplication(state)?;
        }

        let total_rounds = (config.rounds_f + config.rounds_p) as usize;
        for round in partial_round_end..total_rounds {
            self.poseidon2_add_round_constants(&mut state, &config.round_constant[round])?;
            self.poseidon2_sbox(&mut state)?;
            state = self.poseidon2_matrix_multiplication_4x4(state)?;
        }

        for (state_wire, output_wire) in state.into_iter().zip(output_wires) {
            self.enforce_wire_equality(state_wire, output_wire)?;
        }

        Ok(())
    }

    fn resolve_blackbox_function_input_wire(
        &mut self,
        input: &AcirFunctionInput,
        context: &str,
    ) -> Result<u32, R1csError> {
        match input {
            FunctionInput::Witness(witness) => {
                self.ensure_witness_in_range(*witness, context)?;
                self.wire_for_witness(*witness)
            }
            FunctionInput::Constant(value) => {
                self.constrain_linear_combination_to_new_wire(&[], *value)
            }
        }
    }

    fn multiply_wires(&mut self, lhs_wire: u32, rhs_wire: u32) -> Result<u32, R1csError> {
        let output_wire = self.allocate_intermediate_wire();
        self.emit_constraint(
            vec![SparseTerm {
                wire: lhs_wire,
                coeff: FieldElement::one(),
            }],
            vec![SparseTerm {
                wire: rhs_wire,
                coeff: FieldElement::one(),
            }],
            vec![SparseTerm {
                wire: output_wire,
                coeff: FieldElement::one(),
            }],
        )?;
        Ok(output_wire)
    }

    fn add_constant_to_wire(
        &mut self,
        wire: u32,
        constant: FieldElement,
    ) -> Result<u32, R1csError> {
        if constant.is_zero() {
            return Ok(wire);
        }
        self.constrain_linear_combination_to_new_wire(&[(wire, FieldElement::one())], constant)
    }

    fn constrain_linear_combination_to_new_wire(
        &mut self,
        terms: &[(u32, FieldElement)],
        constant: FieldElement,
    ) -> Result<u32, R1csError> {
        let output_wire = self.allocate_intermediate_wire();
        let mut linear_terms: BTreeMap<u32, FieldElement> = BTreeMap::new();
        for (wire, coeff) in terms {
            if coeff.is_zero() {
                continue;
            }
            add_linear(&mut linear_terms, *wire, *coeff);
        }
        if !constant.is_zero() {
            add_linear(&mut linear_terms, 0, constant);
        }

        self.emit_constraint(
            vec![SparseTerm {
                wire: 0,
                coeff: FieldElement::one(),
            }],
            linear_terms
                .into_iter()
                .map(|(wire, coeff)| SparseTerm { wire, coeff })
                .collect(),
            vec![SparseTerm {
                wire: output_wire,
                coeff: FieldElement::one(),
            }],
        )?;
        Ok(output_wire)
    }

    fn enforce_wire_equality(&mut self, lhs_wire: u32, rhs_wire: u32) -> Result<(), R1csError> {
        self.emit_constraint(
            vec![SparseTerm {
                wire: 0,
                coeff: FieldElement::one(),
            }],
            vec![
                SparseTerm {
                    wire: lhs_wire,
                    coeff: FieldElement::one(),
                },
                SparseTerm {
                    wire: rhs_wire,
                    coeff: -FieldElement::one(),
                },
            ],
            Vec::new(),
        )
    }

    fn poseidon2_single_box(&mut self, input_wire: u32) -> Result<u32, R1csError> {
        let square_wire = self.multiply_wires(input_wire, input_wire)?;
        let quad_wire = self.multiply_wires(square_wire, square_wire)?;
        self.multiply_wires(quad_wire, input_wire)
    }

    fn poseidon2_sbox(&mut self, state: &mut [u32; 4]) -> Result<(), R1csError> {
        for state_wire in state.iter_mut() {
            *state_wire = self.poseidon2_single_box(*state_wire)?;
        }
        Ok(())
    }

    fn poseidon2_add_round_constants(
        &mut self,
        state: &mut [u32; 4],
        round_constants: &[FieldElement; 4],
    ) -> Result<(), R1csError> {
        for (state_wire, constant) in state.iter_mut().zip(round_constants.iter()) {
            *state_wire = self.add_constant_to_wire(*state_wire, *constant)?;
        }
        Ok(())
    }

    fn poseidon2_matrix_multiplication_4x4(
        &mut self,
        state: [u32; 4],
    ) -> Result<[u32; 4], R1csError> {
        let one = FieldElement::one();
        let two = FieldElement::from(2u128);
        let four = FieldElement::from(4u128);

        let t0 = self.constrain_linear_combination_to_new_wire(
            &[(state[0], one), (state[1], one)],
            FieldElement::zero(),
        )?;
        let t1 = self.constrain_linear_combination_to_new_wire(
            &[(state[2], one), (state[3], one)],
            FieldElement::zero(),
        )?;
        let t2 = self.constrain_linear_combination_to_new_wire(
            &[(state[1], two), (t1, one)],
            FieldElement::zero(),
        )?;
        let t3 = self.constrain_linear_combination_to_new_wire(
            &[(state[3], two), (t0, one)],
            FieldElement::zero(),
        )?;
        let t4 = self.constrain_linear_combination_to_new_wire(
            &[(t1, four), (t3, one)],
            FieldElement::zero(),
        )?;
        let t5 = self.constrain_linear_combination_to_new_wire(
            &[(t0, four), (t2, one)],
            FieldElement::zero(),
        )?;
        let t6 = self.constrain_linear_combination_to_new_wire(
            &[(t3, one), (t5, one)],
            FieldElement::zero(),
        )?;
        let t7 = self.constrain_linear_combination_to_new_wire(
            &[(t2, one), (t4, one)],
            FieldElement::zero(),
        )?;
        Ok([t6, t5, t7, t4])
    }

    fn poseidon2_internal_m_multiplication(
        &mut self,
        state: [u32; 4],
    ) -> Result<[u32; 4], R1csError> {
        let one = FieldElement::one();
        let sum_wire = self.constrain_linear_combination_to_new_wire(
            &[
                (state[0], one),
                (state[1], one),
                (state[2], one),
                (state[3], one),
            ],
            FieldElement::zero(),
        )?;
        let diagonal = &poseidon2_constants::POSEIDON2_CONFIG.internal_matrix_diagonal;
        Ok([
            self.constrain_linear_combination_to_new_wire(
                &[(state[0], diagonal[0]), (sum_wire, one)],
                FieldElement::zero(),
            )?,
            self.constrain_linear_combination_to_new_wire(
                &[(state[1], diagonal[1]), (sum_wire, one)],
                FieldElement::zero(),
            )?,
            self.constrain_linear_combination_to_new_wire(
                &[(state[2], diagonal[2]), (sum_wire, one)],
                FieldElement::zero(),
            )?,
            self.constrain_linear_combination_to_new_wire(
                &[(state[3], diagonal[3]), (sum_wire, one)],
                FieldElement::zero(),
            )?,
        ])
    }

    fn lower_embedded_curve_add(
        &mut self,
        input1: &[AcirFunctionInput; 3],
        input2: &[AcirFunctionInput; 3],
        predicate: &AcirFunctionInput,
        outputs: (Witness, Witness, Witness),
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        let output_witnesses = [outputs.0, outputs.1, outputs.2];
        let mut output_wires = [0u32; 3];
        for (index, output) in output_witnesses.iter().enumerate() {
            self.ensure_witness_in_range(*output, "BlackBoxFuncCall::EmbeddedCurveAdd output")?;
            output_wires[index] = self.wire_for_witness(*output)?;
        }
        let output_x_wire = output_wires[0];
        let output_y_wire = output_wires[1];
        let output_infinite_wire = output_wires[2];

        let predicate = self.resolve_blackbox_predicate(
            predicate,
            opcode_index,
            "BlackBoxFuncCall::EmbeddedCurveAdd predicate",
        )?;
        if matches!(predicate, ResolvedBlackBoxPredicate::Constant(false)) {
            self.enforce_wire_equals_constant(output_x_wire, FieldElement::zero())?;
            self.enforce_wire_equals_constant(output_y_wire, FieldElement::zero())?;
            self.enforce_wire_equals_constant(output_infinite_wire, FieldElement::one())?;
            return Ok(());
        }

        let predicate_wire = match predicate {
            ResolvedBlackBoxPredicate::Constant(true) => 0,
            ResolvedBlackBoxPredicate::Wire(wire) => wire,
            ResolvedBlackBoxPredicate::Constant(false) => unreachable!(),
        };
        if let ResolvedBlackBoxPredicate::Wire(wire) = predicate {
            let one_minus_predicate = self.boolean_not_wire(wire)?;
            self.enforce_selector_times_linear_zero(
                one_minus_predicate,
                &[(output_x_wire, FieldElement::one())],
                FieldElement::zero(),
            )?;
            self.enforce_selector_times_linear_zero(
                one_minus_predicate,
                &[(output_y_wire, FieldElement::one())],
                FieldElement::zero(),
            )?;
            self.enforce_selector_times_linear_zero(
                one_minus_predicate,
                &[(output_infinite_wire, FieldElement::one())],
                -FieldElement::one(),
            )?;
        }

        let input1_x = self.resolve_blackbox_function_input_wire(
            input1.first().expect("input1 x is present"),
            "BlackBoxFuncCall::EmbeddedCurveAdd input1.x",
        )?;
        let input1_y = self.resolve_blackbox_function_input_wire(
            input1.get(1).expect("input1 y is present"),
            "BlackBoxFuncCall::EmbeddedCurveAdd input1.y",
        )?;
        let input1_infinite = self.resolve_blackbox_function_input_wire(
            input1.get(2).expect("input1 infinite is present"),
            "BlackBoxFuncCall::EmbeddedCurveAdd input1.is_infinite",
        )?;
        let input2_x = self.resolve_blackbox_function_input_wire(
            input2.first().expect("input2 x is present"),
            "BlackBoxFuncCall::EmbeddedCurveAdd input2.x",
        )?;
        let input2_y = self.resolve_blackbox_function_input_wire(
            input2.get(1).expect("input2 y is present"),
            "BlackBoxFuncCall::EmbeddedCurveAdd input2.y",
        )?;
        let input2_infinite = self.resolve_blackbox_function_input_wire(
            input2.get(2).expect("input2 infinite is present"),
            "BlackBoxFuncCall::EmbeddedCurveAdd input2.is_infinite",
        )?;

        self.enforce_selector_times_linear_zero(
            predicate_wire,
            &[(input1_infinite, FieldElement::one())],
            FieldElement::zero(),
        )?;
        self.enforce_selector_times_linear_zero(
            predicate_wire,
            &[(input2_infinite, FieldElement::one())],
            FieldElement::zero(),
        )?;

        let input1_y_squared = self.multiply_wires(input1_y, input1_y)?;
        let input1_x_squared = self.multiply_wires(input1_x, input1_x)?;
        let input1_x_cubed = self.multiply_wires(input1_x_squared, input1_x)?;
        self.enforce_selector_times_linear_zero(
            predicate_wire,
            &[
                (input1_y_squared, FieldElement::one()),
                (input1_x_cubed, -FieldElement::one()),
            ],
            FieldElement::from(17u128),
        )?;

        let input2_y_squared = self.multiply_wires(input2_y, input2_y)?;
        let input2_x_squared = self.multiply_wires(input2_x, input2_x)?;
        let input2_x_cubed = self.multiply_wires(input2_x_squared, input2_x)?;
        self.enforce_selector_times_linear_zero(
            predicate_wire,
            &[
                (input2_y_squared, FieldElement::one()),
                (input2_x_cubed, -FieldElement::one()),
            ],
            FieldElement::from(17u128),
        )?;

        let same_x = self.equality_indicator_wire(input1_x, input2_x)?;
        let same_y = self.equality_indicator_wire(input1_y, input2_y)?;
        let y_sum = self.constrain_linear_combination_to_new_wire(
            &[
                (input1_y, FieldElement::one()),
                (input2_y, FieldElement::one()),
            ],
            FieldElement::zero(),
        )?;
        let zero_wire = self.constrain_linear_combination_to_new_wire(&[], FieldElement::zero())?;
        let opposite_y = self.equality_indicator_wire(y_sum, zero_wire)?;

        let expected_output_infinite = self.boolean_and_wires(same_x, opposite_y)?;
        self.enforce_selector_times_linear_zero(
            predicate_wire,
            &[
                (output_infinite_wire, FieldElement::one()),
                (expected_output_infinite, -FieldElement::one()),
            ],
            FieldElement::zero(),
        )?;

        let one_minus_expected_output_infinite = self.boolean_not_wire(expected_output_infinite)?;
        let finite_selector =
            self.multiply_wires(predicate_wire, one_minus_expected_output_infinite)?;
        self.enforce_boolean_wire(finite_selector)?;
        let infinite_selector = self.multiply_wires(predicate_wire, expected_output_infinite)?;
        self.enforce_boolean_wire(infinite_selector)?;

        let is_double = self.boolean_and_wires(same_x, same_y)?;
        let one_minus_is_double = self.boolean_not_wire(is_double)?;
        let add_selector = self.multiply_wires(finite_selector, one_minus_is_double)?;
        self.enforce_boolean_wire(add_selector)?;
        let double_selector = self.multiply_wires(finite_selector, is_double)?;
        self.enforce_boolean_wire(double_selector)?;

        let x2_minus_x1 = self.constrain_linear_combination_to_new_wire(
            &[
                (input2_x, FieldElement::one()),
                (input1_x, -FieldElement::one()),
            ],
            FieldElement::zero(),
        )?;
        let add_denominator_inverse = self.allocate_intermediate_wire();
        let add_denominator_inverse_check =
            self.multiply_wires(x2_minus_x1, add_denominator_inverse)?;
        self.enforce_selector_times_linear_zero(
            add_selector,
            &[(add_denominator_inverse_check, FieldElement::one())],
            -FieldElement::one(),
        )?;
        let y2_minus_y1 = self.constrain_linear_combination_to_new_wire(
            &[
                (input2_y, FieldElement::one()),
                (input1_y, -FieldElement::one()),
            ],
            FieldElement::zero(),
        )?;
        let add_lambda = self.multiply_wires(y2_minus_y1, add_denominator_inverse)?;

        let two_y1 = self.constrain_linear_combination_to_new_wire(
            &[(input1_y, FieldElement::from(2u128))],
            FieldElement::zero(),
        )?;
        let double_denominator_inverse = self.allocate_intermediate_wire();
        let double_denominator_inverse_check =
            self.multiply_wires(two_y1, double_denominator_inverse)?;
        self.enforce_selector_times_linear_zero(
            double_selector,
            &[(double_denominator_inverse_check, FieldElement::one())],
            -FieldElement::one(),
        )?;
        let three_x1_squared = self.constrain_linear_combination_to_new_wire(
            &[(input1_x_squared, FieldElement::from(3u128))],
            FieldElement::zero(),
        )?;
        let double_lambda = self.multiply_wires(three_x1_squared, double_denominator_inverse)?;

        let add_lambda_squared = self.multiply_wires(add_lambda, add_lambda)?;
        self.enforce_selector_times_linear_zero(
            add_selector,
            &[
                (output_x_wire, FieldElement::one()),
                (add_lambda_squared, -FieldElement::one()),
                (input1_x, FieldElement::one()),
                (input2_x, FieldElement::one()),
            ],
            FieldElement::zero(),
        )?;
        let input1_x_minus_output_x = self.constrain_linear_combination_to_new_wire(
            &[
                (input1_x, FieldElement::one()),
                (output_x_wire, -FieldElement::one()),
            ],
            FieldElement::zero(),
        )?;
        let add_y_intermediate = self.multiply_wires(add_lambda, input1_x_minus_output_x)?;
        self.enforce_selector_times_linear_zero(
            add_selector,
            &[
                (output_y_wire, FieldElement::one()),
                (add_y_intermediate, -FieldElement::one()),
                (input1_y, FieldElement::one()),
            ],
            FieldElement::zero(),
        )?;

        let double_lambda_squared = self.multiply_wires(double_lambda, double_lambda)?;
        self.enforce_selector_times_linear_zero(
            double_selector,
            &[
                (output_x_wire, FieldElement::one()),
                (double_lambda_squared, -FieldElement::one()),
                (input1_x, FieldElement::from(2u128)),
            ],
            FieldElement::zero(),
        )?;
        let double_y_intermediate = self.multiply_wires(double_lambda, input1_x_minus_output_x)?;
        self.enforce_selector_times_linear_zero(
            double_selector,
            &[
                (output_y_wire, FieldElement::one()),
                (double_y_intermediate, -FieldElement::one()),
                (input1_y, FieldElement::one()),
            ],
            FieldElement::zero(),
        )?;

        self.enforce_selector_times_linear_zero(
            infinite_selector,
            &[(output_x_wire, FieldElement::one())],
            FieldElement::zero(),
        )?;
        self.enforce_selector_times_linear_zero(
            infinite_selector,
            &[(output_y_wire, FieldElement::one())],
            FieldElement::zero(),
        )?;

        Ok(())
    }

    fn resolve_blackbox_predicate(
        &mut self,
        predicate: &AcirFunctionInput,
        opcode_index: usize,
        context: &str,
    ) -> Result<ResolvedBlackBoxPredicate, R1csError> {
        match predicate {
            FunctionInput::Constant(value) if value.is_zero() => {
                Ok(ResolvedBlackBoxPredicate::Constant(false))
            }
            FunctionInput::Constant(value) if value.is_one() => {
                Ok(ResolvedBlackBoxPredicate::Constant(true))
            }
            FunctionInput::Constant(value) => {
                self.unsupported_opcode(
                    "BlackBoxFuncCall",
                    opcode_index,
                    format!("{context} must be 0 or 1, found {value}"),
                )?;
                Ok(ResolvedBlackBoxPredicate::Constant(false))
            }
            FunctionInput::Witness(witness) => {
                self.ensure_witness_in_range(*witness, context)?;
                let predicate_wire = self.wire_for_witness(*witness)?;
                self.enforce_boolean_wire(predicate_wire)?;
                Ok(ResolvedBlackBoxPredicate::Wire(predicate_wire))
            }
        }
    }

    fn enforce_wire_equals_constant(
        &mut self,
        wire: u32,
        constant: FieldElement,
    ) -> Result<(), R1csError> {
        self.enforce_selector_times_linear_zero(0, &[(wire, FieldElement::one())], -constant)
    }

    fn enforce_selector_times_linear_zero(
        &mut self,
        selector_wire: u32,
        terms: &[(u32, FieldElement)],
        constant: FieldElement,
    ) -> Result<(), R1csError> {
        let mut linear_terms: BTreeMap<u32, FieldElement> = BTreeMap::new();
        for (wire, coeff) in terms {
            if coeff.is_zero() {
                continue;
            }
            add_linear(&mut linear_terms, *wire, *coeff);
        }
        if !constant.is_zero() {
            add_linear(&mut linear_terms, 0, constant);
        }
        self.emit_constraint(
            vec![SparseTerm {
                wire: selector_wire,
                coeff: FieldElement::one(),
            }],
            linear_terms
                .into_iter()
                .map(|(wire, coeff)| SparseTerm { wire, coeff })
                .collect(),
            Vec::new(),
        )
    }

    fn equality_indicator_wire(&mut self, lhs_wire: u32, rhs_wire: u32) -> Result<u32, R1csError> {
        let difference_wire = self.constrain_linear_combination_to_new_wire(
            &[
                (lhs_wire, FieldElement::one()),
                (rhs_wire, -FieldElement::one()),
            ],
            FieldElement::zero(),
        )?;
        let inverse_wire = self.allocate_intermediate_wire();
        let is_equal_wire = self.allocate_intermediate_wire();
        self.enforce_boolean_wire(is_equal_wire)?;

        let difference_times_inverse = self.multiply_wires(difference_wire, inverse_wire)?;
        self.enforce_selector_times_linear_zero(
            0,
            &[
                (difference_times_inverse, FieldElement::one()),
                (is_equal_wire, FieldElement::one()),
            ],
            -FieldElement::one(),
        )?;
        self.emit_constraint(
            vec![SparseTerm {
                wire: difference_wire,
                coeff: FieldElement::one(),
            }],
            vec![SparseTerm {
                wire: is_equal_wire,
                coeff: FieldElement::one(),
            }],
            Vec::new(),
        )?;
        Ok(is_equal_wire)
    }

    fn boolean_and_wires(&mut self, lhs_wire: u32, rhs_wire: u32) -> Result<u32, R1csError> {
        let and_wire = self.multiply_wires(lhs_wire, rhs_wire)?;
        self.enforce_boolean_wire(and_wire)?;
        Ok(and_wire)
    }

    fn boolean_not_wire(&mut self, wire: u32) -> Result<u32, R1csError> {
        let one_minus_wire = self.constrain_linear_combination_to_new_wire(
            &[(wire, -FieldElement::one())],
            FieldElement::one(),
        )?;
        self.enforce_boolean_wire(one_minus_wire)?;
        Ok(one_minus_wire)
    }

    fn lower_blackbox_as_hint(
        &mut self,
        call: &AcirBlackBoxFuncCall,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        for input in call.get_inputs_vec() {
            if let FunctionInput::Witness(witness) = input {
                self.ensure_witness_in_range(witness, "BlackBox input witness")?;
            }
        }
        if let Some(predicate) = call.get_predicate() {
            self.ensure_witness_in_range(predicate, "BlackBox predicate witness")?;
            self.enforce_boolean_witness(predicate)?;
        }

        let outputs = call.get_outputs_vec();
        if outputs.is_empty() {
            if self.blackbox_no_output_call_is_provably_disabled(call) {
                return Ok(());
            }
            return self.unsupported_opcode(
                "BlackBoxFuncCall",
                opcode_index,
                format!(
                    "blackbox function `{}` has no outputs and cannot be lowered soundly to R1CS",
                    call.name()
                ),
            );
        }

        for output in outputs {
            self.register_hint_output("BlackBoxFuncCall", output, opcode_index)?;
        }

        Ok(())
    }

    fn lower_blackbox_with_mode(
        &mut self,
        call: &AcirBlackBoxFuncCall,
        opcode_index: usize,
        details: String,
    ) -> Result<(), R1csError> {
        match self.options.mode {
            LoweringMode::Strict => {
                self.unsupported_opcode("BlackBoxFuncCall", opcode_index, details)
            }
            LoweringMode::AllowUnsupported => {
                self.unsupported_opcode("BlackBoxFuncCall", opcode_index, details)?;
                self.lower_blackbox_as_hint(call, opcode_index)
            }
        }
    }

    fn blackbox_no_output_call_is_provably_disabled(&self, call: &AcirBlackBoxFuncCall) -> bool {
        matches!(
            call,
            BlackBoxFuncCall::RecursiveAggregation {
                predicate: FunctionInput::Constant(value),
                ..
            } if value.is_zero()
        )
    }

    fn decompose_function_input_to_bits(
        &mut self,
        input: &AcirFunctionInput,
        num_bits: u32,
        opcode_index: usize,
        context: &str,
    ) -> Result<Vec<u32>, R1csError> {
        let wire = match input {
            FunctionInput::Witness(witness) => {
                self.ensure_witness_in_range(*witness, context)?;
                self.wire_for_witness(*witness)?
            }
            FunctionInput::Constant(value) => {
                let expr = AcirExpression::from_field(*value);
                self.bind_expression_to_new_wire(&expr, opcode_index, context)?
            }
        };
        self.decompose_wire_to_bits(wire, num_bits, opcode_index, context)
    }

    fn decompose_wire_to_bits(
        &mut self,
        wire: u32,
        num_bits: u32,
        opcode_index: usize,
        context: &str,
    ) -> Result<Vec<u32>, R1csError> {
        let mut bits = Vec::with_capacity(num_bits as usize);
        for _ in 0..num_bits {
            let bit_wire = self.allocate_intermediate_wire();
            self.enforce_boolean_wire(bit_wire)?;
            bits.push(bit_wire);
        }

        let mut recomposition = Vec::with_capacity(bits.len());
        let mut coeff = FieldElement::one();
        for bit_wire in &bits {
            recomposition.push(SparseTerm {
                wire: *bit_wire,
                coeff,
            });
            coeff += coeff;
        }
        self.emit_constraint(
            vec![SparseTerm {
                wire: 0,
                coeff: FieldElement::one(),
            }],
            recomposition,
            vec![SparseTerm {
                wire,
                coeff: FieldElement::one(),
            }],
        )
        .map_err(|err| match err {
            R1csError::InvalidProgramInvariant { details } => R1csError::InvalidProgramInvariant {
                details: format!(
                    "failed bit decomposition for {context} at opcode index {opcode_index}: {details}"
                ),
            },
            other => other,
        })?;

        Ok(bits)
    }

    fn enforce_boolean_witness(&mut self, witness: Witness) -> Result<(), R1csError> {
        let wire = self.wire_for_witness(witness)?;
        self.enforce_boolean_wire(wire)
    }

    fn emit_constraint(
        &mut self,
        a: SparseRow,
        b: SparseRow,
        c: SparseRow,
    ) -> Result<(), R1csError> {
        let a = canonicalize_row(a);
        let b = canonicalize_row(b);
        let c = canonicalize_row(c);
        ensure_row_is_canonical(&a)?;
        ensure_row_is_canonical(&b)?;
        ensure_row_is_canonical(&c)?;
        self.mark_row_wires(&a);
        self.mark_row_wires(&b);
        self.mark_row_wires(&c);
        self.a_rows.push(a);
        self.b_rows.push(b);
        self.c_rows.push(c);
        Ok(())
    }

    fn emit_hint_plumbing_constraint(
        &mut self,
        a: SparseRow,
        b: SparseRow,
        c: SparseRow,
    ) -> Result<(), R1csError> {
        let row_index = self.a_rows.len();
        self.emit_constraint(a, b, c)?;
        self.hint_plumbing_rows.insert(row_index);
        Ok(())
    }

    fn mark_row_wires(&mut self, row: &SparseRow) {
        for term in row {
            self.constrained_wires.insert(term.wire);
        }
    }

    fn wire_for_witness(&self, witness: Witness) -> Result<u32, R1csError> {
        self.wire_map
            .get(&witness.witness_index())
            .copied()
            .ok_or_else(|| R1csError::InvalidProgramInvariant {
                details: format!("no wire mapped for witness {}", witness.witness_index()),
            })
    }

    fn allocate_intermediate_wire(&mut self) -> u32 {
        let wire = self.next_wire;
        self.next_wire += 1;
        self.allocated_intermediate_wires.insert(wire);
        wire
    }

    fn allocate_virtual_witness(&mut self) -> Witness {
        let witness = Witness(self.next_virtual_witness_index);
        self.next_virtual_witness_index += 1;
        let wire = self.allocate_intermediate_wire();
        self.wire_map.insert(witness.witness_index(), wire);
        witness
    }

    fn allocate_memory_block_id(&mut self) -> u32 {
        let block_id = self.next_memory_block_id;
        self.next_memory_block_id += 1;
        block_id
    }

    fn unsupported_opcode(
        &mut self,
        opcode: &str,
        index: usize,
        details: String,
    ) -> Result<(), R1csError> {
        let context = self.opcode_context(index);
        let function_id = self.active_function_index();
        let opcode_variant = self.active_opcode_variant(index);
        let predicate_state = self.predicate_state_for_index(index);
        let exact_opcode = self.exact_opcode_for_index(index);
        let workaround = suggested_workaround(opcode);
        let info = UnsupportedOpcodeInfo {
            opcode: opcode.to_string(),
            index,
            function_id,
            opcode_variant,
            predicate_state,
            exact_opcode,
            details: format!("{details}; {context}"),
            workaround,
        };
        match self.options.mode {
            LoweringMode::Strict => Err(R1csError::UnsupportedOpcode {
                info: Box::new(info),
            }),
            LoweringMode::AllowUnsupported => {
                self.unsupported.push(info);
                Ok(())
            }
        }
    }

    fn active_function_index(&self) -> usize {
        self.call_stack
            .last()
            .copied()
            .unwrap_or(self.current_function_index)
    }

    fn active_circuit(&self) -> Option<&AcirCircuit> {
        if let Some(program) = self.program {
            return program.functions.get(self.active_function_index());
        }
        Some(self.circuit)
    }

    fn active_opcode(&self, index: usize) -> Option<&AcirOpcode> {
        self.active_circuit()?.opcodes.get(index)
    }

    fn active_opcode_variant(&self, index: usize) -> String {
        self.active_opcode(index)
            .map(|opcode| opcode_variant(opcode).to_string())
            .unwrap_or_else(|| "NestedCallOpcode".to_string())
    }

    fn exact_opcode_for_index(&self, index: usize) -> String {
        self.active_opcode(index)
            .map(ToString::to_string)
            .unwrap_or_else(|| "nested-call-opcode-unavailable".to_string())
    }

    fn predicate_state_for_index(&self, index: usize) -> String {
        let Some(opcode) = self.active_opcode(index) else {
            return "unknown".to_string();
        };

        match opcode {
            Opcode::Call { predicate, .. } | Opcode::BrilligCall { predicate, .. } => {
                expression_predicate_state(predicate)
            }
            Opcode::BlackBoxFuncCall(call) => blackbox_predicate_state(call),
            Opcode::MemoryOp { op, .. } => expression_predicate_state(&op.operation),
            Opcode::AssertZero(_) | Opcode::MemoryInit { .. } => "none".to_string(),
        }
    }

    fn opcode_context(&self, index: usize) -> String {
        let mut parts = Vec::new();
        if let Some(opcode) = self.active_opcode(index) {
            parts.push(format!("opcode_variant={}", opcode_variant(opcode)));
        } else {
            parts.push("opcode_variant=NestedCallOpcode".to_string());
        }
        parts.push(format!("function_id={}", self.active_function_index()));
        if self.call_stack.len() > 1 {
            parts.push(format!("call_stack={:?}", self.call_stack));
        }
        if let Some(assert_msg) = self.assert_message_for_index(index) {
            parts.push(format!("assert_message={assert_msg}"));
        }
        parts.join(", ")
    }

    fn assert_message_for_index(&self, index: usize) -> Option<String> {
        let circuit = self.active_circuit()?;
        for (location, payload) in &circuit.assert_messages {
            if let OpcodeLocation::Acir(i) = *location {
                if i == index {
                    return Some(format!(
                        "selector={}, payload_len={}",
                        payload.error_selector,
                        payload.payload.len()
                    ));
                }
            }
        }
        None
    }

    fn ensure_expression_witnesses_in_range(
        &self,
        expr: &AcirExpression,
        context: &str,
    ) -> Result<(), R1csError> {
        for (_, lhs, rhs) in &expr.mul_terms {
            self.ensure_witness_in_range(*lhs, context)?;
            self.ensure_witness_in_range(*rhs, context)?;
        }
        for (_, witness) in &expr.linear_combinations {
            self.ensure_witness_in_range(*witness, context)?;
        }
        Ok(())
    }

    fn register_hint_output(
        &mut self,
        source: &'static str,
        witness: Witness,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        self.ensure_witness_in_range(witness, "hint output")?;
        let wire = self.wire_for_witness(witness)?;
        self.pending_hint_outputs.push(PendingHintOutputConstraint {
            source,
            opcode_index,
            witness,
            wire,
        });
        Ok(())
    }

    fn validate_hint_output_constraints(&mut self) -> Result<(), R1csError> {
        let mut missing = Vec::new();
        for output in &self.pending_hint_outputs {
            if !self.wire_is_constrained_outside_hint_plumbing(output.wire) {
                if !self.wire_is_referenced_in_any_row(output.wire) {
                    continue;
                }
                missing.push(*output);
            }
        }

        for output in missing {
            self.unsupported_opcode(
                output.source,
                output.opcode_index,
                format!(
                    "hint output witness {} (wire {}) is not constrained by non-hint R1CS rows",
                    output.witness.witness_index(),
                    output.wire
                ),
            )?;
        }

        Ok(())
    }

    fn ensure_witness_in_range(&self, witness: Witness, context: &str) -> Result<(), R1csError> {
        if self.wire_map.contains_key(&witness.witness_index()) {
            return Ok(());
        }
        if witness.witness_index() > self.circuit.current_witness_index {
            return Err(R1csError::InvalidProgramInvariant {
                details: format!(
                    "{context}: witness {} exceeds current_witness_index {}",
                    witness.witness_index(),
                    self.circuit.current_witness_index
                ),
            });
        }
        Ok(())
    }

    fn wire_is_constrained_outside_hint_plumbing(&self, wire: u32) -> bool {
        for (row_idx, row) in self.a_rows.iter().enumerate() {
            if self.hint_plumbing_rows.contains(&row_idx) {
                continue;
            }
            if row.iter().any(|term| term.wire == wire) {
                return true;
            }
            if self.b_rows[row_idx].iter().any(|term| term.wire == wire) {
                return true;
            }
            if self.c_rows[row_idx].iter().any(|term| term.wire == wire) {
                return true;
            }
        }
        false
    }

    fn wire_is_referenced_in_any_row(&self, wire: u32) -> bool {
        for row in self
            .a_rows
            .iter()
            .chain(self.b_rows.iter())
            .chain(self.c_rows.iter())
        {
            if row.iter().any(|term| term.wire == wire) {
                return true;
            }
        }
        false
    }
}

impl R1csSystem {
    pub fn is_satisfied(&self, witness: &[FieldElement]) -> bool {
        let Some(full_witness) = self.materialize_witness(witness) else {
            return false;
        };
        self.is_satisfied_with_full_witness(&full_witness)
    }

    pub fn materialize_witness(&self, witness: &[FieldElement]) -> Option<Vec<FieldElement>> {
        let mut full = vec![FieldElement::zero(); self.n_wires as usize];
        let mut known = vec![false; self.n_wires as usize];
        let copy_len = std::cmp::min(witness.len(), full.len());
        full[..copy_len].copy_from_slice(&witness[..copy_len]);
        for slot in known.iter_mut().take(copy_len) {
            *slot = true;
        }
        if !full.is_empty() {
            full[0] = FieldElement::one();
            known[0] = true;
        }

        let boolean_wires = self.collect_boolean_wires();

        // ACIR witness vectors include only original witnesses. Intermediate wires introduced
        // by lowering can often be solved from a single R1CS row if all other terms are known.
        let max_rounds = (self.n_wires as usize).saturating_mul(8).max(1);
        let mut progress = true;
        for _ in 0..max_rounds {
            if !progress {
                break;
            }
            progress = false;
            if self.populate_bit_decomposition_wires(&boolean_wires, &mut full, &mut known)? {
                progress = true;
            }
            if self.populate_selector_wires_from_one_hot_patterns(&mut full, &mut known)? {
                progress = true;
            }
            for i in 0..self.n_constraints as usize {
                let a = eval_linear_form(&self.a[i], &full, &known)?;
                let b = eval_linear_form(&self.b[i], &full, &known)?;
                let c = eval_linear_form(&self.c[i], &full, &known)?;

                if self.c[i].len() == 1 {
                    let term = self.c[i][0].clone();
                    let target = term.wire as usize;
                    if a.1.is_empty()
                        && b.1.is_empty()
                        && target >= copy_len
                        && target < full.len()
                        && !term.coeff.is_zero()
                    {
                        let lhs = dot(&self.a[i], &full)?;
                        let rhs = dot(&self.b[i], &full)?;
                        let new_value = (lhs * rhs) / term.coeff;
                        if known[target] {
                            if full[target] != new_value {
                                return None;
                            }
                        } else {
                            full[target] = new_value;
                            progress = true;
                            known[target] = true;
                        }
                        continue;
                    }
                }

                // If either side of the multiplication is known zero, the other side
                // is irrelevant and we can solve directly from C.
                if a.1.is_empty() && a.0.is_zero() {
                    if let Some((wire, coeff)) = c.1.first().copied() {
                        if !coeff.is_zero() {
                            let new_value = -c.0 / coeff;
                            if !known[wire] || full[wire] != new_value {
                                full[wire] = new_value;
                                progress = true;
                            }
                            known[wire] = true;
                            continue;
                        }
                    }
                }
                if b.1.is_empty() && b.0.is_zero() {
                    if let Some((wire, coeff)) = c.1.first().copied() {
                        if !coeff.is_zero() {
                            let new_value = -c.0 / coeff;
                            if !known[wire] || full[wire] != new_value {
                                full[wire] = new_value;
                                progress = true;
                            }
                            known[wire] = true;
                            continue;
                        }
                    }
                }

                // Heuristic completion: if C has a single unknown term, solve it
                // directly from the current A/B values.
                if c.1.len() == 1 {
                    let (wire, coeff) = c.1[0];
                    if !coeff.is_zero() && a.1.is_empty() && b.1.is_empty() {
                        let lhs = dot(&self.a[i], &full)?;
                        let rhs = dot(&self.b[i], &full)?;
                        let new_value = (lhs * rhs - c.0) / coeff;
                        if known[wire] {
                            if full[wire] != new_value {
                                return None;
                            }
                        } else {
                            full[wire] = new_value;
                            progress = true;
                            known[wire] = true;
                        }
                        continue;
                    }
                }

                let mut unknown_wire = None;
                for candidate in a.1.iter().chain(b.1.iter()).chain(c.1.iter()) {
                    if let Some(existing) = unknown_wire {
                        if existing != candidate.0 {
                            unknown_wire = None;
                            break;
                        }
                    } else {
                        unknown_wire = Some(candidate.0);
                    }
                }
                let Some(target_wire) = unknown_wire else {
                    continue;
                };

                let a_coeff =
                    a.1.iter()
                        .find(|term| term.0 == target_wire)
                        .map_or(FieldElement::zero(), |term| term.1);
                let b_coeff =
                    b.1.iter()
                        .find(|term| term.0 == target_wire)
                        .map_or(FieldElement::zero(), |term| term.1);
                let c_coeff =
                    c.1.iter()
                        .find(|term| term.0 == target_wire)
                        .map_or(FieldElement::zero(), |term| term.1);

                // We only solve rows that are linear in the unknown variable.
                if !a_coeff.is_zero() && !b_coeff.is_zero() {
                    continue;
                }

                let (denom, rhs) = if !a_coeff.is_zero() {
                    (a_coeff * b.0 - c_coeff, c.0 - a.0 * b.0)
                } else if !b_coeff.is_zero() {
                    (a.0 * b_coeff - c_coeff, c.0 - a.0 * b.0)
                } else if !c_coeff.is_zero() {
                    (c_coeff, a.0 * b.0 - c.0)
                } else {
                    continue;
                };

                if denom.is_zero() {
                    continue;
                }

                let new_value = rhs / denom;
                if !known[target_wire] || full[target_wire] != new_value {
                    full[target_wire] = new_value;
                    progress = true;
                }
                known[target_wire] = true;
            }
        }

        if !self.is_satisfied_with_full_witness(&full) {
            return None;
        }

        Some(full)
    }

    fn is_satisfied_with_full_witness(&self, full_witness: &[FieldElement]) -> bool {
        for i in 0..self.n_constraints as usize {
            let Some(left) = dot(&self.a[i], full_witness) else {
                return false;
            };
            let Some(right) = dot(&self.b[i], full_witness) else {
                return false;
            };
            let Some(out) = dot(&self.c[i], full_witness) else {
                return false;
            };
            if left * right != out {
                return false;
            }
        }
        true
    }

    fn collect_boolean_wires(&self) -> BTreeSet<usize> {
        let mut wires = BTreeSet::new();
        for i in 0..self.n_constraints as usize {
            if let Some(wire) = boolean_constraint_wire(&self.a[i], &self.b[i], &self.c[i]) {
                wires.insert(wire);
            }
        }
        wires
    }

    fn populate_bit_decomposition_wires(
        &self,
        boolean_wires: &BTreeSet<usize>,
        witness: &mut [FieldElement],
        known: &mut [bool],
    ) -> Option<bool> {
        let max_rounds = self.n_constraints as usize;
        let mut progress = true;
        let mut changed = false;
        for _ in 0..max_rounds {
            if !progress {
                break;
            }
            progress = false;

            for i in 0..self.n_constraints as usize {
                let Some((output_wire, bit_wires)) =
                    bit_decomposition_pattern(&self.a[i], &self.b[i], &self.c[i], boolean_wires)
                else {
                    continue;
                };

                if output_wire >= witness.len() || !known[output_wire] {
                    continue;
                }

                let output_bits = field_to_bits_le(witness[output_wire], bit_wires.len());
                for (bit_wire, bit) in bit_wires.iter().zip(output_bits.into_iter()) {
                    if *bit_wire >= witness.len() || *bit_wire >= known.len() {
                        return None;
                    }
                    let value = if bit {
                        FieldElement::one()
                    } else {
                        FieldElement::zero()
                    };
                    if known[*bit_wire] {
                        if witness[*bit_wire] != value {
                            return None;
                        }
                        continue;
                    }
                    witness[*bit_wire] = value;
                    known[*bit_wire] = true;
                    progress = true;
                    changed = true;
                }
            }
        }

        Some(changed)
    }

    fn populate_selector_wires_from_one_hot_patterns(
        &self,
        witness: &mut [FieldElement],
        known: &mut [bool],
    ) -> Option<bool> {
        let max_rounds = self.n_constraints as usize;
        let mut progress = true;
        let mut changed = false;
        for _ in 0..max_rounds {
            if !progress {
                break;
            }
            progress = false;

            for i in 0..self.n_constraints as usize {
                let Some(selector_wires) = selector_sum_pattern(&self.a[i], &self.b[i], &self.c[i])
                else {
                    continue;
                };

                let mut index_wire = None;
                for j in 0..self.n_constraints as usize {
                    if let Some(wire) =
                        selector_index_pattern(&self.a[j], &self.b[j], &self.c[j], &selector_wires)
                    {
                        index_wire = Some(wire);
                        break;
                    }
                }
                let Some(index_wire) = index_wire else {
                    continue;
                };
                if index_wire >= witness.len() || !known[index_wire] {
                    continue;
                }

                let Some(index_value) = field_to_usize(witness[index_wire]) else {
                    continue;
                };
                if index_value >= selector_wires.len() {
                    continue;
                }

                for (position, selector_wire) in selector_wires.iter().copied().enumerate() {
                    if selector_wire >= witness.len() || selector_wire >= known.len() {
                        return None;
                    }
                    let value = if position == index_value {
                        FieldElement::one()
                    } else {
                        FieldElement::zero()
                    };
                    if known[selector_wire] {
                        if witness[selector_wire] != value {
                            return None;
                        }
                        continue;
                    }
                    witness[selector_wire] = value;
                    known[selector_wire] = true;
                    progress = true;
                    changed = true;
                }
            }
        }

        Some(changed)
    }
}

fn boolean_constraint_wire(
    a_row: &SparseRow,
    b_row: &SparseRow,
    c_row: &SparseRow,
) -> Option<usize> {
    if !c_row.is_empty() {
        return None;
    }

    if a_row.len() == 1 && a_row[0].coeff.is_one() {
        let wire = a_row[0].wire as usize;
        if b_row.len() == 2 {
            let has_self = b_row
                .iter()
                .any(|term| term.wire == a_row[0].wire && term.coeff.is_one());
            let has_neg_one = b_row
                .iter()
                .any(|term| term.wire == 0 && term.coeff == -FieldElement::one());
            if has_self && has_neg_one {
                return Some(wire);
            }
        }
    }

    if b_row.len() == 1 && b_row[0].coeff.is_one() {
        let wire = b_row[0].wire as usize;
        if a_row.len() == 2 {
            let has_self = a_row
                .iter()
                .any(|term| term.wire == b_row[0].wire && term.coeff.is_one());
            let has_neg_one = a_row
                .iter()
                .any(|term| term.wire == 0 && term.coeff == -FieldElement::one());
            if has_self && has_neg_one {
                return Some(wire);
            }
        }
    }

    None
}

fn bit_decomposition_pattern(
    a_row: &SparseRow,
    b_row: &SparseRow,
    c_row: &SparseRow,
    boolean_wires: &BTreeSet<usize>,
) -> Option<(usize, Vec<usize>)> {
    if a_row.len() != 1
        || a_row[0].wire != 0
        || !a_row[0].coeff.is_one()
        || c_row.len() != 1
        || !c_row[0].coeff.is_one()
        || b_row.is_empty()
    {
        return None;
    }

    let mut expected_coeff = FieldElement::one();
    let mut bit_wires = Vec::with_capacity(b_row.len());
    for term in b_row {
        if term.coeff != expected_coeff {
            return None;
        }
        if !boolean_wires.contains(&(term.wire as usize)) {
            return None;
        }
        bit_wires.push(term.wire as usize);
        expected_coeff += expected_coeff;
    }

    Some((c_row[0].wire as usize, bit_wires))
}

fn field_to_bits_le(value: FieldElement, num_bits: usize) -> Vec<bool> {
    let be = value.to_be_bytes();
    let mut bits = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        let byte_offset = i / 8;
        let bit_offset = i % 8;
        let bit = if byte_offset < be.len() {
            let byte = be[be.len() - 1 - byte_offset];
            ((byte >> bit_offset) & 1) == 1
        } else {
            false
        };
        bits.push(bit);
    }
    bits
}

fn selector_sum_pattern(
    a_row: &SparseRow,
    b_row: &SparseRow,
    c_row: &SparseRow,
) -> Option<Vec<usize>> {
    if a_row.len() != 1
        || a_row[0].wire != 0
        || !a_row[0].coeff.is_one()
        || c_row.len() != 1
        || c_row[0].wire != 0
        || !c_row[0].coeff.is_one()
        || b_row.is_empty()
    {
        return None;
    }

    let mut selectors = Vec::with_capacity(b_row.len());
    for term in b_row {
        if !term.coeff.is_one() {
            return None;
        }
        selectors.push(term.wire as usize);
    }
    Some(selectors)
}

fn selector_index_pattern(
    a_row: &SparseRow,
    b_row: &SparseRow,
    c_row: &SparseRow,
    selector_wires: &[usize],
) -> Option<usize> {
    if a_row.len() != 1
        || a_row[0].wire != 0
        || !a_row[0].coeff.is_one()
        || c_row.len() != 1
        || !c_row[0].coeff.is_one()
    {
        return None;
    }

    if selector_wires.is_empty() {
        return None;
    }
    // Canonical rows remove zero-coefficient terms, so selector index 0 does not appear.
    if b_row.len() != selector_wires.len().saturating_sub(1) {
        return None;
    }

    for term in b_row {
        let idx = selector_wires
            .iter()
            .position(|wire| *wire == term.wire as usize)?;
        if idx == 0 {
            return None;
        }
        if term.coeff != FieldElement::from(idx as u128) {
            return None;
        }
    }

    for (idx, selector_wire) in selector_wires.iter().enumerate().skip(1) {
        let term = b_row
            .iter()
            .find(|term| term.wire as usize == *selector_wire)?;
        if term.coeff != FieldElement::from(idx as u128) {
            return None;
        };
    }

    Some(c_row[0].wire as usize)
}

fn field_to_usize(value: FieldElement) -> Option<usize> {
    let bytes = value.to_be_bytes();
    let usize_bytes = std::mem::size_of::<usize>();
    let normalized = if bytes.len() > usize_bytes {
        let split = bytes.len() - usize_bytes;
        if bytes[..split].iter().any(|byte| *byte != 0) {
            return None;
        }
        bytes[split..].to_vec()
    } else {
        bytes
    };

    let mut out = 0usize;
    for byte in normalized {
        out = out.checked_mul(256)?;
        out = out.checked_add(byte as usize)?;
    }
    Some(out)
}

fn eval_linear_form(
    row: &SparseRow,
    witness: &[FieldElement],
    known: &[bool],
) -> Option<(FieldElement, Vec<(usize, FieldElement)>)> {
    let mut known_sum = FieldElement::zero();
    let mut unknown = Vec::new();

    for term in row {
        let wire = term.wire as usize;
        if wire >= witness.len() || wire >= known.len() {
            return None;
        }

        if known[wire] {
            known_sum += term.coeff * witness[wire];
        } else {
            unknown.push((wire, term.coeff));
        }
    }

    Some((known_sum, unknown))
}

fn next_memory_block_id(circuit: &AcirCircuit) -> u32 {
    let max_block = circuit
        .opcodes
        .iter()
        .filter_map(|opcode| match opcode {
            Opcode::MemoryInit { block_id, .. } | Opcode::MemoryOp { block_id, .. } => {
                Some(block_id.0)
            }
            _ => None,
        })
        .max()
        .unwrap_or(0);
    max_block.saturating_add(1)
}

fn is_strictly_sorted(values: &[u32]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn ensure_row_is_canonical(row: &SparseRow) -> Result<(), R1csError> {
    for term in row {
        if term.coeff.is_zero() {
            return Err(R1csError::NonDeterministicOrdering {
                context: format!("row contains zero coefficient term for wire {}", term.wire),
            });
        }
    }

    for pair in row.windows(2) {
        if pair[0].wire >= pair[1].wire {
            return Err(R1csError::NonDeterministicOrdering {
                context: format!(
                    "row has non-canonical wire ordering {} then {}",
                    pair[0].wire, pair[1].wire
                ),
            });
        }
    }

    Ok(())
}

fn dot(row: &SparseRow, witness: &[FieldElement]) -> Option<FieldElement> {
    row.iter().try_fold(FieldElement::zero(), |acc, term| {
        witness
            .get(term.wire as usize)
            .map(|value| acc + term.coeff * *value)
    })
}

fn add_linear(map: &mut BTreeMap<u32, FieldElement>, wire: u32, coeff: FieldElement) {
    let entry = map.entry(wire).or_insert(FieldElement::zero());
    *entry += coeff;
    if entry.is_zero() {
        map.remove(&wire);
    }
}

fn canonicalize_row(row: SparseRow) -> SparseRow {
    let mut map = BTreeMap::new();
    for term in row {
        add_linear(&mut map, term.wire, term.coeff);
    }
    map.into_iter()
        .map(|(wire, coeff)| SparseTerm { wire, coeff })
        .collect()
}

fn canonicalize_expression(expr: &AcirExpression) -> AcirExpression {
    let mut mul_map: BTreeMap<(u32, u32), FieldElement> = BTreeMap::new();
    for (coeff, lhs, rhs) in &expr.mul_terms {
        if coeff.is_zero() {
            continue;
        }
        let lw = lhs.witness_index();
        let rw = rhs.witness_index();
        let key = if lw <= rw { (lw, rw) } else { (rw, lw) };
        let entry = mul_map.entry(key).or_insert(FieldElement::zero());
        *entry += *coeff;
        if entry.is_zero() {
            mul_map.remove(&key);
        }
    }

    let mut linear_map: BTreeMap<u32, FieldElement> = BTreeMap::new();
    for (coeff, witness) in &expr.linear_combinations {
        if coeff.is_zero() {
            continue;
        }
        add_linear(&mut linear_map, witness.witness_index(), *coeff);
    }

    Expression {
        mul_terms: mul_map
            .into_iter()
            .map(|((lhs, rhs), coeff)| (coeff, Witness(lhs), Witness(rhs)))
            .collect(),
        linear_combinations: linear_map
            .into_iter()
            .map(|(wire, coeff)| (coeff, Witness(wire)))
            .collect(),
        q_c: expr.q_c,
    }
}

fn remap_opcode(
    opcode: &AcirOpcode,
    witness_map: &BTreeMap<u32, Witness>,
    block_map: &BTreeMap<u32, u32>,
) -> AcirOpcode {
    match opcode {
        Opcode::AssertZero(expr) => Opcode::AssertZero(remap_expression(expr, witness_map)),
        Opcode::MemoryInit {
            block_id,
            init,
            block_type,
        } => Opcode::MemoryInit {
            block_id: BlockId(
                *block_map
                    .get(&block_id.0)
                    .expect("call memory block map must cover MemoryInit"),
            ),
            init: init
                .iter()
                .map(|witness| remap_witness(*witness, witness_map))
                .collect(),
            block_type: block_type.clone(),
        },
        Opcode::MemoryOp { block_id, op } => Opcode::MemoryOp {
            block_id: BlockId(
                *block_map
                    .get(&block_id.0)
                    .expect("call memory block map must cover MemoryOp"),
            ),
            op: MemOp {
                operation: remap_expression(&op.operation, witness_map),
                index: remap_expression(&op.index, witness_map),
                value: remap_expression(&op.value, witness_map),
            },
        },
        Opcode::BlackBoxFuncCall(call) => {
            Opcode::BlackBoxFuncCall(remap_blackbox_call(call, witness_map))
        }
        Opcode::BrilligCall {
            id,
            inputs,
            outputs,
            predicate,
        } => Opcode::BrilligCall {
            id: *id,
            inputs: inputs
                .iter()
                .map(|input| remap_brillig_input(input, witness_map))
                .collect(),
            outputs: outputs
                .iter()
                .map(|output| remap_brillig_output(output, witness_map))
                .collect(),
            predicate: remap_expression(predicate, witness_map),
        },
        Opcode::Call {
            id,
            inputs,
            outputs,
            predicate,
        } => Opcode::Call {
            id: *id,
            inputs: inputs
                .iter()
                .map(|witness| remap_witness(*witness, witness_map))
                .collect(),
            outputs: outputs
                .iter()
                .map(|witness| remap_witness(*witness, witness_map))
                .collect(),
            predicate: remap_expression(predicate, witness_map),
        },
    }
}

fn remap_blackbox_call(
    call: &AcirBlackBoxFuncCall,
    witness_map: &BTreeMap<u32, Witness>,
) -> AcirBlackBoxFuncCall {
    match call {
        BlackBoxFuncCall::AES128Encrypt {
            inputs,
            iv,
            key,
            outputs,
        } => BlackBoxFuncCall::AES128Encrypt {
            inputs: inputs
                .iter()
                .map(|input| remap_function_input(*input, witness_map))
                .collect(),
            iv: Box::new((*iv).map(|input| remap_function_input(input, witness_map))),
            key: Box::new((*key).map(|input| remap_function_input(input, witness_map))),
            outputs: outputs
                .iter()
                .map(|witness| remap_witness(*witness, witness_map))
                .collect(),
        },
        BlackBoxFuncCall::AND {
            lhs,
            rhs,
            num_bits,
            output,
        } => BlackBoxFuncCall::AND {
            lhs: remap_function_input(*lhs, witness_map),
            rhs: remap_function_input(*rhs, witness_map),
            num_bits: *num_bits,
            output: remap_witness(*output, witness_map),
        },
        BlackBoxFuncCall::XOR {
            lhs,
            rhs,
            num_bits,
            output,
        } => BlackBoxFuncCall::XOR {
            lhs: remap_function_input(*lhs, witness_map),
            rhs: remap_function_input(*rhs, witness_map),
            num_bits: *num_bits,
            output: remap_witness(*output, witness_map),
        },
        BlackBoxFuncCall::RANGE { input, num_bits } => BlackBoxFuncCall::RANGE {
            input: remap_function_input(*input, witness_map),
            num_bits: *num_bits,
        },
        BlackBoxFuncCall::Blake2s { inputs, outputs } => BlackBoxFuncCall::Blake2s {
            inputs: inputs
                .iter()
                .map(|input| remap_function_input(*input, witness_map))
                .collect(),
            outputs: Box::new((*outputs).map(|witness| remap_witness(witness, witness_map))),
        },
        BlackBoxFuncCall::Blake3 { inputs, outputs } => BlackBoxFuncCall::Blake3 {
            inputs: inputs
                .iter()
                .map(|input| remap_function_input(*input, witness_map))
                .collect(),
            outputs: Box::new((*outputs).map(|witness| remap_witness(witness, witness_map))),
        },
        BlackBoxFuncCall::EcdsaSecp256k1 {
            public_key_x,
            public_key_y,
            signature,
            hashed_message,
            predicate,
            output,
        } => BlackBoxFuncCall::EcdsaSecp256k1 {
            public_key_x: Box::new(
                (*public_key_x).map(|input| remap_function_input(input, witness_map)),
            ),
            public_key_y: Box::new(
                (*public_key_y).map(|input| remap_function_input(input, witness_map)),
            ),
            signature: Box::new((*signature).map(|input| remap_function_input(input, witness_map))),
            hashed_message: Box::new(
                (*hashed_message).map(|input| remap_function_input(input, witness_map)),
            ),
            predicate: remap_function_input(*predicate, witness_map),
            output: remap_witness(*output, witness_map),
        },
        BlackBoxFuncCall::EcdsaSecp256r1 {
            public_key_x,
            public_key_y,
            signature,
            hashed_message,
            predicate,
            output,
        } => BlackBoxFuncCall::EcdsaSecp256r1 {
            public_key_x: Box::new(
                (*public_key_x).map(|input| remap_function_input(input, witness_map)),
            ),
            public_key_y: Box::new(
                (*public_key_y).map(|input| remap_function_input(input, witness_map)),
            ),
            signature: Box::new((*signature).map(|input| remap_function_input(input, witness_map))),
            hashed_message: Box::new(
                (*hashed_message).map(|input| remap_function_input(input, witness_map)),
            ),
            predicate: remap_function_input(*predicate, witness_map),
            output: remap_witness(*output, witness_map),
        },
        BlackBoxFuncCall::MultiScalarMul {
            points,
            scalars,
            predicate,
            outputs,
        } => BlackBoxFuncCall::MultiScalarMul {
            points: points
                .iter()
                .map(|input| remap_function_input(*input, witness_map))
                .collect(),
            scalars: scalars
                .iter()
                .map(|input| remap_function_input(*input, witness_map))
                .collect(),
            predicate: remap_function_input(*predicate, witness_map),
            outputs: (
                remap_witness(outputs.0, witness_map),
                remap_witness(outputs.1, witness_map),
                remap_witness(outputs.2, witness_map),
            ),
        },
        BlackBoxFuncCall::EmbeddedCurveAdd {
            input1,
            input2,
            predicate,
            outputs,
        } => BlackBoxFuncCall::EmbeddedCurveAdd {
            input1: Box::new((*input1).map(|input| remap_function_input(input, witness_map))),
            input2: Box::new((*input2).map(|input| remap_function_input(input, witness_map))),
            predicate: remap_function_input(*predicate, witness_map),
            outputs: (
                remap_witness(outputs.0, witness_map),
                remap_witness(outputs.1, witness_map),
                remap_witness(outputs.2, witness_map),
            ),
        },
        BlackBoxFuncCall::Keccakf1600 { inputs, outputs } => BlackBoxFuncCall::Keccakf1600 {
            inputs: Box::new((*inputs).map(|input| remap_function_input(input, witness_map))),
            outputs: Box::new((*outputs).map(|witness| remap_witness(witness, witness_map))),
        },
        BlackBoxFuncCall::RecursiveAggregation {
            verification_key,
            proof,
            public_inputs,
            key_hash,
            proof_type,
            predicate,
        } => BlackBoxFuncCall::RecursiveAggregation {
            verification_key: verification_key
                .iter()
                .map(|input| remap_function_input(*input, witness_map))
                .collect(),
            proof: proof
                .iter()
                .map(|input| remap_function_input(*input, witness_map))
                .collect(),
            public_inputs: public_inputs
                .iter()
                .map(|input| remap_function_input(*input, witness_map))
                .collect(),
            key_hash: remap_function_input(*key_hash, witness_map),
            proof_type: *proof_type,
            predicate: remap_function_input(*predicate, witness_map),
        },
        BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs } => {
            BlackBoxFuncCall::Poseidon2Permutation {
                inputs: inputs
                    .iter()
                    .map(|input| remap_function_input(*input, witness_map))
                    .collect(),
                outputs: outputs
                    .iter()
                    .map(|witness| remap_witness(*witness, witness_map))
                    .collect(),
            }
        }
        BlackBoxFuncCall::Sha256Compression {
            inputs,
            hash_values,
            outputs,
        } => BlackBoxFuncCall::Sha256Compression {
            inputs: Box::new((*inputs).map(|input| remap_function_input(input, witness_map))),
            hash_values: Box::new(
                (*hash_values).map(|input| remap_function_input(input, witness_map)),
            ),
            outputs: Box::new((*outputs).map(|witness| remap_witness(witness, witness_map))),
        },
    }
}

fn remap_brillig_input(
    input: &BrilligInputs<FieldElement>,
    witness_map: &BTreeMap<u32, Witness>,
) -> BrilligInputs<FieldElement> {
    match input {
        BrilligInputs::Single(expr) => BrilligInputs::Single(remap_expression(expr, witness_map)),
        BrilligInputs::Array(values) => BrilligInputs::Array(
            values
                .iter()
                .map(|expr| remap_expression(expr, witness_map))
                .collect(),
        ),
        BrilligInputs::MemoryArray(block_id) => BrilligInputs::MemoryArray(*block_id),
    }
}

fn remap_brillig_output(
    output: &BrilligOutputs,
    witness_map: &BTreeMap<u32, Witness>,
) -> BrilligOutputs {
    match output {
        BrilligOutputs::Simple(witness) => {
            BrilligOutputs::Simple(remap_witness(*witness, witness_map))
        }
        BrilligOutputs::Array(witnesses) => BrilligOutputs::Array(
            witnesses
                .iter()
                .map(|witness| remap_witness(*witness, witness_map))
                .collect(),
        ),
    }
}

fn remap_expression(expr: &AcirExpression, witness_map: &BTreeMap<u32, Witness>) -> AcirExpression {
    AcirExpression {
        mul_terms: expr
            .mul_terms
            .iter()
            .map(|(coeff, lhs, rhs)| {
                (
                    *coeff,
                    remap_witness(*lhs, witness_map),
                    remap_witness(*rhs, witness_map),
                )
            })
            .collect(),
        linear_combinations: expr
            .linear_combinations
            .iter()
            .map(|(coeff, witness)| (*coeff, remap_witness(*witness, witness_map)))
            .collect(),
        q_c: expr.q_c,
    }
}

fn remap_function_input(
    input: AcirFunctionInput,
    witness_map: &BTreeMap<u32, Witness>,
) -> AcirFunctionInput {
    match input {
        FunctionInput::Witness(witness) => {
            FunctionInput::Witness(remap_witness(witness, witness_map))
        }
        FunctionInput::Constant(value) => FunctionInput::Constant(value),
    }
}

fn remap_witness(witness: Witness, witness_map: &BTreeMap<u32, Witness>) -> Witness {
    *witness_map
        .get(&witness.witness_index())
        .expect("call witness map should contain every witness")
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
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];
    be.reverse();
    be
}

fn opcode_variant(opcode: &AcirOpcode) -> &'static str {
    match opcode {
        Opcode::AssertZero(_) => "AssertZero",
        Opcode::BlackBoxFuncCall(_) => "BlackBoxFuncCall",
        Opcode::MemoryOp { .. } => "MemoryOp",
        Opcode::MemoryInit { .. } => "MemoryInit",
        Opcode::BrilligCall { .. } => "BrilligCall",
        Opcode::Call { .. } => "Call",
    }
}

fn expression_predicate_state(expr: &AcirExpression) -> String {
    match expr.to_const().copied() {
        Some(value) if value.is_zero() => "constant(0)".to_string(),
        Some(value) if value.is_one() => "constant(1)".to_string(),
        Some(value) => format!("constant({value})"),
        None => "dynamic".to_string(),
    }
}

fn function_input_predicate_state(input: &AcirFunctionInput) -> String {
    match input {
        FunctionInput::Constant(value) if value.is_zero() => "constant(0)".to_string(),
        FunctionInput::Constant(value) if value.is_one() => "constant(1)".to_string(),
        FunctionInput::Constant(value) => format!("constant({value})"),
        FunctionInput::Witness(witness) => format!("witness({})", witness.witness_index()),
    }
}

fn blackbox_predicate_state(call: &AcirBlackBoxFuncCall) -> String {
    match call {
        BlackBoxFuncCall::AES128Encrypt { .. }
        | BlackBoxFuncCall::AND { .. }
        | BlackBoxFuncCall::XOR { .. }
        | BlackBoxFuncCall::RANGE { .. }
        | BlackBoxFuncCall::Blake2s { .. }
        | BlackBoxFuncCall::Blake3 { .. }
        | BlackBoxFuncCall::Keccakf1600 { .. }
        | BlackBoxFuncCall::Poseidon2Permutation { .. }
        | BlackBoxFuncCall::Sha256Compression { .. } => "constant(1)".to_string(),
        BlackBoxFuncCall::EcdsaSecp256k1 { predicate, .. }
        | BlackBoxFuncCall::EcdsaSecp256r1 { predicate, .. }
        | BlackBoxFuncCall::MultiScalarMul { predicate, .. }
        | BlackBoxFuncCall::EmbeddedCurveAdd { predicate, .. }
        | BlackBoxFuncCall::RecursiveAggregation { predicate, .. } => {
            function_input_predicate_state(predicate)
        }
    }
}

fn suggested_workaround(opcode: &str) -> String {
    match opcode {
        "Call" => "Constrain the Call predicate to boolean (0/1), avoid recursion, and ensure callee outputs are transitively constrained by AssertZero rows.".to_string(),
        "BrilligCall" => "Constrain Brillig outputs with non-hint AssertZero/blackbox relations, or set predicate to constant 0 when outputs are intentionally unused.".to_string(),
        "BlackBoxFuncCall" => "Use supported blackboxes or add explicit constraints tying every blackbox output into AssertZero equations; use --allow-unsupported to get full diagnostics.".to_string(),
        "MemoryOp" | "MemoryInit" => "Ensure memory blocks are initialized, indices are valid, and memory operations/predicates evaluate to boolean values.".to_string(),
        _ => "Rewrite the opcode into supported AssertZero/blackbox patterns and keep predicates boolean-constrained.".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, io::Cursor};

    use acir::{
        circuit::{
            brillig::{BrilligFunctionId, BrilligInputs, BrilligOutputs},
            opcodes::{AcirFunctionId, BlackBoxFuncCall, BlockType, FunctionInput, MemOp},
            Circuit, Opcode, Program, PublicInputs,
        },
        native_types::{Expression, Witness},
        FieldElement,
    };
    use acvm::blackbox_solver::{blake2s, blake3, sha256_compression};
    use bn254_blackbox_solver::{embedded_curve_add, multi_scalar_mul as bn254_multi_scalar_mul};
    use noir_acir::Artifact;
    use noir_witness::{generate_witness_from_json_str, poseidon2_permutation};
    use proptest::prelude::*;
    use r1cs_file::R1csFile;
    use tempfile::TempDir;

    use super::{poseidon2_constants::field_from_hex, *};

    fn assert_r1cs_satisfied(system: &R1csSystem, witness: &[FieldElement]) {
        let full = system
            .materialize_witness(witness)
            .expect("materialized witness should fit all row references");
        for i in 0..system.n_constraints as usize {
            let left = dot(&system.a[i], &full).expect("A row must reference existing wires");
            let right = dot(&system.b[i], &full).expect("B row must reference existing wires");
            let out = dot(&system.c[i], &full).expect("C row must reference existing wires");
            assert_eq!(
                left * right - out,
                FieldElement::zero(),
                "unsatisfied constraint index {i}, left={left}, right={right}, out={out}, a_row={:?}, b_row={:?}, c_row={:?}",
                system.a[i],
                system.b[i],
                system.c[i],
            );
        }
    }

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
        assert_r1cs_satisfied(&system, &witness.witness_vector);
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
        tampered[2] += FieldElement::one();

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
    fn unsupported_opcode_has_index_and_details() {
        let circuit = Circuit {
            current_witness_index: 0,
            opcodes: vec![Opcode::BrilligCall {
                id: BrilligFunctionId(0),
                inputs: Vec::new(),
                outputs: Vec::new(),
                predicate: Expression::one(),
            }],
            ..Circuit::default()
        };

        let err = compile_r1cs_circuit(&circuit).expect_err("unsupported opcode should fail");
        match err {
            R1csError::UnsupportedOpcode { info } => {
                assert_eq!(info.opcode, "BrilligCall");
                assert_eq!(info.index, 0);
                assert_eq!(info.function_id, 0);
                assert_eq!(info.predicate_state, "constant(1)");
                assert!(info.exact_opcode.contains("BRILLIG CALL"));
                assert!(info.details.contains("at least one output witness"));
                assert!(info.details.contains("opcode_variant=BrilligCall"));
                assert!(info.workaround.contains("Constrain Brillig outputs"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn brillig_without_outputs_with_false_predicate_is_noop() {
        let circuit = Circuit {
            current_witness_index: 0,
            opcodes: vec![Opcode::BrilligCall {
                id: BrilligFunctionId(0),
                inputs: Vec::new(),
                outputs: Vec::new(),
                predicate: Expression::zero(),
            }],
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system =
            compile_r1cs(&program).expect("predicate-zero Brillig call without outputs is a no-op");
        assert_eq!(system.n_constraints, 0);
        assert!(system.is_satisfied(&[FieldElement::one()]));
    }

    #[test]
    fn recursive_aggregation_without_outputs_is_allowed_when_const_false() {
        let circuit = Circuit {
            current_witness_index: 0,
            opcodes: vec![Opcode::BlackBoxFuncCall(
                BlackBoxFuncCall::RecursiveAggregation {
                    verification_key: Vec::new(),
                    proof: Vec::new(),
                    public_inputs: Vec::new(),
                    key_hash: FunctionInput::Constant(FieldElement::zero()),
                    proof_type: 0,
                    predicate: FunctionInput::Constant(FieldElement::zero()),
                },
            )],
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program)
            .expect("predicate-zero recursive aggregation without outputs is a no-op");
        assert_eq!(system.n_constraints, 0);
        assert!(system.is_satisfied(&[FieldElement::one()]));
    }

    #[test]
    fn brillig_inverse_hint_is_supported_when_outputs_are_constrained() {
        let circuit = Circuit {
            current_witness_index: 3,
            opcodes: vec![
                Opcode::BrilligCall {
                    id: BrilligFunctionId(0),
                    inputs: vec![BrilligInputs::Single(
                        &Expression::from(Witness(1)) - &Expression::from(Witness(2)),
                    )],
                    outputs: vec![BrilligOutputs::Simple(Witness(3))],
                    predicate: Expression::one(),
                },
                Opcode::AssertZero(Expression {
                    mul_terms: vec![
                        (FieldElement::one(), Witness(1), Witness(3)),
                        (-FieldElement::one(), Witness(2), Witness(3)),
                    ],
                    linear_combinations: Vec::new(),
                    q_c: -FieldElement::one(),
                }),
            ],
            private_parameters: BTreeSet::from([Witness(1), Witness(2)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("Brillig inverse hint pattern should compile");
        let witness = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::from(3u128),
            FieldElement::from(2u128),
            FieldElement::one(),
        ];
        assert_r1cs_satisfied(&system, &witness);
        assert!(system.is_satisfied(&witness));
    }

    #[test]
    fn tampered_brillig_inverse_output_fails_constraints() {
        let circuit = Circuit {
            current_witness_index: 3,
            opcodes: vec![
                Opcode::BrilligCall {
                    id: BrilligFunctionId(0),
                    inputs: vec![BrilligInputs::Single(
                        &Expression::from(Witness(1)) - &Expression::from(Witness(2)),
                    )],
                    outputs: vec![BrilligOutputs::Simple(Witness(3))],
                    predicate: Expression::one(),
                },
                Opcode::AssertZero(Expression {
                    mul_terms: vec![
                        (FieldElement::one(), Witness(1), Witness(3)),
                        (-FieldElement::one(), Witness(2), Witness(3)),
                    ],
                    linear_combinations: Vec::new(),
                    q_c: -FieldElement::one(),
                }),
            ],
            private_parameters: BTreeSet::from([Witness(1), Witness(2)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let system = compile_r1cs(&program).expect("compile should succeed");

        let tampered = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::from(3u128),
            FieldElement::from(2u128),
            FieldElement::from(2u128),
        ];
        assert!(!system.is_satisfied(&tampered));
    }

    #[test]
    fn non_constant_brillig_predicate_requires_output_constraints() {
        let circuit = Circuit {
            current_witness_index: 2,
            opcodes: vec![Opcode::BrilligCall {
                id: BrilligFunctionId(0),
                inputs: vec![BrilligInputs::Single(Expression::from(Witness(1)))],
                outputs: vec![BrilligOutputs::Simple(Witness(2))],
                predicate: Expression::from(Witness(1)),
            }],
            ..Circuit::default()
        };

        let err = compile_r1cs_circuit(&circuit)
            .expect_err("dynamic-predicate Brillig output must still be constrained");
        match err {
            R1csError::UnsupportedOpcode { info } => {
                assert_eq!(info.opcode, "BrilligCall");
                assert_eq!(info.index, 0);
                assert_eq!(info.function_id, 0);
                assert_eq!(info.predicate_state, "dynamic");
                assert!(info
                    .details
                    .contains("not constrained by non-hint R1CS rows"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn poseidon2_permutation_is_natively_lowered_and_tamper_fails() {
        let circuit = Circuit {
            current_witness_index: 7,
            opcodes: vec![Opcode::BlackBoxFuncCall(
                BlackBoxFuncCall::Poseidon2Permutation {
                    inputs: vec![
                        FunctionInput::Witness(Witness(0)),
                        FunctionInput::Witness(Witness(1)),
                        FunctionInput::Witness(Witness(2)),
                        FunctionInput::Witness(Witness(3)),
                    ],
                    outputs: vec![Witness(4), Witness(5), Witness(6), Witness(7)],
                },
            )],
            private_parameters: BTreeSet::from([Witness(0), Witness(1), Witness(2), Witness(3)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("Poseidon2 permutation should lower natively");
        assert!(system.n_constraints > 0);

        let inputs = [
            FieldElement::from(3u128),
            FieldElement::from(9u128),
            FieldElement::from(27u128),
            FieldElement::from(81u128),
        ];
        let outputs_vec =
            poseidon2_permutation(&inputs).expect("poseidon2 permutation should solve");
        let outputs: [FieldElement; 4] = outputs_vec
            .try_into()
            .expect("poseidon2 permutation must produce four outputs");

        let witness = vec![
            FieldElement::one(),
            inputs[0],
            inputs[1],
            inputs[2],
            inputs[3],
            outputs[0],
            outputs[1],
            outputs[2],
            outputs[3],
        ];
        assert_r1cs_satisfied(&system, &witness);
        assert!(system.is_satisfied(&witness));

        let mut tampered = witness.clone();
        tampered[6] += FieldElement::one();
        assert!(!system.is_satisfied(&tampered));
    }

    #[test]
    fn embedded_curve_add_is_natively_lowered_and_tamper_fails() {
        let circuit = Circuit {
            current_witness_index: 9,
            opcodes: vec![Opcode::BlackBoxFuncCall(
                BlackBoxFuncCall::EmbeddedCurveAdd {
                    input1: Box::new([
                        FunctionInput::Witness(Witness(0)),
                        FunctionInput::Witness(Witness(1)),
                        FunctionInput::Witness(Witness(2)),
                    ]),
                    input2: Box::new([
                        FunctionInput::Witness(Witness(3)),
                        FunctionInput::Witness(Witness(4)),
                        FunctionInput::Witness(Witness(5)),
                    ]),
                    predicate: FunctionInput::Witness(Witness(9)),
                    outputs: (Witness(6), Witness(7), Witness(8)),
                },
            )],
            private_parameters: BTreeSet::from([
                Witness(0),
                Witness(1),
                Witness(2),
                Witness(3),
                Witness(4),
                Witness(5),
                Witness(9),
            ]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let generator_x =
            field_from_hex("083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a");
        let generator_y =
            field_from_hex("1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d");
        let (output_x, output_y, output_infinite) = embedded_curve_add(
            [generator_x, generator_y, FieldElement::zero()],
            [generator_x, generator_y, FieldElement::zero()],
        )
        .expect("embedded curve add should succeed for doubled generator");

        let system = compile_r1cs(&program).expect("embedded curve add should lower natively");
        assert!(system.n_constraints > 0);
        let witness = vec![
            FieldElement::one(),
            generator_x,
            generator_y,
            FieldElement::zero(),
            generator_x,
            generator_y,
            FieldElement::zero(),
            output_x,
            output_y,
            output_infinite,
            FieldElement::one(),
        ];
        assert_r1cs_satisfied(&system, &witness);
        assert!(system.is_satisfied(&witness));

        let mut tampered = witness.clone();
        tampered[8] += FieldElement::one();
        assert!(!system.is_satisfied(&tampered));
    }

    #[test]
    fn embedded_curve_add_predicate_false_allows_unconstrained_inputs_and_forces_infinity_output() {
        let circuit = Circuit {
            current_witness_index: 9,
            opcodes: vec![Opcode::BlackBoxFuncCall(
                BlackBoxFuncCall::EmbeddedCurveAdd {
                    input1: Box::new([
                        FunctionInput::Witness(Witness(0)),
                        FunctionInput::Witness(Witness(1)),
                        FunctionInput::Witness(Witness(2)),
                    ]),
                    input2: Box::new([
                        FunctionInput::Witness(Witness(3)),
                        FunctionInput::Witness(Witness(4)),
                        FunctionInput::Witness(Witness(5)),
                    ]),
                    predicate: FunctionInput::Witness(Witness(9)),
                    outputs: (Witness(6), Witness(7), Witness(8)),
                },
            )],
            private_parameters: BTreeSet::from([
                Witness(0),
                Witness(1),
                Witness(2),
                Witness(3),
                Witness(4),
                Witness(5),
                Witness(9),
            ]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let system = compile_r1cs(&program).expect("embedded curve add should lower natively");

        let witness = vec![
            FieldElement::one(),
            FieldElement::from(123u128),
            FieldElement::from(456u128),
            FieldElement::from(5u128),
            FieldElement::from(789u128),
            FieldElement::from(999u128),
            FieldElement::from(7u128),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::one(),
            FieldElement::zero(),
        ];
        assert!(system.is_satisfied(&witness));
        assert_r1cs_satisfied(&system, &witness);

        let mut tampered = witness.clone();
        tampered[9] = FieldElement::zero();
        assert!(!system.is_satisfied(&tampered));
    }

    #[test]
    fn embedded_curve_add_opposite_points_force_infinity_branch() {
        let circuit = Circuit {
            current_witness_index: 8,
            opcodes: vec![Opcode::BlackBoxFuncCall(
                BlackBoxFuncCall::EmbeddedCurveAdd {
                    input1: Box::new([
                        FunctionInput::Witness(Witness(0)),
                        FunctionInput::Witness(Witness(1)),
                        FunctionInput::Witness(Witness(2)),
                    ]),
                    input2: Box::new([
                        FunctionInput::Witness(Witness(3)),
                        FunctionInput::Witness(Witness(4)),
                        FunctionInput::Witness(Witness(5)),
                    ]),
                    predicate: FunctionInput::Constant(FieldElement::one()),
                    outputs: (Witness(6), Witness(7), Witness(8)),
                },
            )],
            private_parameters: BTreeSet::from([
                Witness(0),
                Witness(1),
                Witness(2),
                Witness(3),
                Witness(4),
                Witness(5),
            ]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let system = compile_r1cs(&program).expect("embedded curve add should lower natively");

        let generator_x =
            field_from_hex("083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a");
        let generator_y =
            field_from_hex("1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d");
        let witness = vec![
            FieldElement::one(),
            generator_x,
            generator_y,
            FieldElement::zero(),
            generator_x,
            -generator_y,
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::one(),
        ];
        assert!(system.is_satisfied(&witness));
        assert_r1cs_satisfied(&system, &witness);

        let mut tampered = witness.clone();
        tampered[7] = FieldElement::one();
        assert!(!system.is_satisfied(&tampered));
    }

    #[test]
    fn embedded_curve_add_rejects_infinite_input_when_predicate_true() {
        let circuit = Circuit {
            current_witness_index: 8,
            opcodes: vec![Opcode::BlackBoxFuncCall(
                BlackBoxFuncCall::EmbeddedCurveAdd {
                    input1: Box::new([
                        FunctionInput::Witness(Witness(0)),
                        FunctionInput::Witness(Witness(1)),
                        FunctionInput::Witness(Witness(2)),
                    ]),
                    input2: Box::new([
                        FunctionInput::Witness(Witness(3)),
                        FunctionInput::Witness(Witness(4)),
                        FunctionInput::Witness(Witness(5)),
                    ]),
                    predicate: FunctionInput::Constant(FieldElement::one()),
                    outputs: (Witness(6), Witness(7), Witness(8)),
                },
            )],
            private_parameters: BTreeSet::from([
                Witness(0),
                Witness(1),
                Witness(2),
                Witness(3),
                Witness(4),
                Witness(5),
            ]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let system = compile_r1cs(&program).expect("embedded curve add should lower natively");

        let generator_x =
            field_from_hex("083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a");
        let generator_y =
            field_from_hex("1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d");
        let witness = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::one(),
            generator_x,
            generator_y,
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::one(),
        ];
        assert!(!system.is_satisfied(&witness));
    }

    #[test]
    fn multi_scalar_mul_constant_inputs_are_natively_lowered_and_tamper_fails() {
        let generator_x =
            field_from_hex("083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a");
        let generator_y =
            field_from_hex("1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d");

        let circuit = Circuit {
            current_witness_index: 2,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul {
                points: vec![
                    FunctionInput::Constant(generator_x),
                    FunctionInput::Constant(generator_y),
                    FunctionInput::Constant(FieldElement::zero()),
                ],
                scalars: vec![
                    FunctionInput::Constant(FieldElement::one()),
                    FunctionInput::Constant(FieldElement::zero()),
                ],
                predicate: FunctionInput::Constant(FieldElement::one()),
                outputs: (Witness(0), Witness(1), Witness(2)),
            })],
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let (output_x, output_y, output_infinite) = bn254_multi_scalar_mul(
            &[generator_x, generator_y, FieldElement::zero()],
            &[FieldElement::one()],
            &[FieldElement::zero()],
        )
        .expect("constant multi-scalar multiplication should succeed");

        let system = compile_r1cs(&program).expect("multi-scalar multiplication should lower");
        let witness = vec![FieldElement::one(), output_x, output_y, output_infinite];
        assert!(system.is_satisfied(&witness));
        assert_r1cs_satisfied(&system, &witness);

        let mut tampered = witness.clone();
        tampered[2] += FieldElement::one();
        assert!(!system.is_satisfied(&tampered));
    }

    #[test]
    fn multi_scalar_mul_predicate_false_forces_infinity_output() {
        let generator_x =
            field_from_hex("083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a");
        let generator_y =
            field_from_hex("1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d");

        let circuit = Circuit {
            current_witness_index: 3,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul {
                points: vec![
                    FunctionInput::Constant(generator_x),
                    FunctionInput::Constant(generator_y),
                    FunctionInput::Constant(FieldElement::zero()),
                ],
                scalars: vec![
                    FunctionInput::Constant(FieldElement::one()),
                    FunctionInput::Constant(FieldElement::zero()),
                ],
                predicate: FunctionInput::Witness(Witness(3)),
                outputs: (Witness(0), Witness(1), Witness(2)),
            })],
            private_parameters: BTreeSet::from([Witness(3)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("multi-scalar multiplication should lower");
        let witness = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::one(),
            FieldElement::zero(),
        ];
        assert!(system.is_satisfied(&witness));
        assert_r1cs_satisfied(&system, &witness);

        let mut tampered = witness.clone();
        tampered[3] = FieldElement::zero();
        assert!(!system.is_satisfied(&tampered));
    }

    #[test]
    fn multi_scalar_mul_dynamic_predicate_uses_native_constant_path() {
        let generator_x =
            field_from_hex("083e7911d835097629f0067531fc15cafd79a89beecb39903f69572c636f4a5a");
        let generator_y =
            field_from_hex("1a7f5efaad7f315c25a918f30cc8d7333fccab7ad7c90f14de81bcc528f9935d");

        let circuit = Circuit {
            current_witness_index: 3,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul {
                points: vec![
                    FunctionInput::Constant(generator_x),
                    FunctionInput::Constant(generator_y),
                    FunctionInput::Constant(FieldElement::zero()),
                ],
                scalars: vec![
                    FunctionInput::Constant(FieldElement::one()),
                    FunctionInput::Constant(FieldElement::zero()),
                ],
                predicate: FunctionInput::Witness(Witness(3)),
                outputs: (Witness(0), Witness(1), Witness(2)),
            })],
            private_parameters: BTreeSet::from([Witness(3)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let (output_x, output_y, output_infinite) = bn254_multi_scalar_mul(
            &[generator_x, generator_y, FieldElement::zero()],
            &[FieldElement::one()],
            &[FieldElement::zero()],
        )
        .expect("constant multi-scalar multiplication should succeed");

        let system = compile_r1cs(&program).expect("multi-scalar multiplication should lower");
        let witness_predicate_true = vec![
            FieldElement::one(),
            output_x,
            output_y,
            output_infinite,
            FieldElement::one(),
        ];
        assert!(system.is_satisfied(&witness_predicate_true));
        assert_r1cs_satisfied(&system, &witness_predicate_true);

        let witness_predicate_false = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::one(),
            FieldElement::zero(),
        ];
        assert!(system.is_satisfied(&witness_predicate_false));
        assert_r1cs_satisfied(&system, &witness_predicate_false);

        let mut tampered = witness_predicate_true.clone();
        tampered[2] += FieldElement::one();
        assert!(!system.is_satisfied(&tampered));
    }

    #[test]
    fn multi_scalar_mul_witness_inputs_require_native_relation_in_strict_mode() {
        let circuit = Circuit {
            current_witness_index: 7,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul {
                points: vec![
                    FunctionInput::Witness(Witness(0)),
                    FunctionInput::Witness(Witness(1)),
                    FunctionInput::Witness(Witness(2)),
                ],
                scalars: vec![
                    FunctionInput::Witness(Witness(3)),
                    FunctionInput::Witness(Witness(4)),
                ],
                predicate: FunctionInput::Constant(FieldElement::one()),
                outputs: (Witness(5), Witness(6), Witness(7)),
            })],
            private_parameters: BTreeSet::from([
                Witness(0),
                Witness(1),
                Witness(2),
                Witness(3),
                Witness(4),
            ]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let err = compile_r1cs(&program)
            .expect_err("strict mode should reject witness-driven multi-scalar multiplication");
        assert!(format!("{err}")
            .contains("MultiScalarMul witness-driven native lowering is not implemented"));
    }

    #[test]
    fn allow_unsupported_collects_coverage_without_emitting_r1cs() {
        let circuit = Circuit {
            current_witness_index: 1,
            opcodes: vec![
                Opcode::BrilligCall {
                    id: BrilligFunctionId(0),
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    predicate: Expression::one(),
                },
                Opcode::Call {
                    id: AcirFunctionId(1),
                    inputs: vec![Witness(1)],
                    outputs: vec![Witness(1)],
                    predicate: Expression::one(),
                },
            ],
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let err = compile_r1cs_with_options(&program, LoweringOptions::allow_unsupported())
            .expect_err("allow mode still fails without emitting an R1CS");
        match err {
            R1csError::UnsupportedOpcodes { opcodes } => {
                assert_eq!(opcodes.len(), 2);
                assert_eq!(opcodes[0].opcode, "BrilligCall");
                assert_eq!(opcodes[1].opcode, "Call");
            }
            other => panic!("unexpected error: {other}"),
        }
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
        assert_eq!(
            parsed.header.prime,
            R1csFieldElement::from(bn254_modulus_le_bytes())
        );
    }

    #[test]
    fn static_memory_read_write_is_supported() {
        let circuit = Circuit {
            current_witness_index: 4,
            opcodes: vec![
                Opcode::MemoryInit {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    init: vec![Witness(1), Witness(2)],
                    block_type: BlockType::Memory,
                },
                Opcode::MemoryOp {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    op: MemOp::read_at_mem_index(
                        Expression::from_field(FieldElement::zero()),
                        Witness(3),
                    ),
                },
                Opcode::AssertZero(Expression {
                    mul_terms: Vec::new(),
                    linear_combinations: vec![
                        (FieldElement::one(), Witness(3)),
                        (-FieldElement::one(), Witness(1)),
                    ],
                    q_c: FieldElement::zero(),
                }),
                Opcode::MemoryOp {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    op: MemOp::write_to_mem_index(
                        Expression::from_field(FieldElement::one()),
                        &Expression::from(Witness(1)) + &Expression::from(Witness(2)),
                    ),
                },
                Opcode::MemoryOp {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    op: MemOp::read_at_mem_index(
                        Expression::from_field(FieldElement::one()),
                        Witness(4),
                    ),
                },
                Opcode::AssertZero(Expression {
                    mul_terms: Vec::new(),
                    linear_combinations: vec![
                        (FieldElement::one(), Witness(4)),
                        (-FieldElement::one(), Witness(1)),
                        (-FieldElement::one(), Witness(2)),
                    ],
                    q_c: FieldElement::zero(),
                }),
            ],
            private_parameters: BTreeSet::from([Witness(1), Witness(2)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("memory lowering should compile");
        let witness = [
            FieldElement::one(),
            FieldElement::from(3u128),
            FieldElement::from(5u128),
            FieldElement::from(3u128),
            FieldElement::from(8u128),
        ];
        assert_eq!(witness.len(), 5);
        assert!(system.n_constraints > 0);
    }

    #[test]
    fn dynamic_memory_index_is_supported() {
        let circuit = Circuit {
            current_witness_index: 2,
            opcodes: vec![
                Opcode::MemoryInit {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    init: vec![Witness(1)],
                    block_type: BlockType::Memory,
                },
                Opcode::MemoryOp {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    op: MemOp::read_at_mem_index(Expression::from(Witness(2)), Witness(1)),
                },
            ],
            private_parameters: BTreeSet::from([Witness(1), Witness(2)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("dynamic memory index should compile");
        assert!(system.n_constraints > 0);
    }

    #[test]
    fn boolean_blackboxes_are_supported() {
        let and = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
            lhs: FunctionInput::Witness(Witness(1)),
            rhs: FunctionInput::Witness(Witness(2)),
            num_bits: 1,
            output: Witness(3),
        });
        let xor = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR {
            lhs: FunctionInput::Witness(Witness(1)),
            rhs: FunctionInput::Witness(Witness(2)),
            num_bits: 1,
            output: Witness(4),
        });
        let range = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
            input: FunctionInput::Witness(Witness(1)),
            num_bits: 1,
        });
        let bind = Opcode::AssertZero(Expression {
            mul_terms: Vec::new(),
            linear_combinations: vec![
                (FieldElement::one(), Witness(5)),
                (-FieldElement::one(), Witness(3)),
                (-FieldElement::one(), Witness(4)),
            ],
            q_c: FieldElement::zero(),
        });

        let circuit = Circuit {
            current_witness_index: 5,
            opcodes: vec![and, xor, range, bind],
            private_parameters: BTreeSet::from([Witness(1), Witness(2)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("boolean blackboxes should compile");
        let witness = [
            FieldElement::one(),
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::one(),
            FieldElement::one(),
        ];
        assert_eq!(witness.len(), 6);
        assert!(system.n_constraints > 0);
    }

    #[test]
    fn blake2s_constant_inputs_are_natively_lowered_and_tamper_fails() {
        let outputs: [Witness; 32] = std::array::from_fn(|index| Witness(index as u32));
        let circuit = Circuit {
            current_witness_index: 31,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake2s {
                inputs: vec![
                    FunctionInput::Constant(FieldElement::from(u128::from(b'a'))),
                    FunctionInput::Constant(FieldElement::from(u128::from(b'b'))),
                    FunctionInput::Constant(FieldElement::from(u128::from(b'c'))),
                ],
                outputs: Box::new(outputs),
            })],
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let system = compile_r1cs(&program).expect("Blake2s constants should lower natively");

        let digest = blake2s(b"abc").expect("blake2s should evaluate");
        let mut witness = vec![FieldElement::one()];
        witness.extend(
            digest
                .into_iter()
                .map(|byte| FieldElement::from(u128::from(byte))),
        );
        assert!(system.is_satisfied(&witness));
        assert_r1cs_satisfied(&system, &witness);

        let mut tampered = witness.clone();
        tampered[10] += FieldElement::one();
        assert!(!system.is_satisfied(&tampered));
    }

    #[test]
    fn blake3_constant_inputs_are_natively_lowered_and_tamper_fails() {
        let outputs: [Witness; 32] = std::array::from_fn(|index| Witness(index as u32));
        let circuit = Circuit {
            current_witness_index: 31,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake3 {
                inputs: vec![
                    FunctionInput::Constant(FieldElement::from(u128::from(b'a'))),
                    FunctionInput::Constant(FieldElement::from(u128::from(b'b'))),
                    FunctionInput::Constant(FieldElement::from(u128::from(b'c'))),
                ],
                outputs: Box::new(outputs),
            })],
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let system = compile_r1cs(&program).expect("Blake3 constants should lower natively");

        let digest = blake3(b"abc").expect("blake3 should evaluate");
        let mut witness = vec![FieldElement::one()];
        witness.extend(
            digest
                .into_iter()
                .map(|byte| FieldElement::from(u128::from(byte))),
        );
        assert!(system.is_satisfied(&witness));
        assert_r1cs_satisfied(&system, &witness);

        let mut tampered = witness.clone();
        tampered[10] += FieldElement::one();
        assert!(!system.is_satisfied(&tampered));
    }

    #[test]
    fn blake2s_witness_inputs_require_native_relation_in_strict_mode() {
        let outputs: [Witness; 32] = std::array::from_fn(|index| Witness((3 + index) as u32));
        let circuit = Circuit {
            current_witness_index: 34,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake2s {
                inputs: vec![
                    FunctionInput::Witness(Witness(0)),
                    FunctionInput::Witness(Witness(1)),
                    FunctionInput::Witness(Witness(2)),
                ],
                outputs: Box::new(outputs),
            })],
            private_parameters: BTreeSet::from([Witness(0), Witness(1), Witness(2)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let err = compile_r1cs(&program).expect_err("strict mode should reject witness Blake2s");
        assert!(
            format!("{err}").contains("Blake2s witness-driven native lowering is not implemented")
        );
    }

    #[test]
    fn blake3_witness_inputs_require_native_relation_in_strict_mode() {
        let outputs: [Witness; 32] = std::array::from_fn(|index| Witness((3 + index) as u32));
        let circuit = Circuit {
            current_witness_index: 34,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Blake3 {
                inputs: vec![
                    FunctionInput::Witness(Witness(0)),
                    FunctionInput::Witness(Witness(1)),
                    FunctionInput::Witness(Witness(2)),
                ],
                outputs: Box::new(outputs),
            })],
            private_parameters: BTreeSet::from([Witness(0), Witness(1), Witness(2)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let err = compile_r1cs(&program).expect_err("strict mode should reject witness Blake3");
        assert!(
            format!("{err}").contains("Blake3 witness-driven native lowering is not implemented")
        );
    }

    #[test]
    fn sha256_compression_constant_inputs_are_natively_lowered_and_tamper_fails() {
        let outputs: [Witness; 8] = std::array::from_fn(|index| Witness(index as u32));
        let message_words = [0u32; 16];
        let hash_words = [0u32; 8];
        let circuit =
            Circuit {
                current_witness_index: 7,
                opcodes: vec![Opcode::BlackBoxFuncCall(
                    BlackBoxFuncCall::Sha256Compression {
                        inputs: Box::new(message_words.map(|word| {
                            FunctionInput::Constant(FieldElement::from(u128::from(word)))
                        })),
                        hash_values: Box::new(hash_words.map(|word| {
                            FunctionInput::Constant(FieldElement::from(u128::from(word)))
                        })),
                        outputs: Box::new(outputs),
                    },
                )],
                ..Circuit::default()
            };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let system =
            compile_r1cs(&program).expect("Sha256Compression constants should lower natively");

        let mut expected_state = hash_words;
        sha256_compression(&mut expected_state, &message_words);
        let mut witness = vec![FieldElement::one()];
        witness.extend(
            expected_state
                .into_iter()
                .map(|word| FieldElement::from(u128::from(word))),
        );
        assert!(system.is_satisfied(&witness));
        assert_r1cs_satisfied(&system, &witness);

        let mut tampered = witness.clone();
        tampered[4] += FieldElement::one();
        assert!(!system.is_satisfied(&tampered));
    }

    #[test]
    fn sha256_compression_witness_inputs_emit_native_relation_rows() {
        let inputs: [FunctionInput<FieldElement>; 16] =
            std::array::from_fn(|index| FunctionInput::Witness(Witness(index as u32)));
        let hash_values: [FunctionInput<FieldElement>; 8] =
            std::array::from_fn(|index| FunctionInput::Witness(Witness((16 + index) as u32)));
        let outputs: [Witness; 8] = std::array::from_fn(|index| Witness((24 + index) as u32));

        let circuit = Circuit {
            current_witness_index: 31,
            opcodes: vec![Opcode::BlackBoxFuncCall(
                BlackBoxFuncCall::Sha256Compression {
                    inputs: Box::new(inputs),
                    hash_values: Box::new(hash_values),
                    outputs: Box::new(outputs),
                },
            )],
            private_parameters: BTreeSet::from_iter((0..24).map(Witness)),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let system =
            compile_r1cs(&program).expect("Sha256Compression witnesses should lower natively");

        let constant_circuit =
            Circuit {
                current_witness_index: 7,
                opcodes: vec![Opcode::BlackBoxFuncCall(
                    BlackBoxFuncCall::Sha256Compression {
                        inputs: Box::new([0u32; 16].map(|word| {
                            FunctionInput::Constant(FieldElement::from(u128::from(word)))
                        })),
                        hash_values: Box::new([0u32; 8].map(|word| {
                            FunctionInput::Constant(FieldElement::from(u128::from(word)))
                        })),
                        outputs: Box::new(std::array::from_fn(|index| Witness(index as u32))),
                    },
                )],
                ..Circuit::default()
            };
        let constant_program = Program {
            functions: vec![constant_circuit],
            unconstrained_functions: Vec::new(),
        };
        let constant_system = compile_r1cs(&constant_program)
            .expect("Sha256Compression constants should lower natively");

        assert!(
            system.n_constraints > constant_system.n_constraints + 1_000,
            "witness-input Sha256Compression should emit a large native relation (got {} vs constant path {})",
            system.n_constraints,
            constant_system.n_constraints
        );
    }

    #[test]
    fn ecdsa_secp256k1_constant_inputs_are_natively_lowered_and_tamper_fails() {
        let hashed_message: [u8; 32] = [
            0x3a, 0x73, 0xf4, 0x12, 0x3a, 0x5c, 0xd2, 0x12, 0x1f, 0x21, 0xcd, 0x7e, 0x8d, 0x35,
            0x88, 0x35, 0x47, 0x69, 0x49, 0xd0, 0x35, 0xd9, 0xc2, 0xda, 0x68, 0x06, 0xb4, 0x63,
            0x3a, 0xc8, 0xc1, 0xe2,
        ];
        let pub_key_x: [u8; 32] = [
            0xa0, 0x43, 0x4d, 0x9e, 0x47, 0xf3, 0xc8, 0x62, 0x35, 0x47, 0x7c, 0x7b, 0x1a, 0xe6,
            0xae, 0x5d, 0x34, 0x42, 0xd4, 0x9b, 0x19, 0x43, 0xc2, 0xb7, 0x52, 0xa6, 0x8e, 0x2a,
            0x47, 0xe2, 0x47, 0xc7,
        ];
        let pub_key_y: [u8; 32] = [
            0x89, 0x3a, 0xba, 0x42, 0x54, 0x19, 0xbc, 0x27, 0xa3, 0xb6, 0xc7, 0xe6, 0x93, 0xa2,
            0x4c, 0x69, 0x6f, 0x79, 0x4c, 0x2e, 0xd8, 0x77, 0xa1, 0x59, 0x3c, 0xbe, 0xe5, 0x3b,
            0x03, 0x73, 0x68, 0xd7,
        ];
        let signature: [u8; 64] = [
            0xe5, 0x08, 0x1c, 0x80, 0xab, 0x42, 0x7d, 0xc3, 0x70, 0x34, 0x6f, 0x4a, 0x0e, 0x31,
            0xaa, 0x2b, 0xad, 0x8d, 0x97, 0x98, 0xc3, 0x80, 0x61, 0xdb, 0x9a, 0xe5, 0x5a, 0x4e,
            0x8d, 0xf4, 0x54, 0xfd, 0x28, 0x11, 0x98, 0x94, 0x34, 0x4e, 0x71, 0xb7, 0x87, 0x70,
            0xcc, 0x93, 0x1d, 0x61, 0xf4, 0x80, 0xec, 0xbb, 0x0b, 0x89, 0xd6, 0xeb, 0x69, 0x69,
            0x01, 0x61, 0xe4, 0x9a, 0x71, 0x5f, 0xcd, 0x55,
        ];
        let circuit = Circuit {
            current_witness_index: 0,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EcdsaSecp256k1 {
                public_key_x: Box::new(
                    pub_key_x
                        .map(|byte| FunctionInput::Constant(FieldElement::from(u128::from(byte)))),
                ),
                public_key_y: Box::new(
                    pub_key_y
                        .map(|byte| FunctionInput::Constant(FieldElement::from(u128::from(byte)))),
                ),
                signature: Box::new(
                    signature
                        .map(|byte| FunctionInput::Constant(FieldElement::from(u128::from(byte)))),
                ),
                hashed_message: Box::new(
                    hashed_message
                        .map(|byte| FunctionInput::Constant(FieldElement::from(u128::from(byte)))),
                ),
                predicate: FunctionInput::Constant(FieldElement::one()),
                output: Witness(0),
            })],
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let system =
            compile_r1cs(&program).expect("constant secp256k1 ECDSA should lower natively");
        let witness_ok = vec![FieldElement::one(), FieldElement::one()];
        assert!(system.is_satisfied(&witness_ok));
        assert_r1cs_satisfied(&system, &witness_ok);

        let witness_bad = vec![FieldElement::one(), FieldElement::zero()];
        assert!(!system.is_satisfied(&witness_bad));
    }

    #[test]
    fn ecdsa_predicate_false_forces_true_output() {
        let public_key_x: [FunctionInput<FieldElement>; 32] =
            std::array::from_fn(|index| FunctionInput::Witness(Witness(index as u32)));
        let public_key_y: [FunctionInput<FieldElement>; 32] =
            std::array::from_fn(|index| FunctionInput::Witness(Witness(32 + index as u32)));
        let signature: [FunctionInput<FieldElement>; 64] =
            std::array::from_fn(|index| FunctionInput::Witness(Witness(64 + index as u32)));
        let hashed_message: [FunctionInput<FieldElement>; 32] =
            std::array::from_fn(|index| FunctionInput::Witness(Witness(128 + index as u32)));
        let circuit = Circuit {
            current_witness_index: 160,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EcdsaSecp256k1 {
                public_key_x: Box::new(public_key_x),
                public_key_y: Box::new(public_key_y),
                signature: Box::new(signature),
                hashed_message: Box::new(hashed_message),
                predicate: FunctionInput::Constant(FieldElement::zero()),
                output: Witness(160),
            })],
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let system =
            compile_r1cs(&program).expect("predicate-false secp256k1 ECDSA should lower natively");

        let witness_ok = vec![FieldElement::one(); 162];
        assert!(system.is_satisfied(&witness_ok));
        assert_r1cs_satisfied(&system, &witness_ok);

        let mut witness_bad = witness_ok.clone();
        witness_bad[161] = FieldElement::zero();
        assert!(!system.is_satisfied(&witness_bad));
    }

    #[test]
    fn ecdsa_witness_inputs_require_native_relation_in_strict_mode() {
        let public_key_x: [FunctionInput<FieldElement>; 32] =
            std::array::from_fn(|index| FunctionInput::Witness(Witness(index as u32)));
        let public_key_y: [FunctionInput<FieldElement>; 32] =
            std::array::from_fn(|index| FunctionInput::Witness(Witness(32 + index as u32)));
        let signature: [FunctionInput<FieldElement>; 64] =
            std::array::from_fn(|index| FunctionInput::Witness(Witness(64 + index as u32)));
        let hashed_message: [FunctionInput<FieldElement>; 32] =
            std::array::from_fn(|index| FunctionInput::Witness(Witness(128 + index as u32)));
        let circuit = Circuit {
            current_witness_index: 160,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::EcdsaSecp256k1 {
                public_key_x: Box::new(public_key_x),
                public_key_y: Box::new(public_key_y),
                signature: Box::new(signature),
                hashed_message: Box::new(hashed_message),
                predicate: FunctionInput::Constant(FieldElement::one()),
                output: Witness(160),
            })],
            private_parameters: BTreeSet::from_iter((0..160).map(Witness)),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let err =
            compile_r1cs(&program).expect_err("strict mode should reject witness-driven ECDSA");
        assert!(
            format!("{err}").contains("ECDSA witness-driven native lowering is not implemented")
        );
    }

    #[test]
    fn non_boolean_range_is_supported() {
        let circuit = Circuit {
            current_witness_index: 1,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(Witness(1)),
                num_bits: 8,
            })],
            private_parameters: BTreeSet::from([Witness(1)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("8-bit range should compile");
        assert!(system.n_constraints > 0);
    }

    #[test]
    fn range_253_bits_accepts_small_value_and_rejects_field_max() {
        let circuit = Circuit {
            current_witness_index: 0,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(Witness(0)),
                num_bits: 253,
            })],
            private_parameters: BTreeSet::from([Witness(0)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("253-bit range should compile");
        let ok_value = FieldElement::from(2u128).pow(&FieldElement::from(252u128));
        let witness_ok = vec![FieldElement::one(), ok_value];
        assert!(system.is_satisfied(&witness_ok));
        assert_r1cs_satisfied(&system, &witness_ok);

        let witness_bad = vec![FieldElement::one(), -FieldElement::one()];
        assert!(!system.is_satisfied(&witness_bad));
    }

    #[test]
    fn range_at_or_above_field_width_is_tautological() {
        let circuit = Circuit {
            current_witness_index: 0,
            opcodes: vec![
                Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                    input: FunctionInput::Witness(Witness(0)),
                    num_bits: 254,
                }),
                Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                    input: FunctionInput::Witness(Witness(0)),
                    num_bits: 512,
                }),
            ],
            private_parameters: BTreeSet::from([Witness(0)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("range >= field width should compile");
        assert_eq!(system.n_constraints, 0);
        assert!(system.is_satisfied(&[FieldElement::one(), -FieldElement::one()]));
    }

    #[test]
    fn materialized_witness_satisfies_non_boolean_range_constraints() {
        let circuit = Circuit {
            current_witness_index: 0,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput::Witness(Witness(0)),
                num_bits: 8,
            })],
            private_parameters: BTreeSet::from([Witness(0)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("8-bit range should compile");
        let partial_witness = vec![FieldElement::one(), FieldElement::from(13u128)];
        assert!(
            system.is_satisfied(&partial_witness),
            "materialized witness should satisfy 8-bit range constraints"
        );
    }

    #[test]
    fn materialized_witness_satisfies_multi_bit_and_constraints() {
        let circuit = Circuit {
            current_witness_index: 2,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
                lhs: FunctionInput::Witness(Witness(0)),
                rhs: FunctionInput::Witness(Witness(1)),
                num_bits: 8,
                output: Witness(2),
            })],
            private_parameters: BTreeSet::from([Witness(0), Witness(1), Witness(2)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("8-bit AND should compile");
        let partial_witness = vec![
            FieldElement::one(),
            FieldElement::from(13u128),
            FieldElement::from(11u128),
            FieldElement::from(9u128),
        ];
        assert!(
            system.is_satisfied(&partial_witness),
            "materialized witness should satisfy 8-bit AND constraints"
        );
    }

    #[test]
    fn materialized_witness_satisfies_dynamic_memory_read_constraints() {
        let circuit = Circuit {
            current_witness_index: 5,
            opcodes: vec![
                Opcode::MemoryInit {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    init: vec![Witness(0), Witness(1), Witness(2), Witness(3)],
                    block_type: BlockType::Memory,
                },
                Opcode::MemoryOp {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    op: MemOp::read_at_mem_index(Expression::from(Witness(4)), Witness(5)),
                },
            ],
            private_parameters: BTreeSet::from([
                Witness(0),
                Witness(1),
                Witness(2),
                Witness(3),
                Witness(4),
                Witness(5),
            ]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("dynamic memory read should compile");
        let partial_witness = vec![
            FieldElement::one(),
            FieldElement::from(5u128),
            FieldElement::from(11u128),
            FieldElement::from(17u128),
            FieldElement::from(23u128),
            FieldElement::from(2u128),
            FieldElement::from(17u128),
        ];
        assert!(
            system.is_satisfied(&partial_witness),
            "materialized witness should satisfy dynamic memory read constraints"
        );
    }

    #[test]
    fn field_to_usize_parses_small_values() {
        assert_eq!(field_to_usize(FieldElement::from(0u128)), Some(0));
        assert_eq!(field_to_usize(FieldElement::from(2u128)), Some(2));
        assert_eq!(field_to_usize(FieldElement::from(17u128)), Some(17));
    }

    #[test]
    fn compile_is_deterministic_for_fixture_bytes() {
        let artifact = Artifact::from_json_bytes(include_bytes!(
            "../../../test-vectors/fixture_artifact.json"
        ))
        .expect("fixture should parse");
        let first = compile_r1cs(&artifact.program).expect("compile should succeed");
        let second = compile_r1cs(&artifact.program).expect("compile should succeed");
        assert_eq!(first, second);

        let dir = TempDir::new().expect("temp dir should be creatable");
        let first_path = dir.path().join("first.r1cs");
        let second_path = dir.path().join("second.r1cs");
        write_r1cs_binary(&first, &first_path).expect("write should succeed");
        write_r1cs_binary(&second, &second_path).expect("write should succeed");
        assert_eq!(
            fs::read(&first_path).expect("first bytes"),
            fs::read(&second_path).expect("second bytes")
        );
    }

    #[test]
    fn memory_mux_fixture_solves_lowers_and_is_deterministic() {
        let artifact = Artifact::from_json_bytes(include_bytes!(
            "../../../test-vectors/memory_mux_artifact.json"
        ))
        .expect("memory fixture should parse");

        let witness_a = generate_witness_from_json_str(
            &artifact,
            include_str!("../../../test-vectors/memory_mux_inputs.json"),
        )
        .expect("memory fixture witness should solve");
        let witness_b = generate_witness_from_json_str(
            &artifact,
            include_str!("../../../test-vectors/memory_mux_inputs.json"),
        )
        .expect("memory fixture witness should solve deterministically");

        let system_a = compile_r1cs(&artifact.program).expect("memory fixture should lower");
        let system_b = compile_r1cs(&artifact.program).expect("second lowering should match");
        assert_eq!(system_a, system_b);
        assert_eq!(witness_a.witness_vector, witness_b.witness_vector);

        let dir = TempDir::new().expect("temp dir");
        let r1cs_a = dir.path().join("memory_a.r1cs");
        let r1cs_b = dir.path().join("memory_b.r1cs");
        write_r1cs_binary(&system_a, &r1cs_a).expect("write first r1cs");
        write_r1cs_binary(&system_b, &r1cs_b).expect("write second r1cs");
        assert_eq!(
            fs::read(&r1cs_a).expect("read first r1cs"),
            fs::read(&r1cs_b).expect("read second r1cs")
        );

        let wtns_a = dir.path().join("memory_a.wtns");
        let wtns_b = dir.path().join("memory_b.wtns");
        witness_a.write_wtns(&wtns_a).expect("write first wtns");
        witness_b.write_wtns(&wtns_b).expect("write second wtns");
        assert_eq!(
            fs::read(&wtns_a).expect("read first wtns"),
            fs::read(&wtns_b).expect("read second wtns")
        );
    }

    #[test]
    fn blackbox_bool_fixture_solves_lowers_and_is_deterministic() {
        let artifact = Artifact::from_json_bytes(include_bytes!(
            "../../../test-vectors/blackbox_bool_artifact.json"
        ))
        .expect("blackbox fixture should parse");

        let witness_a = generate_witness_from_json_str(
            &artifact,
            include_str!("../../../test-vectors/blackbox_bool_inputs.json"),
        )
        .expect("blackbox fixture witness should solve");
        let witness_b = generate_witness_from_json_str(
            &artifact,
            include_str!("../../../test-vectors/blackbox_bool_inputs.json"),
        )
        .expect("blackbox fixture witness should solve deterministically");

        let system_a = compile_r1cs(&artifact.program).expect("blackbox fixture should lower");
        let system_b = compile_r1cs(&artifact.program).expect("second lowering should match");
        assert_eq!(system_a, system_b);
        assert_eq!(witness_a.witness_vector, witness_b.witness_vector);

        let dir = TempDir::new().expect("temp dir");
        let r1cs_a = dir.path().join("blackbox_a.r1cs");
        let r1cs_b = dir.path().join("blackbox_b.r1cs");
        write_r1cs_binary(&system_a, &r1cs_a).expect("write first r1cs");
        write_r1cs_binary(&system_b, &r1cs_b).expect("write second r1cs");
        assert_eq!(
            fs::read(&r1cs_a).expect("read first r1cs"),
            fs::read(&r1cs_b).expect("read second r1cs")
        );

        let wtns_a = dir.path().join("blackbox_a.wtns");
        let wtns_b = dir.path().join("blackbox_b.wtns");
        witness_a.write_wtns(&wtns_a).expect("write first wtns");
        witness_b.write_wtns(&wtns_b).expect("write second wtns");
        assert_eq!(
            fs::read(&wtns_a).expect("read first wtns"),
            fs::read(&wtns_b).expect("read second wtns")
        );
    }

    proptest! {
        #[test]
        fn lowering_is_deterministic_for_small_assertzero_programs(
            muls in prop::collection::vec((0u8..=3u8, 1u8..=4u8, 1u8..=4u8), 0..4),
            lins in prop::collection::vec((0u8..=3u8, 1u8..=4u8), 0..6),
            q_c in 0u8..=3u8,
        ) {
            let expr = Expression {
                mul_terms: muls.into_iter().map(|(coeff, lhs, rhs)| {
                    (FieldElement::from(coeff as u128), Witness(lhs as u32), Witness(rhs as u32))
                }).collect(),
                linear_combinations: lins.into_iter().map(|(coeff, witness)| {
                    (FieldElement::from(coeff as u128), Witness(witness as u32))
                }).collect(),
                q_c: FieldElement::from(q_c as u128),
            };
            let circuit = Circuit {
                current_witness_index: 4,
                opcodes: vec![Opcode::AssertZero(expr)],
                private_parameters: BTreeSet::from([Witness(1), Witness(2), Witness(3), Witness(4)]),
                public_parameters: PublicInputs(BTreeSet::new()),
                return_values: PublicInputs(BTreeSet::new()),
                ..Circuit::default()
            };
            let program = Program {
                functions: vec![circuit],
                unconstrained_functions: Vec::new(),
            };

            let first = compile_r1cs(&program).expect("first compile");
            let second = compile_r1cs(&program).expect("second compile");
            prop_assert_eq!(first, second);
        }
    }

    #[test]
    fn collect_unsupported_opcodes_reports_multiple_entries() {
        let circuit = Circuit {
            current_witness_index: 1,
            opcodes: vec![
                Opcode::BrilligCall {
                    id: BrilligFunctionId(0),
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    predicate: Expression::one(),
                },
                Opcode::Call {
                    id: AcirFunctionId(1),
                    inputs: vec![Witness(1)],
                    outputs: vec![Witness(1)],
                    predicate: Expression::one(),
                },
            ],
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let unsupported = collect_unsupported_opcodes(&program).expect("coverage should succeed");
        assert_eq!(unsupported.len(), 2);
        assert_eq!(unsupported[0].index, 0);
        assert_eq!(unsupported[1].index, 1);
        assert_eq!(unsupported[0].function_id, 0);
        assert_eq!(unsupported[0].predicate_state, "constant(1)");
        assert!(unsupported[0]
            .workaround
            .contains("Constrain Brillig outputs"));
        assert!(unsupported[1]
            .workaround
            .contains("Constrain the Call predicate"));
    }

    #[test]
    fn nested_call_is_inlined_deterministically() {
        let callee = Circuit {
            current_witness_index: 2,
            opcodes: vec![Opcode::AssertZero(Expression {
                mul_terms: Vec::new(),
                linear_combinations: vec![
                    (FieldElement::one(), Witness(2)),
                    (-FieldElement::one(), Witness(0)),
                    (-FieldElement::one(), Witness(1)),
                ],
                q_c: FieldElement::zero(),
            })],
            return_values: PublicInputs(BTreeSet::from([Witness(2)])),
            ..Circuit::default()
        };

        let caller = Circuit {
            current_witness_index: 3,
            opcodes: vec![Opcode::Call {
                id: AcirFunctionId(1),
                inputs: vec![Witness(1), Witness(2)],
                outputs: vec![Witness(3)],
                predicate: Expression::one(),
            }],
            private_parameters: BTreeSet::from([Witness(1), Witness(2)]),
            ..Circuit::default()
        };

        let program = Program {
            functions: vec![caller, callee],
            unconstrained_functions: Vec::new(),
        };

        let first = compile_r1cs(&program).expect("first compile should succeed");
        let second = compile_r1cs(&program).expect("second compile should match");
        assert_eq!(first, second);

        let witness = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::from(7u128),
            FieldElement::from(9u128),
            FieldElement::from(16u128),
        ];
        assert!(first.is_satisfied(&witness));
        assert_r1cs_satisfied(&first, &witness);

        let mut tampered = witness.clone();
        tampered[4] = FieldElement::from(17u128);
        assert!(!first.is_satisfied(&tampered));
    }

    #[test]
    fn call_with_false_predicate_forces_zero_outputs() {
        let callee = Circuit {
            current_witness_index: 1,
            opcodes: vec![Opcode::AssertZero(Expression::from(Witness(1)))],
            return_values: PublicInputs(BTreeSet::from([Witness(1)])),
            ..Circuit::default()
        };
        let caller = Circuit {
            current_witness_index: 2,
            opcodes: vec![Opcode::Call {
                id: AcirFunctionId(1),
                inputs: vec![Witness(1)],
                outputs: vec![Witness(2)],
                predicate: Expression::zero(),
            }],
            private_parameters: BTreeSet::from([Witness(1)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![caller, callee],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("predicate-zero call should lower");
        let witness_ok = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::from(123u128),
            FieldElement::zero(),
        ];
        assert!(system.is_satisfied(&witness_ok));

        let witness_bad = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::from(123u128),
            FieldElement::one(),
        ];
        assert!(!system.is_satisfied(&witness_bad));
    }

    #[test]
    fn call_with_dynamic_predicate_is_supported() {
        let callee = Circuit {
            current_witness_index: 2,
            opcodes: vec![Opcode::AssertZero(Expression {
                mul_terms: Vec::new(),
                linear_combinations: vec![
                    (FieldElement::one(), Witness(2)),
                    (-FieldElement::one(), Witness(0)),
                    (-FieldElement::one(), Witness(1)),
                ],
                q_c: FieldElement::zero(),
            })],
            return_values: PublicInputs(BTreeSet::from([Witness(2)])),
            ..Circuit::default()
        };
        let caller = Circuit {
            current_witness_index: 4,
            opcodes: vec![Opcode::Call {
                id: AcirFunctionId(1),
                inputs: vec![Witness(1), Witness(2)],
                outputs: vec![Witness(4)],
                predicate: Expression::from(Witness(3)),
            }],
            private_parameters: BTreeSet::from([Witness(1), Witness(2), Witness(3)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![caller, callee],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("dynamic-predicate call should lower");

        let pred_true = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::from(7u128),
            FieldElement::from(9u128),
            FieldElement::one(),
            FieldElement::from(16u128),
        ];
        assert!(system.is_satisfied(&pred_true));
        assert_r1cs_satisfied(&system, &pred_true);

        let pred_false = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::from(7u128),
            FieldElement::from(9u128),
            FieldElement::zero(),
            FieldElement::zero(),
        ];
        assert!(system.is_satisfied(&pred_false));
        assert_r1cs_satisfied(&system, &pred_false);

        let pred_true_tampered = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::from(7u128),
            FieldElement::from(9u128),
            FieldElement::one(),
            FieldElement::from(15u128),
        ];
        assert!(!system.is_satisfied(&pred_true_tampered));

        let pred_false_tampered = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::from(7u128),
            FieldElement::from(9u128),
            FieldElement::zero(),
            FieldElement::from(1u128),
        ];
        assert!(!system.is_satisfied(&pred_false_tampered));
    }

    #[test]
    fn call_with_dynamic_predicate_requires_boolean_predicate() {
        let callee = Circuit {
            current_witness_index: 2,
            opcodes: vec![Opcode::AssertZero(Expression {
                mul_terms: Vec::new(),
                linear_combinations: vec![
                    (FieldElement::one(), Witness(2)),
                    (-FieldElement::one(), Witness(0)),
                    (-FieldElement::one(), Witness(1)),
                ],
                q_c: FieldElement::zero(),
            })],
            return_values: PublicInputs(BTreeSet::from([Witness(2)])),
            ..Circuit::default()
        };
        let caller = Circuit {
            current_witness_index: 4,
            opcodes: vec![Opcode::Call {
                id: AcirFunctionId(1),
                inputs: vec![Witness(1), Witness(2)],
                outputs: vec![Witness(4)],
                predicate: Expression::from(Witness(3)),
            }],
            private_parameters: BTreeSet::from([Witness(1), Witness(2), Witness(3)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![caller, callee],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("dynamic-predicate call should lower");
        let non_boolean_predicate = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::from(7u128),
            FieldElement::from(9u128),
            FieldElement::from(2u128),
            FieldElement::zero(),
        ];
        assert!(!system.is_satisfied(&non_boolean_predicate));
    }

    #[test]
    fn public_input_ordering_must_be_stable() {
        let mut public = BTreeSet::new();
        public.insert(Witness(2));
        public.insert(Witness(1));
        let circuit = Circuit {
            current_witness_index: 2,
            opcodes: vec![Opcode::AssertZero(Expression::zero())],
            public_parameters: PublicInputs(public),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let system = compile_r1cs(&program).expect("btree ordering should be stable");
        assert_eq!(system.n_public_inputs, 2);
    }

    #[test]
    fn assertzero_mux_pattern_satisfies_constraints() {
        // result = b + cond*(a-b) and cond is boolean
        let cond_bool = Opcode::AssertZero(Expression {
            mul_terms: vec![(FieldElement::one(), Witness(1), Witness(1))],
            linear_combinations: vec![(-FieldElement::one(), Witness(1))],
            q_c: FieldElement::zero(),
        });
        let mux_expr = Opcode::AssertZero(Expression {
            mul_terms: vec![
                (FieldElement::one(), Witness(1), Witness(2)),
                (-FieldElement::one(), Witness(1), Witness(3)),
            ],
            linear_combinations: vec![
                (FieldElement::one(), Witness(3)),
                (-FieldElement::one(), Witness(4)),
            ],
            q_c: FieldElement::zero(),
        });
        let circuit = Circuit {
            current_witness_index: 4,
            opcodes: vec![cond_bool, mux_expr],
            private_parameters: BTreeSet::from([Witness(1), Witness(2), Witness(3), Witness(4)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };
        let system = compile_r1cs(&program).expect("mux-style assertzero should compile");
        let witness = vec![
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::one(),
            FieldElement::from(9u128),
            FieldElement::from(4u128),
            FieldElement::from(9u128),
        ];
        assert!(system.is_satisfied(&witness));
        assert_r1cs_satisfied(&system, &witness);
    }
}
