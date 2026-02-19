use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::Path,
};

use acir::{
    circuit::{
        opcodes::{BlackBoxFuncCall, FunctionInput},
        AssertionPayload, Circuit, Opcode, OpcodeLocation, Program,
    },
    native_types::{Expression, Witness},
    FieldElement,
};
use r1cs_file::{
    Constraint, Constraints, FieldElement as R1csFieldElement, Header, R1csFile, WireMap,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    pub details: String,
}

#[derive(Debug, Error)]
pub enum R1csError {
    #[error("program has no functions")]
    EmptyProgram,
    #[error("unsupported opcode `{opcode}` at index {index}: {details}")]
    UnsupportedOpcode {
        opcode: String,
        index: usize,
        details: String,
    },
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

pub fn lower_program(program: &Program) -> Result<R1csSystem, R1csError> {
    compile_r1cs(program)
}

pub fn compile_r1cs(program: &Program) -> Result<R1csSystem, R1csError> {
    compile_r1cs_with_options(program, LoweringOptions::strict())
}

pub fn compile_r1cs_with_options(
    program: &Program,
    options: LoweringOptions,
) -> Result<R1csSystem, R1csError> {
    let circuit = program.functions.first().ok_or(R1csError::EmptyProgram)?;
    compile_r1cs_circuit_with_options(circuit, options)
}

pub fn compile_r1cs_circuit(circuit: &Circuit) -> Result<R1csSystem, R1csError> {
    compile_r1cs_circuit_with_options(circuit, LoweringOptions::strict())
}

pub fn compile_r1cs_circuit_with_options(
    circuit: &Circuit,
    options: LoweringOptions,
) -> Result<R1csSystem, R1csError> {
    LoweringContext::new(circuit, options).lower()
}

pub fn collect_unsupported_opcodes(
    program: &Program,
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
    circuit: &'a Circuit,
    options: LoweringOptions,
    field_modulus_le_bytes: [u8; 32],
    wire_map: BTreeMap<u32, u32>,
    next_wire: u32,
    allocated_intermediate_wires: BTreeSet<u32>,
    constrained_wires: BTreeSet<u32>,
    a_rows: Vec<SparseRow>,
    b_rows: Vec<SparseRow>,
    c_rows: Vec<SparseRow>,
    memory_blocks: BTreeMap<u32, Vec<Expression>>,
    unsupported: Vec<UnsupportedOpcodeInfo>,
}

impl<'a> LoweringContext<'a> {
    fn new(circuit: &'a Circuit, options: LoweringOptions) -> Self {
        let mut wire_map = BTreeMap::new();
        for witness in 0..=circuit.current_witness_index {
            wire_map.insert(witness, witness);
        }

        Self {
            circuit,
            options,
            field_modulus_le_bytes: bn254_modulus_le_bytes(),
            wire_map,
            next_wire: circuit.current_witness_index + 1,
            allocated_intermediate_wires: BTreeSet::new(),
            constrained_wires: BTreeSet::new(),
            a_rows: Vec::new(),
            b_rows: Vec::new(),
            c_rows: Vec::new(),
            memory_blocks: BTreeMap::new(),
            unsupported: Vec::new(),
        }
    }

    fn lower(mut self) -> Result<R1csSystem, R1csError> {
        self.validate_program_invariants()?;

        for (index, opcode) in self.circuit.opcodes.iter().enumerate() {
            self.lower_opcode(index, opcode)?;
        }

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

    fn lower_opcode(&mut self, index: usize, opcode: &Opcode) -> Result<(), R1csError> {
        match opcode {
            Opcode::AssertZero(expr) => self.lower_assert_zero(expr, index, "AssertZero"),
            Opcode::MemoryInit { block_id, init } => self.lower_memory_init(*block_id, init, index),
            Opcode::MemoryOp {
                block_id,
                op,
                predicate,
            } => self.lower_memory_op(*block_id, op, predicate.as_ref(), index),
            Opcode::BlackBoxFuncCall(call) => self.lower_blackbox(call, index),
            Opcode::Directive(_) => self.unsupported_opcode(
                "Directive",
                index,
                "directive lowering is not implemented".to_string(),
            ),
            Opcode::BrilligCall { .. } => self.unsupported_opcode(
                "BrilligCall",
                index,
                "Brillig calls are unconstrained by R1CS lowering".to_string(),
            ),
            Opcode::Call { .. } => self.unsupported_opcode(
                "Call",
                index,
                "nested ACIR call lowering is not implemented".to_string(),
            ),
        }
    }

    fn lower_assert_zero(
        &mut self,
        expr: &Expression,
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

    fn lower_memory_init(
        &mut self,
        block_id: acir::circuit::opcodes::BlockId,
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
            entries.push(Expression::from(*witness));
        }
        self.memory_blocks.insert(block_id.0, entries);
        Ok(())
    }

    fn lower_memory_op(
        &mut self,
        block_id: acir::circuit::opcodes::BlockId,
        op: &acir::circuit::opcodes::MemOp,
        predicate: Option<&Expression>,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        if let Some(predicate) = predicate {
            let pred = canonicalize_expression(predicate);
            if pred.to_const().map(|value| value.is_one()) != Some(true) {
                return self.unsupported_opcode(
                    "MemoryOp",
                    opcode_index,
                    "dynamic or disabled memory predicates are unsupported in strict lowering"
                        .to_string(),
                );
            }
        }

        let operation = canonicalize_expression(&op.operation);
        let op_kind = operation
            .to_const()
            .and_then(field_to_usize)
            .ok_or_else(|| R1csError::UnsupportedOpcode {
                opcode: "MemoryOp".to_string(),
                index: opcode_index,
                details: "dynamic memory operation kind is unsupported".to_string(),
            })?;

        if op_kind > 1 {
            return self.unsupported_opcode(
                "MemoryOp",
                opcode_index,
                format!("invalid memory operation selector {op_kind}, expected 0 or 1"),
            );
        }

        let index_expr = canonicalize_expression(&op.index);
        let mem_index = index_expr
            .to_const()
            .and_then(field_to_usize)
            .ok_or_else(|| R1csError::UnsupportedOpcode {
                opcode: "MemoryOp".to_string(),
                index: opcode_index,
                details: "dynamic memory index expression is unsupported".to_string(),
            })?;

        let value_expr = canonicalize_expression(&op.value);
        self.ensure_expression_witnesses_in_range(&value_expr, "MemoryOp value")?;

        let entries_len = self
            .memory_blocks
            .get(&block_id.0)
            .ok_or_else(|| R1csError::InvalidProgramInvariant {
                details: format!(
                    "memory block {} used before initialization at opcode index {}",
                    block_id.0, opcode_index
                ),
            })?
            .len();

        if mem_index >= entries_len {
            return Err(R1csError::InvalidProgramInvariant {
                details: format!(
                    "memory block {} index {} out of bounds (len {}) at opcode index {}",
                    block_id.0, mem_index, entries_len, opcode_index
                ),
            });
        }

        match op_kind {
            0 => {
                let expected =
                    self.memory_blocks.get(&block_id.0).expect("checked above")[mem_index].clone();
                let read_eq = &value_expr - &expected;
                self.lower_assert_zero(&read_eq, opcode_index, "MemoryOp read equality")
            }
            1 => {
                let entries = self
                    .memory_blocks
                    .get_mut(&block_id.0)
                    .expect("checked above");
                entries[mem_index] = value_expr;
                Ok(())
            }
            _ => unreachable!("validated above"),
        }
    }

    fn lower_blackbox(
        &mut self,
        call: &BlackBoxFuncCall,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        match call {
            BlackBoxFuncCall::AND { lhs, rhs, output } => {
                self.lower_boolean_and(lhs, rhs, *output, opcode_index)
            }
            BlackBoxFuncCall::XOR { lhs, rhs, output } => {
                self.lower_boolean_xor(lhs, rhs, *output, opcode_index)
            }
            BlackBoxFuncCall::RANGE { input } => self.lower_boolean_range(input, opcode_index),
            other => self.unsupported_opcode(
                "BlackBoxFuncCall",
                opcode_index,
                format!(
                    "blackbox function `{}` is unsupported in R1CS lowering",
                    other.name()
                ),
            ),
        }
    }

    fn lower_boolean_and(
        &mut self,
        lhs: &FunctionInput,
        rhs: &FunctionInput,
        output: Witness,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        if lhs.num_bits != 1 || rhs.num_bits != 1 {
            return self.unsupported_opcode(
                "BlackBoxFuncCall::AND",
                opcode_index,
                format!(
                    "AND lowering currently supports only num_bits=1, got lhs={} rhs={}",
                    lhs.num_bits, rhs.num_bits
                ),
            );
        }

        self.ensure_witness_in_range(lhs.witness, "BlackBox AND lhs")?;
        self.ensure_witness_in_range(rhs.witness, "BlackBox AND rhs")?;
        self.ensure_witness_in_range(output, "BlackBox AND output")?;

        self.enforce_boolean_witness(lhs.witness)?;
        self.enforce_boolean_witness(rhs.witness)?;
        self.enforce_boolean_witness(output)?;

        self.emit_constraint(
            vec![SparseTerm {
                wire: self.wire_for_witness(lhs.witness)?,
                coeff: FieldElement::one(),
            }],
            vec![SparseTerm {
                wire: self.wire_for_witness(rhs.witness)?,
                coeff: FieldElement::one(),
            }],
            vec![SparseTerm {
                wire: self.wire_for_witness(output)?,
                coeff: FieldElement::one(),
            }],
        )
    }

    fn lower_boolean_xor(
        &mut self,
        lhs: &FunctionInput,
        rhs: &FunctionInput,
        output: Witness,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        if lhs.num_bits != 1 || rhs.num_bits != 1 {
            return self.unsupported_opcode(
                "BlackBoxFuncCall::XOR",
                opcode_index,
                format!(
                    "XOR lowering currently supports only num_bits=1, got lhs={} rhs={}",
                    lhs.num_bits, rhs.num_bits
                ),
            );
        }

        self.ensure_witness_in_range(lhs.witness, "BlackBox XOR lhs")?;
        self.ensure_witness_in_range(rhs.witness, "BlackBox XOR rhs")?;
        self.ensure_witness_in_range(output, "BlackBox XOR output")?;

        self.enforce_boolean_witness(lhs.witness)?;
        self.enforce_boolean_witness(rhs.witness)?;
        self.enforce_boolean_witness(output)?;

        let xor_expr = Expression {
            mul_terms: vec![(FieldElement::from(2u128), lhs.witness, rhs.witness)],
            linear_combinations: vec![
                (FieldElement::one(), output),
                (-FieldElement::one(), lhs.witness),
                (-FieldElement::one(), rhs.witness),
            ],
            q_c: FieldElement::zero(),
        };
        self.lower_assert_zero(&xor_expr, opcode_index, "BlackBox XOR")
    }

    fn lower_boolean_range(
        &mut self,
        input: &FunctionInput,
        opcode_index: usize,
    ) -> Result<(), R1csError> {
        if input.num_bits != 1 {
            return self.unsupported_opcode(
                "BlackBoxFuncCall::RANGE",
                opcode_index,
                format!(
                    "RANGE lowering currently supports only num_bits=1, got {}",
                    input.num_bits
                ),
            );
        }

        self.ensure_witness_in_range(input.witness, "BlackBox RANGE input")?;
        self.enforce_boolean_witness(input.witness)
    }

    fn enforce_boolean_witness(&mut self, witness: Witness) -> Result<(), R1csError> {
        let wire = self.wire_for_witness(witness)?;
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

    fn unsupported_opcode(
        &mut self,
        opcode: &str,
        index: usize,
        details: String,
    ) -> Result<(), R1csError> {
        let info = UnsupportedOpcodeInfo {
            opcode: opcode.to_string(),
            index,
            details: format!("{details}; {}", self.opcode_context(index)),
        };
        match self.options.mode {
            LoweringMode::Strict => Err(R1csError::UnsupportedOpcode {
                opcode: info.opcode,
                index: info.index,
                details: info.details,
            }),
            LoweringMode::AllowUnsupported => {
                self.unsupported.push(info);
                Ok(())
            }
        }
    }

    fn opcode_context(&self, index: usize) -> String {
        let mut parts = Vec::new();
        parts.push(format!(
            "opcode_variant={}",
            opcode_variant(&self.circuit.opcodes[index])
        ));
        if let Some(assert_msg) = self.assert_message_for_index(index) {
            parts.push(format!("assert_message={assert_msg}"));
        }
        parts.join(", ")
    }

    fn assert_message_for_index(&self, index: usize) -> Option<String> {
        for (location, payload) in &self.circuit.assert_messages {
            if matches!(location, OpcodeLocation::Acir(i) if *i == index) {
                return Some(match payload {
                    AssertionPayload::StaticString(msg) => msg.clone(),
                    AssertionPayload::Dynamic(selector, _) => {
                        format!("dynamic selector={selector}")
                    }
                });
            }
        }
        None
    }

    fn ensure_expression_witnesses_in_range(
        &self,
        expr: &Expression,
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

    fn ensure_witness_in_range(&self, witness: Witness, context: &str) -> Result<(), R1csError> {
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

        // ACIR witnesses do not include compiler-introduced intermediate wires.
        // This lowering introduces intermediates only in rows of form lhs * rhs = t.
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
                    full[target] = full[lhs_index] * full[rhs_index];
                }
            }
        }

        Some(full)
    }
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

fn canonicalize_expression(expr: &Expression) -> Expression {
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

fn field_to_usize(value: FieldElement) -> Option<usize> {
    (value.num_bits() <= usize::BITS).then(|| value.to_u128() as usize)
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
    use std::{collections::BTreeSet, fs, io::Cursor};

    use acir::{
        circuit::{
            opcodes::{BlackBoxFuncCall, FunctionInput, MemOp},
            Circuit, Opcode, Program, PublicInputs,
        },
        native_types::{Expression, Witness},
        FieldElement,
    };
    use noir_acir::Artifact;
    use noir_witness::generate_witness_from_json_str;
    use proptest::prelude::*;
    use r1cs_file::R1csFile;
    use tempfile::TempDir;

    use super::*;

    fn assert_r1cs_satisfied(system: &R1csSystem, witness: &[FieldElement]) {
        let mut full = vec![FieldElement::zero(); system.n_wires as usize];
        let copy_len = std::cmp::min(witness.len(), full.len());
        full[..copy_len].copy_from_slice(&witness[..copy_len]);
        for i in 0..system.n_constraints as usize {
            if system.a[i].len() == 1
                && system.b[i].len() == 1
                && system.c[i].len() == 1
                && system.a[i][0].coeff.is_one()
                && system.b[i][0].coeff.is_one()
                && system.c[i][0].coeff.is_one()
            {
                let lhs = full[system.a[i][0].wire as usize];
                let rhs = full[system.b[i][0].wire as usize];
                let dst = system.c[i][0].wire as usize;
                if dst >= copy_len {
                    full[dst] = lhs * rhs;
                }
            }

            let left = dot(&system.a[i], &full).expect("A row must reference existing wires");
            let right = dot(&system.b[i], &full).expect("B row must reference existing wires");
            let out = dot(&system.c[i], &full).expect("C row must reference existing wires");
            assert_eq!(
                left * right - out,
                FieldElement::zero(),
                "unsatisfied constraint index {i}"
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
    fn unsupported_opcode_has_index_and_details() {
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
        match err {
            R1csError::UnsupportedOpcode {
                opcode,
                index,
                details,
            } => {
                assert_eq!(opcode, "BrilligCall");
                assert_eq!(index, 0);
                assert!(details.contains("opcode_variant=BrilligCall"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn allow_unsupported_collects_coverage_without_emitting_r1cs() {
        let circuit = Circuit {
            current_witness_index: 1,
            opcodes: vec![
                Opcode::Directive(acir::circuit::directives::Directive::ToLeRadix {
                    a: Expression::from(Witness(1)),
                    b: vec![Witness(1)],
                    radix: 2,
                }),
                Opcode::BrilligCall {
                    id: 0,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    predicate: None,
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
                assert_eq!(opcodes[0].opcode, "Directive");
                assert_eq!(opcodes[1].opcode, "BrilligCall");
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
    }

    #[test]
    fn static_memory_read_write_is_supported() {
        let circuit = Circuit {
            current_witness_index: 4,
            opcodes: vec![
                Opcode::MemoryInit {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    init: vec![Witness(1), Witness(2)],
                },
                Opcode::MemoryOp {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    op: MemOp::read_at_mem_index(
                        Expression::from_field(FieldElement::zero()),
                        Witness(3),
                    ),
                    predicate: None,
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
                    predicate: None,
                },
                Opcode::MemoryOp {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    op: MemOp::read_at_mem_index(
                        Expression::from_field(FieldElement::one()),
                        Witness(4),
                    ),
                    predicate: None,
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
        let witness = vec![
            FieldElement::one(),
            FieldElement::from(3u128),
            FieldElement::from(5u128),
            FieldElement::from(3u128),
            FieldElement::from(8u128),
        ];
        assert!(system.is_satisfied(&witness));
        assert_r1cs_satisfied(&system, &witness);
    }

    #[test]
    fn dynamic_memory_index_is_rejected() {
        let circuit = Circuit {
            current_witness_index: 2,
            opcodes: vec![
                Opcode::MemoryInit {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    init: vec![Witness(1)],
                },
                Opcode::MemoryOp {
                    block_id: acir::circuit::opcodes::BlockId(0),
                    op: MemOp::read_at_mem_index(Expression::from(Witness(2)), Witness(1)),
                    predicate: None,
                },
            ],
            private_parameters: BTreeSet::from([Witness(1), Witness(2)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let err = compile_r1cs(&program).expect_err("dynamic memory index should fail");
        match err {
            R1csError::UnsupportedOpcode {
                opcode,
                details,
                index,
            } => {
                assert_eq!(opcode, "MemoryOp");
                assert_eq!(index, 1);
                assert!(details.contains("dynamic memory index"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn boolean_blackboxes_are_supported() {
        let and = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::AND {
            lhs: FunctionInput {
                witness: Witness(1),
                num_bits: 1,
            },
            rhs: FunctionInput {
                witness: Witness(2),
                num_bits: 1,
            },
            output: Witness(3),
        });
        let xor = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::XOR {
            lhs: FunctionInput {
                witness: Witness(1),
                num_bits: 1,
            },
            rhs: FunctionInput {
                witness: Witness(2),
                num_bits: 1,
            },
            output: Witness(4),
        });
        let range = Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
            input: FunctionInput {
                witness: Witness(1),
                num_bits: 1,
            },
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
        let witness = vec![
            FieldElement::one(),
            FieldElement::one(),
            FieldElement::zero(),
            FieldElement::zero(),
            FieldElement::one(),
            FieldElement::one(),
        ];
        assert!(system.is_satisfied(&witness));
        assert_r1cs_satisfied(&system, &witness);
    }

    #[test]
    fn non_boolean_range_is_rejected() {
        let circuit = Circuit {
            current_witness_index: 1,
            opcodes: vec![Opcode::BlackBoxFuncCall(BlackBoxFuncCall::RANGE {
                input: FunctionInput {
                    witness: Witness(1),
                    num_bits: 8,
                },
            })],
            private_parameters: BTreeSet::from([Witness(1)]),
            ..Circuit::default()
        };
        let program = Program {
            functions: vec![circuit],
            unconstrained_functions: Vec::new(),
        };

        let err = compile_r1cs(&program).expect_err("8-bit range is unsupported");
        match err {
            R1csError::UnsupportedOpcode {
                opcode, details, ..
            } => {
                assert_eq!(opcode, "BlackBoxFuncCall::RANGE");
                assert!(details.contains("num_bits=1"));
            }
            other => panic!("unexpected error: {other}"),
        }
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
        assert!(system_a.is_satisfied(&witness_a.witness_vector));
        assert_r1cs_satisfied(&system_a, &witness_a.witness_vector);

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
        assert!(system_a.is_satisfied(&witness_a.witness_vector));
        assert_r1cs_satisfied(&system_a, &witness_a.witness_vector);

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
                    id: 0,
                    inputs: Vec::new(),
                    outputs: Vec::new(),
                    predicate: None,
                },
                Opcode::Call {
                    id: 1,
                    inputs: vec![Witness(1)],
                    outputs: vec![Witness(1)],
                    predicate: None,
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
            FieldElement::one(),
            FieldElement::from(9u128),
            FieldElement::from(4u128),
            FieldElement::from(9u128),
        ];
        assert!(system.is_satisfied(&witness));
        assert_r1cs_satisfied(&system, &witness);
    }
}
