use crate::record_codec::{
    FieldReader, RecordFields, RecordMalformed, RecordTooLarge, RecordWriter, Records,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProgramKind {
    Logical,
    ExecutableUnpacker,
    Pdf,
    EveryExecutable,
    BeforeClassification,
    ElfUnpacker,
    MachOUnpacker,
    Startup,
}

impl ProgramKind {
    pub const ALL: [Self; 8] = [
        Self::Logical,
        Self::ExecutableUnpacker,
        Self::Pdf,
        Self::EveryExecutable,
        Self::BeforeClassification,
        Self::ElfUnpacker,
        Self::MachOUnpacker,
        Self::Startup,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProgramOperation {
    Add,
    Subtract,
    Multiply,
    UnsignedDivide,
    SignedDivide,
    UnsignedRemainder,
    SignedRemainder,
    ShiftLeft,
    LogicalShiftRight,
    ArithmeticShiftRight,
    And,
    Or,
    Xor,
    Truncate,
    SignExtend,
    ZeroExtend,
    Branch,
    Jump,
    Return,
    ReturnVoid,
    CompareEqual,
    CompareNotEqual,
    CompareUnsignedGreater,
    CompareUnsignedGreaterOrEqual,
    CompareUnsignedLess,
    CompareUnsignedLessOrEqual,
    CompareSignedGreater,
    CompareSignedGreaterOrEqual,
    CompareSignedLessOrEqual,
    CompareSignedLess,
    Select,
    CallFunction,
    CallApi,
    Copy,
    ElementPointer,
    ElementPointerFromStart,
    ElementPointerNested,
    Store,
    Load,
    MemorySet,
    MemoryCopy,
    MemoryMove,
    MemoryCompare,
    IsBigEndian,
    Abort,
    ByteSwap16,
    ByteSwap32,
    ByteSwap64,
    PointerDifference32,
    PointerToInteger64,
}

impl ProgramOperation {
    pub const ALL: [Self; 50] = [
        Self::Add,
        Self::Subtract,
        Self::Multiply,
        Self::UnsignedDivide,
        Self::SignedDivide,
        Self::UnsignedRemainder,
        Self::SignedRemainder,
        Self::ShiftLeft,
        Self::LogicalShiftRight,
        Self::ArithmeticShiftRight,
        Self::And,
        Self::Or,
        Self::Xor,
        Self::Truncate,
        Self::SignExtend,
        Self::ZeroExtend,
        Self::Branch,
        Self::Jump,
        Self::Return,
        Self::ReturnVoid,
        Self::CompareEqual,
        Self::CompareNotEqual,
        Self::CompareUnsignedGreater,
        Self::CompareUnsignedGreaterOrEqual,
        Self::CompareUnsignedLess,
        Self::CompareUnsignedLessOrEqual,
        Self::CompareSignedGreater,
        Self::CompareSignedGreaterOrEqual,
        Self::CompareSignedLessOrEqual,
        Self::CompareSignedLess,
        Self::Select,
        Self::CallFunction,
        Self::CallApi,
        Self::Copy,
        Self::ElementPointer,
        Self::ElementPointerFromStart,
        Self::ElementPointerNested,
        Self::Store,
        Self::Load,
        Self::MemorySet,
        Self::MemoryCopy,
        Self::MemoryMove,
        Self::MemoryCompare,
        Self::IsBigEndian,
        Self::Abort,
        Self::ByteSwap16,
        Self::ByteSwap32,
        Self::ByteSwap64,
        Self::PointerDifference32,
        Self::PointerToInteger64,
    ];
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramType {
    Function { returns: u16, arguments: Vec<u16> },
    PackedStruct(Vec<u16>),
    Struct(Vec<u16>),
    Array { length: u32, element: u16 },
    Pointer(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramGlobal {
    pub type_id: u16,
    pub initial: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramOperand {
    Value(u32),
    Constant(u32),
    Global(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramConstant {
    pub value: u64,
    pub bits: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramValue {
    pub type_id: u16,
    pub stack_allocated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramInstruction {
    pub operation: ProgramOperation,
    pub result_type: u16,
    pub destination: u32,
    pub operands: Vec<ProgramOperand>,
    pub blocks: Vec<u16>,
    pub callee: Option<u32>,
    pub type_operand: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramFunction {
    pub argument_count: u8,
    pub return_type: u16,
    pub values: Vec<ProgramValue>,
    pub constants: Vec<ProgramConstant>,
    pub blocks: Vec<Vec<ProgramInstruction>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureProgram {
    pub name: String,
    pub kind: ProgramKind,
    pub from_signed_container: bool,
    pub triggered: bool,
    pub apis: Vec<u16>,
    pub types: Vec<ProgramType>,
    pub globals: Vec<ProgramGlobal>,
    pub functions: Vec<ProgramFunction>,
}

fn kind_code(kind: ProgramKind) -> u8 {
    ProgramKind::ALL
        .iter()
        .position(|known| *known == kind)
        .and_then(|position| u8::try_from(position).ok())
        .unwrap_or(u8::MAX)
}

fn operation_code(operation: ProgramOperation) -> u8 {
    ProgramOperation::ALL
        .iter()
        .position(|known| *known == operation)
        .and_then(|position| u8::try_from(position).ok())
        .unwrap_or(u8::MAX)
}

fn put_ids(fields: &mut RecordFields, ids: &[u16]) -> Result<(), RecordTooLarge> {
    fields.count_of(ids.len())?;
    for id in ids {
        fields.u16(*id);
    }
    Ok(())
}

fn put_type(fields: &mut RecordFields, program_type: &ProgramType) -> Result<(), RecordTooLarge> {
    match program_type {
        ProgramType::Function { returns, arguments } => {
            fields.byte(1).u16(*returns);
            put_ids(fields, arguments)
        }
        ProgramType::PackedStruct(members) => {
            fields.byte(2);
            put_ids(fields, members)
        }
        ProgramType::Struct(members) => {
            fields.byte(3);
            put_ids(fields, members)
        }
        ProgramType::Array { length, element } => {
            fields.byte(4).u32(*length).u16(*element);
            Ok(())
        }
        ProgramType::Pointer(pointee) => {
            fields.byte(5).u16(*pointee);
            Ok(())
        }
    }
}

fn put_instruction(
    fields: &mut RecordFields,
    instruction: &ProgramInstruction,
) -> Result<(), RecordTooLarge> {
    fields
        .byte(operation_code(instruction.operation))
        .u16(instruction.result_type)
        .u32(instruction.destination)
        .count_of(instruction.operands.len())?;
    for operand in &instruction.operands {
        let (kind, index) = match operand {
            ProgramOperand::Value(index) => (1, *index),
            ProgramOperand::Constant(index) => (2, *index),
            ProgramOperand::Global(index) => (3, *index),
        };
        fields.byte(kind).u32(index);
    }
    put_ids(fields, &instruction.blocks)?;
    fields
        .flag(instruction.callee.is_some())
        .u32(instruction.callee.unwrap_or(0))
        .flag(instruction.type_operand.is_some())
        .u32(instruction.type_operand.unwrap_or(0));
    Ok(())
}

pub fn build(programs: &[SignatureProgram]) -> Result<Vec<u8>, RecordTooLarge> {
    let mut writer = RecordWriter::default();
    for program in programs {
        let mut fields = RecordFields::default();
        fields
            .bytes(program.name.as_bytes())?
            .byte(kind_code(program.kind))
            .flag(program.from_signed_container)
            .flag(program.triggered);
        put_ids(&mut fields, &program.apis)?;
        fields.count_of(program.types.len())?;
        for program_type in &program.types {
            put_type(&mut fields, program_type)?;
        }
        fields.count_of(program.globals.len())?;
        for global in &program.globals {
            fields.u16(global.type_id).count_of(global.initial.len())?;
            for component in &global.initial {
                fields.u64(*component);
            }
        }
        fields.count_of(program.functions.len())?;
        for function in &program.functions {
            fields
                .byte(function.argument_count)
                .u16(function.return_type)
                .count_of(function.values.len())?;
            for value in &function.values {
                fields.u16(value.type_id).flag(value.stack_allocated);
            }
            fields.count_of(function.constants.len())?;
            for constant in &function.constants {
                fields.u64(constant.value).byte(constant.bits);
            }
            fields.count_of(function.blocks.len())?;
            for block in &function.blocks {
                fields.count_of(block.len())?;
                for instruction in block {
                    put_instruction(&mut fields, instruction)?;
                }
            }
        }
        writer.record(&fields)?;
    }
    Ok(writer.finish())
}

#[derive(Clone, Copy)]
pub struct SignaturePrograms<'m> {
    records: Records<'m>,
}

impl<'m> SignaturePrograms<'m> {
    pub fn read(bytes: &'m [u8]) -> Result<Self, RecordMalformed> {
        Records::read(bytes).map(|records| Self { records })
    }

    #[must_use]
    pub fn count(&self) -> u32 {
        self.records.record_count()
    }

    pub fn programs(&self) -> impl Iterator<Item = Result<SignatureProgram, RecordMalformed>> + 'm {
        self.records
            .each()
            .map(|record| record.and_then(|mut fields| program_of(&mut fields)))
    }
}

fn ids(fields: &mut FieldReader<'_>) -> Result<Vec<u16>, RecordMalformed> {
    (0..fields.count(2)?).map(|_| fields.u16()).collect()
}

fn type_of(fields: &mut FieldReader<'_>) -> Result<ProgramType, RecordMalformed> {
    Ok(match fields.byte()? {
        1 => ProgramType::Function {
            returns: fields.u16()?,
            arguments: ids(fields)?,
        },
        2 => ProgramType::PackedStruct(ids(fields)?),
        3 => ProgramType::Struct(ids(fields)?),
        4 => ProgramType::Array {
            length: fields.u32()?,
            element: fields.u16()?,
        },
        5 => ProgramType::Pointer(fields.u16()?),
        _ => return Err(RecordMalformed),
    })
}

fn optional(fields: &mut FieldReader<'_>) -> Result<Option<u32>, RecordMalformed> {
    let present = fields.flag()?;
    let value = fields.u32()?;
    Ok(present.then_some(value))
}

fn instruction_of(fields: &mut FieldReader<'_>) -> Result<ProgramInstruction, RecordMalformed> {
    let operation = ProgramOperation::ALL
        .get(usize::from(fields.byte()?))
        .copied()
        .ok_or(RecordMalformed)?;
    let result_type = fields.u16()?;
    let destination = fields.u32()?;
    let operands = (0..fields.count(5)?)
        .map(|_| {
            let kind = fields.byte()?;
            let index = fields.u32()?;
            match kind {
                1 => Ok(ProgramOperand::Value(index)),
                2 => Ok(ProgramOperand::Constant(index)),
                3 => Ok(ProgramOperand::Global(index)),
                _ => Err(RecordMalformed),
            }
        })
        .collect::<Result<_, _>>()?;
    let blocks = ids(fields)?;
    Ok(ProgramInstruction {
        operation,
        result_type,
        destination,
        operands,
        blocks,
        callee: optional(fields)?,
        type_operand: optional(fields)?,
    })
}

fn program_of(fields: &mut FieldReader<'_>) -> Result<SignatureProgram, RecordMalformed> {
    let name = fields.text()?.to_owned();
    let kind = ProgramKind::ALL
        .get(usize::from(fields.byte()?))
        .copied()
        .ok_or(RecordMalformed)?;
    let from_signed_container = fields.flag()?;
    let triggered = fields.flag()?;
    let apis = ids(fields)?;
    let types = (0..fields.count(1)?)
        .map(|_| type_of(fields))
        .collect::<Result<_, _>>()?;
    let globals = (0..fields.count(6)?)
        .map(|_| {
            let type_id = fields.u16()?;
            let initial = (0..fields.count(8)?)
                .map(|_| fields.u64())
                .collect::<Result<_, _>>()?;
            Ok(ProgramGlobal { type_id, initial })
        })
        .collect::<Result<_, RecordMalformed>>()?;
    let mut functions = Vec::new();
    for _ in 0..fields.count(11)? {
        let argument_count = fields.byte()?;
        let return_type = fields.u16()?;
        let values = (0..fields.count(3)?)
            .map(|_| {
                Ok(ProgramValue {
                    type_id: fields.u16()?,
                    stack_allocated: fields.flag()?,
                })
            })
            .collect::<Result<_, RecordMalformed>>()?;
        let constants = (0..fields.count(9)?)
            .map(|_| {
                Ok(ProgramConstant {
                    value: fields.u64()?,
                    bits: fields.byte()?,
                })
            })
            .collect::<Result<_, RecordMalformed>>()?;
        let mut blocks = Vec::new();
        for _ in 0..fields.count(4)? {
            blocks.push(
                (0..fields.count(21)?)
                    .map(|_| instruction_of(fields))
                    .collect::<Result<_, _>>()?,
            );
        }
        functions.push(ProgramFunction {
            argument_count,
            return_type,
            values,
            constants,
            blocks,
        });
    }
    fields.finish()?;
    Ok(SignatureProgram {
        name,
        kind,
        from_signed_container,
        triggered,
        apis,
        types,
        globals,
        functions,
    })
}
