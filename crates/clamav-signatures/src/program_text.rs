use std::fmt;

use debar_image::{
    ProgramConstant, ProgramFunction, ProgramGlobal, ProgramInstruction, ProgramKind,
    ProgramOperand, ProgramOperation, ProgramType, ProgramValue,
};

use crate::FUNCTIONALITY_LEVEL;
use crate::line_text::{lines, without_line_ending};
use crate::program_interface::{
    FIRST_DEFINED_TYPE, INTERFACE_FUNCTIONS, INTERFACE_TYPES, InterfaceTypeKind,
};

const FILE_MAGIC: &[u8] = b"ClamBC";
const FORMAT_LEVELS: [u64; 2] = [6, 7];
const FIRST_MAGIC: u64 = 0x53e5_493e_9f3d_1c30;
const SECOND_MAGIC: u64 = 42;
const FIRST_LINE_BUFFER: usize = 8_192;
const MOST_NIBBLES: u64 = 16;
const NIBBLE_HIGH: u8 = 0x60;
const CONSTANT_MARK: u8 = 0x20;
const ZERO_INITIALISER: [u8; 2] = [0x40, 0x60];
const LIST_END: u8 = 0x60;
const DATA_MARK: u8 = b'|';
const TERMINATOR_MARK: u8 = b'T';
const BUILT_IN_POINTERS: u16 = 65;
const RESERVED_TYPE_SLOTS: u64 = 5;
const HIGHEST_INTERFACE_FUNCTION: u64 = 107;
const HIGHEST_GLOBAL: u64 = 0x8005;
const ENGINE_GLOBALS: u64 = 0x8000;
const MOST_INTERFACE_CALL_ARGUMENTS: usize = 5;
const OPCODE_COUNT: u64 = 51;
const DEEPEST_TYPE_NESTING: usize = 64;
const KIND_STARTUP: u64 = 1;
const KIND_LOGICAL: u64 = 256;
const HOOK_KINDS: [(u64, ProgramKind); 6] = [
    (257, ProgramKind::ExecutableUnpacker),
    (258, ProgramKind::Pdf),
    (259, ProgramKind::EveryExecutable),
    (260, ProgramKind::BeforeClassification),
    (261, ProgramKind::ElfUnpacker),
    (262, ProgramKind::MachOUnpacker),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MalformedProgram {
    Empty,
    MissingFileMagic,
    InvalidHeader,
    MagicMismatch,
    LineLength,
    LineTooLong { line: usize },
    MissingLine(&'static str),
    WrongLine { line: usize, expected: &'static str },
    TypeStart,
    TypeKind(u64),
    FunctionWithoutReturnType,
    TypeIdOutOfRange { line: usize },
    TypeNestingTooDeep,
    ApiCallsBeyondHighest,
    ApiIdOutOfRange(u64),
    ApiNameMismatch(u64),
    ApiPrototypeMismatch(u64),
    GlobalCountUnreadable,
    GlobalOfFunctionType,
    TooManyComponents,
    TooFewComponents,
    TrailingBytes { line: usize },
    MoreFunctionsThanDeclared,
    FewerFunctionsThanDeclared,
    MalformedNumber { line: usize },
    InvalidOpcode(u64),
    OperandOutOfRange { line: usize },
    BlockOutOfRange { line: usize },
    FunctionOutOfRange { line: usize },
    UndeclaredApi { line: usize },
    MoreInstructionsThanDeclared { line: usize },
    InstructionCountDisagrees,
    MissingTerminator { line: usize },
    MissingTrigger,
    UnhandledKind(u64),
    SecondStartupProgram,
    NotPrepared(&'static str),
}

impl fmt::Display for MalformedProgram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramSkip {
    FormatLevel,
    FunctionalityLevel,
    InterfaceBeyondEngine,
    GlobalsBeyondEngine,
}

pub struct ParsedProgram<'a> {
    pub kind: ProgramKind,
    pub trigger: Option<&'a [u8]>,
    pub apis: Vec<u16>,
    pub types: Vec<ProgramType>,
    pub globals: Vec<ProgramGlobal>,
    pub functions: Vec<ProgramFunction>,
}

pub enum ReadProgram<'a> {
    Skipped(ProgramSkip),
    Program(ParsedProgram<'a>),
}

struct Cursor<'l> {
    text: &'l [u8],
    at: usize,
    line: usize,
}

impl<'l> Cursor<'l> {
    fn new(text: &'l [u8], line: usize) -> Self {
        Self { text, at: 0, line }
    }

    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn peek_at(&self, distance: usize) -> Option<u8> {
        self.text.get(self.at.saturating_add(distance)).copied()
    }

    fn advance(&mut self, count: usize) {
        self.at = self.at.saturating_add(count);
    }

    fn at_end(&self) -> bool {
        self.at >= self.text.len()
    }

    fn expect(&mut self, letter: u8, expected: &'static str) -> Result<(), MalformedProgram> {
        if self.peek() == Some(letter) {
            self.advance(1);
            Ok(())
        } else {
            Err(MalformedProgram::WrongLine {
                line: self.line,
                expected,
            })
        }
    }

    fn malformed(&self) -> MalformedProgram {
        MalformedProgram::MalformedNumber { line: self.line }
    }

    fn nibbles(&mut self, count: u64) -> Result<u64, MalformedProgram> {
        let mut value = 0u64;
        for shift in 0..count {
            let byte = self.peek().ok_or_else(|| self.malformed())?;
            if byte & 0xF0 != NIBBLE_HIGH {
                return Err(self.malformed());
            }
            value |= u64::from(byte & 0x0F)
                .wrapping_shl(u32::try_from(shift.saturating_mul(4)).unwrap_or(0));
            self.advance(1);
        }
        Ok(value)
    }

    fn number_from(&mut self, first: u8) -> Result<u64, MalformedProgram> {
        let count = u64::from(first.wrapping_sub(NIBBLE_HIGH));
        if count > MOST_NIBBLES {
            return Err(self.malformed());
        }
        self.advance(1);
        self.nibbles(count)
    }

    fn number(&mut self) -> Result<u64, MalformedProgram> {
        let first = self.peek().ok_or_else(|| self.malformed())?;
        self.number_from(first)
    }

    fn fixed(&mut self, width: u64) -> Result<u64, MalformedProgram> {
        self.nibbles(width)
    }

    fn data(&mut self) -> Result<Vec<u8>, MalformedProgram> {
        if self.peek() != Some(DATA_MARK) {
            return Err(self.malformed());
        }
        self.advance(1);
        let length = self.number()?;
        let mut bytes = Vec::new();
        for _ in 0..length {
            let low = self.fixed(1)?;
            let high = self.fixed(1)?;
            bytes.push(u8::try_from(low | high.wrapping_shl(4)).map_err(|_| self.malformed())?);
        }
        Ok(bytes)
    }

    fn string(&mut self) -> Result<Vec<u8>, MalformedProgram> {
        let mut bytes = self.data()?;
        if bytes.is_empty() {
            return Ok(bytes);
        }
        if bytes.pop() != Some(0) {
            return Err(self.malformed());
        }
        Ok(bytes)
    }
}

struct Header {
    kind: u64,
    type_count: u64,
    function_count: u64,
    longest_line: usize,
}

enum ReadHeader {
    Skipped(ProgramSkip),
    Header(Header),
}

fn read_header(line: &[u8]) -> Result<ReadHeader, MalformedProgram> {
    let mut cursor = Cursor::new(line, 1);
    if !line.starts_with(FILE_MAGIC) {
        return Err(MalformedProgram::MissingFileMagic);
    }
    cursor.advance(FILE_MAGIC.len());
    let format = cursor
        .number()
        .map_err(|_| MalformedProgram::InvalidHeader)?;
    if !FORMAT_LEVELS.contains(&(format & u64::from(u32::MAX))) {
        return Ok(ReadHeader::Skipped(ProgramSkip::FormatLevel));
    }
    let header = (|| -> Result<(u64, u64, u64), MalformedProgram> {
        cursor.number()?;
        cursor.string()?;
        cursor.number()?;
        let kind = cursor.number()? & u64::from(u32::MAX);
        let lowest = cursor.number()? & u64::from(u32::MAX);
        let highest = cursor.number()? & u64::from(u32::MAX);
        Ok((kind, lowest, highest))
    })();
    let (kind, lowest, highest) = header.map_err(|_| MalformedProgram::InvalidHeader)?;
    let level = u64::try_from(FUNCTIONALITY_LEVEL).unwrap_or(u64::MAX);
    if (lowest != 0 && lowest > level) || (highest != 0 && highest < level) {
        return Ok(ReadHeader::Skipped(ProgramSkip::FunctionalityLevel));
    }
    let counts = (|| -> Result<(u64, u64), MalformedProgram> {
        cursor.number()?;
        cursor.string()?;
        let types = cursor.number()? & u64::from(u32::MAX);
        let functions = cursor.number()? & u64::from(u32::MAX);
        Ok((types, functions))
    })();
    let (type_count, function_count) = counts.map_err(|_| MalformedProgram::InvalidHeader)?;
    if cursor
        .number()
        .map_err(|_| MalformedProgram::MagicMismatch)?
        != FIRST_MAGIC
        || cursor
            .fixed(2)
            .map_err(|_| MalformedProgram::MagicMismatch)?
            != SECOND_MAGIC
    {
        return Err(MalformedProgram::MagicMismatch);
    }
    if cursor.peek() != Some(b':') {
        return Err(MalformedProgram::LineLength);
    }
    let rest = line.get(cursor.at.saturating_add(1)..).unwrap_or_default();
    let digits = rest
        .iter()
        .position(|byte| *byte != b' ')
        .and_then(|start| rest.get(start..))
        .unwrap_or_default();
    let digits = digits.strip_prefix(b"+").unwrap_or(digits);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(MalformedProgram::LineLength);
    }
    let longest_line = std::str::from_utf8(digits)
        .ok()
        .and_then(|digits| digits.parse::<usize>().ok())
        .ok_or(MalformedProgram::LineLength)?;
    if type_count < RESERVED_TYPE_SLOTS {
        return Err(MalformedProgram::TypeIdOutOfRange { line: 1 });
    }
    Ok(ReadHeader::Header(Header {
        kind,
        type_count,
        function_count,
        longest_line,
    }))
}

struct Program {
    type_count: u64,
    types: Vec<ProgramType>,
    used_apis: Vec<bool>,
}

impl Program {
    fn type_id(&self, cursor: &mut Cursor<'_>) -> Result<u16, MalformedProgram> {
        let id = cursor.number()?;
        let beyond_array = self.type_count.saturating_add(u64::from(BUILT_IN_POINTERS));
        if id >= beyond_array {
            return Err(MalformedProgram::TypeIdOutOfRange { line: cursor.line });
        }
        u16::try_from(id).map_err(|_| MalformedProgram::TypeIdOutOfRange { line: cursor.line })
    }

    fn defined(&self, id: u16) -> Option<ProgramType> {
        if id < BUILT_IN_POINTERS {
            return None;
        }
        if id < FIRST_DEFINED_TYPE {
            let pointee = 8u16.wrapping_shl(u32::from(id.saturating_sub(BUILT_IN_POINTERS)));
            return Some(ProgramType::Pointer(pointee));
        }
        self.types
            .get(usize::from(id.saturating_sub(FIRST_DEFINED_TYPE)))
            .cloned()
    }

    fn components(&self, id: u16, depth: usize) -> Result<u64, MalformedProgram> {
        if depth > DEEPEST_TYPE_NESTING {
            return Err(MalformedProgram::TypeNestingTooDeep);
        }
        if id < BUILT_IN_POINTERS {
            return Ok(1);
        }
        let depth = depth.saturating_add(1);
        match self
            .defined(id)
            .ok_or(MalformedProgram::TypeIdOutOfRange { line: 5 })?
        {
            ProgramType::Pointer(_) => Ok(2),
            ProgramType::Function { .. } => Err(MalformedProgram::GlobalOfFunctionType),
            ProgramType::PackedStruct(members) | ProgramType::Struct(members) => {
                members.iter().try_fold(0u64, |total, member| {
                    Ok(total.saturating_add(self.components(*member, depth)?))
                })
            }
            ProgramType::Array { length, element } => Ok(self
                .components(element, depth)?
                .saturating_mul(u64::from(length))),
        }
    }

    fn size(&self, id: u16, depth: usize) -> Result<u64, MalformedProgram> {
        if depth > DEEPEST_TYPE_NESTING {
            return Err(MalformedProgram::TypeNestingTooDeep);
        }
        let depth = depth.saturating_add(1);
        match id {
            0 => Ok(0),
            1..=8 => Ok(1),
            9..=16 => Ok(2),
            17..=32 => Ok(4),
            33..=64 => Ok(8),
            _ => match self
                .defined(id)
                .ok_or(MalformedProgram::TypeIdOutOfRange { line: 0 })?
            {
                ProgramType::Pointer(_) | ProgramType::Function { .. } => Ok(8),
                ProgramType::PackedStruct(members) | ProgramType::Struct(members) => {
                    members.iter().try_fold(0u64, |total, member| {
                        Ok(total.saturating_add(self.size(*member, depth)?))
                    })
                }
                ProgramType::Array { length, element } => {
                    Ok(self.size(element, depth)?.saturating_mul(u64::from(length)))
                }
            },
        }
    }

    fn matches_interface(
        &self,
        program_id: u16,
        interface_index: usize,
        memo: &mut [Option<u16>],
        depth: usize,
    ) -> Result<bool, MalformedProgram> {
        if depth > DEEPEST_TYPE_NESTING {
            return Err(MalformedProgram::TypeNestingTooDeep);
        }
        if memo.get(interface_index).copied().flatten() == Some(program_id) {
            return Ok(true);
        }
        if let Some(slot) = memo.get_mut(interface_index) {
            *slot = Some(program_id);
        }
        let interface = INTERFACE_TYPES
            .get(interface_index)
            .ok_or(MalformedProgram::ApiPrototypeMismatch(0))?;
        let Some(program_type) = self.defined(program_id) else {
            return Err(MalformedProgram::TypeIdOutOfRange { line: 4 });
        };
        let (elements, contained): (u64, Vec<u16>) = match (&program_type, interface.kind) {
            (ProgramType::Function { returns, arguments }, InterfaceTypeKind::Function) => {
                let mut contained = vec![*returns];
                contained.extend(arguments);
                (
                    u64::try_from(contained.len()).unwrap_or(u64::MAX),
                    contained,
                )
            }
            (ProgramType::Struct(members), InterfaceTypeKind::Struct) => (
                u64::try_from(members.len()).unwrap_or(u64::MAX),
                members.clone(),
            ),
            (ProgramType::Array { length, element }, InterfaceTypeKind::Array) => {
                (u64::from(*length), vec![*element])
            }
            (ProgramType::Pointer(pointee), InterfaceTypeKind::Pointer) => (1, vec![*pointee]),
            _ => return Ok(false),
        };
        if elements != u64::from(interface.elements) {
            return Ok(false);
        }
        for (program_contained, interface_contained) in contained.iter().zip(interface.contained) {
            if *interface_contained < FIRST_DEFINED_TYPE {
                if program_contained != interface_contained {
                    return Ok(false);
                }
            } else if !self.matches_interface(
                *program_contained,
                usize::from(interface_contained.saturating_sub(FIRST_DEFINED_TYPE)),
                memo,
                depth.saturating_add(1),
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

struct ProgramLines<'c> {
    lines: Vec<&'c [u8]>,
    at: usize,
    longest_content: usize,
}

impl<'c> ProgramLines<'c> {
    fn next_if_any(&mut self) -> Option<Result<(usize, &'c [u8]), MalformedProgram>> {
        let line = *self.lines.get(self.at)?;
        self.at = self.at.saturating_add(1);
        Some(if line.len() > self.longest_content {
            Err(MalformedProgram::LineTooLong { line: self.at })
        } else {
            Ok((self.at, line))
        })
    }

    fn next(&mut self, expected: &'static str) -> Result<(usize, &'c [u8]), MalformedProgram> {
        self.next_if_any()
            .unwrap_or(Err(MalformedProgram::MissingLine(expected)))
    }
}

pub fn read_program(
    contents: &[u8],
    inside_container: bool,
) -> Result<ReadProgram<'_>, MalformedProgram> {
    let all_lines: Vec<&[u8]> = lines(contents).map(without_line_ending).collect();
    let first = all_lines.first().copied().ok_or(MalformedProgram::Empty)?;
    if first.len() >= FIRST_LINE_BUFFER {
        return Err(MalformedProgram::LineTooLong { line: 1 });
    }
    let header = match read_header(first)? {
        ReadHeader::Skipped(skip) => return Ok(ReadProgram::Skipped(skip)),
        ReadHeader::Header(header) => header,
    };
    let mut lines = ProgramLines {
        lines: all_lines,
        at: 1,
        longest_content: if inside_container {
            header.longest_line.saturating_sub(1)
        } else {
            header.longest_line.saturating_sub(2)
        },
    };
    let (_, trigger_line) = lines.next("trigger")?;
    let trigger = trigger_line.contains(&b';').then_some(trigger_line);
    let kind = program_kind(header.kind, trigger.is_some())?;
    let mut program = Program {
        type_count: header.type_count,
        types: Vec::new(),
        used_apis: vec![false; usize::try_from(HIGHEST_INTERFACE_FUNCTION).unwrap_or(0)],
    };
    let (number, types_line) = lines.next("types")?;
    read_types(&mut program, &mut Cursor::new(types_line, number))?;
    let (number, apis_line) = lines.next("interface functions")?;
    let Some(apis) = read_apis(&mut program, &mut Cursor::new(apis_line, number))? else {
        return Ok(ReadProgram::Skipped(ProgramSkip::InterfaceBeyondEngine));
    };
    let (number, globals_line) = lines.next("globals")?;
    let Some(globals) = read_globals(&program, &mut Cursor::new(globals_line, number))? else {
        return Ok(ReadProgram::Skipped(ProgramSkip::GlobalsBeyondEngine));
    };
    let functions = read_functions(&program, &mut lines, header.function_count)?;
    prepare(&program, &globals, &functions)?;
    Ok(ReadProgram::Program(ParsedProgram {
        kind,
        trigger,
        apis,
        types: program.types,
        globals,
        functions,
    }))
}

fn read_functions(
    program: &Program,
    lines: &mut ProgramLines<'_>,
    declared_functions: u64,
) -> Result<Vec<ProgramFunction>, MalformedProgram> {
    let mut functions = Vec::new();
    while let Some(next) = lines.next_if_any() {
        let (number, line) = next?;
        match line.first() {
            Some(b'D') if functions.is_empty() => {
                read_metadata(&mut Cursor::new(line, number))?;
                continue;
            }
            Some(b'S') => break,
            _ => {}
        }
        if u64::try_from(functions.len()).unwrap_or(u64::MAX) >= declared_functions {
            return Err(MalformedProgram::MoreFunctionsThanDeclared);
        }
        functions.push(read_function(
            program,
            lines,
            Cursor::new(line, number),
            declared_functions,
        )?);
    }
    if u64::try_from(functions.len()).unwrap_or(u64::MAX) != declared_functions {
        return Err(MalformedProgram::FewerFunctionsThanDeclared);
    }
    Ok(functions)
}

fn read_function(
    program: &Program,
    lines: &mut ProgramLines<'_>,
    mut cursor: Cursor<'_>,
    declared_functions: u64,
) -> Result<ProgramFunction, MalformedProgram> {
    let FunctionHeader {
        mut function,
        declared_instructions,
        block_count,
    } = read_function_header(program, &mut cursor)?;
    let mut instruction_total = 0usize;
    if block_count == 0 {
        lines.next("block")?;
        return Err(MalformedProgram::BlockOutOfRange { line: cursor.line });
    }
    for block_index in 0..block_count {
        let (number, line) = lines.next("block")?;
        let block = read_block(
            program,
            &mut function,
            &mut Cursor::new(line, number),
            BlockLimits {
                block_count,
                declared_instructions,
                function_count: declared_functions,
                last: block_index.saturating_add(1) == block_count,
            },
            &mut instruction_total,
        )?;
        function.blocks.push(block);
    }
    if instruction_total != declared_instructions {
        return Err(MalformedProgram::InstructionCountDisagrees);
    }
    Ok(function)
}

fn program_kind(kind: u64, has_trigger: bool) -> Result<ProgramKind, MalformedProgram> {
    if kind == KIND_LOGICAL {
        return if has_trigger {
            Ok(ProgramKind::Logical)
        } else {
            Err(MalformedProgram::MissingTrigger)
        };
    }
    if kind == KIND_STARTUP {
        return Ok(ProgramKind::Startup);
    }
    HOOK_KINDS
        .iter()
        .find(|(code, _)| *code == kind)
        .map(|(_, kind)| *kind)
        .ok_or(MalformedProgram::UnhandledKind(kind))
}

fn read_types(program: &mut Program, cursor: &mut Cursor<'_>) -> Result<(), MalformedProgram> {
    cursor.expect(b'T', "types")?;
    if cursor.fixed(2)? != u64::from(FIRST_DEFINED_TYPE) {
        return Err(MalformedProgram::TypeStart);
    }
    let defined = program
        .type_count
        .saturating_sub(RESERVED_TYPE_SLOTS)
        .min(u64::try_from(cursor.text.len()).unwrap_or(u64::MAX));
    for _ in 0..defined {
        let kind = cursor.fixed(1)?;
        let read_ids =
            |cursor: &mut Cursor<'_>, program: &Program| -> Result<Vec<u16>, MalformedProgram> {
                let count = cursor.number()?;
                let mut ids = Vec::new();
                for _ in 0..count.min(u64::try_from(cursor.text.len()).unwrap_or(0)) {
                    ids.push(program.type_id(cursor)?);
                }
                if u64::try_from(ids.len()).unwrap_or(0) != count {
                    return Err(MalformedProgram::MalformedNumber { line: cursor.line });
                }
                Ok(ids)
            };
        let program_type = match kind {
            1 => {
                let mut ids = read_ids(cursor, program)?;
                if ids.is_empty() {
                    return Err(MalformedProgram::FunctionWithoutReturnType);
                }
                let returns = ids.remove(0);
                ProgramType::Function {
                    returns,
                    arguments: ids,
                }
            }
            2 => ProgramType::PackedStruct(read_ids(cursor, program)?),
            3 => ProgramType::Struct(read_ids(cursor, program)?),
            4 => {
                let length = u32::try_from(cursor.number()? & u64::from(u32::MAX))
                    .map_err(|_| cursor.malformed())?;
                ProgramType::Array {
                    length,
                    element: program.type_id(cursor)?,
                }
            }
            5 => ProgramType::Pointer(program.type_id(cursor)?),
            other => return Err(MalformedProgram::TypeKind(other)),
        };
        program.types.push(program_type);
    }
    if u64::try_from(program.types.len()).unwrap_or(0)
        != program.type_count.saturating_sub(RESERVED_TYPE_SLOTS)
    {
        return Err(cursor.malformed());
    }
    let beyond_defined = u64::from(FIRST_DEFINED_TYPE)
        .saturating_add(u64::try_from(program.types.len()).unwrap_or(0));
    let reaches_beyond = |id: u16| u64::from(id) >= beyond_defined;
    for program_type in &program.types {
        let outside = match program_type {
            ProgramType::Function { returns, arguments } => {
                reaches_beyond(*returns) || arguments.iter().any(|id| reaches_beyond(*id))
            }
            ProgramType::PackedStruct(members) | ProgramType::Struct(members) => {
                members.iter().any(|id| reaches_beyond(*id))
            }
            ProgramType::Array { element, .. } => reaches_beyond(*element),
            ProgramType::Pointer(pointee) => reaches_beyond(*pointee),
        };
        if outside {
            return Err(MalformedProgram::TypeIdOutOfRange { line: cursor.line });
        }
    }
    Ok(())
}

fn read_apis(
    program: &mut Program,
    cursor: &mut Cursor<'_>,
) -> Result<Option<Vec<u16>>, MalformedProgram> {
    cursor.expect(b'E', "interface functions")?;
    let highest = cursor.number()? & u64::from(u32::MAX);
    if highest > HIGHEST_INTERFACE_FUNCTION {
        return Ok(None);
    }
    let calls = cursor.number()? & u64::from(u32::MAX);
    if calls > highest {
        return Err(MalformedProgram::ApiCallsBeyondHighest);
    }
    let mut memo = vec![None; INTERFACE_TYPES.len()];
    let mut apis = Vec::new();
    for _ in 0..calls {
        let id = cursor.number()? & u64::from(u32::MAX);
        if id > highest || id == 0 {
            return Err(MalformedProgram::ApiIdOutOfRange(id));
        }
        let type_id = program.type_id(cursor)?;
        let name = cursor.string()?;
        let index = usize::try_from(id.saturating_sub(1))
            .map_err(|_| MalformedProgram::ApiIdOutOfRange(id))?;
        let (known_name, interface_type) = INTERFACE_FUNCTIONS
            .get(index)
            .copied()
            .ok_or(MalformedProgram::ApiIdOutOfRange(id))?;
        if !name.is_empty() && name != known_name.as_bytes() {
            return Err(MalformedProgram::ApiNameMismatch(id));
        }
        if type_id < BUILT_IN_POINTERS
            || !program.matches_interface(type_id, usize::from(interface_type), &mut memo, 0)?
        {
            return Err(MalformedProgram::ApiPrototypeMismatch(id));
        }
        if let Some(used) = program.used_apis.get_mut(index) {
            *used = true;
        }
        apis.push(u16::try_from(id).map_err(|_| MalformedProgram::ApiIdOutOfRange(id))?);
    }
    apis.sort_unstable();
    apis.dedup();
    Ok(Some(apis))
}

fn read_globals(
    program: &Program,
    cursor: &mut Cursor<'_>,
) -> Result<Option<Vec<ProgramGlobal>>, MalformedProgram> {
    cursor.expect(b'G', "globals")?;
    let highest = cursor.number();
    let count = cursor.number();
    let (Ok(highest), Ok(count)) = (highest, count) else {
        return Err(MalformedProgram::GlobalCountUnreadable);
    };
    if highest & u64::from(u32::MAX) > HIGHEST_GLOBAL {
        return Ok(None);
    }
    let count = count & u64::from(u32::MAX);
    let mut globals = Vec::new();
    for _ in 0..count.min(u64::try_from(cursor.text.len()).unwrap_or(0)) {
        let type_id = program.type_id(cursor)?;
        let expected = program.components(type_id, 0)?;
        let mut initial = Vec::new();
        if cursor.peek() == ZERO_INITIALISER.first().copied()
            && cursor.peek_at(1) == ZERO_INITIALISER.get(1).copied()
        {
            cursor.advance(2);
        } else {
            loop {
                match cursor.peek() {
                    Some(LIST_END) => {
                        cursor.advance(1);
                        break;
                    }
                    Some(first) => {
                        if u64::try_from(initial.len()).unwrap_or(u64::MAX) >= expected {
                            return Err(MalformedProgram::TooManyComponents);
                        }
                        initial.push(cursor.number_from(first | CONSTANT_MARK)?);
                    }
                    None => return Err(cursor.malformed()),
                }
            }
            if u64::try_from(initial.len()).unwrap_or(0) < expected {
                return Err(MalformedProgram::TooFewComponents);
            }
        }
        globals.push(ProgramGlobal { type_id, initial });
    }
    if u64::try_from(globals.len()).unwrap_or(0) != count {
        return Err(cursor.malformed());
    }
    if !cursor.at_end() {
        return Err(MalformedProgram::TrailingBytes { line: cursor.line });
    }
    Ok(Some(globals))
}

fn read_metadata(cursor: &mut Cursor<'_>) -> Result<(), MalformedProgram> {
    cursor.expect(b'D', "metadata")?;
    let nodes = cursor.number()?;
    for _ in 0..nodes.min(u64::try_from(cursor.text.len()).unwrap_or(0)) {
        let elements = cursor.number()?;
        for _ in 0..elements.min(u64::try_from(cursor.text.len()).unwrap_or(0)) {
            if cursor.peek() == Some(DATA_MARK) {
                cursor.data()?;
            } else {
                cursor.number()?;
                cursor.number()?;
            }
        }
    }
    Ok(())
}

struct FunctionHeader {
    function: ProgramFunction,
    declared_instructions: usize,
    block_count: usize,
}

fn read_function_header(
    program: &Program,
    cursor: &mut Cursor<'_>,
) -> Result<FunctionHeader, MalformedProgram> {
    cursor.expect(b'A', "function header")?;
    let argument_count = u8::try_from(cursor.fixed(1)?).map_err(|_| cursor.malformed())?;
    let return_type = program.type_id(cursor)?;
    cursor.expect(b'L', "function locals")?;
    let locals = cursor.number()? & u64::from(u16::MAX);
    let mut values = Vec::new();
    for _ in 0..u64::from(argument_count).saturating_add(locals) {
        let type_id = u16::try_from(cursor.number()? & u64::from(u16::MAX))
            .map_err(|_| cursor.malformed())?;
        if u64::from(type_id)
            >= u64::from(FIRST_DEFINED_TYPE)
                .saturating_add(u64::try_from(program.types.len()).unwrap_or(0))
        {
            return Err(MalformedProgram::TypeIdOutOfRange { line: cursor.line });
        }
        let stack_allocated = cursor.fixed(1)? != 0;
        values.push(ProgramValue {
            type_id,
            stack_allocated,
        });
    }
    cursor.expect(b'F', "function counts")?;
    let instructions =
        usize::try_from(cursor.number()? & u64::from(u32::MAX)).map_err(|_| cursor.malformed())?;
    let blocks =
        usize::try_from(cursor.number()? & u64::from(u16::MAX)).map_err(|_| cursor.malformed())?;
    Ok(FunctionHeader {
        function: ProgramFunction {
            argument_count,
            return_type,
            values,
            constants: Vec::new(),
            blocks: Vec::new(),
        },
        declared_instructions: instructions,
        block_count: blocks,
    })
}

#[derive(Clone, Copy)]
struct BlockLimits {
    block_count: usize,
    declared_instructions: usize,
    function_count: u64,
    last: bool,
}

const OPERAND_COUNTS: [u8; 51] = [
    0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 3, 1, 1, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3,
    0, 0, 2, 3, 3, 0, 2, 1, 3, 3, 3, 3, 0, 0, 1, 1, 1, 2, 1,
];

fn read_operand(
    function: &mut ProgramFunction,
    cursor: &mut Cursor<'_>,
) -> Result<ProgramOperand, MalformedProgram> {
    let first = cursor.peek().ok_or_else(|| cursor.malformed())?;
    if (0x60..=0x70).contains(&first) {
        let id = cursor.number()?;
        if id >= u64::try_from(function.values.len()).unwrap_or(0) {
            return Err(MalformedProgram::OperandOutOfRange { line: cursor.line });
        }
        return Ok(ProgramOperand::Value(
            u32::try_from(id).map_err(|_| cursor.malformed())?,
        ));
    }
    if (0x40..=0x50).contains(&first) {
        let value = cursor.number_from(first | CONSTANT_MARK)?;
        let width = cursor.fixed(1)?;
        if width == 0 {
            return Ok(ProgramOperand::Global(
                u32::try_from(value & u64::from(u32::MAX >> 1)).map_err(|_| cursor.malformed())?,
            ));
        }
        let bits = width.saturating_mul(8);
        let stored_bits: u8 = match bits {
            0..=8 => 8,
            9..=16 => 16,
            17..=32 => 32,
            _ => 64,
        };
        let kept = if stored_bits == 64 {
            value
        } else {
            value & (1u64.wrapping_shl(u32::from(stored_bits)).wrapping_sub(1))
        };
        function.constants.push(ProgramConstant {
            value: kept,
            bits: stored_bits,
        });
        return Ok(ProgramOperand::Constant(
            u32::try_from(function.constants.len().saturating_sub(1))
                .map_err(|_| cursor.malformed())?,
        ));
    }
    Err(cursor.malformed())
}

fn read_tail(
    program: &Program,
    function: &mut ProgramFunction,
    cursor: &mut Cursor<'_>,
    limits: BlockLimits,
    opcode: u64,
    instruction: &mut ProgramInstruction,
) -> Result<(), MalformedProgram> {
    let operation = instruction.operation;
    let block_id = |cursor: &mut Cursor<'_>| -> Result<u16, MalformedProgram> {
        let id = cursor.number()?;
        if id == 0 || id >= u64::try_from(limits.block_count).unwrap_or(0) {
            return Err(MalformedProgram::BlockOutOfRange { line: cursor.line });
        }
        u16::try_from(id).map_err(|_| MalformedProgram::BlockOutOfRange { line: cursor.line })
    };
    match operation {
        ProgramOperation::Branch => {
            instruction.operands.push(read_operand(function, cursor)?);
            instruction.blocks.push(block_id(cursor)?);
            instruction.blocks.push(block_id(cursor)?);
        }
        ProgramOperation::Jump => instruction.blocks.push(block_id(cursor)?),
        ProgramOperation::Return
        | ProgramOperation::CompareEqual
        | ProgramOperation::CompareNotEqual
        | ProgramOperation::CompareUnsignedGreater
        | ProgramOperation::CompareUnsignedGreaterOrEqual
        | ProgramOperation::CompareUnsignedLess
        | ProgramOperation::CompareUnsignedLessOrEqual
        | ProgramOperation::CompareSignedGreater
        | ProgramOperation::CompareSignedGreaterOrEqual
        | ProgramOperation::CompareSignedLessOrEqual
        | ProgramOperation::CompareSignedLess => {
            let overriding = cursor.number()? & u64::from(u16::MAX);
            instruction.result_type = u16::try_from(overriding).map_err(|_| cursor.malformed())?;
            let count = if operation == ProgramOperation::Return {
                1
            } else {
                2
            };
            for _ in 0..count {
                instruction.operands.push(read_operand(function, cursor)?);
            }
        }
        ProgramOperation::CallFunction | ProgramOperation::CallApi => {
            let count = cursor.fixed(1)?;
            let target = cursor.number()?.wrapping_sub(1) & u64::from(u16::MAX);
            if operation == ProgramOperation::CallFunction {
                if target >= limits.function_count {
                    return Err(MalformedProgram::FunctionOutOfRange { line: cursor.line });
                }
            } else if !usize::try_from(target)
                .ok()
                .and_then(|index| program.used_apis.get(index))
                .copied()
                .unwrap_or(false)
            {
                return Err(MalformedProgram::UndeclaredApi { line: cursor.line });
            }
            instruction.callee = Some(u32::try_from(target).map_err(|_| cursor.malformed())?);
            for _ in 0..count {
                instruction.operands.push(read_operand(function, cursor)?);
            }
        }
        ProgramOperation::ElementPointer | ProgramOperation::ElementPointerFromStart => {
            instruction.type_operand = Some(
                u32::try_from(cursor.number()? & u64::from(u32::MAX))
                    .map_err(|_| cursor.malformed())?,
            );
            instruction.operands.push(read_operand(function, cursor)?);
            instruction.operands.push(read_operand(function, cursor)?);
        }
        ProgramOperation::ElementPointerNested => {
            let count = cursor.fixed(1)?;
            instruction.type_operand = Some(
                u32::try_from(cursor.number()? & u64::from(u32::MAX))
                    .map_err(|_| cursor.malformed())?,
            );
            for _ in 0..=count {
                instruction.operands.push(read_operand(function, cursor)?);
            }
        }
        _ => {
            let count = OPERAND_COUNTS
                .get(usize::try_from(opcode).unwrap_or(0))
                .copied()
                .unwrap_or(0);
            for _ in 0..count {
                instruction.operands.push(read_operand(function, cursor)?);
            }
        }
    }
    Ok(())
}

fn read_block(
    program: &Program,
    function: &mut ProgramFunction,
    cursor: &mut Cursor<'_>,
    limits: BlockLimits,
    instruction_total: &mut usize,
) -> Result<Vec<ProgramInstruction>, MalformedProgram> {
    cursor.expect(b'B', "block")?;
    let mut instructions = Vec::new();
    loop {
        let terminator = cursor.peek() == Some(TERMINATOR_MARK);
        let (result_type, destination) = if terminator {
            cursor.advance(1);
            (0, 0)
        } else {
            let result_type = cursor.number()? & u64::from(u16::MAX);
            let destination = cursor.number()? & u64::from(u32::MAX);
            (
                u16::try_from(result_type).map_err(|_| cursor.malformed())?,
                u32::try_from(destination).map_err(|_| cursor.malformed())?,
            )
        };
        let opcode = cursor.fixed(2)?;
        if opcode >= OPCODE_COUNT {
            return Err(MalformedProgram::InvalidOpcode(opcode));
        }
        let operation = usize::try_from(opcode)
            .ok()
            .and_then(|code| code.checked_sub(1))
            .and_then(|index| ProgramOperation::ALL.get(index))
            .copied()
            .ok_or(MalformedProgram::NotPrepared("unhandled opcode"))?;
        let mut instruction = ProgramInstruction {
            operation,
            result_type,
            destination,
            operands: Vec::new(),
            blocks: Vec::new(),
            callee: None,
            type_operand: None,
        };
        read_tail(program, function, cursor, limits, opcode, &mut instruction)?;
        if matches!(
            operation,
            ProgramOperation::Truncate
                | ProgramOperation::SignExtend
                | ProgramOperation::ZeroExtend
        ) && !matches!(instruction.operands.first(), Some(ProgramOperand::Value(_)))
        {
            return Err(MalformedProgram::NotPrepared(
                "a cast of a constant or global",
            ));
        }
        *instruction_total = instruction_total.saturating_add(1);
        if *instruction_total > limits.declared_instructions {
            return Err(MalformedProgram::MoreInstructionsThanDeclared { line: cursor.line });
        }
        instructions.push(instruction);
        if terminator {
            break;
        }
        if cursor.at_end() {
            return Err(MalformedProgram::MissingTerminator { line: cursor.line });
        }
    }
    if limits.last {
        if cursor.peek() != Some(b'E') {
            return Err(MalformedProgram::MissingTerminator { line: cursor.line });
        }
        cursor.advance(1);
    }
    if cursor.peek() == Some(b'D') {
        cursor.advance(3);
        if cursor.at_end() {
            return Err(MalformedProgram::TrailingBytes { line: cursor.line });
        }
        let count = cursor.number()?;
        if count != u64::try_from(limits.declared_instructions).unwrap_or(u64::MAX) {
            return Err(MalformedProgram::TrailingBytes { line: cursor.line });
        }
        for _ in 0..count.min(u64::try_from(cursor.text.len()).unwrap_or(0)) {
            cursor.number()?;
        }
    }
    if !cursor.at_end() {
        return Err(MalformedProgram::TrailingBytes { line: cursor.line });
    }
    Ok(instructions)
}

fn prepare(
    program: &Program,
    globals: &[ProgramGlobal],
    functions: &[ProgramFunction],
) -> Result<(), MalformedProgram> {
    let global_count = u32::try_from(globals.len()).unwrap_or(u32::MAX);
    let beyond_types = program
        .type_count
        .saturating_add(u64::from(BUILT_IN_POINTERS));
    for global in globals {
        if program.size(global.type_id, 0)? == 0 && global.type_id != 0 {
            return Err(MalformedProgram::NotPrepared("a global of zero size"));
        }
        if let Some(ProgramType::Pointer(_)) = program.defined(global.type_id)
            && let Some(target) = global.initial.get(1)
            && *target < ENGINE_GLOBALS
            && *target == u64::from(global_count)
        {
            return Err(MalformedProgram::NotPrepared(
                "a pointer to the global past the last",
            ));
        }
    }
    for function in functions {
        for value in &function.values {
            if value.type_id != 0 && program.size(value.type_id, 0)? == 0 {
                return Err(MalformedProgram::NotPrepared("a value of zero size"));
            }
        }
        let slots = function
            .values
            .len()
            .saturating_add(function.constants.len());
        for instruction in function.blocks.iter().flatten() {
            if usize::try_from(instruction.destination).unwrap_or(usize::MAX) >= slots.max(1) {
                return Err(MalformedProgram::NotPrepared("a destination out of range"));
            }
            for operand in &instruction.operands {
                if let ProgramOperand::Global(global) = operand
                    && *global >= global_count
                {
                    return Err(MalformedProgram::NotPrepared("global out of range"));
                }
            }
            prepare_instruction(program, function, functions, instruction, beyond_types)?;
        }
    }
    Ok(())
}

fn prepare_instruction(
    program: &Program,
    function: &ProgramFunction,
    functions: &[ProgramFunction],
    instruction: &ProgramInstruction,
    beyond_types: u64,
) -> Result<(), MalformedProgram> {
    match instruction.operation {
        ProgramOperation::CallFunction => {
            let target = instruction
                .callee
                .and_then(|callee| usize::try_from(callee).ok())
                .and_then(|callee| functions.get(callee))
                .ok_or(MalformedProgram::NotPrepared(
                    "call to a function out of range",
                ))?;
            if instruction.operands.len() != usize::from(target.argument_count) {
                return Err(MalformedProgram::NotPrepared(
                    "call operands don't match function prototype",
                ));
            }
        }
        ProgramOperation::CallApi => {
            if instruction.operands.len() > MOST_INTERFACE_CALL_ARGUMENTS {
                return Err(MalformedProgram::NotPrepared(
                    "call operands don't match function prototype",
                ));
            }
        }
        ProgramOperation::ElementPointer => {
            match instruction.operands.first() {
                Some(ProgramOperand::Value(base))
                    if !function
                        .values
                        .get(usize::try_from(*base).unwrap_or(usize::MAX))
                        .is_some_and(|value| value.stack_allocated) => {}
                _ => {
                    return Err(MalformedProgram::NotPrepared(
                        "gep1 of alloca is not allowed",
                    ));
                }
            }
            let type_id = u64::from(instruction.type_operand.unwrap_or(0));
            if type_id >= beyond_types || type_id <= 64 {
                return Err(MalformedProgram::NotPrepared("invalid type for gep"));
            }
            let pointer = u16::try_from(type_id)
                .ok()
                .and_then(|id| program.defined(id))
                .is_some_and(|defined| matches!(defined, ProgramType::Pointer(_)));
            if !pointer {
                return Err(MalformedProgram::NotPrepared(
                    "invalid gep type, must be pointer",
                ));
            }
        }
        ProgramOperation::ElementPointerFromStart => {
            if !matches!(instruction.operands.first(), Some(ProgramOperand::Value(_))) {
                return Err(MalformedProgram::NotPrepared("gepz of a constant"));
            }
            let type_id = u64::from(instruction.type_operand.unwrap_or(0));
            if type_id >= beyond_types || type_id <= 65 {
                return Err(MalformedProgram::NotPrepared("invalid type for gep"));
            }
            let pointee = u16::try_from(type_id)
                .ok()
                .and_then(|id| program.defined(id))
                .and_then(|defined| match defined {
                    ProgramType::Pointer(pointee) => Some(pointee),
                    _ => None,
                })
                .filter(|pointee| *pointee >= BUILT_IN_POINTERS)
                .ok_or(MalformedProgram::NotPrepared("must be pointer to nonint"))?;
            if let Some(ProgramType::Struct(members) | ProgramType::PackedStruct(members)) =
                program.defined(pointee)
            {
                let Some(ProgramOperand::Constant(index)) = instruction.operands.get(1) else {
                    return Err(MalformedProgram::NotPrepared("gep index is not a constant"));
                };
                let offset = function
                    .constants
                    .get(usize::try_from(*index).unwrap_or(usize::MAX))
                    .map(|constant| constant.value)
                    .ok_or(MalformedProgram::NotPrepared("gep offset out of range"))?;
                if offset >= u64::try_from(members.len()).unwrap_or(0) {
                    return Err(MalformedProgram::NotPrepared("gep offset out of range"));
                }
            }
        }
        ProgramOperation::ElementPointerNested => {
            return Err(MalformedProgram::NotPrepared("unhandled opcode"));
        }
        _ => {}
    }
    Ok(())
}
