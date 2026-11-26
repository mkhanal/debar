mod builder;
mod byte_rarity;
mod fuse_filter;
mod hash_partition;
mod image;
mod layout;
mod model;
mod names;
mod object_kind;
mod object_kinds;
mod pattern_group;
mod pattern_program;
mod type_magic;

pub use builder::{BuildError, HashBucket, HashEntryId, ImageBuilder};
pub use hash_partition::{HashPartition, PartitionKey, PartitionMalformed};
pub use image::{Image, ImageError, SectionExtent};
pub use layout::SectionKind;
pub use model::{
    ByteSet, Category, ContextTest, DatabaseRecord, Digest, DigestAlgorithm, ExecutableAnchor,
    HashPurpose, HashSignature, HashedSize, Indicator, MaskedByte, PartMemory, Pattern,
    PatternElement, PatternOutcome, PatternSignature, Placement, Provenance, ReportWindows,
    SignatureGroup, SignatureName, TypeFinding,
};
pub use names::NameId;
pub use object_kind::ObjectKind;
pub use object_kinds::{
    KindDescription, KindView, KindsMalformed, KindsNotBuilt, ObjectKinds, OwnBytes,
    RecognitionRank, TypingRules, WideTextRetry,
};
pub use pattern_group::{
    AnchoredProgram, GroupMalformed, LongAnchorFilter, PatternGroup, PatternSignatureId,
    PatternSignatureRecord, ProgramId, RecordedOutcome, ShortAnchorFilter,
};
pub use pattern_program::{
    ContextView, Displacement, LONG_ANCHOR_LENGTH, MaskedRun, PatternNotCompiled, ProgramHeader,
    ProgramMalformed, ProgramView, Runs, SHORT_ANCHOR_LENGTH, StepView, set_in_sequence_contains,
};
pub use type_magic::{MagicMalformed, MagicTable, TypeMagic};
