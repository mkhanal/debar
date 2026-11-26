mod builder;
mod byte_rarity;
mod fuse_filter;
mod hash_partition;
mod image;
mod layout;
mod model;
mod names;
mod pattern_group;
mod pattern_program;

pub use builder::{BuildError, ImageBuilder};
pub use hash_partition::{HashPartition, PartitionKey, PartitionMalformed};
pub use image::{Image, ImageError, SectionExtent};
pub use layout::SectionKind;
pub use model::{
    ByteSet, Category, ContextTest, DatabaseRecord, Digest, DigestAlgorithm, HashPurpose,
    HashSignature, HashedSize, Indicator, MaskedByte, Pattern, PatternElement, PatternSignature,
    Placement, Provenance, ReportWindows, SignatureName,
};
pub use names::NameId;
pub use pattern_group::{
    AnchoredProgram, GroupMalformed, LongAnchorFilter, PatternGroup, PatternSignatureId,
    PatternSignatureRecord, ProgramId, ShortAnchorFilter,
};
pub use pattern_program::{
    ContextView, Displacement, LONG_ANCHOR_LENGTH, MaskedRun, PatternNotCompiled, ProgramHeader,
    ProgramMalformed, ProgramView, Runs, SHORT_ANCHOR_LENGTH, StepView, set_in_sequence_contains,
};
