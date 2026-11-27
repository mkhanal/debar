#![forbid(unsafe_code)]

mod backtracking_program;
mod builder;
mod byte_rarity;
mod certificate_rules;
mod container_signatures;
mod engine_alerts;
mod engine_features;
mod expression_automata;
mod expression_tree;
mod fuse_filter;
mod hash_partition;
mod icon_signatures;
mod image;
mod layout;
mod logical_expression;
mod logical_group;
mod model;
mod names;
mod object_kind;
mod object_kinds;
mod pattern_group;
mod pattern_program;
mod plug_in_subsignatures;
mod record_codec;
mod selection_filters;
mod signature_programs;
mod type_magic;
mod unwanted_categories;
mod url_rules;

pub use backtracking_program::{
    BacktrackingNotCompiled, BacktrackingProgram, BacktrackingProgramMalformed,
    DEEPEST_NESTED_ASSERTION, Instruction as BacktrackingInstruction, LARGEST_BACKTRACKING_PROGRAM,
    LookInstruction, MOST_CAPTURE_GROUPS, RepeatedByte, compile_backtracking,
};
pub use builder::{BuildError, HashBucket, HashEntryId, ImageBuilder};
pub use certificate_rules::{
    CERTIFICATE_KEY_IDENTIFIER_LENGTH, CertificateRule, CertificateRules, CertificateTrust,
};
pub use container_signatures::{
    ContainerSignatureRecord, ContainerSignatures, ContainerSignaturesMalformed,
    EntryNameExpression,
};
pub use engine_alerts::{EngineAlert, EngineAlerts, EngineAlertsMalformed};
pub use engine_features::{EngineFeature, EngineFeatures, EngineFeaturesMalformed};
pub use expression_automata::{
    AutomatonMalformed, InPlaceAutomaton, LARGEST_AUTOMATON_IN_IMAGE, LazyExpression,
    automaton_in_place, compile_text, compile_text_lazily,
};
pub use expression_tree::{
    Assertion, ExpressionTree, Greed, LookDirection, NeedsBacktracking, TreeRepetition,
    byte_set_hir,
};
pub use hash_partition::{HashPartition, PartitionKey, PartitionMalformed};
pub use icon_signatures::{ICON_METRIC_POINTS, IconGroups, IconMetrics, IconPoint, IconSignature};
pub use image::{Image, ImageError, SectionExtent};
pub use layout::SectionKind;
pub use logical_expression::{DEEPEST_EXPRESSION, ExpressionNotCompiled, MOST_SUBSIGNATURES};
pub use logical_group::{
    ConditionsRecord, LogicalGroup, LogicalGroupMalformed, LogicalSignatureId,
    LogicalSignatureRecord, MatchingPass, SubsignatureRecord,
};
pub use model::{
    ByteComparison, ByteEncoding, ByteOrder, ByteSet, Category, ContainerSignature,
    ContentSubsignature, ContextTest, CountComparison, CountTest, DatabaseRecord, Digest,
    DigestAlgorithm, ExecutableAnchor, Expression, ExpressionAnchoring, ExpressionForm,
    ExpressionMatches, HashPurpose, HashSignature, HashedSize, InclusiveRange, Indicator,
    KindCondition, LogicalConditions, LogicalOutcome, LogicalSignature, MaskedByte, PartMemory,
    Pattern, PatternElement, PatternOutcome, PatternSignature, Placement, Provenance,
    RegularExpressionSubsignature, ReportWindows, SignatureGroup, SignatureName,
    SignatureProgramId, SizeCondition, Subsignature, TypeFinding, UnwantedCategory,
    ValueComparison,
};
pub use names::NameId;
pub use object_kind::ObjectKind;
pub use object_kinds::{
    EmbeddedObject, FoundAtAnOffset, Hosts, KindDescription, KindView, KindsMalformed,
    KindsNotBuilt, ObjectKinds, OffsetAction, OwnBytes, RecognitionRank, TextNormalisation,
    TypingRules, WideTextRetry,
};
pub use pattern_group::{
    AnchorTables, AnchoredProgram, GroupMalformed, LongAnchorFilter, LongAnchorTable, PatternGroup,
    PatternSignatureId, PatternSignatureRecord, ProgramId, RecordedOutcome, ShortAnchorFilter,
};
pub use pattern_program::{
    AnchorBytes, AnchorCase, ArmedAnchor, ContextView, Displacement, LONG_ANCHOR_LENGTH, MaskedRun,
    PatternNotCompiled, ProgramAnchor, ProgramHeader, ProgramMalformed, ProgramView, Runs,
    SHORT_ANCHOR_LENGTH, StepView, ascii_lowercase, set_in_sequence_contains,
};
pub use plug_in_subsignatures::{
    ComparisonRecord, ExpressionRecord, ExpressionTrigger, PlugInSubsignatures, PlugInsMalformed,
    PlugInsNotBuilt, RecordedForm,
};
pub use record_codec::RecordMalformed;
pub use selection_filters::{FiltersMalformed, SelectionFilter};
pub use signature_programs::{
    ProgramConstant, ProgramFunction, ProgramGlobal, ProgramInstruction, ProgramKind,
    ProgramOperand, ProgramOperation, ProgramType, ProgramValue, SignatureProgram,
    SignaturePrograms,
};
pub use type_magic::{MagicMalformed, MagicTable, TypeMagic};
pub use unwanted_categories::CategoriesMalformed;
pub use url_rules::{
    RecordedUrlPattern, UrlList, UrlPattern, UrlRule, UrlRuleRecord, UrlRules, UrlRulesNotBuilt,
    UrlVerdict,
};
