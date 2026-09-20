//! The coverage policy: every threshold generation and validation share.
//!
//! Evidence is produced by [`crate::analysis::coverage`] and judged again by
//! [`crate::stages::coverage::alternatives`] when it is read back. Both used to
//! carry their own copies of these numbers, in different integer types, and
//! nothing but care kept them equal. They live here once, and the serialized
//! [`CoveragePolicy`] (whose digest every transaction records) is built from
//! the same constants.

use serde::{Deserialize, Serialize};

/// The acceptance semantics this build applies. Bumped whenever what the policy
/// accepts changes, even when no JSON shape does.
pub const POLICY_VERSION: u32 = 24;
pub const MIN_COMPILED_TERMINAL_MEMBERS: usize = 3;
pub const MAX_COMPILED_TERMINAL_MEMBERS: usize = 8;
pub const MIN_REFERENCE_PLACED_DATA_PAIRS: usize = 2;
pub const MIN_VTABLE_HEAD_SHARED_CALLS: usize = 2;

pub const MIN_ANCHOR_BYTES: u32 = 128;
pub const MIN_LAYOUT_SHIFT_FUNCTIONS: u32 = 2;
pub const MIN_LAYOUT_SHIFT_CHANGED_ACCESSES: u32 = 4;
pub const MIN_LAYOUT_SHIFT_BYTES: u32 = 128;
pub const MAX_LAYOUT_SHIFT_SEGMENTS: u32 = 2;
pub const MIN_SEQUENCE_FUNCTIONS: u32 = 4;
pub const MIN_SEQUENCE_MATCH_RATIO: f32 = 0.75;
pub const MIN_SEQUENCE_ORDER_RATIO: f32 = 0.90;
pub const MIN_SEQUENCE_MATCHED_BYTES: u32 = 512;
pub const MIN_SEQUENCE_TARGET_COVERAGE: f32 = 0.40;
pub const MIN_SEQUENCE_STRONG_FUNCTIONS: u32 = 2;
pub const MIN_SEQUENCE_DIRECT_ANCHORS: u32 = 2;
/// The smallest margin between the best ordered alignment and its runner-up a
/// boundary decision may rest on. Below it the choice between them is
/// arbitrary.
pub const MIN_SEQUENCE_ALIGNMENT_MARGIN: f32 = 0.10;
pub const MIN_SEQUENCE_SIZE_RATIO: f32 = 0.5;
pub const MAX_SEQUENCE_SIZE_RATIO: f32 = 1.5;
/// A direct anchor inside a sequence may be smaller than [`MIN_ANCHOR_BYTES`],
/// because the sequence already bounds it, but not trivially small.
pub const MIN_SEQUENCE_ANCHOR_BYTES: u32 = 16;
pub const MIN_LAYOUT_BOUNDARY_FUNCTIONS: u32 = 4;
pub const MIN_LAYOUT_BOUNDARY_BYTES: u32 = 1024;
pub const MIN_LAYOUT_BOUNDARY_CHANGED_ACCESSES: u32 = 16;
pub const MAX_LAYOUT_BOUNDARY_SIZE_DELTA: f32 = 0.02;
pub const MAX_LAYOUT_BOUNDARY_FUNCTION_DELTA: u32 = 1;
pub const MIN_VTABLE_BOUNDARY_FUNCTIONS: u32 = 8;
pub const MIN_VTABLE_BOUNDARY_MATCH_RATIO: f32 = 0.85;
pub const MIN_VTABLE_BOUNDARY_TARGET_COVERAGE: f32 = 0.85;
pub const MIN_VTABLE_BOUNDARY_MATCHED_SLOTS: u32 = 8;
pub const MIN_VTABLE_BOUNDARY_UNIT_SLOTS: u32 = 4;
pub const MAX_VTABLE_BOUNDARY_SIZE_DELTA: f32 = 0.03;
pub const MAX_VTABLE_BOUNDARY_FUNCTION_DELTA: u32 = 1;
pub const MAX_VTABLE_BOUNDARY_GAP_HELPERS: u32 = 1;
pub const MAX_VTABLE_SIZE_PADDING: u32 = 16;
pub const MIN_OWNERSHIP_TRANSITION_FUNCTIONS: u32 = 8;
pub const MIN_OWNERSHIP_TRANSITION_STRONG_FUNCTIONS: u32 = 2;
pub const MIN_OWNERSHIP_TRANSITION_EDGE_STRONG_FUNCTIONS: u32 = 1;
pub const MAX_OWNERSHIP_TRANSITION_SIZE_DELTA: f32 = 0.02;
pub const MIN_ADJACENT_OWNER_TRANSITION_FUNCTIONS: u32 = 8;
pub const MIN_ADJACENT_OWNER_TRANSITION_STRONG_FUNCTIONS: u32 = 2;
pub const MIN_ADJACENT_OWNER_TRANSITION_DIRECT_ANCHORS: u32 = 2;
pub const MIN_ADJACENT_OWNER_SUPPORT_FUNCTIONS: u32 = 4;
pub const MIN_ADJACENT_OWNER_SUPPORT_STRONG_FUNCTIONS: u32 = 2;
pub const MAX_ADJACENT_OWNER_SIZE_DELTA: f32 = 0.10;
pub const MAX_ADJACENT_OWNER_GAP_HELPERS: u32 = 1;
/// At most this many functions of new ground may be explained only as a
/// caller-confined helper. More than one unexplained function is no longer a
/// helper the unit emitted but a cluster needing its own identification.
pub const MAX_NEW_CALLER_CONFINED_HELPERS: u32 = 1;
/// A composed claim must be tiled by target functions. Between them, and at
/// either end, only alignment padding may be left: a larger stretch holding no
/// function is ground nothing explains.
pub const MAX_COMPOSED_PADDING_GAP: u32 = 31;
/// A complete ordered sequence may resolve weak members and name-only edges,
/// but not on weak evidence alone: this many of its members must be
/// independently attributed.
pub const MIN_COMPLETE_SEQUENCE_INDEPENDENT_MEMBERS: u32 = 2;
/// Hard bounds on joint source-order search. Exhaustion is reported and never
/// taken as evidence that the best partition seen so far is unique.
pub const MAX_JOINT_UNITS: usize = 6;
pub const MAX_JOINT_FUNCTIONS: usize = 40;
pub const MAX_JOINT_WINDOWS: usize = 2048;
pub const MAX_JOINT_SEARCH_STATES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoveragePolicy {
    pub version: u32,
    /// Every alternative carries the unit's whole body, and must claim ground
    /// the unit does not already hold.
    pub complete_replacement_bodies: bool,
    /// A unit already holding a block may still be extended into unowned space.
    pub refine_represented_units: bool,
    /// Where a run of exact anchors and its members are equally supported, the
    /// whole run is offered before any single anchor of it.
    pub prefer_combined_exact_anchors: bool,
    /// A change may not take ground from any unit without an owner revision
    /// saying so.
    pub refuse_unevidenced_ownership_loss: bool,
    /// Every change is one ownership transaction over all the units it
    /// touches, with exact before-state preconditions, a named receiver for
    /// every transferred address, and a stable identity.
    pub atomic_ownership_transactions: bool,
    pub minimum_anchor_bytes: u32,
    pub normalized_body_must_be_unique: bool,
    pub confirm_normalized_bytes_after_hash: bool,
    pub require_relocation_layout: bool,
    pub require_known_extents: bool,
    pub require_explicit_whole_source_ownership: bool,
    pub reject_weak_symbols: bool,
    pub reject_template_anchors: bool,
    pub reject_conflicting_target_ownership: bool,
    pub require_split_alignment: bool,
    pub infer_this_relative_layout_shifts: bool,
    pub minimum_layout_shift_functions: u32,
    pub minimum_layout_shift_changed_accesses: u32,
    pub minimum_layout_shift_bytes: u32,
    pub maximum_layout_shift_segments: u32,
    pub infer_boundary_constrained_sequences: bool,
    pub minimum_sequence_functions: u32,
    pub minimum_sequence_match_ratio: f32,
    pub minimum_sequence_order_ratio: f32,
    pub minimum_sequence_matched_bytes: u32,
    pub minimum_sequence_target_coverage: f32,
    pub minimum_sequence_strong_functions: u32,
    pub minimum_sequence_direct_anchors: u32,
    pub allow_small_exact_sequence_anchors: bool,
    pub minimum_sequence_alignment_margin: f32,
    pub minimum_sequence_size_ratio: f32,
    pub maximum_sequence_size_ratio: f32,
    pub require_explicit_sequence_neighbors: bool,
    pub reject_sequence_runner_up: bool,
    pub infer_boundary_data_matches: bool,
    /// A function pair contributes no data-symbol evidence if any aligned
    /// relocation differs in kind or addend.
    #[serde(default)]
    pub require_complete_data_reference_alignment: bool,
    pub preserve_target_extract_extents: bool,
    pub infer_layout_corroborated_boundaries: bool,
    pub minimum_layout_boundary_functions: u32,
    pub minimum_layout_boundary_bytes: u32,
    pub minimum_layout_boundary_changed_accesses: u32,
    pub maximum_layout_boundary_size_delta: f32,
    pub maximum_layout_boundary_function_delta: u32,
    pub infer_vtable_corroborated_boundaries: bool,
    pub minimum_vtable_boundary_functions: u32,
    pub minimum_vtable_boundary_match_ratio: f32,
    pub minimum_vtable_boundary_target_coverage: f32,
    pub minimum_vtable_boundary_matched_slots: u32,
    pub minimum_vtable_boundary_unit_slots: u32,
    pub maximum_vtable_boundary_size_delta: f32,
    pub maximum_vtable_boundary_function_delta: u32,
    pub maximum_vtable_boundary_gap_helpers: u32,
    pub maximum_vtable_size_padding: u32,
    pub infer_ownership_transition_boundaries: bool,
    pub minimum_ownership_transition_functions: u32,
    pub minimum_ownership_transition_strong_functions: u32,
    pub minimum_ownership_transition_edge_strong_functions: u32,
    pub maximum_ownership_transition_size_delta: f32,
    pub require_complete_ownership_transition_sequence: bool,
    pub require_nonempty_ownership_transition_correction: bool,
    pub infer_adjacent_owner_transition_boundaries: bool,
    pub minimum_adjacent_owner_transition_functions: u32,
    pub minimum_adjacent_owner_transition_strong_functions: u32,
    pub minimum_adjacent_owner_transition_direct_anchors: u32,
    pub minimum_adjacent_owner_support_functions: u32,
    pub minimum_adjacent_owner_support_strong_functions: u32,
    pub maximum_adjacent_owner_size_delta: f32,
    pub maximum_adjacent_owner_gap_helpers: u32,
    pub require_complete_adjacent_owner_sequences: bool,
    pub require_atomic_adjacent_owner_revision: bool,
    /// A left edge from one evidence family and a right edge from another may
    /// be composed into one claim, when both edges are independently supported
    /// and the whole interior passes attribution.
    #[serde(default)]
    pub compose_independent_edges: bool,
    /// New ground may include a function attributed to the unit only weakly,
    /// when both its target neighbours are independent members of the unit
    /// that bracket it in source order.
    #[serde(default)]
    pub explain_order_bracketed_members: bool,
    /// New ground may include an unattributed function every caller of which is
    /// a member of the unit inside the claimed body.
    #[serde(default)]
    pub explain_caller_confined_helpers: bool,
    #[serde(default)]
    pub maximum_new_caller_confined_helpers: u32,
    #[serde(default)]
    pub maximum_composed_padding_gap: u32,
    /// A range tiled exactly by every source function of the unit in that
    /// section, paired in order, bounded by the unit's source-order neighbours
    /// or independent foreign attributions, may be claimed without the byte
    /// and function minimums of an ordinary sequence.
    #[serde(default)]
    pub recover_complete_small_sequences: bool,
    #[serde(default)]
    pub minimum_complete_sequence_independent_members: u32,
    /// A decisive partition of a bounded source-order run may move several
    /// units together in one ownership transaction.
    #[serde(default)]
    pub infer_joint_unit_runs: bool,
    #[serde(default)]
    pub maximum_joint_units: u32,
    #[serde(default)]
    pub maximum_joint_functions: u32,
    #[serde(default)]
    pub maximum_joint_windows: u32,
    #[serde(default)]
    pub maximum_joint_search_states: u32,
    /// A clean compiled two-unit boundary may be tried only as one transaction
    /// when its source and retail function orders and both outer flanks agree.
    #[serde(default)]
    pub infer_compiled_boundaries: bool,
    /// Claim a complete terminal run only when source, clean compiled object,
    /// and retail order agree between a held predecessor and foreign bound.
    #[serde(default)]
    pub infer_compiled_terminal_suffixes: bool,
    #[serde(default)]
    pub minimum_compiled_terminal_members: u32,
    #[serde(default)]
    pub maximum_compiled_terminal_members: u32,
    /// An isolated exact-body identity is not an ownership anchor when
    /// another unit has a same-sized source function in the matching slot
    /// between two binary-supported target neighbours.
    #[serde(default)]
    pub veto_competing_source_slots: bool,
    /// An unattributed function may extend the head of an owned unit when
    /// independent local data references, a same-unit callee and exact source
    /// and retail seams identify its emitter together.
    #[serde(default)]
    pub infer_reference_placed_prefixes: bool,
    #[serde(default)]
    pub minimum_reference_placed_data_pairs: u32,
    /// A changed destructor may occupy a two-function head when independent
    /// bounds, a unique class vtable and relocation structure all agree.
    #[serde(default)]
    pub infer_vtable_placed_heads: bool,
    #[serde(default)]
    pub minimum_vtable_head_shared_calls: u32,
}

/// The policy as this build of the tool applies it.
///
/// One constructor, because the report, the stage and the tests all have to
/// agree about what the rules currently are — three copies of the literal
/// drifted apart once already.
pub fn current_policy() -> CoveragePolicy {
    CoveragePolicy {
        version: POLICY_VERSION,
        complete_replacement_bodies: true,
        refine_represented_units: true,
        prefer_combined_exact_anchors: true,
        refuse_unevidenced_ownership_loss: true,
        atomic_ownership_transactions: true,
        minimum_anchor_bytes: MIN_ANCHOR_BYTES,
        normalized_body_must_be_unique: true,
        confirm_normalized_bytes_after_hash: true,
        require_relocation_layout: true,
        require_known_extents: true,
        require_explicit_whole_source_ownership: true,
        reject_weak_symbols: true,
        reject_template_anchors: true,
        reject_conflicting_target_ownership: true,
        require_split_alignment: true,
        infer_this_relative_layout_shifts: true,
        minimum_layout_shift_functions: MIN_LAYOUT_SHIFT_FUNCTIONS,
        minimum_layout_shift_changed_accesses: MIN_LAYOUT_SHIFT_CHANGED_ACCESSES,
        minimum_layout_shift_bytes: MIN_LAYOUT_SHIFT_BYTES,
        maximum_layout_shift_segments: MAX_LAYOUT_SHIFT_SEGMENTS,
        infer_boundary_constrained_sequences: true,
        minimum_sequence_functions: MIN_SEQUENCE_FUNCTIONS,
        minimum_sequence_match_ratio: MIN_SEQUENCE_MATCH_RATIO,
        minimum_sequence_order_ratio: MIN_SEQUENCE_ORDER_RATIO,
        minimum_sequence_matched_bytes: MIN_SEQUENCE_MATCHED_BYTES,
        minimum_sequence_target_coverage: MIN_SEQUENCE_TARGET_COVERAGE,
        minimum_sequence_strong_functions: MIN_SEQUENCE_STRONG_FUNCTIONS,
        minimum_sequence_direct_anchors: MIN_SEQUENCE_DIRECT_ANCHORS,
        allow_small_exact_sequence_anchors: true,
        minimum_sequence_alignment_margin: MIN_SEQUENCE_ALIGNMENT_MARGIN,
        minimum_sequence_size_ratio: MIN_SEQUENCE_SIZE_RATIO,
        maximum_sequence_size_ratio: MAX_SEQUENCE_SIZE_RATIO,
        require_explicit_sequence_neighbors: true,
        reject_sequence_runner_up: true,
        infer_boundary_data_matches: true,
        require_complete_data_reference_alignment: true,
        preserve_target_extract_extents: true,
        infer_layout_corroborated_boundaries: true,
        minimum_layout_boundary_functions: MIN_LAYOUT_BOUNDARY_FUNCTIONS,
        minimum_layout_boundary_bytes: MIN_LAYOUT_BOUNDARY_BYTES,
        minimum_layout_boundary_changed_accesses: MIN_LAYOUT_BOUNDARY_CHANGED_ACCESSES,
        maximum_layout_boundary_size_delta: MAX_LAYOUT_BOUNDARY_SIZE_DELTA,
        maximum_layout_boundary_function_delta: MAX_LAYOUT_BOUNDARY_FUNCTION_DELTA,
        infer_vtable_corroborated_boundaries: true,
        minimum_vtable_boundary_functions: MIN_VTABLE_BOUNDARY_FUNCTIONS,
        minimum_vtable_boundary_match_ratio: MIN_VTABLE_BOUNDARY_MATCH_RATIO,
        minimum_vtable_boundary_target_coverage: MIN_VTABLE_BOUNDARY_TARGET_COVERAGE,
        minimum_vtable_boundary_matched_slots: MIN_VTABLE_BOUNDARY_MATCHED_SLOTS,
        minimum_vtable_boundary_unit_slots: MIN_VTABLE_BOUNDARY_UNIT_SLOTS,
        maximum_vtable_boundary_size_delta: MAX_VTABLE_BOUNDARY_SIZE_DELTA,
        maximum_vtable_boundary_function_delta: MAX_VTABLE_BOUNDARY_FUNCTION_DELTA,
        maximum_vtable_boundary_gap_helpers: MAX_VTABLE_BOUNDARY_GAP_HELPERS,
        maximum_vtable_size_padding: MAX_VTABLE_SIZE_PADDING,
        infer_ownership_transition_boundaries: true,
        minimum_ownership_transition_functions: MIN_OWNERSHIP_TRANSITION_FUNCTIONS,
        minimum_ownership_transition_strong_functions: MIN_OWNERSHIP_TRANSITION_STRONG_FUNCTIONS,
        minimum_ownership_transition_edge_strong_functions:
            MIN_OWNERSHIP_TRANSITION_EDGE_STRONG_FUNCTIONS,
        maximum_ownership_transition_size_delta: MAX_OWNERSHIP_TRANSITION_SIZE_DELTA,
        require_complete_ownership_transition_sequence: true,
        require_nonempty_ownership_transition_correction: true,
        infer_adjacent_owner_transition_boundaries: true,
        minimum_adjacent_owner_transition_functions: MIN_ADJACENT_OWNER_TRANSITION_FUNCTIONS,
        minimum_adjacent_owner_transition_strong_functions:
            MIN_ADJACENT_OWNER_TRANSITION_STRONG_FUNCTIONS,
        minimum_adjacent_owner_transition_direct_anchors:
            MIN_ADJACENT_OWNER_TRANSITION_DIRECT_ANCHORS,
        minimum_adjacent_owner_support_functions: MIN_ADJACENT_OWNER_SUPPORT_FUNCTIONS,
        minimum_adjacent_owner_support_strong_functions:
            MIN_ADJACENT_OWNER_SUPPORT_STRONG_FUNCTIONS,
        maximum_adjacent_owner_size_delta: MAX_ADJACENT_OWNER_SIZE_DELTA,
        maximum_adjacent_owner_gap_helpers: MAX_ADJACENT_OWNER_GAP_HELPERS,
        require_complete_adjacent_owner_sequences: true,
        require_atomic_adjacent_owner_revision: true,
        compose_independent_edges: true,
        explain_order_bracketed_members: true,
        explain_caller_confined_helpers: true,
        maximum_new_caller_confined_helpers: MAX_NEW_CALLER_CONFINED_HELPERS,
        maximum_composed_padding_gap: MAX_COMPOSED_PADDING_GAP,
        recover_complete_small_sequences: true,
        minimum_complete_sequence_independent_members: MIN_COMPLETE_SEQUENCE_INDEPENDENT_MEMBERS,
        infer_joint_unit_runs: true,
        maximum_joint_units: MAX_JOINT_UNITS as u32,
        maximum_joint_functions: MAX_JOINT_FUNCTIONS as u32,
        maximum_joint_windows: MAX_JOINT_WINDOWS as u32,
        maximum_joint_search_states: MAX_JOINT_SEARCH_STATES as u32,
        infer_compiled_boundaries: true,
        infer_compiled_terminal_suffixes: true,
        minimum_compiled_terminal_members: MIN_COMPILED_TERMINAL_MEMBERS as u32,
        maximum_compiled_terminal_members: MAX_COMPILED_TERMINAL_MEMBERS as u32,
        veto_competing_source_slots: true,
        infer_reference_placed_prefixes: true,
        minimum_reference_placed_data_pairs: MIN_REFERENCE_PLACED_DATA_PAIRS as u32,
        infer_vtable_placed_heads: true,
        minimum_vtable_head_shared_calls: MIN_VTABLE_HEAD_SHARED_CALLS as u32,
    }
}
