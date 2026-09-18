use std::collections::{BTreeMap, HashMap, HashSet};

use decomp_toolkit::{
    obj::{ObjRelocKind, ObjSectionKind, ObjSymbolKind},
    util::split::default_section_align,
};
use serde::{Deserialize, Serialize};
use xxhash_rust::xxh3::xxh3_64;

use crate::analysis::{
    callgraph::{FunctionNode, NodeIndex},
    data_matching::match_data_pairs,
    fingerprint::{LayoutShiftBody, layout_shift_body, normalized_body},
    mask::Masked,
    matching::{MatchResult, MatchTarget, MatchTier},
    ownership::IdentificationReport,
};

pub const COVERAGE_SCHEMA: u32 = 10;
/// Kept in step with [`crate::stages::coverage::POLICY_VERSION`], which gates
/// the proposals this evidence produces; the two are checked against each other
/// on every read, so they have to move together.
pub const POLICY_VERSION: u32 = 9;
pub const MIN_ANCHOR_BYTES: u32 = 128;
pub const MIN_LAYOUT_SHIFT_FUNCTIONS: u32 = 2;
pub const MIN_LAYOUT_SHIFT_CHANGED_ACCESSES: u32 = 4;
pub const MIN_LAYOUT_SHIFT_BYTES: u32 = 128;
pub const MIN_SEQUENCE_FUNCTIONS: u32 = 4;
pub const MIN_SEQUENCE_MATCH_RATIO: f32 = 0.75;
pub const MIN_SEQUENCE_ORDER_RATIO: f32 = 0.90;
pub const MIN_SEQUENCE_MATCHED_BYTES: u32 = 512;
pub const MIN_SEQUENCE_TARGET_COVERAGE: f32 = 0.40;
pub const MIN_SEQUENCE_STRONG_FUNCTIONS: u32 = 2;
pub const MIN_SEQUENCE_DIRECT_ANCHORS: u32 = 2;
pub const MIN_SEQUENCE_ALIGNMENT_MARGIN: f32 = 0.10;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub schema: u32,
    pub policy: CoveragePolicy,
    pub source: String,
    pub target: String,
    /// What was hidden from the analysis that produced this, and from whom.
    /// The masking happened to the object, so every generator below saw the
    /// same world — there is no second, unmasked view for one of them to read.
    pub mask: Masked,
    /// Function attribution and TU identity observations, retained regardless
    /// of whether mutation policy can offer an ownership change.
    pub identifications: IdentificationReport,
    pub source_units: Vec<CoverageUnit>,
    pub target_layout: Vec<TargetFunction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

/// Extraction metadata from a project configuration. It is supplied by the
/// command layer so coverage can connect a source-generated include to a
/// target data symbol without embedding project-specific asset knowledge.
#[derive(Debug, Clone)]
pub struct ExtractSpec {
    pub symbol: String,
    pub rename: Option<String>,
    pub binary: Option<String>,
    pub header: Option<String>,
    pub relocations: Option<String>,
    pub header_type: Option<String>,
    pub custom_type: Option<String>,
    pub custom_data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy)]
pub struct ExtractCatalogs<'a> {
    pub source: &'a [ExtractSpec],
    pub target: &'a [ExtractSpec],
}

impl ExtractSpec {
    fn output_symbol(&self) -> &str { self.rename.as_deref().unwrap_or(&self.symbol) }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageUnit {
    pub name: String,
    pub code_bytes: u64,
    pub autogenerated: bool,
    pub source_functions: u32,
    pub no_exact_target_body: u32,
    pub name_only_candidates: u32,
    pub ambiguous_exact_bodies: u32,
    pub anchors: Vec<CoverageAnchor>,
    pub layout_shift_candidates: u32,
    pub layout_shift_anchors: Vec<LayoutShiftAnchor>,
    pub boundary_sequences: Vec<BoundarySequence>,
    pub adjacent_owner_transitions: Vec<AdjacentOwnerTransition>,
    pub required_extracts: Vec<RequiredExtract>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequiredExtract {
    pub source_symbol: String,
    pub target_symbol: String,
    pub target_address: String,
    pub target_size: u64,
    pub rename: Option<String>,
    pub binary: Option<String>,
    pub header: Option<String>,
    pub relocations: Option<String>,
    pub header_type: Option<String>,
    pub custom_type: Option<String>,
    pub custom_data: Option<serde_json::Value>,
    pub reference_evidence: u32,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAnchor {
    pub source_name: String,
    pub source_address: String,
    pub target_name: String,
    pub target_address: String,
    pub target_end: String,
    pub section: String,
    pub size: u32,
    pub source_local: bool,
    pub target_local: bool,
    pub source_weak: bool,
    pub target_weak: bool,
    pub source_extent_known: bool,
    pub target_extent_known: bool,
    pub source_unit_explicit: bool,
    pub source_unit_wholly_owned: bool,
    pub template_instantiation: bool,
    pub unique_source: bool,
    pub unique_target: bool,
    pub normalized_body_equal: bool,
    pub relocation_layout_equal: bool,
    pub required_alignment: u32,
    pub existing_target_owner: Option<String>,
    pub existing_owner_autogenerated: bool,
    pub eligible: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutShiftAnchor {
    pub source_name: String,
    pub source_address: String,
    pub target_name: String,
    pub target_address: String,
    pub target_end: String,
    pub section: String,
    pub size: u32,
    pub source_local: bool,
    pub target_local: bool,
    pub source_weak: bool,
    pub target_weak: bool,
    pub source_extent_known: bool,
    pub target_extent_known: bool,
    pub source_unit_explicit: bool,
    pub source_unit_wholly_owned: bool,
    pub template_instantiation: bool,
    pub unique_source: bool,
    pub unique_target: bool,
    pub layout_masked_body_equal: bool,
    pub relocation_layout_equal: bool,
    pub this_accesses: u32,
    pub changed_this_accesses: u32,
    pub offset_deltas: Vec<i32>,
    pub inferred_breakpoint: Option<i32>,
    pub support_group: String,
    pub support_functions: u32,
    pub support_bytes: u32,
    pub support_changed_accesses: u32,
    pub required_alignment: u32,
    pub existing_target_owner: Option<String>,
    pub existing_owner_autogenerated: bool,
    pub eligible: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetFunction {
    pub address: String,
    pub end: String,
    pub section: String,
    pub current_owner: Option<String>,
    pub owner_autogenerated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundarySequence {
    pub section: String,
    pub target_start: String,
    pub target_end: String,
    pub target_bytes: u32,
    pub target_functions: u32,
    pub previous_unit: String,
    pub next_unit: String,
    pub source_functions: u32,
    pub aligned_functions: u32,
    pub aligned_bytes: u32,
    pub strong_functions: u32,
    pub direct_anchors: u32,
    pub match_ratio: f32,
    pub order_ratio: f32,
    pub target_coverage: f32,
    pub best_alignment_score: f32,
    pub second_alignment_score: f32,
    pub alignment_margin: f32,
    pub acceptance_method: String,
    pub layout_support_group: Option<String>,
    pub vtable_support: Option<VtableSupport>,
    pub gap_helpers: Vec<GapHelper>,
    pub ownership_transition_support: Option<OwnershipTransitionSupport>,
    pub functions: Vec<SequenceFunction>,
    pub eligible: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtableSupport {
    pub source_address: String,
    pub target_address: String,
    pub source_size: u32,
    pub target_size: u32,
    pub matched_slots: u32,
    pub agreeing_slots: u32,
    pub unit_slots: Vec<VtableFunction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtableFunction {
    pub slot_offset: u32,
    pub source_address: String,
    pub target_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapHelper {
    pub target_address: String,
    pub target_end: String,
    pub size: u32,
    pub callers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipTransitionSupport {
    pub original_target_start: String,
    pub original_target_end: String,
    pub aligned_target_start: String,
    pub aligned_target_end: String,
    pub source_bytes: u32,
    pub aligned_target_bytes: u32,
    pub size_delta: f32,
    pub left: OwnershipTransitionEdge,
    pub right: OwnershipTransitionEdge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipTransitionEdge {
    pub unit: String,
    pub start: String,
    pub end: String,
    pub bytes: u32,
    pub functions: Vec<OwnershipTransitionFunction>,
    pub strong_functions: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipTransitionFunction {
    pub source_name: String,
    pub source_address: String,
    pub target_address: String,
    pub target_end: String,
    pub size: u32,
    pub tier: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjacentOwnerTransition {
    pub section: String,
    pub side: String,
    pub target_start: String,
    pub target_end: String,
    pub target_bytes: u32,
    pub source_bytes: u32,
    pub previous_unit: String,
    pub next_unit: String,
    pub source_functions: u32,
    pub aligned_functions: u32,
    pub strong_functions: u32,
    pub direct_anchors: u32,
    pub match_ratio: f32,
    pub target_coverage: f32,
    pub best_alignment_score: f32,
    pub second_alignment_score: f32,
    pub alignment_margin: f32,
    pub size_delta: f32,
    pub owner: AdjacentOwnerSupport,
    pub functions: Vec<SequenceFunction>,
    pub eligible: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdjacentOwnerSupport {
    pub unit: String,
    pub original_start: String,
    pub original_end: String,
    pub revised_start: String,
    pub revised_end: String,
    pub source_bytes: u32,
    pub target_bytes: u32,
    pub size_delta: f32,
    pub source_functions: u32,
    pub aligned_functions: u32,
    pub target_functions: u32,
    pub strong_functions: u32,
    pub functions: Vec<SequenceFunction>,
    pub gap_helpers: Vec<GapHelper>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceFunction {
    pub source_name: String,
    pub source_address: String,
    pub target_address: String,
    pub target_end: String,
    pub size: u32,
    pub tier: String,
    pub method: String,
    pub confidence: f32,
    pub primary: bool,
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
        maximum_layout_shift_segments: 2,
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
        minimum_sequence_size_ratio: 0.5,
        maximum_sequence_size_ratio: 1.5,
        require_explicit_sequence_neighbors: true,
        reject_sequence_runner_up: true,
        infer_boundary_data_matches: true,
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
    }
}

/// Turns two analysed executables into the evidence a coverage policy reasons
/// over.
///
/// `hide_target_names` and `mask` are two different kinds of ignorance, and a
/// migration has both: the target's symbol names are meaningless until matching
/// supplies them, and its split ownership does not exist yet. They are kept
/// apart because the evidence needs them apart — a function's identity and the
/// linker's choice of owner are established by different observations.
pub fn build_report(
    source: &MatchTarget,
    target: &MatchTarget,
    matches: &MatchResult,
    identifications: IdentificationReport,
    hide_target_names: bool,
    mask: &Masked,
    extracts: ExtractCatalogs<'_>,
) -> CoverageReport {
    let mut source_hashes: HashMap<u64, Vec<NodeIndex>> = HashMap::new();
    let mut target_hashes: HashMap<u64, Vec<NodeIndex>> = HashMap::new();
    for node in 0..source.graph.len() as NodeIndex {
        source_hashes.entry(source.fingerprints[node as usize].exact_hash).or_default().push(node);
    }
    for node in 0..target.graph.len() as NodeIndex {
        target_hashes.entry(target.fingerprints[node as usize].exact_hash).or_default().push(node);
    }
    let target_names: HashSet<&str> =
        (0..target.graph.len() as NodeIndex).map(|node| target.symbol_name(node)).collect();

    let mut units: BTreeMap<String, CoverageUnit> = BTreeMap::new();
    for (_, section, start, split) in source.obj.sections.all_splits() {
        let entry = units.entry(split.unit.clone()).or_insert_with(|| CoverageUnit {
            name: split.unit.clone(),
            code_bytes: 0,
            autogenerated: source.obj.is_unit_autogenerated(&split.unit),
            source_functions: 0,
            no_exact_target_body: 0,
            name_only_candidates: 0,
            ambiguous_exact_bodies: 0,
            anchors: Vec::new(),
            layout_shift_candidates: 0,
            layout_shift_anchors: Vec::new(),
            boundary_sequences: Vec::new(),
            adjacent_owner_transitions: Vec::new(),
            required_extracts: Vec::new(),
        });
        if section.kind == ObjSectionKind::Code {
            let end =
                if split.end == 0 { (section.address + section.size) as u32 } else { split.end };
            entry.code_bytes += end.saturating_sub(start) as u64;
        }
    }

    for source_node in 0..source.graph.len() as NodeIndex {
        let Some(unit) = source.unit_of(source_node) else { continue };
        let source_name = source.symbol_name(source_node);
        if let Some(entry) = units.get_mut(unit) {
            entry.source_functions += 1;
        }
        let fingerprint = &source.fingerprints[source_node as usize];
        let source_candidate = unique_hash_node(&source_hashes, fingerprint.exact_hash);
        if source_candidate != Some(source_node) {
            if let Some(entry) = units.get_mut(unit) {
                entry.ambiguous_exact_bodies += 1;
            }
            continue;
        }
        if !target_hashes.contains_key(&fingerprint.exact_hash) {
            if let Some(entry) = units.get_mut(unit) {
                entry.no_exact_target_body += 1;
                entry.name_only_candidates += u32::from(target_names.contains(source_name));
            }
            continue;
        }
        let target_candidate = unique_hash_node(&target_hashes, fingerprint.exact_hash);
        if target_candidate.is_none() {
            if let Some(entry) = units.get_mut(unit) {
                entry.ambiguous_exact_bodies += 1;
            }
            continue;
        }
        let target_node = target_candidate.unwrap();
        let a = source.graph.node(source_node);
        let b = target.graph.node(target_node);
        let target_name = target.symbol_name(target_node);
        // Whatever a scenario hid is already gone from the object, so this is
        // the ownership the analysis is entitled to see.
        let target_owner = target.unit_of(target_node).map(str::to_string);
        let owner_auto =
            target_owner.as_deref().is_some_and(|name| target.obj.is_unit_autogenerated(name));
        let source_body = normalized_body(&source.obj, a);
        let target_body = normalized_body(&target.obj, b);
        let source_extent_known =
            source.obj.symbols[a.symbol].size_known && source_body.len() == a.size as usize;
        let target_extent_known =
            target.obj.symbols[b.symbol].size_known && target_body.len() == b.size as usize;
        let body_equal = source_body == target_body;
        let reloc_equal = relocation_layout(a) == relocation_layout(b);
        let template =
            is_template_symbol(source, source_node) || is_template_symbol(target, target_node);
        let source_unit_explicit = !source.obj.is_unit_autogenerated(unit);
        let source_unit_wholly_owned =
            range_is_owned_by(source, a.section, a.address, a.address + a.size, unit);
        let section = &target.obj.sections[b.section];
        let align = required_alignment(target, b);
        let mut reasons = eligibility_reasons(
            a.size,
            source.is_weak(source_node),
            target.is_weak(target_node),
            source_extent_known,
            target_extent_known,
            source_unit_explicit,
            source_unit_wholly_owned,
            template,
            body_equal,
            reloc_equal,
            target_owner.as_deref(),
            owner_auto,
            unit,
        );
        if b.address % align != 0 || (b.address + b.size) % align != 0 {
            reasons.push("function range is not split-aligned".to_string());
        }
        units
            .entry(unit.to_string())
            .or_insert_with(|| CoverageUnit {
                name: unit.to_string(),
                code_bytes: 0,
                autogenerated: source.obj.is_unit_autogenerated(unit),
                source_functions: 0,
                no_exact_target_body: 0,
                name_only_candidates: 0,
                ambiguous_exact_bodies: 0,
                anchors: Vec::new(),
                layout_shift_candidates: 0,
                layout_shift_anchors: Vec::new(),
                boundary_sequences: Vec::new(),
                adjacent_owner_transitions: Vec::new(),
                required_extracts: Vec::new(),
            })
            .anchors
            .push(CoverageAnchor {
                source_name: source_name.to_string(),
                source_address: hex(a.address),
                target_name: if hide_target_names {
                    String::new()
                } else {
                    target_name.to_string()
                },
                target_address: hex(b.address),
                target_end: hex(b.address + b.size),
                section: section.name.clone(),
                size: a.size,
                source_local: source.is_local(source_node),
                target_local: target.is_local(target_node),
                source_weak: source.is_weak(source_node),
                target_weak: target.is_weak(target_node),
                source_extent_known,
                target_extent_known,
                source_unit_explicit,
                source_unit_wholly_owned,
                template_instantiation: template,
                unique_source: true,
                unique_target: true,
                normalized_body_equal: body_equal,
                relocation_layout_equal: reloc_equal,
                required_alignment: align,
                existing_target_owner: target_owner,
                existing_owner_autogenerated: owner_auto,
                eligible: reasons.is_empty(),
                reasons,
            });
    }

    add_layout_shift_evidence(source, target, hide_target_names, &mut units);
    add_boundary_sequence_evidence(
        source,
        target,
        matches,
        extracts.source,
        extracts.target,
        &mut units,
    );
    add_adjacent_owner_transition_evidence(
        source,
        target,
        matches,
        extracts.source,
        extracts.target,
        &mut units,
    );

    for unit in units.values_mut() {
        unit.anchors
            .sort_by(|a, b| b.size.cmp(&a.size).then(a.target_address.cmp(&b.target_address)));
        unit.layout_shift_anchors.sort_by(|a, b| {
            a.support_group.cmp(&b.support_group).then(a.target_address.cmp(&b.target_address))
        });
    }
    let target_layout = target
        .layout()
        .iter()
        .map(|&index| {
            let node = target.graph.node(index);
            let owner = target.unit_of(index).map(str::to_string);
            TargetFunction {
                address: hex(node.address),
                end: hex(node.address + node.size),
                section: target.obj.sections[node.section].name.clone(),
                owner_autogenerated: owner
                    .as_deref()
                    .is_some_and(|name| target.obj.is_unit_autogenerated(name)),
                current_owner: owner,
            }
        })
        .collect();

    CoverageReport {
        schema: COVERAGE_SCHEMA,
        policy: current_policy(),
        source: source.name.clone(),
        target: target.name.clone(),
        mask: mask.clone(),
        identifications,
        source_units: units.into_values().collect(),
        target_layout,
    }
}

#[derive(Debug, Clone)]
struct SplitRange {
    unit: String,
    start: u32,
    end: u32,
    autogenerated: bool,
}

#[derive(Debug, Clone)]
struct SequenceEdge {
    source: NodeIndex,
    target: NodeIndex,
    source_position: u32,
    target_position: u32,
    weight: f32,
    primary: bool,
    tier: String,
    method: String,
    confidence: f32,
}

#[derive(Debug, Default)]
struct Alignment {
    edges: Vec<usize>,
    score: f32,
}

fn code_split_ranges(target: &MatchTarget) -> BTreeMap<String, Vec<SplitRange>> {
    let mut result: BTreeMap<String, Vec<SplitRange>> = BTreeMap::new();
    for (_, section, start, split) in target.obj.sections.all_splits() {
        if section.kind != ObjSectionKind::Code {
            continue;
        }
        result.entry(section.name.clone()).or_default().push(SplitRange {
            unit: split.unit.clone(),
            start,
            end: if split.end == 0 { (section.address + section.size) as u32 } else { split.end },
            autogenerated: split.autogenerated,
        });
    }
    for ranges in result.values_mut() {
        ranges.sort_by_key(|range| (range.start, range.end, range.unit.clone()));
    }
    result
}

fn unique_unit_range<'a>(ranges: &'a [SplitRange], unit: &str) -> Option<&'a SplitRange> {
    let mut found = ranges.iter().filter(|range| range.unit == unit);
    let result = found.next()?;
    found.next().is_none().then_some(result)
}

fn better_alignment(length: usize, score: f32, best_length: usize, best_score: f32) -> bool {
    length > best_length || (length == best_length && score > best_score)
}

fn best_alignment(edges: &[SequenceEdge], excluded: Option<usize>) -> Alignment {
    let mut order: Vec<usize> = (0..edges.len()).filter(|index| Some(*index) != excluded).collect();
    order.sort_by_key(|&index| {
        let edge = &edges[index];
        (edge.source_position, edge.target_position, !edge.primary)
    });
    let mut lengths = vec![1usize; order.len()];
    let mut scores = order.iter().map(|&index| edges[index].weight).collect::<Vec<_>>();
    let mut previous = vec![None; order.len()];
    for i in 0..order.len() {
        for j in 0..i {
            let (left, right) = (&edges[order[j]], &edges[order[i]]);
            if left.source_position >= right.source_position
                || left.target_position >= right.target_position
            {
                continue;
            }
            let candidate_length = lengths[j] + 1;
            let candidate_score = scores[j] + right.weight;
            if better_alignment(candidate_length, candidate_score, lengths[i], scores[i]) {
                lengths[i] = candidate_length;
                scores[i] = candidate_score;
                previous[i] = Some(j);
            }
        }
    }
    let Some(mut current) = (0..order.len())
        .max_by(|&a, &b| lengths[a].cmp(&lengths[b]).then_with(|| scores[a].total_cmp(&scores[b])))
    else {
        return Alignment::default();
    };
    let score = scores[current];
    let mut selected = Vec::new();
    loop {
        selected.push(order[current]);
        let Some(parent) = previous[current] else { break };
        current = parent;
    }
    selected.reverse();
    Alignment { edges: selected, score }
}

fn round_ratio(value: f32) -> f32 { (value * 1000.0).round() / 1000.0 }

fn boundary_required_extracts(
    source: &MatchTarget,
    target: &MatchTarget,
    selected: &[&SequenceEdge],
    source_extracts: &[ExtractSpec],
    target_extracts: &[ExtractSpec],
) -> Vec<RequiredExtract> {
    let source_by_symbol: HashMap<&str, &ExtractSpec> =
        source_extracts.iter().map(|extract| (extract.symbol.as_str(), extract)).collect();
    let pairs = selected.iter().filter(|edge| edge.primary).map(|edge| (edge.source, edge.target));
    let mut required = Vec::new();
    for data_match in match_data_pairs(source, target, pairs) {
        let source_symbol = source.symbol_name_at(data_match.source);
        let Some(source_extract) = source_by_symbol.get(source_symbol).copied() else { continue };
        let output_symbol = source_extract.output_symbol();
        let target_symbol = target.symbol_name_at(data_match.target);
        let already_configured = target_extracts.iter().any(|extract| {
            extract.output_symbol() == output_symbol
                && extract.header == source_extract.header
                && extract.binary == source_extract.binary
                && extract.relocations == source_extract.relocations
        });
        // Do not introduce a second interpretation of an already-extracted
        // target object. Existing configuration remains authoritative.
        let target_already_extracted =
            target_extracts.iter().any(|extract| extract.symbol == target_symbol);
        if already_configured || target_already_extracted {
            continue;
        }
        let symbol = &target.obj.symbols[data_match.target];
        required.push(RequiredExtract {
            source_symbol: source_symbol.to_string(),
            target_symbol: target_symbol.to_string(),
            target_address: hex(symbol.address as u32),
            target_size: symbol.size,
            rename: (target_symbol != output_symbol).then(|| output_symbol.to_string()),
            binary: source_extract.binary.clone(),
            header: source_extract.header.clone(),
            relocations: source_extract.relocations.clone(),
            header_type: source_extract.header_type.clone(),
            custom_type: source_extract.custom_type.clone(),
            custom_data: source_extract.custom_data.clone(),
            reference_evidence: data_match.evidence,
            evidence: "boundary-sequence-data-reference".to_string(),
        });
    }
    required.sort_by(|a, b| {
        a.target_address.cmp(&b.target_address).then(a.source_symbol.cmp(&b.source_symbol))
    });
    required.dedup_by(|a, b| {
        a.target_symbol == b.target_symbol
            && a.rename == b.rename
            && a.binary == b.binary
            && a.header == b.header
    });
    required
}

struct LayoutBoundaryMetrics {
    source_bytes: u32,
    target_bytes: u32,
    source_functions: u32,
    target_functions: u32,
}

struct VtableBoundaryContext<'a> {
    unit: &'a str,
    section: &'a str,
    start: u32,
    end: u32,
    source_bytes: u32,
    target_bytes: u32,
    source_functions: u32,
    target_functions: u32,
    match_ratio: f32,
    target_coverage: f32,
    alignment_margin: f32,
}

fn vtable_boundary_support(
    source: &MatchTarget,
    target: &MatchTarget,
    matches: &MatchResult,
    selected: &[&SequenceEdge],
    context: &VtableBoundaryContext<'_>,
) -> Option<(VtableSupport, Vec<GapHelper>)> {
    let size_base = context.source_bytes.max(context.target_bytes);
    let size_delta = if size_base == 0 {
        0.0
    } else {
        context.source_bytes.abs_diff(context.target_bytes) as f32 / size_base as f32
    };
    if selected.len() < MIN_VTABLE_BOUNDARY_FUNCTIONS as usize
        || context.match_ratio < MIN_VTABLE_BOUNDARY_MATCH_RATIO
        || context.target_coverage < MIN_VTABLE_BOUNDARY_TARGET_COVERAGE
        || context.alignment_margin < MIN_SEQUENCE_ALIGNMENT_MARGIN
        || size_delta > MAX_VTABLE_BOUNDARY_SIZE_DELTA
        || context.source_functions.abs_diff(context.target_functions)
            > MAX_VTABLE_BOUNDARY_FUNCTION_DELTA
        || context.source_functions.saturating_sub(selected.len() as u32) > 1
        || selected.iter().any(|edge| !edge.primary)
        || selected.windows(2).any(|pair| {
            pair[0].source_position >= pair[1].source_position
                || pair[0].target_position >= pair[1].target_position
        })
    {
        return None;
    }

    let source_node_by_address: HashMap<u32, NodeIndex> =
        source.graph.iter().map(|(index, node)| (node.address, index)).collect();
    let source_to_target: HashMap<NodeIndex, NodeIndex> =
        matches.matches.iter().map(|m| (m.source, m.target)).collect();
    let selected_pairs: HashSet<(NodeIndex, NodeIndex)> =
        selected.iter().map(|edge| (edge.source, edge.target)).collect();

    let mut supports = BTreeMap::<(u32, u32), VtableSupport>::new();
    for (source_symbol_index, source_symbol) in source.obj.symbols.by_kind(ObjSymbolKind::Object) {
        if !source_symbol.name.starts_with("__vt__")
            || source.unit_of_symbol(source_symbol_index) != Some(context.unit)
            || !source_symbol.size_known
            || source_symbol.size > u32::MAX as u64
        {
            continue;
        }
        let source_size = source_symbol.size as u32;
        let Some(source_section_index) = source_symbol.section else { continue };
        let Some(source_section) = source.obj.sections.get(source_section_index) else { continue };
        if !matches!(source_section.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData) {
            continue;
        }
        let mapped_slots: Vec<(u32, NodeIndex, NodeIndex)> = source_section
            .relocations
            .range(source_symbol.address as u32..source_symbol.address as u32 + source_size)
            .filter(|(_, reloc)| reloc.kind == ObjRelocKind::Absolute)
            .filter_map(|(address, reloc)| {
                let offset = address - source_symbol.address as u32;
                if offset % 4 != 0 || offset.saturating_add(4) > source_size {
                    return None;
                }
                let target_address =
                    (source.obj.symbols[reloc.target_symbol].address as i64 + reloc.addend) as u32;
                let source_node = source_node_by_address.get(&target_address).copied()?;
                let target_node = source_to_target.get(&source_node).copied()?;
                Some((offset, source_node, target_node))
            })
            .collect();
        if mapped_slots.len() < MIN_VTABLE_BOUNDARY_MATCHED_SLOTS as usize {
            continue;
        }

        for (target_symbol_index, target_symbol) in
            target.obj.symbols.by_kind(ObjSymbolKind::Object)
        {
            if !target_symbol.size_known
                || target_symbol.size > u32::MAX as u64
                || (target_symbol.size as u32).abs_diff(source_size) > MAX_VTABLE_SIZE_PADDING
                || mapped_slots
                    .iter()
                    .any(|(offset, _, _)| offset.saturating_add(4) > target_symbol.size as u32)
            {
                continue;
            }
            let Some(target_section_index) = target_symbol.section else { continue };
            let Some(target_section) = target.obj.sections.get(target_section_index) else {
                continue;
            };
            if !matches!(target_section.kind, ObjSectionKind::Data | ObjSectionKind::ReadOnlyData) {
                continue;
            }
            let target_owner = target.unit_of_symbol(target_symbol_index);
            if target_owner.is_some_and(|owner| {
                owner != context.unit && !target.obj.is_unit_autogenerated(owner)
            }) {
                continue;
            }

            let agreeing: Vec<(u32, NodeIndex, NodeIndex)> = mapped_slots
                .iter()
                .copied()
                .filter(|(offset, _, target_node)| {
                    target_section
                        .relocations
                        .at(target_symbol.address as u32 + offset)
                        .is_some_and(|reloc| {
                            reloc.kind == ObjRelocKind::Absolute
                                && (target.obj.symbols[reloc.target_symbol].address as i64
                                    + reloc.addend) as u32
                                    == target.graph.node(*target_node).address
                        })
                })
                .collect();
            if agreeing.len() != mapped_slots.len() {
                continue;
            }
            let unit_slots: Vec<VtableFunction> = agreeing
                .iter()
                .filter(|(_, source_node, target_node)| {
                    source.unit_of(*source_node) == Some(context.unit)
                        && selected_pairs.contains(&(*source_node, *target_node))
                })
                .map(|(offset, source_node, target_node)| VtableFunction {
                    slot_offset: *offset,
                    source_address: hex(source.graph.node(*source_node).address),
                    target_address: hex(target.graph.node(*target_node).address),
                })
                .collect();
            let mapped_unit_slots = agreeing
                .iter()
                .filter(|(_, source_node, _)| source.unit_of(*source_node) == Some(context.unit))
                .count();
            if unit_slots.len() < MIN_VTABLE_BOUNDARY_UNIT_SLOTS as usize
                || unit_slots.len() != mapped_unit_slots
            {
                continue;
            }
            supports.insert(
                (source_symbol.address as u32, target_symbol.address as u32),
                VtableSupport {
                    source_address: hex(source_symbol.address as u32),
                    target_address: hex(target_symbol.address as u32),
                    source_size,
                    target_size: target_symbol.size as u32,
                    matched_slots: mapped_slots.len() as u32,
                    agreeing_slots: agreeing.len() as u32,
                    unit_slots,
                },
            );
        }
    }
    if supports.len() != 1 {
        return None;
    }
    let support = supports.into_values().next()?;

    let selected_targets: HashSet<NodeIndex> = selected.iter().map(|edge| edge.target).collect();
    let helpers: Vec<GapHelper> = target
        .layout()
        .iter()
        .copied()
        .filter(|node| {
            let function = target.graph.node(*node);
            target.obj.sections[function.section].name == context.section
                && function.address >= context.start
                && function.address.saturating_add(function.size) <= context.end
                && !selected_targets.contains(node)
        })
        .filter_map(|node| {
            let function = target.graph.node(node);
            let callers: Vec<NodeIndex> = function.callers.clone();
            (!callers.is_empty()
                && callers.iter().all(|caller| {
                    let caller = target.graph.node(*caller);
                    target.obj.sections[caller.section].name == context.section
                        && caller.address >= context.start
                        && caller.address.saturating_add(caller.size) <= context.end
                })
                && callers.iter().any(|caller| selected_targets.contains(caller)))
            .then(|| GapHelper {
                target_address: hex(function.address),
                target_end: hex(function.address + function.size),
                size: function.size,
                callers: callers
                    .iter()
                    .map(|caller| hex(target.graph.node(*caller).address))
                    .collect(),
            })
        })
        .collect();
    let unmatched_target_functions = context.target_functions.saturating_sub(selected.len() as u32);
    if helpers.is_empty()
        || helpers.len() as u32 != unmatched_target_functions
        || helpers.len() as u32 > MAX_VTABLE_BOUNDARY_GAP_HELPERS
    {
        return None;
    }
    Some((support, helpers))
}

fn layout_boundary_support(
    unit: &CoverageUnit,
    section: &str,
    start: u32,
    end: u32,
    metrics: LayoutBoundaryMetrics,
) -> Option<String> {
    let LayoutBoundaryMetrics { source_bytes, target_bytes, source_functions, target_functions } =
        metrics;
    let size_base = source_bytes.max(target_bytes);
    let size_delta = if size_base == 0 {
        0.0
    } else {
        source_bytes.abs_diff(target_bytes) as f32 / size_base as f32
    };
    if size_delta > MAX_LAYOUT_BOUNDARY_SIZE_DELTA
        || source_functions.abs_diff(target_functions) > MAX_LAYOUT_BOUNDARY_FUNCTION_DELTA
    {
        return None;
    }

    let mut groups: BTreeMap<&str, Vec<&LayoutShiftAnchor>> = BTreeMap::new();
    for anchor in unit.layout_shift_anchors.iter().filter(|anchor| anchor.eligible) {
        let anchor_start = u32::from_str_radix(anchor.target_address.trim_start_matches("0x"), 16)
            .expect("coverage addresses are generated as hexadecimal");
        let anchor_end = u32::from_str_radix(anchor.target_end.trim_start_matches("0x"), 16)
            .expect("coverage addresses are generated as hexadecimal");
        if anchor.section == section && anchor_start >= start && anchor_end <= end {
            groups.entry(&anchor.support_group).or_default().push(anchor);
        }
    }

    groups
        .into_iter()
        .filter_map(|(group, mut anchors)| {
            anchors.sort_by_key(|anchor| {
                u32::from_str_radix(anchor.source_address.trim_start_matches("0x"), 16)
                    .expect("coverage addresses are generated as hexadecimal")
            });
            let source_addresses: Vec<u32> = anchors
                .iter()
                .map(|anchor| {
                    u32::from_str_radix(anchor.source_address.trim_start_matches("0x"), 16)
                        .expect("coverage addresses are generated as hexadecimal")
                })
                .collect();
            let target_ranges: Vec<(u32, u32)> = anchors
                .iter()
                .map(|anchor| {
                    (
                        u32::from_str_radix(anchor.target_address.trim_start_matches("0x"), 16)
                            .expect("coverage addresses are generated as hexadecimal"),
                        u32::from_str_radix(anchor.target_end.trim_start_matches("0x"), 16)
                            .expect("coverage addresses are generated as hexadecimal"),
                    )
                })
                .collect();
            let support_functions = anchors.first()?.support_functions;
            let support_bytes = anchors.first()?.support_bytes;
            let support_changed_accesses = anchors.first()?.support_changed_accesses;
            let consistent = anchors.iter().all(|anchor| {
                anchor.support_functions == support_functions
                    && anchor.support_bytes == support_bytes
                    && anchor.support_changed_accesses == support_changed_accesses
            });
            let monotone = source_addresses.windows(2).all(|pair| pair[0] < pair[1])
                && target_ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0);
            (consistent
                && monotone
                && support_functions == anchors.len() as u32
                && support_bytes == anchors.iter().map(|anchor| anchor.size).sum::<u32>()
                && support_changed_accesses
                    == anchors.iter().map(|anchor| anchor.changed_this_accesses).sum::<u32>()
                && support_functions >= MIN_LAYOUT_BOUNDARY_FUNCTIONS
                && support_bytes >= MIN_LAYOUT_BOUNDARY_BYTES
                && support_changed_accesses >= MIN_LAYOUT_BOUNDARY_CHANGED_ACCESSES)
                .then_some((support_bytes, support_functions, support_changed_accesses, group))
        })
        .max_by_key(|&(bytes, functions, changed, _)| (bytes, functions, changed))
        .map(|(_, _, _, group)| group.to_string())
}

fn ownership_transition_edge(
    source: &MatchTarget,
    target: &MatchTarget,
    matches: &MatchResult,
    section: &str,
    start: u32,
    end: u32,
    unit: &str,
) -> Option<OwnershipTransitionEdge> {
    if start == end {
        return Some(OwnershipTransitionEdge {
            unit: unit.to_string(),
            start: hex(start),
            end: hex(end),
            bytes: 0,
            functions: Vec::new(),
            strong_functions: 0,
        });
    }
    let nodes: Vec<NodeIndex> = target
        .layout()
        .iter()
        .copied()
        .filter(|&node| {
            let function = target.graph.node(node);
            target.obj.sections[function.section].name == section
                && function.address >= start
                && function.address.saturating_add(function.size) <= end
        })
        .collect();
    if nodes.is_empty()
        || target.graph.node(nodes[0]).address != start
        || target
            .graph
            .node(*nodes.last().expect("nonempty transition node list"))
            .address
            .saturating_add(
                target.graph.node(*nodes.last().expect("nonempty transition node list")).size,
            )
            != end
        || nodes.windows(2).any(|pair| {
            let left = target.graph.node(pair[0]);
            left.address.saturating_add(left.size) != target.graph.node(pair[1]).address
        })
    {
        return None;
    }

    let by_target: HashMap<NodeIndex, _> =
        matches.matches.iter().map(|matched| (matched.target, matched)).collect();
    let mut functions = Vec::with_capacity(nodes.len());
    let mut strong_functions = 0;
    for node in nodes {
        let matched = by_target.get(&node)?;
        if matched.runner_up.is_some() || source.unit_of(matched.source) != Some(unit) {
            return None;
        }
        strong_functions += u32::from(matched.tier() != MatchTier::Candidate);
        let source_function = source.graph.node(matched.source);
        let target_function = target.graph.node(node);
        functions.push(OwnershipTransitionFunction {
            source_name: source.symbol_name(matched.source).to_string(),
            source_address: hex(source_function.address),
            target_address: hex(target_function.address),
            target_end: hex(target_function.address + target_function.size),
            size: target_function.size,
            tier: matched.tier().as_str().to_string(),
            confidence: round_ratio(matched.confidence),
        });
    }
    if strong_functions < MIN_OWNERSHIP_TRANSITION_EDGE_STRONG_FUNCTIONS {
        return None;
    }
    Some(OwnershipTransitionEdge {
        unit: unit.to_string(),
        start: hex(start),
        end: hex(end),
        bytes: end - start,
        functions,
        strong_functions,
    })
}

#[allow(clippy::too_many_arguments)]
fn ownership_transition_support(
    source: &MatchTarget,
    target: &MatchTarget,
    matches: &MatchResult,
    selected: &[&SequenceEdge],
    source_nodes: &[NodeIndex],
    section: &str,
    original_start: u32,
    original_end: u32,
    source_bytes: u32,
    strong_functions: u32,
    alignment_margin: f32,
    previous_unit: &str,
    next_unit: &str,
) -> Option<OwnershipTransitionSupport> {
    if selected.len() < MIN_OWNERSHIP_TRANSITION_FUNCTIONS as usize
        || selected.len() != source_nodes.len()
        || strong_functions < MIN_OWNERSHIP_TRANSITION_STRONG_FUNCTIONS
        || alignment_margin < MIN_SEQUENCE_ALIGNMENT_MARGIN
        || selected.iter().any(|edge| !edge.primary)
        || selected.iter().map(|edge| edge.source).collect::<HashSet<_>>().len()
            != source_nodes.len()
        || selected.windows(2).any(|pair| {
            pair[0].source_position >= pair[1].source_position
                || pair[0].target_position >= pair[1].target_position
        })
    {
        return None;
    }
    let first = target.graph.node(selected.first()?.target);
    let last = target.graph.node(selected.last()?.target);
    let aligned_start = first.address;
    let aligned_end = last.address.saturating_add(last.size);
    if aligned_start < original_start
        || aligned_end > original_end
        || aligned_start >= aligned_end
        || (aligned_start == original_start && aligned_end == original_end)
        || selected.windows(2).any(|pair| {
            let left = target.graph.node(pair[0].target);
            left.address.saturating_add(left.size) != target.graph.node(pair[1].target).address
        })
    {
        return None;
    }
    let aligned_bytes = aligned_end - aligned_start;
    if selected.iter().map(|edge| target.graph.node(edge.target).size).sum::<u32>() != aligned_bytes
    {
        return None;
    }
    let size_base = source_bytes.max(aligned_bytes);
    let size_delta = if size_base == 0 {
        0.0
    } else {
        source_bytes.abs_diff(aligned_bytes) as f32 / size_base as f32
    };
    if size_delta > MAX_OWNERSHIP_TRANSITION_SIZE_DELTA {
        return None;
    }
    let left = ownership_transition_edge(
        source,
        target,
        matches,
        section,
        original_start,
        aligned_start,
        previous_unit,
    )?;
    let right = ownership_transition_edge(
        source,
        target,
        matches,
        section,
        aligned_end,
        original_end,
        next_unit,
    )?;
    Some(OwnershipTransitionSupport {
        original_target_start: hex(original_start),
        original_target_end: hex(original_end),
        aligned_target_start: hex(aligned_start),
        aligned_target_end: hex(aligned_end),
        source_bytes,
        aligned_target_bytes: aligned_bytes,
        size_delta: round_ratio(size_delta),
        left,
        right,
    })
}

#[derive(Debug)]
struct CompleteUnitAlignment {
    selected: Vec<SequenceEdge>,
    source_functions: u32,
    strong_functions: u32,
    score: f32,
    second_score: f32,
    margin: f32,
    start: u32,
    end: u32,
}

fn complete_unit_alignment(
    source: &MatchTarget,
    target: &MatchTarget,
    matches: &MatchResult,
    unit: &str,
    section: &str,
) -> Option<CompleteUnitAlignment> {
    let source_nodes: Vec<NodeIndex> = source
        .layout()
        .iter()
        .copied()
        .filter(|&node| {
            source.unit_of(node) == Some(unit)
                && source.obj.sections[source.graph.node(node).section].name == section
        })
        .collect();
    if source_nodes.is_empty() {
        return None;
    }

    let mut edges = Vec::new();
    for matched in &matches.matches {
        let target_node = target.graph.node(matched.target);
        if target.obj.sections[target_node.section].name != section {
            continue;
        }
        if source.unit_of(matched.source) == Some(unit) {
            edges.push(SequenceEdge {
                source: matched.source,
                target: matched.target,
                source_position: source.layout_position(matched.source),
                target_position: target.layout_position(matched.target),
                weight: matched.confidence * target_node.size as f32,
                primary: true,
                tier: matched.tier().as_str().to_string(),
                method: matched.method.as_str().to_string(),
                confidence: matched.confidence,
            });
        }
        if let Some(alternative) = matched.runner_up
            && source.unit_of(alternative.source) == Some(unit)
        {
            edges.push(SequenceEdge {
                source: alternative.source,
                target: matched.target,
                source_position: source.layout_position(alternative.source),
                target_position: target.layout_position(matched.target),
                weight: matched.confidence * alternative.relative_score * target_node.size as f32,
                primary: false,
                tier: "alternative".to_string(),
                method: "reported-alternative".to_string(),
                confidence: matched.confidence * alternative.relative_score,
            });
        }
    }
    let best = best_alignment(&edges, None);
    let mut second_score = 0.0f32;
    for &edge in &best.edges {
        let alternative = best_alignment(&edges, Some(edge));
        if alternative.edges.len() == best.edges.len() {
            second_score = second_score.max(alternative.score);
        }
    }
    let selected: Vec<SequenceEdge> =
        best.edges.iter().map(|&index| edges[index].clone()).collect();
    let selected_sources: HashSet<NodeIndex> = selected.iter().map(|edge| edge.source).collect();
    if selected.len() != source_nodes.len()
        || selected_sources.len() != source_nodes.len()
        || source_nodes.iter().any(|node| !selected_sources.contains(node))
        || selected.iter().any(|edge| !edge.primary)
        || selected.windows(2).any(|pair| {
            pair[0].source_position >= pair[1].source_position
                || pair[0].target_position >= pair[1].target_position
        })
    {
        return None;
    }
    let margin = if best.score > 0.0 { 1.0 - second_score / best.score } else { 0.0 };
    if margin < MIN_SEQUENCE_ALIGNMENT_MARGIN {
        return None;
    }
    let first = target.graph.node(selected.first()?.target);
    let last = target.graph.node(selected.last()?.target);
    Some(CompleteUnitAlignment {
        source_functions: source_nodes.len() as u32,
        strong_functions: selected
            .iter()
            .filter(|edge| edge.tier != MatchTier::Candidate.as_str())
            .count() as u32,
        score: best.score,
        second_score,
        margin,
        start: first.address,
        end: last.address.saturating_add(last.size),
        selected,
    })
}

fn sequence_functions(
    source: &MatchTarget,
    target: &MatchTarget,
    selected: &[SequenceEdge],
) -> Vec<SequenceFunction> {
    selected
        .iter()
        .map(|edge| {
            let source_function = source.graph.node(edge.source);
            let target_function = target.graph.node(edge.target);
            SequenceFunction {
                source_name: source.symbol_name(edge.source).to_string(),
                source_address: hex(source_function.address),
                target_address: hex(target_function.address),
                target_end: hex(target_function.address.saturating_add(target_function.size)),
                size: target_function.size,
                tier: edge.tier.clone(),
                method: edge.method.clone(),
                confidence: round_ratio(edge.confidence),
                primary: edge.primary,
            }
        })
        .collect()
}

fn relative_size_delta(source_bytes: u32, target_bytes: u32) -> f32 {
    let base = source_bytes.max(target_bytes);
    if base == 0 { 0.0 } else { source_bytes.abs_diff(target_bytes) as f32 / base as f32 }
}

fn direct_anchor_count_for_owner_revision(
    unit: &CoverageUnit,
    section: &str,
    start: u32,
    end: u32,
    allowed_owner: &str,
) -> u32 {
    unit.anchors
        .iter()
        .filter(|anchor| {
            let anchor_start =
                u32::from_str_radix(anchor.target_address.trim_start_matches("0x"), 16)
                    .expect("coverage addresses are generated as hexadecimal");
            let anchor_end = u32::from_str_radix(anchor.target_end.trim_start_matches("0x"), 16)
                .expect("coverage addresses are generated as hexadecimal");
            anchor.section == section
                && anchor_start >= start
                && anchor_end <= end
                && anchor.size >= 16
                && !anchor.source_weak
                && !anchor.target_weak
                && anchor.source_extent_known
                && anchor.target_extent_known
                && anchor.source_unit_explicit
                && anchor.source_unit_wholly_owned
                && !anchor.template_instantiation
                && anchor.unique_source
                && anchor.unique_target
                && anchor.normalized_body_equal
                && anchor.relocation_layout_equal
                && anchor.existing_target_owner.as_deref().is_none_or(|owner| {
                    owner == unit.name
                        || owner == allowed_owner
                        || anchor.existing_owner_autogenerated
                })
        })
        .count() as u32
}

fn partitioned_target_range(
    target: &MatchTarget,
    selected: &[SequenceEdge],
    section: &str,
    start: u32,
    end: u32,
    required_owner: Option<&str>,
) -> Option<Vec<GapHelper>> {
    let nodes: Vec<NodeIndex> = target
        .layout()
        .iter()
        .copied()
        .filter(|&node| {
            let function = target.graph.node(node);
            target.obj.sections[function.section].name == section
                && function.address >= start
                && function.address.saturating_add(function.size) <= end
        })
        .collect();
    if nodes.is_empty()
        || target.graph.node(nodes[0]).address != start
        || target
            .graph
            .node(*nodes.last().expect("nonempty target range"))
            .address
            .saturating_add(target.graph.node(*nodes.last().expect("nonempty target range")).size)
            != end
        || nodes.windows(2).any(|pair| {
            let left = target.graph.node(pair[0]);
            left.address.saturating_add(left.size) != target.graph.node(pair[1]).address
        })
        || required_owner.is_some_and(|owner| {
            nodes.iter().any(|node| {
                target.unit_of(*node) != Some(owner) || target.obj.is_unit_autogenerated(owner)
            })
        })
    {
        return None;
    }
    let selected_targets: HashSet<NodeIndex> = selected.iter().map(|edge| edge.target).collect();
    if selected_targets.len() != selected.len()
        || selected_targets.iter().any(|node| !nodes.contains(node))
    {
        return None;
    }
    let mut helpers = Vec::new();
    for node in nodes.iter().copied().filter(|node| !selected_targets.contains(node)) {
        let function = target.graph.node(node);
        let callers: Vec<NodeIndex> = function.callers.clone();
        if callers.is_empty()
            || callers.iter().any(|caller| {
                let caller = target.graph.node(*caller);
                target.obj.sections[caller.section].name != section
                    || caller.address < start
                    || caller.address.saturating_add(caller.size) > end
            })
            || !callers.iter().any(|caller| selected_targets.contains(caller))
        {
            return None;
        }
        helpers.push(GapHelper {
            target_address: hex(function.address),
            target_end: hex(function.address.saturating_add(function.size)),
            size: function.size,
            callers: callers.iter().map(|caller| hex(target.graph.node(*caller).address)).collect(),
        });
    }
    Some(helpers)
}

#[allow(clippy::too_many_arguments)]
fn adjacent_owner_transition(
    source: &MatchTarget,
    target: &MatchTarget,
    matches: &MatchResult,
    units: &BTreeMap<String, CoverageUnit>,
    section: &str,
    previous: &SplitRange,
    candidate: &SplitRange,
    next: &SplitRange,
    target_previous: &SplitRange,
    target_next: &SplitRange,
    side: &'static str,
) -> Option<(AdjacentOwnerTransition, Vec<SequenceEdge>)> {
    let candidate_alignment =
        complete_unit_alignment(source, target, matches, &candidate.unit, section)?;
    if candidate_alignment.source_functions < MIN_ADJACENT_OWNER_TRANSITION_FUNCTIONS
        || candidate_alignment.strong_functions < MIN_ADJACENT_OWNER_TRANSITION_STRONG_FUNCTIONS
    {
        return None;
    }
    let candidate_start = candidate_alignment.start;
    let candidate_end = candidate_alignment.end;
    let candidate_source_bytes = candidate.end.saturating_sub(candidate.start);
    let candidate_target_bytes = candidate_end.checked_sub(candidate_start)?;
    let candidate_size_delta = relative_size_delta(candidate_source_bytes, candidate_target_bytes);
    if candidate_size_delta > MAX_ADJACENT_OWNER_SIZE_DELTA {
        return None;
    }
    let candidate_helpers = partitioned_target_range(
        target,
        &candidate_alignment.selected,
        section,
        candidate_start,
        candidate_end,
        None,
    )?;
    if !candidate_helpers.is_empty() {
        return None;
    }

    let (owner_source, owner_target, owner_unit, revised_start, revised_end) = match side {
        "next-prefix" => {
            if candidate_start != target_previous.end
                || target_next.start >= candidate_end
                || candidate_end >= target_next.end
            {
                return None;
            }
            (next, target_next, next.unit.as_str(), candidate_end, target_next.end)
        }
        "previous-suffix" => {
            if candidate_end != target_next.start
                || candidate_start <= target_previous.start
                || candidate_start >= target_previous.end
            {
                return None;
            }
            (
                previous,
                target_previous,
                previous.unit.as_str(),
                target_previous.start,
                candidate_start,
            )
        }
        _ => return None,
    };
    let direct_anchors = direct_anchor_count_for_owner_revision(
        units.get(&candidate.unit)?,
        section,
        candidate_start,
        candidate_end,
        owner_unit,
    );
    if direct_anchors < MIN_ADJACENT_OWNER_TRANSITION_DIRECT_ANCHORS {
        return None;
    }
    let mut overlaps_owner = false;
    for edge in &candidate_alignment.selected {
        if let Some(owner) = target.unit_of(edge.target)
            && !target.obj.is_unit_autogenerated(owner)
        {
            if owner != owner_unit {
                return None;
            }
            overlaps_owner = true;
        }
    }
    if !overlaps_owner {
        return None;
    }

    let owner_alignment = complete_unit_alignment(source, target, matches, owner_unit, section)?;
    if owner_alignment.source_functions < MIN_ADJACENT_OWNER_SUPPORT_FUNCTIONS
        || owner_alignment.strong_functions < MIN_ADJACENT_OWNER_SUPPORT_STRONG_FUNCTIONS
        || owner_alignment.start != revised_start
        || owner_alignment.end != revised_end
    {
        return None;
    }
    let owner_source_bytes = owner_source.end.saturating_sub(owner_source.start);
    let owner_target_bytes = revised_end.checked_sub(revised_start)?;
    let owner_size_delta = relative_size_delta(owner_source_bytes, owner_target_bytes);
    if owner_size_delta > MAX_ADJACENT_OWNER_SIZE_DELTA {
        return None;
    }
    let owner_helpers = partitioned_target_range(
        target,
        &owner_alignment.selected,
        section,
        revised_start,
        revised_end,
        Some(owner_unit),
    )?;
    if owner_helpers.len() as u32 > MAX_ADJACENT_OWNER_GAP_HELPERS {
        return None;
    }
    let owner_target_functions = owner_alignment.selected.len() as u32 + owner_helpers.len() as u32;
    let target_section = target.obj.sections.by_name(section).ok().flatten()?.1;
    let align = default_section_align(target_section) as u32;
    if candidate_start % align != 0
        || candidate_end % align != 0
        || revised_start % align != 0
        || revised_end % align != 0
    {
        return None;
    }

    let transition = AdjacentOwnerTransition {
        section: section.to_string(),
        side: side.to_string(),
        target_start: hex(candidate_start),
        target_end: hex(candidate_end),
        target_bytes: candidate_target_bytes,
        source_bytes: candidate_source_bytes,
        previous_unit: previous.unit.clone(),
        next_unit: next.unit.clone(),
        source_functions: candidate_alignment.source_functions,
        aligned_functions: candidate_alignment.selected.len() as u32,
        strong_functions: candidate_alignment.strong_functions,
        direct_anchors,
        match_ratio: 1.0,
        target_coverage: 1.0,
        best_alignment_score: round_ratio(candidate_alignment.score),
        second_alignment_score: round_ratio(candidate_alignment.second_score),
        alignment_margin: round_ratio(candidate_alignment.margin),
        size_delta: round_ratio(candidate_size_delta),
        owner: AdjacentOwnerSupport {
            unit: owner_unit.to_string(),
            original_start: hex(owner_target.start),
            original_end: hex(owner_target.end),
            revised_start: hex(revised_start),
            revised_end: hex(revised_end),
            source_bytes: owner_source_bytes,
            target_bytes: owner_target_bytes,
            size_delta: round_ratio(owner_size_delta),
            source_functions: owner_alignment.source_functions,
            aligned_functions: owner_alignment.selected.len() as u32,
            target_functions: owner_target_functions,
            strong_functions: owner_alignment.strong_functions,
            functions: sequence_functions(source, target, &owner_alignment.selected),
            gap_helpers: owner_helpers,
        },
        functions: sequence_functions(source, target, &candidate_alignment.selected),
        eligible: true,
        reasons: Vec::new(),
    };
    Some((transition, candidate_alignment.selected))
}

fn add_adjacent_owner_transition_evidence(
    source: &MatchTarget,
    target: &MatchTarget,
    matches: &MatchResult,
    source_extracts: &[ExtractSpec],
    target_extracts: &[ExtractSpec],
    units: &mut BTreeMap<String, CoverageUnit>,
) {
    let source_ranges = code_split_ranges(source);
    let target_ranges = code_split_ranges(target);
    for (section, source_section) in source_ranges {
        let Some(target_section) = target_ranges.get(&section) else { continue };
        for window in source_section.windows(3) {
            let (previous, candidate, next) = (&window[0], &window[1], &window[2]);
            if candidate.autogenerated
                || previous.autogenerated
                || next.autogenerated
                || previous.unit == candidate.unit
                || candidate.unit == next.unit
                || previous.unit == next.unit
                || unique_unit_range(target_section, &candidate.unit).is_some()
            {
                continue;
            }
            let (Some(target_previous), Some(target_next)) = (
                unique_unit_range(target_section, &previous.unit),
                unique_unit_range(target_section, &next.unit),
            ) else {
                continue;
            };
            if target_previous.autogenerated || target_next.autogenerated {
                continue;
            }
            for side in ["next-prefix", "previous-suffix"] {
                let Some((transition, candidate_edges)) = adjacent_owner_transition(
                    source,
                    target,
                    matches,
                    units,
                    &section,
                    previous,
                    candidate,
                    next,
                    target_previous,
                    target_next,
                    side,
                ) else {
                    continue;
                };
                let selected: Vec<&SequenceEdge> = candidate_edges.iter().collect();
                let required = boundary_required_extracts(
                    source,
                    target,
                    &selected,
                    source_extracts,
                    target_extracts,
                );
                let unit = units
                    .get_mut(&candidate.unit)
                    .expect("source unit was collected before adjacent-owner evidence");
                unit.required_extracts.extend(required);
                unit.required_extracts.sort_by(|a, b| {
                    a.target_address
                        .cmp(&b.target_address)
                        .then(a.source_symbol.cmp(&b.source_symbol))
                });
                unit.required_extracts.dedup_by(|a, b| {
                    a.target_symbol == b.target_symbol
                        && a.rename == b.rename
                        && a.binary == b.binary
                        && a.header == b.header
                });
                unit.adjacent_owner_transitions.push(transition);
            }
        }
    }
}

fn add_boundary_sequence_evidence(
    source: &MatchTarget,
    target: &MatchTarget,
    matches: &MatchResult,
    source_extracts: &[ExtractSpec],
    target_extracts: &[ExtractSpec],
    units: &mut BTreeMap<String, CoverageUnit>,
) {
    let source_ranges = code_split_ranges(source);
    let target_ranges = code_split_ranges(target);

    for (section_name, source_section) in source_ranges {
        let Some(target_section) = target_ranges.get(&section_name) else { continue };
        for window in source_section.windows(3) {
            let (previous, candidate, next) = (&window[0], &window[1], &window[2]);
            if candidate.autogenerated
                || previous.autogenerated
                || next.autogenerated
                || previous.unit == candidate.unit
                || candidate.unit == next.unit
                || previous.unit == next.unit
            {
                continue;
            }
            let (Some(target_previous), Some(target_next)) = (
                unique_unit_range(target_section, &previous.unit),
                unique_unit_range(target_section, &next.unit),
            ) else {
                continue;
            };
            if target_previous.autogenerated || target_next.autogenerated {
                continue;
            }
            let start = target_previous.end;
            let end = target_next.start;
            if start >= end {
                continue;
            }

            let source_nodes: Vec<NodeIndex> = (0..source.graph.len() as NodeIndex)
                .filter(|&node| source.unit_of(node) == Some(candidate.unit.as_str()))
                .collect();
            if source_nodes.is_empty() {
                continue;
            }
            let mut edges = Vec::new();
            for m in &matches.matches {
                let target_node = target.graph.node(m.target);
                let in_gap = target.obj.sections[target_node.section].name == section_name
                    && target_node.address >= start
                    && target_node.address.saturating_add(target_node.size) <= end;
                if !in_gap {
                    continue;
                }
                if source.unit_of(m.source) == Some(candidate.unit.as_str()) {
                    edges.push(SequenceEdge {
                        source: m.source,
                        target: m.target,
                        source_position: source.layout_position(m.source),
                        target_position: target.layout_position(m.target),
                        weight: m.confidence * target_node.size as f32,
                        primary: true,
                        tier: m.tier().as_str().to_string(),
                        method: m.method.as_str().to_string(),
                        confidence: m.confidence,
                    });
                }
                if let Some(alternative) = m.runner_up
                    && source.unit_of(alternative.source) == Some(candidate.unit.as_str())
                {
                    edges.push(SequenceEdge {
                        source: alternative.source,
                        target: m.target,
                        source_position: source.layout_position(alternative.source),
                        target_position: target.layout_position(m.target),
                        weight: m.confidence * alternative.relative_score * target_node.size as f32,
                        primary: false,
                        tier: "alternative".to_string(),
                        method: "reported-alternative".to_string(),
                        confidence: m.confidence * alternative.relative_score,
                    });
                }
            }
            let alignment = best_alignment(&edges, None);
            let mut second_score = 0.0f32;
            for &edge in &alignment.edges {
                let alternative = best_alignment(&edges, Some(edge));
                if alternative.edges.len() == alignment.edges.len() {
                    second_score = second_score.max(alternative.score);
                }
            }
            let selected: Vec<&SequenceEdge> =
                alignment.edges.iter().map(|&index| &edges[index]).collect();
            let aligned_functions = selected.len() as u32;
            let aligned_bytes =
                selected.iter().map(|edge| target.graph.node(edge.target).size).sum::<u32>();
            let strong_functions = selected
                .iter()
                .filter(|edge| edge.primary && edge.tier != MatchTier::Candidate.as_str())
                .count() as u32;
            // A pre-existing name may itself have come from automated matching,
            // so it cannot independently corroborate unit ownership. Reuse the
            // exact-body inventory instead, allowing small bodies only as part
            // of an already bounded multi-function sequence.
            let direct_anchors = units
                .get(&candidate.unit)
                .into_iter()
                .flat_map(|unit| unit.anchors.iter())
                .filter(|anchor| {
                    let anchor_start =
                        u32::from_str_radix(anchor.target_address.trim_start_matches("0x"), 16)
                            .expect("coverage addresses are generated as hexadecimal");
                    let anchor_end =
                        u32::from_str_radix(anchor.target_end.trim_start_matches("0x"), 16)
                            .expect("coverage addresses are generated as hexadecimal");
                    anchor_start >= start
                        && anchor_end <= end
                        && anchor.size >= 16
                        && !anchor.source_weak
                        && !anchor.target_weak
                        && anchor.source_extent_known
                        && anchor.target_extent_known
                        && anchor.source_unit_explicit
                        && anchor.source_unit_wholly_owned
                        && !anchor.template_instantiation
                        && anchor.unique_source
                        && anchor.unique_target
                        && anchor.normalized_body_equal
                        && anchor.relocation_layout_equal
                        && anchor.existing_target_owner.as_deref().is_none_or(|owner| {
                            owner == candidate.unit || anchor.existing_owner_autogenerated
                        })
                })
                .count() as u32;
            let target_bytes = end - start;
            let target_functions = target
                .layout()
                .iter()
                .filter(|&&node| {
                    let function = target.graph.node(node);
                    target.obj.sections[function.section].name == section_name
                        && function.address >= start
                        && function.address.saturating_add(function.size) <= end
                })
                .count() as u32;
            let match_ratio = aligned_functions as f32 / source_nodes.len() as f32;
            let primary_in_gap = edges.iter().filter(|edge| edge.primary).count() as u32;
            let order_ratio = if primary_in_gap == 0 {
                0.0
            } else {
                selected.iter().filter(|edge| edge.primary).count() as f32 / primary_in_gap as f32
            };
            let target_coverage = aligned_bytes as f32 / target_bytes as f32;
            let alignment_margin =
                if alignment.score > 0.0 { 1.0 - second_score / alignment.score } else { 0.0 };
            let source_bytes = candidate.end.saturating_sub(candidate.start);
            let ownership_transition_support = ownership_transition_support(
                source,
                target,
                matches,
                &selected,
                &source_nodes,
                &section_name,
                start,
                end,
                source_bytes,
                strong_functions,
                alignment_margin,
                &previous.unit,
                &next.unit,
            );
            let (start, end, target_bytes, target_functions, target_coverage) =
                ownership_transition_support.as_ref().map_or(
                    (start, end, target_bytes, target_functions, target_coverage),
                    |support| {
                        (
                            u32::from_str_radix(
                                support.aligned_target_start.trim_start_matches("0x"),
                                16,
                            )
                            .expect("coverage addresses are generated as hexadecimal"),
                            u32::from_str_radix(
                                support.aligned_target_end.trim_start_matches("0x"),
                                16,
                            )
                            .expect("coverage addresses are generated as hexadecimal"),
                            support.aligned_target_bytes,
                            selected.len() as u32,
                            1.0,
                        )
                    },
                );
            let mut sequence_reasons = Vec::new();
            if aligned_functions < MIN_SEQUENCE_FUNCTIONS {
                sequence_reasons
                    .push("too few functions participate in the ordered alignment".to_string());
            }
            if match_ratio < MIN_SEQUENCE_MATCH_RATIO {
                sequence_reasons
                    .push("ordered alignment covers too few source functions".to_string());
            }
            if order_ratio < MIN_SEQUENCE_ORDER_RATIO {
                sequence_reasons
                    .push("function matches do not preserve enough source order".to_string());
            }
            if aligned_bytes < MIN_SEQUENCE_MATCHED_BYTES {
                sequence_reasons
                    .push("ordered alignment covers too few function bytes".to_string());
            }
            if target_coverage < MIN_SEQUENCE_TARGET_COVERAGE {
                sequence_reasons.push(
                    "ordered functions cover too little of the bounded target gap".to_string(),
                );
            }
            if strong_functions < MIN_SEQUENCE_STRONG_FUNCTIONS {
                sequence_reasons
                    .push("ordered alignment lacks strong function matches".to_string());
            }
            if direct_anchors < MIN_SEQUENCE_DIRECT_ANCHORS {
                sequence_reasons
                    .push("ordered alignment lacks independent direct anchors".to_string());
            }
            if alignment_margin < MIN_SEQUENCE_ALIGNMENT_MARGIN {
                sequence_reasons
                    .push("an alternative ordered alignment scores too closely".to_string());
            }
            if selected.iter().any(|edge| !edge.primary) {
                sequence_reasons
                    .push("best ordered alignment depends on a reported runner-up".to_string());
            }
            let layout_support_group = units.get(&candidate.unit).and_then(|unit| {
                layout_boundary_support(unit, &section_name, start, end, LayoutBoundaryMetrics {
                    source_bytes,
                    target_bytes,
                    source_functions: source_nodes.len() as u32,
                    target_functions,
                })
            });
            let vtable_support = vtable_boundary_support(
                source,
                target,
                matches,
                &selected,
                &VtableBoundaryContext {
                    unit: &candidate.unit,
                    section: &section_name,
                    start,
                    end,
                    source_bytes,
                    target_bytes,
                    source_functions: source_nodes.len() as u32,
                    target_functions,
                    match_ratio,
                    target_coverage,
                    alignment_margin,
                },
            );
            let mut boundary_reasons = Vec::new();
            if target_bytes.saturating_mul(2) < source_bytes
                || target_bytes > source_bytes.saturating_mul(3) / 2
            {
                boundary_reasons
                    .push("bounded target gap size is implausible for the source unit".to_string());
            }
            let conflicting_owners: Vec<&str> = target_section
                .iter()
                .filter(|range| range.start < end && start < range.end)
                .filter(|range| range.unit != candidate.unit && !range.autogenerated)
                .map(|range| range.unit.as_str())
                .collect();
            if !conflicting_owners.is_empty() {
                boundary_reasons
                    .push("bounded target gap overlaps another explicit unit".to_string());
            }
            let target_obj_section = target
                .obj
                .sections
                .by_name(&section_name)
                .ok()
                .flatten()
                .map(|(_, section)| section);
            if target_obj_section.is_none_or(|section| {
                let align = default_section_align(section) as u32;
                start % align != 0 || end % align != 0
            }) {
                boundary_reasons.push("bounded target gap is not section-aligned".to_string());
            }

            let matched_sequence = sequence_reasons.is_empty();
            let layout_corroborated = layout_support_group.is_some();
            let vtable_corroborated = vtable_support.is_some();
            let ownership_transition_corroborated = ownership_transition_support.is_some();
            let eligible = boundary_reasons.is_empty()
                && (matched_sequence
                    || layout_corroborated
                    || vtable_corroborated
                    || ownership_transition_corroborated);
            let acceptance_method = if matched_sequence {
                "matched-sequence"
            } else if ownership_transition_corroborated {
                "ownership-transition-boundary"
            } else if layout_corroborated {
                "layout-corroborated-boundary"
            } else if vtable_corroborated {
                "vtable-corroborated-boundary"
            } else {
                "none"
            };
            let reasons = if eligible {
                Vec::new()
            } else {
                sequence_reasons.into_iter().chain(boundary_reasons).collect()
            };
            if eligible && (matched_sequence || ownership_transition_corroborated) {
                let required = boundary_required_extracts(
                    source,
                    target,
                    &selected,
                    source_extracts,
                    target_extracts,
                );
                let unit = units
                    .get_mut(&candidate.unit)
                    .expect("source unit was collected before sequence evidence");
                unit.required_extracts.extend(required);
                unit.required_extracts.sort_by(|a, b| {
                    a.target_address
                        .cmp(&b.target_address)
                        .then(a.source_symbol.cmp(&b.source_symbol))
                });
                unit.required_extracts.dedup_by(|a, b| {
                    a.target_symbol == b.target_symbol
                        && a.rename == b.rename
                        && a.binary == b.binary
                        && a.header == b.header
                });
            }

            let functions = selected
                .iter()
                .map(|edge| {
                    let a = source.graph.node(edge.source);
                    let b = target.graph.node(edge.target);
                    SequenceFunction {
                        source_name: source.symbol_name(edge.source).to_string(),
                        source_address: hex(a.address),
                        target_address: hex(b.address),
                        target_end: hex(b.address + b.size),
                        size: b.size,
                        tier: edge.tier.clone(),
                        method: edge.method.clone(),
                        confidence: round_ratio(edge.confidence),
                        primary: edge.primary,
                    }
                })
                .collect();
            let (vtable_support, gap_helpers) = vtable_support
                .map_or((None, Vec::new()), |(support, helpers)| (Some(support), helpers));
            units
                .get_mut(&candidate.unit)
                .expect("source unit was collected before sequence evidence")
                .boundary_sequences
                .push(BoundarySequence {
                    section: section_name.clone(),
                    target_start: hex(start),
                    target_end: hex(end),
                    target_bytes,
                    target_functions,
                    previous_unit: previous.unit.clone(),
                    next_unit: next.unit.clone(),
                    source_functions: source_nodes.len() as u32,
                    aligned_functions,
                    aligned_bytes,
                    strong_functions,
                    direct_anchors,
                    match_ratio: round_ratio(match_ratio),
                    order_ratio: round_ratio(order_ratio),
                    target_coverage: round_ratio(target_coverage),
                    best_alignment_score: round_ratio(alignment.score),
                    second_alignment_score: round_ratio(second_score),
                    alignment_margin: round_ratio(alignment_margin),
                    acceptance_method: acceptance_method.to_string(),
                    layout_support_group,
                    vtable_support,
                    gap_helpers,
                    ownership_transition_support,
                    functions,
                    eligible,
                    reasons,
                });
        }
    }
}

#[derive(Debug, Clone)]
struct OffsetTransform {
    deltas: Vec<i32>,
    breakpoint: Option<i32>,
    changed_accesses: u32,
}

impl OffsetTransform {
    fn grouping_delta(&self) -> i32 {
        if self.deltas.len() == 2 && self.deltas[0] == 0 { self.deltas[1] } else { self.deltas[0] }
    }
}

#[derive(Debug, Clone)]
struct LayoutPair {
    unit: String,
    source: NodeIndex,
    target: NodeIndex,
    observations: Vec<(i32, i32)>,
    transform: OffsetTransform,
    base_reasons: Vec<String>,
}

fn add_layout_shift_evidence(
    source: &MatchTarget,
    target: &MatchTarget,
    hide_target_names: bool,
    units: &mut BTreeMap<String, CoverageUnit>,
) {
    let source_bodies: Vec<LayoutShiftBody> = (0..source.graph.len() as NodeIndex)
        .map(|node| layout_shift_body(&source.obj, source.graph.node(node)))
        .collect();
    let target_bodies: Vec<LayoutShiftBody> = (0..target.graph.len() as NodeIndex)
        .map(|node| layout_shift_body(&target.obj, target.graph.node(node)))
        .collect();
    let source_hashes = layout_hashes(&source_bodies);
    let target_hashes = layout_hashes(&target_bodies);
    let mut pairs = Vec::new();

    for source_node in 0..source.graph.len() as NodeIndex {
        let Some(unit) = source.unit_of(source_node) else { continue };
        let a = source.graph.node(source_node);
        let source_body = &source_bodies[source_node as usize];
        if a.size < 16
            || source_body.accesses.is_empty()
            || unique_hash_node(&source_hashes, source_body.hash) != Some(source_node)
        {
            continue;
        }
        let Some(target_node) = unique_hash_node(&target_hashes, source_body.hash) else {
            continue;
        };
        let b = target.graph.node(target_node);
        let target_body = &target_bodies[target_node as usize];
        if source_body.bytes != target_body.bytes
            || source.fingerprints[source_node as usize].exact_hash
                == target.fingerprints[target_node as usize].exact_hash
        {
            continue;
        }
        let Some(observations) = corresponding_accesses(source_body, target_body) else { continue };
        let Some(transform) = infer_offset_transform(&observations) else { continue };

        let source_extent_known = source.obj.symbols[a.symbol].size_known
            && normalized_body(&source.obj, a).len() == a.size as usize;
        let target_extent_known = target.obj.symbols[b.symbol].size_known
            && normalized_body(&target.obj, b).len() == b.size as usize;
        let target_owner = target.unit_of(target_node).map(str::to_string);
        let owner_auto =
            target_owner.as_deref().is_some_and(|name| target.obj.is_unit_autogenerated(name));
        let source_unit_explicit = !source.obj.is_unit_autogenerated(unit);
        let source_unit_wholly_owned =
            range_is_owned_by(source, a.section, a.address, a.address + a.size, unit);
        let template =
            is_template_symbol(source, source_node) || is_template_symbol(target, target_node);
        let reloc_equal = relocation_layout(a) == relocation_layout(b);
        let align = required_alignment(target, b);
        let mut reasons = Vec::new();
        if source.is_weak(source_node) || target.is_weak(target_node) {
            reasons.push("weak symbol cannot establish ownership".to_string());
        }
        if !source_extent_known || !target_extent_known {
            reasons.push("function extent is not completely known".to_string());
        }
        if !source_unit_explicit {
            reasons.push("source unit is autogenerated".to_string());
        }
        if !source_unit_wholly_owned {
            reasons.push("source function is not wholly owned by one unit".to_string());
        }
        if template {
            reasons.push("template instantiation cannot establish ownership alone".to_string());
        }
        if !reloc_equal {
            reasons.push("relocation layout differs".to_string());
        }
        if target_owner.as_deref().is_some_and(|name| name != unit && !owner_auto) {
            reasons.push("target range is owned by another explicit unit".to_string());
        }
        if b.address % align != 0 || (b.address + b.size) % align != 0 {
            reasons.push("function range is not split-aligned".to_string());
        }
        pairs.push(LayoutPair {
            unit: unit.to_string(),
            source: source_node,
            target: target_node,
            observations,
            transform,
            base_reasons: reasons,
        });
    }

    let mut groups: BTreeMap<(String, decomp_toolkit::obj::SectionIndex, i32), Vec<usize>> =
        BTreeMap::new();
    for (index, pair) in pairs.iter().enumerate() {
        let section = target.graph.node(pair.target).section;
        groups
            .entry((pair.unit.clone(), section, pair.transform.grouping_delta()))
            .or_default()
            .push(index);
    }

    for ((unit_name, _, grouping_delta), indexes) in groups {
        let support: Vec<usize> =
            indexes.iter().copied().filter(|&index| pairs[index].base_reasons.is_empty()).collect();
        let observations: Vec<(i32, i32)> =
            support.iter().flat_map(|&index| pairs[index].observations.iter().copied()).collect();
        let group_transform = infer_offset_transform(&observations);
        let support_functions = support.len() as u32;
        let support_bytes: u32 = support
            .iter()
            .map(|&index| source.graph.node(pairs[index].source).size)
            .fold(0, u32::saturating_add);
        let support_changed_accesses =
            group_transform.as_ref().map_or(0, |transform| transform.changed_accesses);
        let mut group_reasons = Vec::new();
        if support_functions < MIN_LAYOUT_SHIFT_FUNCTIONS {
            group_reasons.push("layout shift lacks a second corroborating function".to_string());
        }
        if support_bytes < MIN_LAYOUT_SHIFT_BYTES {
            group_reasons.push("layout-shift support is smaller than policy minimum".to_string());
        }
        if support_changed_accesses < MIN_LAYOUT_SHIFT_CHANGED_ACCESSES {
            group_reasons
                .push("layout shift has too few changed this-relative accesses".to_string());
        }
        if group_transform.is_none() {
            group_reasons
                .push("functions disagree on one simple layout transformation".to_string());
        }
        let group_id = layout_group_id(
            source,
            target,
            group_transform
                .as_ref()
                .map(|transform| transform.deltas.as_slice())
                .unwrap_or(std::slice::from_ref(&grouping_delta)),
            &support,
        );

        if let Some(unit) = units.get_mut(&unit_name) {
            unit.layout_shift_candidates += indexes.len() as u32;
        }
        for index in indexes {
            let pair = &pairs[index];
            let a = source.graph.node(pair.source);
            let b = target.graph.node(pair.target);
            let source_body = &source_bodies[pair.source as usize];
            let target_body = &target_bodies[pair.target as usize];
            let source_name = source.symbol_name(pair.source);
            let target_name = target.symbol_name(pair.target);
            let target_owner = target.unit_of(pair.target).map(str::to_string);
            let owner_auto =
                target_owner.as_deref().is_some_and(|name| target.obj.is_unit_autogenerated(name));
            let section = &target.obj.sections[b.section];
            let align = required_alignment(target, b);
            let mut reasons = pair.base_reasons.clone();
            reasons.extend(group_reasons.iter().cloned());
            if !support.contains(&index) && group_reasons.is_empty() {
                reasons
                    .push("function failed an individual layout-shift ownership gate".to_string());
            }
            let transform = group_transform.as_ref().unwrap_or(&pair.transform);
            units
                .get_mut(&unit_name)
                .expect("source unit was collected before function evidence")
                .layout_shift_anchors
                .push(LayoutShiftAnchor {
                    source_name: source_name.to_string(),
                    source_address: hex(a.address),
                    target_name: if hide_target_names {
                        String::new()
                    } else {
                        target_name.to_string()
                    },
                    target_address: hex(b.address),
                    target_end: hex(b.address + b.size),
                    section: section.name.clone(),
                    size: a.size,
                    source_local: source.is_local(pair.source),
                    target_local: target.is_local(pair.target),
                    source_weak: source.is_weak(pair.source),
                    target_weak: target.is_weak(pair.target),
                    source_extent_known: source.obj.symbols[a.symbol].size_known
                        && normalized_body(&source.obj, a).len() == a.size as usize,
                    target_extent_known: target.obj.symbols[b.symbol].size_known
                        && normalized_body(&target.obj, b).len() == b.size as usize,
                    source_unit_explicit: !source.obj.is_unit_autogenerated(&unit_name),
                    source_unit_wholly_owned: range_is_owned_by(
                        source,
                        a.section,
                        a.address,
                        a.address + a.size,
                        &unit_name,
                    ),
                    template_instantiation: is_template_symbol(source, pair.source)
                        || is_template_symbol(target, pair.target),
                    unique_source: true,
                    unique_target: true,
                    layout_masked_body_equal: source_body.bytes == target_body.bytes,
                    relocation_layout_equal: relocation_layout(a) == relocation_layout(b),
                    this_accesses: pair.observations.len() as u32,
                    changed_this_accesses: pair.transform.changed_accesses,
                    offset_deltas: transform.deltas.clone(),
                    inferred_breakpoint: transform.breakpoint,
                    support_group: group_id.clone(),
                    support_functions,
                    support_bytes,
                    support_changed_accesses,
                    required_alignment: align,
                    existing_target_owner: target_owner,
                    existing_owner_autogenerated: owner_auto,
                    eligible: reasons.is_empty(),
                    reasons,
                });
        }
    }
}

fn layout_hashes(bodies: &[LayoutShiftBody]) -> HashMap<u64, Vec<NodeIndex>> {
    let mut hashes = HashMap::new();
    for (index, body) in bodies.iter().enumerate() {
        if !body.accesses.is_empty() {
            hashes.entry(body.hash).or_insert_with(Vec::new).push(index as NodeIndex);
        }
    }
    hashes
}

fn corresponding_accesses(
    source: &LayoutShiftBody,
    target: &LayoutShiftBody,
) -> Option<Vec<(i32, i32)>> {
    if source.accesses.len() != target.accesses.len() || source.accesses.is_empty() {
        return None;
    }
    source
        .accesses
        .iter()
        .zip(&target.accesses)
        .map(|(a, b)| {
            (a.instruction_offset == b.instruction_offset
                && plausible_object_offset(a.object_offset)
                && plausible_object_offset(b.object_offset))
            .then_some((a.object_offset, b.object_offset))
        })
        .collect()
}

fn plausible_object_offset(offset: i32) -> bool { (0..=0x10000).contains(&offset) }

fn infer_offset_transform(observations: &[(i32, i32)]) -> Option<OffsetTransform> {
    let mut mappings = BTreeMap::new();
    for &(source, target) in observations {
        if mappings.insert(source, target).is_some_and(|previous| previous != target) {
            return None;
        }
    }
    let mut deltas = Vec::new();
    let mut previous_target = None;
    let mut breakpoint = None;
    for (&source, &target) in &mappings {
        let current_delta = target.wrapping_sub(source);
        if previous_target.is_some_and(|previous| target <= previous) {
            return None;
        }
        if deltas.last().copied() != Some(current_delta) {
            if !deltas.is_empty() {
                breakpoint = Some(source);
            }
            deltas.push(current_delta);
            if deltas.len() > 2 {
                return None;
            }
        }
        previous_target = Some(target);
    }
    if deltas.iter().all(|&delta| delta == 0) {
        return None;
    }
    let changed_accesses =
        observations.iter().filter(|(source, target)| source != target).count() as u32;
    Some(OffsetTransform { deltas, breakpoint, changed_accesses })
}

fn layout_group_id(
    source: &MatchTarget,
    target: &MatchTarget,
    deltas: &[i32],
    support: &[usize],
) -> String {
    let mut identity = Vec::with_capacity(deltas.len() * 4 + support.len() * 8);
    for delta in deltas {
        identity.extend_from_slice(&delta.to_be_bytes());
    }
    for &index in support {
        // `support` contains indexes into the caller's pair vector, so only its
        // stable ordinal is needed to distinguish independently supported groups.
        identity.extend_from_slice(&(index as u64).to_be_bytes());
    }
    format!("layout-shift:{}:{}:{:016x}", source.name, target.name, xxh3_64(&identity))
}

fn required_alignment(target: &MatchTarget, node: &FunctionNode) -> u32 {
    let section = &target.obj.sections[node.section];
    target
        .obj
        .symbols
        .for_section_range(node.section, node.address..node.address + node.size)
        .filter(|&(_, symbol)| symbol.size_known && symbol.size > 0)
        .filter_map(|(_, symbol)| symbol.align)
        .max()
        .unwrap_or(default_section_align(section) as u32)
        .max(default_section_align(section) as u32)
}

fn relocation_layout(node: &FunctionNode) -> Vec<(u32, decomp_toolkit::obj::ObjRelocKind)> {
    node.refs.iter().map(|reference| (reference.offset, reference.kind)).collect()
}

fn is_template_name(name: &str) -> bool {
    let callable = name.split_once('(').map_or(name, |(callable, _)| callable);
    callable.contains('<') && callable.contains('>')
}

fn is_template_symbol(target: &MatchTarget, node: NodeIndex) -> bool {
    let symbol = &target.obj.symbols[target.graph.node(node).symbol];
    is_template_name(symbol.demangled_name.as_deref().unwrap_or(&symbol.name))
}

fn unique_hash_node(hashes: &HashMap<u64, Vec<NodeIndex>>, hash: u64) -> Option<NodeIndex> {
    let nodes = hashes.get(&hash)?;
    (nodes.len() == 1).then_some(nodes[0])
}

/// Confirm that the complete function interval belongs to one explicit source
/// split, rather than inferring ownership from its first instruction alone.
fn range_is_owned_by(
    object: &MatchTarget,
    section_index: decomp_toolkit::obj::SectionIndex,
    start: u32,
    end: u32,
    unit: &str,
) -> bool {
    let section = &object.obj.sections[section_index];
    let Some((owner_start, owner)) = section.splits.for_address(start) else { return false };
    let owner_end =
        if owner.end == 0 { (section.address + section.size) as u32 } else { owner.end };
    owner_start <= start && owner_end >= end && owner.unit == unit
}

#[allow(clippy::too_many_arguments)]
fn eligibility_reasons(
    size: u32,
    source_weak: bool,
    target_weak: bool,
    source_extent_known: bool,
    target_extent_known: bool,
    source_unit_explicit: bool,
    source_unit_wholly_owned: bool,
    template: bool,
    body_equal: bool,
    reloc_equal: bool,
    owner: Option<&str>,
    owner_autogenerated: bool,
    unit: &str,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if size < MIN_ANCHOR_BYTES {
        reasons.push("anchor is smaller than policy minimum".to_string());
    }
    if source_weak || target_weak {
        reasons.push("weak symbol cannot establish ownership".to_string());
    }
    if !source_extent_known || !target_extent_known {
        reasons.push("function extent is not completely known".to_string());
    }
    if !source_unit_explicit {
        reasons.push("source unit is autogenerated".to_string());
    }
    if !source_unit_wholly_owned {
        reasons.push("source function is not wholly owned by one unit".to_string());
    }
    if template {
        reasons.push("template instantiation cannot establish ownership alone".to_string());
    }
    if !body_equal {
        reasons.push("normalized bytes differ after hash lookup".to_string());
    }
    if !reloc_equal {
        reasons.push("relocation layout differs".to_string());
    }
    if owner.is_some_and(|name| name != unit && !owner_autogenerated) {
        reasons.push("target range is owned by another explicit unit".to_string());
    }
    reasons
}

fn hex(value: u32) -> String { format!("{value:#010X}") }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eligibility_is_conservative_and_deterministic() {
        assert!(
            eligibility_reasons(
                128, false, false, true, true, true, true, false, true, true, None, false, "A",
            )
            .is_empty()
        );
        assert_eq!(
            eligibility_reasons(
                64,
                true,
                false,
                false,
                true,
                false,
                false,
                true,
                false,
                false,
                Some("B"),
                false,
                "A",
            ),
            vec![
                "anchor is smaller than policy minimum",
                "weak symbol cannot establish ownership",
                "function extent is not completely known",
                "source unit is autogenerated",
                "source function is not wholly owned by one unit",
                "template instantiation cannot establish ownership alone",
                "normalized bytes differ after hash lookup",
                "relocation layout differs",
                "target range is owned by another explicit unit",
            ]
        );
    }

    #[test]
    fn autogenerated_ownership_does_not_conflict() {
        assert!(
            eligibility_reasons(
                128,
                false,
                false,
                true,
                true,
                true,
                true,
                false,
                true,
                true,
                Some("auto_text"),
                true,
                "A",
            )
            .is_empty()
        );
    }

    #[test]
    fn duplicate_normalized_bodies_are_not_unique() {
        let hashes = HashMap::from([(7, vec![3]), (8, vec![4, 5])]);
        assert_eq!(unique_hash_node(&hashes, 7), Some(3));
        assert_eq!(unique_hash_node(&hashes, 8), None);
        assert_eq!(unique_hash_node(&hashes, 9), None);
    }

    #[test]
    fn body_confirmation_blocks_a_hash_collision() {
        let reasons = eligibility_reasons(
            128, false, false, true, true, true, true, false, false, true, None, false, "A",
        );
        assert_eq!(reasons, vec!["normalized bytes differ after hash lookup"]);
    }

    #[test]
    fn names_only_apply_the_template_exclusion() {
        assert!(!is_template_name("MisleadingButOrdinaryName"));
        assert!(is_template_name("rstl::vector<int>"));
        assert!(is_template_name("rstl::vector<int>::size() const"));
        assert!(!is_template_name("CBomb::CBomb(rstl::reserved_vector<CEntity*, 8>)"));
    }

    #[test]
    fn infers_one_base_class_insertion_without_a_magic_breakpoint() {
        let transform = infer_offset_transform(&[
            (0x40, 0x40),
            (0x60, 0x60),
            (0x158, 0x168),
            (0x17C, 0x18C),
            (0x190, 0x1A0),
        ])
        .unwrap();
        assert_eq!(transform.deltas, vec![0, 0x10]);
        assert_eq!(transform.breakpoint, Some(0x158));
        assert_eq!(transform.changed_accesses, 3);
    }

    #[test]
    fn infers_two_shifted_layout_segments() {
        let transform = infer_offset_transform(&[
            (0x478, 0x4A0),
            (0x498, 0x4C0),
            (0x4C4, 0x4F0),
            (0x4E0, 0x50C),
        ])
        .unwrap();
        assert_eq!(transform.deltas, vec![0x28, 0x2C]);
        assert_eq!(transform.breakpoint, Some(0x4C4));
        assert_eq!(transform.changed_accesses, 4);
    }

    #[test]
    fn rejects_three_layout_segments_or_non_monotone_offsets() {
        assert!(infer_offset_transform(&[(0x40, 0x50), (0x60, 0x80), (0x90, 0xC0)]).is_none());
        assert!(infer_offset_transform(&[(0x40, 0x70), (0x60, 0x60)]).is_none());
    }

    #[test]
    fn sequence_alignment_keeps_the_longest_monotone_chain() {
        let edge = |source, target, weight, primary| SequenceEdge {
            source,
            target,
            source_position: source,
            target_position: target,
            weight,
            primary,
            tier: "candidate".into(),
            method: "layout".into(),
            confidence: weight,
        };
        let edges = vec![
            edge(1, 10, 1.0, true),
            edge(2, 20, 1.0, true),
            edge(3, 30, 1.0, true),
            edge(2, 25, 0.9, false),
            edge(3, 15, 4.0, false),
        ];
        let best = best_alignment(&edges, None);
        assert_eq!(best.edges, vec![0, 1, 2]);
        assert_eq!(best.score, 3.0);
        let rival = best_alignment(&edges, Some(1));
        assert_eq!(rival.edges, vec![0, 3, 2]);
        assert!((rival.score - 2.9).abs() < f32::EPSILON);
    }

    #[test]
    fn empty_evidence_serialization_is_deterministic() {
        let report = CoverageReport {
            schema: COVERAGE_SCHEMA,
            policy: CoveragePolicy {
                version: POLICY_VERSION,
                complete_replacement_bodies: true,
                refine_represented_units: true,
                prefer_combined_exact_anchors: true,
                refuse_unevidenced_ownership_loss: true,
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
                maximum_layout_shift_segments: 2,
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
                minimum_sequence_size_ratio: 0.5,
                maximum_sequence_size_ratio: 1.5,
                require_explicit_sequence_neighbors: true,
                reject_sequence_runner_up: true,
                infer_boundary_data_matches: true,
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
                minimum_ownership_transition_strong_functions:
                    MIN_OWNERSHIP_TRANSITION_STRONG_FUNCTIONS,
                minimum_ownership_transition_edge_strong_functions:
                    MIN_OWNERSHIP_TRANSITION_EDGE_STRONG_FUNCTIONS,
                maximum_ownership_transition_size_delta: MAX_OWNERSHIP_TRANSITION_SIZE_DELTA,
                require_complete_ownership_transition_sequence: true,
                require_nonempty_ownership_transition_correction: true,
                infer_adjacent_owner_transition_boundaries: true,
                minimum_adjacent_owner_transition_functions:
                    MIN_ADJACENT_OWNER_TRANSITION_FUNCTIONS,
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
            },
            source: "source".into(),
            target: "target".into(),
            mask: Masked::default(),
            identifications: IdentificationReport::empty("source", "target"),
            source_units: Vec::new(),
            target_layout: Vec::new(),
        };
        let first = serde_json::to_string(&report).unwrap();
        assert_eq!(first, serde_json::to_string(&report).unwrap());
    }
}
