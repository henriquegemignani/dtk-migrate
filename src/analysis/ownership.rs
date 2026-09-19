//! Source-independent observations about function identity and translation-unit membership.
//!
//! This module deliberately stops before deciding whether a split may be changed. Existing
//! ownership, policy byte thresholds, `--only`, source-object availability and build results are
//! application concerns. Keeping the observations separate means an uncompilable project still
//! gets a useful inventory, and a rejected mutation does not erase what identified the unit.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analysis::{
    callgraph::NodeIndex,
    fingerprint::normalized_body,
    helpers::{self, HelperFamily, UnresolvedTargetCluster},
    matching::{
        CONTESTED_MARGIN, Match, MatchMethod, MatchResult, MatchTarget, MatchTier, classify_tier,
    },
    policy::{
        MAX_COMPOSED_PADDING_GAP, MAX_NEW_CALLER_CONFINED_HELPERS,
        MIN_COMPLETE_SEQUENCE_INDEPENDENT_MEMBERS,
    },
};

pub const IDENTIFICATION_SCHEMA: u32 = 5;
/// Schema 2 lacks the caller inventory. It is still readable, and reads as a
/// report in which no helper is caller-confined, which only ever refuses more.
const OLDEST_READABLE_IDENTIFICATION_SCHEMA: u32 = 2;
const EXECUTABLE_MODULE: &str = "main";

/// Whether this build can read an identification report of `schema`.
pub fn identification_schema_supported(schema: u32) -> bool {
    (OLDEST_READABLE_IDENTIFICATION_SCHEMA..=IDENTIFICATION_SCHEMA).contains(&schema)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentificationReport {
    pub schema: u32,
    pub source: String,
    pub target: String,
    pub attributions: Vec<FunctionAttribution>,
    #[serde(default)]
    pub source_functions: Vec<SourceFunctionObservation>,
    #[serde(default)]
    pub target_functions: Vec<TargetFunctionObservation>,
    /// Diagnostic exact-body families. These never certify emitted ownership.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub helper_families: Vec<HelperFamily>,
    /// Target function runs that have no corresponding source TU in this
    /// baseline. A cluster is not a proposed split or a guessed filename.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved_target_clusters: Vec<UnresolvedTargetCluster>,
    pub units: Vec<UnitIdentification>,
}

impl IdentificationReport {
    pub fn empty(source: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            schema: IDENTIFICATION_SCHEMA,
            source: source.into(),
            target: target.into(),
            attributions: Vec::new(),
            source_functions: Vec::new(),
            target_functions: Vec::new(),
            helper_families: Vec::new(),
            unresolved_target_clusters: Vec::new(),
            units: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAttribution {
    /// Stable within this source/target pair and suitable for references from unit records.
    pub id: String,
    pub target: FunctionLocation,
    pub source: SourceFunction,
    pub method: MatchMethod,
    pub tier: MatchTier,
    pub confidence: f32,
    pub evidence_count: u32,
    pub origin: AttributionOrigin,
    /// Raw observation used to derive `binary_supported`. Kept separately so a
    /// serialized diagnostic flag can never become policy input when evidence
    /// is loaded again.
    #[serde(default)]
    pub distinctive_body: bool,
    /// The normalized body is equal and unique in both binaries.
    #[serde(default)]
    pub unique_exact_body: bool,
    pub binary_supported: bool,
    pub independent: bool,
    /// True only when an alternative is close enough to make the selected
    /// identity non-decisive. Weaker runner-ups remain in `competing` without
    /// poisoning the unit-level result.
    pub ambiguous: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub competing: Option<CompetingAttribution>,
    pub source_weak: bool,
    pub target_weak: bool,
    pub template_instantiation: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_target_owner: Option<String>,
    pub evidence: Vec<EvidenceReference>,
}

/// Canonical address used by ownership policy. The module is explicit even
/// though Prime currently has one executable module; later REL support must
/// not make two identical section addresses alias one another.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AddressKey {
    pub module: String,
    pub section: String,
    pub address: u32,
}

/// A validated, canonicalized identification report and its address indexes.
///
/// Fields such as `independent`, unit counts and confidence are serialized for
/// people and old tooling, but are recomputed here before any migration policy
/// consumes them. The report digest is therefore a digest of canonical facts,
/// not of whichever aggregate values an input happened to claim.
#[derive(Debug, Clone)]
pub struct ObservationIndex {
    report: IdentificationReport,
    digest: String,
    by_id: BTreeMap<String, usize>,
    by_target: BTreeMap<AddressKey, usize>,
    by_unit: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationReference {
    pub schema: u32,
    pub sha256: String,
    /// Path used while the run is active. Published summaries replace this
    /// with a run-relative path so copied run directories remain readable.
    pub file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetExtent {
    pub module: String,
    pub section: String,
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetFunctionObservation {
    pub name: String,
    pub module: String,
    pub section: String,
    pub address: String,
    pub end: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_owner: Option<String>,
    #[serde(default)]
    pub owner_autogenerated: bool,
    /// Every target function that calls this one, in the same module. Omitted
    /// when empty so that a report without the inventory keeps its digest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callers: Vec<CallerReference>,
    /// Exact relocation-masked body digest, only when the function size is
    /// known. It groups possible helpers but does not establish their owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_body_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub weak: bool,
}

/// A calling function, named by where it starts.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CallerReference {
    pub section: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFunctionObservation {
    pub name: String,
    pub unit: String,
    pub module: String,
    pub section: String,
    pub address: String,
    pub end: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_body_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub weak: bool,
}

fn is_false(value: &bool) -> bool { !*value }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimClass {
    IndependentlyAttributed,
    SharedHelper,
    ConflictingAttribution,
    UnresolvedFunction,
    Padding,
    /// Attributed to the unit without independent support, but both of its
    /// target neighbours are independent members of the unit that bracket it
    /// in source order, so the ordered sequence itself places it.
    OrderBracketedMember,
    /// Unattributed, placed with the unit by its target neighbours (inside the
    /// unit, or at the seam where the unit's source sequence ends and another's
    /// begins), and called only by the unit from inside the same body: a
    /// helper the unit emitted that has no counterpart to match. Callers alone
    /// never place it; see [`ObservationIndex::helper_placement`].
    CallerConfinedHelper,
    /// Weak or weakly attributed, but held in a range that is exactly the
    /// unit's complete source sequence for the section, paired in order and
    /// bounded by the unit's source-order neighbours. Its ordinal position is
    /// the unit's; see [`ObservationIndex::complete_sequence`].
    CompleteSequenceMember,
}

/// Where position places an unattributed function relative to a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperPosition {
    /// Between two of the unit's functions.
    Interior,
    /// Before the unit's first source function, with nothing of anyone else's
    /// before it.
    Head,
    /// After the unit's last source function, with nothing of anyone else's
    /// after it.
    Tail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperPlacement {
    pub position: HelperPosition,
    /// The target extents of the unit's functions that place it.
    pub members: Vec<(u32, u32)>,
}

/// One target neighbour of a candidate helper.
enum Beside {
    Member { extent: (u32, u32), source: u32, outermost: bool },
    Bound,
    Other,
}

/// What stands outside one end of a complete sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "unit")]
pub enum SequenceEdge {
    /// The section ends there.
    SectionBoundary,
    /// A function independently attributed to another unit.
    ForeignIndependent(String),
    /// A function attributed, not necessarily independently, to the unit that
    /// is this one's neighbour in the source version's link order.
    SourceOrderNeighbour(String),
}

/// A range that is exactly one unit's complete ordered sequence in a section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteSequence {
    pub section: String,
    pub start: String,
    pub end: String,
    pub members: u32,
    pub independent_members: u32,
    pub left: SequenceEdge,
    pub right: SequenceEdge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRecord {
    pub module: String,
    pub section: String,
    pub start: String,
    pub end: String,
    pub class: ClaimClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributed_unit: Option<String>,
    pub retained: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipAssessment {
    pub observation_sha256: String,
    pub records: Vec<ClaimRecord>,
    pub independent_members: u32,
    pub padding_bytes: u32,
    pub retained_questionable: u32,
    pub complete_membership: bool,
    pub supported_edges: u32,
    pub new_shared_helpers: u32,
    pub new_conflicts: u32,
    pub new_unresolved: u32,
    /// New ground placed by its independent neighbours rather than by its own
    /// evidence.
    #[serde(default)]
    pub new_order_bracketed: u32,
    #[serde(default)]
    pub new_caller_confined_helpers: u32,
    #[serde(default)]
    pub new_complete_sequence_members: u32,
}

impl OwnershipAssessment {
    pub fn permits_automatic_claim(&self) -> bool {
        self.independent_members > 0
            && self.new_shared_helpers == 0
            && self.new_conflicts == 0
            && self.new_unresolved == 0
            && self.new_caller_confined_helpers <= MAX_NEW_CALLER_CONFINED_HELPERS
    }
}

impl ObservationIndex {
    /// Validate an identification report against the coverage report that
    /// carried it, then bind the persisted artifact to the migration's stable
    /// version ids. Match targets are named by their config paths, which are
    /// workspace-specific and must not become the identity workers compare
    /// after preparation moves into a different workspace.
    pub fn load_enclosed_for_run(
        mut report: IdentificationReport,
        enclosing_source: &str,
        enclosing_target: &str,
        run_source: &str,
        run_target: &str,
        expected_units: &BTreeSet<String>,
    ) -> Result<Self> {
        if report.source != enclosing_source || report.target != enclosing_target {
            bail!("Coverage identification source/target does not match its enclosing evidence");
        }
        report.source = run_source.to_string();
        report.target = run_target.to_string();
        Self::load(report, run_source, run_target, expected_units)
    }

    pub fn load_self_contained(
        report: IdentificationReport,
        source: &str,
        target: &str,
    ) -> Result<Self> {
        let expected = report.units.iter().map(|unit| unit.unit.clone()).collect();
        Self::load(report, source, target, &expected)
    }

    pub fn load(
        mut report: IdentificationReport,
        source: &str,
        target: &str,
        expected_units: &BTreeSet<String>,
    ) -> Result<Self> {
        if !identification_schema_supported(report.schema) {
            bail!(
                "identification schema {} is incompatible; this build understands {IDENTIFICATION_SCHEMA}",
                report.schema
            );
        }
        if report.source != source || report.target != target {
            bail!("Identification source/target does not match its enclosing evidence");
        }
        if report.schema < 4
            && (!report.helper_families.is_empty()
                || !report.unresolved_target_clusters.is_empty()
                || report
                    .source_functions
                    .iter()
                    .any(|item| item.normalized_body_sha256.is_some() || item.weak)
                || report
                    .target_functions
                    .iter()
                    .any(|item| item.normalized_body_sha256.is_some() || item.weak))
        {
            bail!("Identification schema {} cannot carry helper evidence", report.schema);
        }
        report.attributions.sort_by(|left, right| left.id.cmp(&right.id));

        let mut by_id = BTreeMap::new();
        let mut by_target = BTreeMap::new();
        let mut source_locations = BTreeSet::new();
        let mut source_functions = BTreeSet::new();
        for function in &mut report.source_functions {
            validate_body_digest(function.normalized_body_sha256.as_deref(), &function.name)?;
            let start =
                parse_address_checked(&function.address, "source function", &function.name)?;
            let end = parse_address_checked(&function.end, "source function", &function.name)?;
            if !expected_units.contains(&function.unit)
                || function.module.is_empty()
                || function.section.is_empty()
                || end <= start
            {
                bail!("Source function {} has an invalid extent or unit", function.name);
            }
            if !source_functions.insert((
                function.module.clone(),
                function.section.clone(),
                start,
                end,
                function.unit.clone(),
            )) {
                bail!("Identification contains a duplicate source function extent");
            }
            function.address = hex(start);
            function.end = hex(end);
        }
        for pair in source_functions.iter().collect::<Vec<_>>().windows(2) {
            let (left, right) = (pair[0], pair[1]);
            if left.0 == right.0 && left.1 == right.1 && left.3 > right.2 {
                bail!("Identification contains overlapping source function extents");
            }
        }
        let mut target_functions = BTreeSet::new();
        let mut target_owners = BTreeMap::new();
        for function in &mut report.target_functions {
            validate_body_digest(function.normalized_body_sha256.as_deref(), &function.name)?;
            let start =
                parse_address_checked(&function.address, "target function", &function.name)?;
            let end = parse_address_checked(&function.end, "target function", &function.name)?;
            if function.module.is_empty()
                || function.section.is_empty()
                || end <= start
                || (function.current_owner.is_none() && function.owner_autogenerated)
            {
                bail!("Target function {} has an invalid extent", function.name);
            }
            if !target_functions.insert((
                function.module.clone(),
                function.section.clone(),
                start,
                end,
            )) {
                bail!("Identification contains a duplicate target function extent");
            }
            if target_owners
                .insert(
                    (function.module.clone(), function.section.clone(), start),
                    function.current_owner.clone(),
                )
                .is_some()
            {
                bail!("Identification contains two target functions at one address");
            }
            function.address = hex(start);
            function.end = hex(end);
        }
        for pair in target_functions.iter().collect::<Vec<_>>().windows(2) {
            let (left, right) = (pair[0], pair[1]);
            if left.0 == right.0 && left.1 == right.1 && left.3 > right.2 {
                bail!("Identification contains overlapping target function extents");
            }
        }
        for function in &mut report.target_functions {
            if report.schema < 3 && !function.callers.is_empty() {
                bail!("Identification schema {} cannot carry a caller inventory", report.schema);
            }
            for caller in &mut function.callers {
                let address = parse_address_checked(&caller.address, "caller", &function.name)?;
                if !target_owners.contains_key(&(
                    function.module.clone(),
                    caller.section.clone(),
                    address,
                )) {
                    bail!("Target function {} has a caller outside the inventory", function.name);
                }
                caller.address = hex(address);
            }
            function.callers.sort();
            function.callers.dedup();
        }
        report.source_functions.sort_by(|left, right| {
            (&left.module, &left.section, &left.address, &left.end, &left.unit, &left.name).cmp(&(
                &right.module,
                &right.section,
                &right.address,
                &right.end,
                &right.unit,
                &right.name,
            ))
        });
        report.target_functions.sort_by(|left, right| {
            (&left.module, &left.section, &left.address, &left.end, &left.name).cmp(&(
                &right.module,
                &right.section,
                &right.address,
                &right.end,
                &right.name,
            ))
        });
        for (index, item) in report.attributions.iter_mut().enumerate() {
            validate_location(&item.target, "target", &item.id)?;
            validate_source(&item.source, &item.id)?;
            if !expected_units.contains(&item.source.unit) {
                bail!(
                    "Identification attributes {} to unknown source unit {}",
                    item.id,
                    item.source.unit
                );
            }
            if by_id.insert(item.id.clone(), index).is_some() {
                bail!("Identification contains duplicate attribution {}", item.id);
            }
            let key = AddressKey {
                module: item.target.module.clone(),
                section: item.target.section.clone(),
                address: parse_address_checked(&item.target.address, "target", &item.id)?,
            };
            if by_target.insert(key, index).is_some() {
                bail!("Identification contains two attributions for one target function");
            }
            let target_start = parse_address_checked(&item.target.address, "target", &item.id)?;
            let target_end = parse_address_checked(&item.target.end, "target", &item.id)?;
            if !target_functions.contains(&(
                item.target.module.clone(),
                item.target.section.clone(),
                target_start,
                target_end,
            )) {
                bail!("Attribution {} is absent from the target function inventory", item.id);
            }
            let source_key = (
                item.source.module.clone(),
                item.source.section.clone(),
                parse_address_checked(&item.source.address, "source", &item.id)?,
            );
            if !source_locations.insert(source_key) {
                bail!("Identification contains two attributions for one source function");
            }
            let source_start = parse_address_checked(&item.source.address, "source", &item.id)?;
            let source_end = parse_address_checked(&item.source.end, "source", &item.id)?;
            if !source_functions.contains(&(
                item.source.module.clone(),
                item.source.section.clone(),
                source_start,
                source_end,
                item.source.unit.clone(),
            )) {
                bail!("Attribution {} is absent from the source function inventory", item.id);
            }
            item.target.address = hex(target_start);
            item.target.end = hex(target_end);
            item.source.address = hex(source_start);
            item.source.end = hex(source_end);

            // These are derived diagnostics. Never trust their serialized
            // value when an artifact is resumed or injected by a test.
            item.origin = origin(item.method);
            item.binary_supported = item.method != MatchMethod::Name || item.distinctive_body;
            if item
                .competing
                .as_ref()
                .is_some_and(|competing| !competing.relative_score.is_finite())
            {
                bail!("Identification {} has an invalid competing score", item.id);
            }
            item.ambiguous = item
                .competing
                .as_ref()
                .is_some_and(|competing| competing.relative_score > 1.0 - CONTESTED_MARGIN);
            item.tier = classify_tier(
                item.method,
                item.distinctive_body,
                item.evidence_count,
                item.ambiguous,
            );
            item.independent = decisive(item);
            item.current_target_owner = target_owners
                .get(&(item.target.module.clone(), item.target.section.clone(), target_start))
                .cloned()
                .flatten();
        }

        let mut by_unit = BTreeMap::new();
        let supplied_count = report.units.len();
        let mut supplied: BTreeMap<String, UnitIdentification> =
            report.units.drain(..).map(|unit| (unit.unit.clone(), unit)).collect();
        if supplied_count != expected_units.len()
            || supplied.len() != expected_units.len()
            || supplied.keys().collect::<BTreeSet<_>>() != expected_units.iter().collect()
        {
            bail!("Identification inventory does not cover exactly the source split units");
        }
        let mut units = Vec::with_capacity(expected_units.len());
        for name in expected_units {
            let diagnostics = supplied.remove(name).expect("unit set was checked");
            let items: Vec<&FunctionAttribution> =
                report.attributions.iter().filter(|item| item.source.unit == *name).collect();
            let canonical = canonical_unit(
                diagnostics,
                &items,
                &report.attributions,
                &report.source_functions,
                &report.target_functions,
            );
            by_unit.insert(name.clone(), units.len());
            units.push(canonical);
        }
        report.units = units;
        // Schema 4+ aggregates are regenerated from canonical function facts.
        // Older reports never carried these fields; synthesizing clusters for
        // them would change their canonical digest and invalidate saved refs.
        if report.schema >= 4 {
            report.helper_families = if report.schema == 4 {
                helpers::families_schema_4(&report.source_functions, &report.target_functions)
            } else {
                helpers::families(&report.source_functions, &report.target_functions)
            };
            report.unresolved_target_clusters =
                helpers::unresolved_clusters(&report.target_functions, &report.attributions);
        }

        let bytes = serde_json::to_vec(&report)?;
        let digest = format!("{:x}", Sha256::digest(bytes));
        Ok(Self { report, digest, by_id, by_target, by_unit })
    }

    pub fn report(&self) -> &IdentificationReport { &self.report }

    pub fn digest(&self) -> &str { &self.digest }

    pub fn attribution(&self, id: &str) -> Option<&FunctionAttribution> {
        self.by_id.get(id).map(|&index| &self.report.attributions[index])
    }

    pub fn at_target(
        &self,
        module: &str,
        section: &str,
        address: u32,
    ) -> Option<&FunctionAttribution> {
        self.by_target
            .get(&AddressKey { module: module.into(), section: section.into(), address })
            .map(|&index| &self.report.attributions[index])
    }

    /// Every target function of one section, in address order. The inventory
    /// is canonically sorted on load, and addresses are fixed-width hex, so the
    /// section is one contiguous run of it.
    pub fn section_functions(&self, module: &str, section: &str) -> &[TargetFunctionObservation] {
        let functions = &self.report.target_functions;
        let order = |function: &TargetFunctionObservation| {
            function.module.as_str().cmp(module).then(function.section.as_str().cmp(section))
        };
        let first = functions.partition_point(|function| order(function).is_lt());
        let last = functions.partition_point(|function| order(function).is_le());
        &functions[first..last]
    }

    pub fn unit(&self, name: &str) -> Option<&UnitIdentification> {
        self.by_unit.get(name).map(|&index| &self.report.units[index])
    }

    pub fn target_function_count(&self, module: &str, section: &str, start: u32, end: u32) -> u32 {
        self.report
            .target_functions
            .iter()
            .filter(|function| {
                function.module == module && function.section == section && {
                    let address = parse_hex(&function.address);
                    start <= address && address < end
                }
            })
            .count() as u32
    }

    pub fn source_function_count(&self, unit: &str, module: &str, section: &str) -> u32 {
        self.report
            .source_functions
            .iter()
            .filter(|function| {
                function.unit == unit && function.module == module && function.section == section
            })
            .count() as u32
    }

    pub fn independent_members(
        &self,
        unit: &str,
        module: &str,
        section: &str,
        start: u32,
        end: u32,
    ) -> u32 {
        self.report
            .attributions
            .iter()
            .filter(|item| {
                item.source.unit == unit
                    && item.target.module == module
                    && item.target.section == section
                    && item.independent
                    && {
                        let address = parse_hex(&item.target.address);
                        start <= address && address < end
                    }
            })
            .count() as u32
    }

    pub fn persist(&self, directory: &Path) -> Result<ObservationReference> {
        std::fs::create_dir_all(directory)?;
        let name = format!("ownership-{}.json", self.digest);
        let path = directory.join(&name);
        if path.exists() {
            let report: IdentificationReport = serde_json::from_slice(&std::fs::read(&path)?)?;
            let existing = ObservationIndex::load_self_contained(
                report,
                &self.report.source,
                &self.report.target,
            )?;
            if existing.digest != self.digest {
                bail!("Existing ownership observation artifact has the wrong digest");
            }
        } else {
            std::fs::write(&path, serde_json::to_vec_pretty(&self.report)?)?;
        }
        // The reference states the schema of the artifact it names, which is
        // the report's own: a schema 2 report stays schema 2 when it is kept.
        Ok(ObservationReference {
            schema: self.report.schema,
            sha256: self.digest.clone(),
            file: path.to_string_lossy().into_owned(),
        })
    }

    /// Whether `reference` names exactly this report: the same content and
    /// the same schema. A reference that misstates its artifact's schema is
    /// refused even when the content is intact, because readers decide what
    /// the artifact may carry from the reference.
    pub fn verify_reference(&self, reference: &ObservationReference) -> Result<()> {
        if self.digest != reference.sha256 {
            bail!("Ownership observation digest does not match its reference");
        }
        if self.report.schema != reference.schema {
            bail!(
                "Ownership observation is identification schema {}, but its reference states {}",
                self.report.schema,
                reference.schema
            );
        }
        Ok(())
    }

    /// Whether `start..end` is exactly `unit`'s complete ordered sequence in
    /// `section`, and what bounds it.
    ///
    /// Every source function the unit has in the section must pair, in order
    /// and by its exact source address, with the target functions that tile the
    /// range: the same count, no extra target function the source does not
    /// explain, none ambiguous. Enough of them must be independent that the
    /// pairing does not rest on weak evidence. Each end must then be bounded:
    /// by the end of the section, by a function independently attributed
    /// elsewhere, or by one attributed to the unit that neighbours this one on
    /// that side in the source version. A complete sequence bounded like that
    /// leaves no position for its members but their own.
    pub fn complete_sequence(
        &self,
        unit: &str,
        module: &str,
        section: &str,
        start: u32,
        end: u32,
    ) -> Option<CompleteSequence> {
        let mut source: Vec<&SourceFunctionObservation> = self
            .report
            .source_functions
            .iter()
            .filter(|function| function.module == module && function.section == section)
            .collect();
        source.sort_by_key(|function| parse_hex(&function.address));
        let positions: Vec<usize> = source
            .iter()
            .enumerate()
            .filter(|(_, function)| function.unit == unit)
            .map(|(index, _)| index)
            .collect();
        let (&first, &last) = (positions.first()?, positions.last()?);
        // The unit's source functions are one run: nothing of another unit
        // is interleaved with them.
        if last - first + 1 != positions.len() {
            return None;
        }
        let functions = self.section_functions(module, section);
        let split = functions.partition_point(|function| parse_hex(&function.end) <= start);
        let inside: Vec<&TargetFunctionObservation> = functions[split..]
            .iter()
            .take_while(|function| parse_hex(&function.address) < end)
            .collect();
        if inside.len() != positions.len() {
            return None;
        }
        let mut cursor = start;
        let mut independent = 0;
        for (target, &position) in inside.iter().zip(&positions) {
            let (left, right) = (parse_hex(&target.address), parse_hex(&target.end));
            let item = self.at_target(module, section, left)?;
            if left < cursor
                || left - cursor > MAX_COMPOSED_PADDING_GAP
                || right > end
                || item.source.unit != unit
                || item.ambiguous
                || item.source.address != source[position].address
            {
                return None;
            }
            independent += u32::from(item.independent);
            cursor = right;
        }
        if end - cursor > MAX_COMPOSED_PADDING_GAP
            || independent < MIN_COMPLETE_SEQUENCE_INDEPENDENT_MEMBERS
        {
            return None;
        }

        let bound = |outside: Option<&TargetFunctionObservation>,
                     neighbour: Option<&SourceFunctionObservation>|
         -> Option<SequenceEdge> {
            let Some(outside) = outside else { return Some(SequenceEdge::SectionBoundary) };
            let item = self.at_target(module, section, parse_hex(&outside.address))?;
            if item.source.unit == unit || item.ambiguous {
                return None;
            }
            if item.independent {
                return Some(SequenceEdge::ForeignIndependent(item.source.unit.clone()));
            }
            (neighbour.is_some_and(|neighbour| neighbour.unit == item.source.unit))
                .then(|| SequenceEdge::SourceOrderNeighbour(item.source.unit.clone()))
        };
        let before = split.checked_sub(1).map(|index| &functions[index]);
        let after = functions.get(split + inside.len());
        // Only padding may separate the range from what bounds it.
        if before
            .is_some_and(|function| start - parse_hex(&function.end) > MAX_COMPOSED_PADDING_GAP)
            || after.is_some_and(|function| {
                parse_hex(&function.address) - end > MAX_COMPOSED_PADDING_GAP
            })
        {
            return None;
        }
        let left = bound(before, first.checked_sub(1).map(|index| source[index]))?;
        let right = bound(after, source.get(last + 1).copied())?;
        Some(CompleteSequence {
            section: section.to_string(),
            start: hex(start),
            end: hex(end),
            members: positions.len() as u32,
            independent_members: independent,
            left,
            right,
        })
    }

    /// Whether `item`, attributed to `unit` without independent support, is
    /// placed by its target neighbours: both are independent members of the
    /// same unit inside the same resulting range, and their source addresses
    /// bracket its own. An ordered alignment anchored on both sides leaves no
    /// other position for it.
    fn order_bracketed(
        &self,
        unit: &str,
        item: &FunctionAttribution,
        (previous, next): (Option<&TargetExtent>, Option<&TargetExtent>),
        ranges: &[(u32, u32)],
    ) -> bool {
        if item.source.unit != unit
            || item.ambiguous
            || item.source_weak
            || item.target_weak
            || item.template_instantiation
        {
            return false;
        }
        let source = parse_hex(&item.source.address);
        let (Some(previous), Some(next)) = (previous, next) else { return false };
        let anchor = |extent: &TargetExtent| {
            self.at_target(&extent.module, &extent.section, extent.start).filter(|anchor| {
                anchor.source.unit == unit
                    && anchor.independent
                    && anchor.source.module == item.source.module
                    && anchor.source.section == item.source.section
                    && interval_covered(ranges, extent.start, extent.end)
            })
        };
        let (Some(before), Some(after)) = (anchor(previous), anchor(next)) else { return false };
        parse_hex(&before.source.address) < source && source < parse_hex(&after.source.address)
    }

    /// Where position alone puts the unattributed target function at `start`
    /// relative to `unit`, if anywhere.
    ///
    /// Position decides which units could have emitted it; its callers only
    /// choose among those (see [`Self::helper_callers_confined`]). Each target
    /// neighbour, separated from it by at most alignment padding, must be one
    /// of:
    ///
    /// - a *member*: attributed to `unit` without ambiguity;
    /// - a *bound*: the end of the section, or a function independently
    ///   attributed to another unit that is that unit's outermost source
    ///   function facing the helper (its first, when the helper precedes it;
    ///   its last, when the helper follows it).
    ///
    /// Two members in source order place it inside the unit. A member that is
    /// the unit's own outermost source function on that side, with a bound on
    /// the other, places it at the seam where the unit ends and nothing else
    /// begins. Anything else leaves the owner open, whoever calls it.
    pub fn helper_placement(
        &self,
        unit: &str,
        module: &str,
        section: &str,
        start: u32,
    ) -> Option<HelperPlacement> {
        let functions = self.section_functions(module, section);
        let position = functions.partition_point(|function| parse_hex(&function.address) < start);
        let function =
            functions.get(position).filter(|function| parse_hex(&function.address) == start)?;
        if self.at_target(module, section, start).is_some() {
            return None;
        }
        let end = parse_hex(&function.end);
        let beside = |neighbour: Option<&TargetFunctionObservation>, follows: bool| {
            let Some(neighbour) = neighbour else { return Beside::Bound };
            let extent = (parse_hex(&neighbour.address), parse_hex(&neighbour.end));
            let gap = if follows { extent.0 - end } else { start - extent.1 };
            let Some(item) = self.at_target(module, section, extent.0) else {
                return Beside::Other;
            };
            if gap > MAX_COMPOSED_PADDING_GAP || item.ambiguous {
                return Beside::Other;
            }
            // Facing the helper: a unit that follows it must begin here, one
            // that precedes it must end here.
            let outermost = self.source_outermost(item, follows);
            if item.source.unit == unit {
                Beside::Member { extent, source: parse_hex(&item.source.address), outermost }
            } else if item.independent && outermost {
                Beside::Bound
            } else {
                Beside::Other
            }
        };
        let before = beside(position.checked_sub(1).map(|index| &functions[index]), false);
        let after = beside(functions.get(position + 1), true);
        match (before, after) {
            (
                Beside::Member { extent: left, source: left_source, .. },
                Beside::Member { extent: right, source: right_source, .. },
            ) if left_source < right_source => Some(HelperPlacement {
                position: HelperPosition::Interior,
                members: vec![left, right],
            }),
            (Beside::Member { extent, outermost: true, .. }, Beside::Bound) => {
                Some(HelperPlacement { position: HelperPosition::Tail, members: vec![extent] })
            }
            (Beside::Bound, Beside::Member { extent, outermost: true, .. }) => {
                Some(HelperPlacement { position: HelperPosition::Head, members: vec![extent] })
            }
            _ => None,
        }
    }

    /// Whether `item` is its unit's first (`first`) or last source function in
    /// its source section.
    fn source_outermost(&self, item: &FunctionAttribution, first: bool) -> bool {
        let addresses = self
            .report
            .source_functions
            .iter()
            .filter(|function| {
                function.unit == item.source.unit
                    && function.module == item.source.module
                    && function.section == item.source.section
            })
            .map(|function| parse_hex(&function.address));
        let outermost = if first { addresses.min() } else { addresses.max() };
        outermost == Some(parse_hex(&item.source.address))
    }

    /// Whether every call into a placed helper comes from `unit`, and from
    /// ground `held` keeps. A caller must be independently the unit's, or be
    /// one of the members that place the helper: a weakly attributed caller
    /// elsewhere would make the helper's owner rest on that weak attribution,
    /// while the member beside it already rests on position. At least one
    /// caller is required; an uncalled function corroborates nothing.
    pub fn helper_callers_confined(
        &self,
        unit: &str,
        module: &str,
        function: &TargetFunctionObservation,
        placement: &HelperPlacement,
        held: impl Fn(&str, u32, u32) -> bool,
    ) -> bool {
        let own = function.address.as_str();
        let callers: Vec<&CallerReference> = function
            .callers
            .iter()
            .filter(|caller| !(caller.section == function.section && caller.address == own))
            .collect();
        !callers.is_empty()
            && callers.iter().all(|caller| {
                let Some(item) =
                    self.at_target(module, &caller.section, parse_hex(&caller.address))
                else {
                    return false;
                };
                let extent = (parse_hex(&item.target.address), parse_hex(&item.target.end));
                let placing =
                    caller.section == function.section && placement.members.contains(&extent);
                item.source.unit == unit
                    && !item.ambiguous
                    && (item.independent || placing)
                    && held(&caller.section, extent.0, extent.1)
            })
    }

    /// Whether an unattributed function is a helper of `unit` that the
    /// resulting body explains: placed by its position, with the members that
    /// place it and every caller held by the body.
    fn placed_helper(
        &self,
        unit: &str,
        module: &str,
        function: &TargetFunctionObservation,
        after: &BTreeMap<String, Vec<(u32, u32)>>,
    ) -> bool {
        let held = |section: &str, start: u32, end: u32| {
            after.get(section).is_some_and(|ranges| interval_covered(ranges, start, end))
        };
        self.helper_placement(unit, module, &function.section, parse_hex(&function.address))
            .is_some_and(|placement| {
                placement.members.iter().all(|&(start, end)| held(&function.section, start, end))
                    && self.helper_callers_confined(unit, module, function, &placement, held)
            })
    }

    /// Classify every target function and padding interval in a resulting code
    /// body. `before` and `after` are section ranges; questionable ground that
    /// was already retained remains visible but does not veto an otherwise safe
    /// extension. Any questionable *new* function does.
    pub fn assess(
        &self,
        unit: &str,
        module: &str,
        before: &BTreeMap<String, Vec<(u32, u32)>>,
        after: &BTreeMap<String, Vec<(u32, u32)>>,
    ) -> OwnershipAssessment {
        let mut result =
            OwnershipAssessment { observation_sha256: self.digest.clone(), ..Default::default() };
        for (section, ranges) in after {
            let old = before.get(section).map(Vec::as_slice).unwrap_or_default();
            let members = self.section_functions(module, section);
            let extent = |member: &TargetFunctionObservation| TargetExtent {
                module: member.module.clone(),
                section: member.section.clone(),
                start: parse_hex(&member.address),
                end: parse_hex(&member.end),
            };
            for &(start, end) in ranges {
                let mut covered = Vec::new();
                let mut complete: Option<bool> = None;
                let first = members.partition_point(|member| parse_hex(&member.end) <= start);
                for position in first..members.len() {
                    let observed = &members[position];
                    let member = extent(observed);
                    if member.start >= end {
                        break;
                    }
                    let left = start.max(member.start);
                    let right = end.min(member.end);
                    if right <= left {
                        continue;
                    }
                    covered.push((left, right));
                    let retained = interval_covered(old, left, right);
                    let attribution = self.at_target(module, section, member.start);
                    let cuts_member = left != member.start || right != member.end;
                    let (class, attribution_id, attributed_unit) = if cuts_member {
                        (
                            ClaimClass::UnresolvedFunction,
                            attribution.map(|item| item.id.clone()),
                            attribution.map(|item| item.source.unit.clone()),
                        )
                    } else {
                        match attribution {
                            Some(item)
                                if item.source_weak
                                    || item.target_weak
                                    || item.template_instantiation =>
                            {
                                (
                                    ClaimClass::SharedHelper,
                                    Some(item.id.clone()),
                                    Some(item.source.unit.clone()),
                                )
                            }
                            Some(item) if item.source.unit == unit && item.independent => (
                                ClaimClass::IndependentlyAttributed,
                                Some(item.id.clone()),
                                Some(item.source.unit.clone()),
                            ),
                            Some(item) if item.source.unit != unit && item.independent => (
                                ClaimClass::ConflictingAttribution,
                                Some(item.id.clone()),
                                Some(item.source.unit.clone()),
                            ),
                            Some(item) => (
                                ClaimClass::UnresolvedFunction,
                                Some(item.id.clone()),
                                Some(item.source.unit.clone()),
                            ),
                            None => (ClaimClass::UnresolvedFunction, None, None),
                        }
                    };
                    // Questionable new ground may still be explained by what
                    // surrounds it. Retained ground keeps its class: it vetoes
                    // nothing, and reclassifying it would change certificates
                    // that already stand.
                    let class =
                        if class == ClaimClass::UnresolvedFunction && !cuts_member && !retained {
                            let neighbours = (
                                position.checked_sub(1).map(|index| extent(&members[index])),
                                members.get(position + 1).map(extent),
                            );
                            if attribution.is_some_and(|item| {
                                self.order_bracketed(
                                    unit,
                                    item,
                                    (neighbours.0.as_ref(), neighbours.1.as_ref()),
                                    ranges,
                                )
                            }) {
                                ClaimClass::OrderBracketedMember
                            } else if attribution.is_none()
                                && self.placed_helper(unit, module, observed, after)
                            {
                                ClaimClass::CallerConfinedHelper
                            } else {
                                class
                            }
                        } else {
                            class
                        };
                    let class = if matches!(
                        class,
                        ClaimClass::UnresolvedFunction | ClaimClass::SharedHelper
                    ) && !cuts_member
                        && !retained
                        && attribution.is_some_and(|item| item.source.unit == unit)
                        && *complete.get_or_insert_with(|| {
                            self.complete_sequence(unit, module, section, start, end).is_some()
                        }) {
                        ClaimClass::CompleteSequenceMember
                    } else {
                        class
                    };
                    match (retained, class) {
                        (_, ClaimClass::IndependentlyAttributed) => {
                            result.independent_members += 1;
                        }
                        (true, _) => result.retained_questionable += 1,
                        (false, ClaimClass::SharedHelper) => result.new_shared_helpers += 1,
                        (false, ClaimClass::ConflictingAttribution) => result.new_conflicts += 1,
                        (false, ClaimClass::UnresolvedFunction) => result.new_unresolved += 1,
                        (false, ClaimClass::OrderBracketedMember) => {
                            result.new_order_bracketed += 1;
                        }
                        (false, ClaimClass::CallerConfinedHelper) => {
                            result.new_caller_confined_helpers += 1;
                        }
                        (false, ClaimClass::CompleteSequenceMember) => {
                            result.new_complete_sequence_members += 1;
                        }
                        (false, ClaimClass::Padding) => unreachable!(),
                    }
                    result.records.push(ClaimRecord {
                        module: module.to_string(),
                        section: section.clone(),
                        start: hex(left),
                        end: hex(right),
                        class,
                        attribution_id,
                        attributed_unit,
                        retained,
                    });
                }

                covered.sort_unstable();
                let mut cursor = start;
                for (left, right) in covered {
                    if cursor < left {
                        record_padding(&mut result, module, section, cursor, left, old);
                    }
                    cursor = cursor.max(right);
                }
                if cursor < end {
                    record_padding(&mut result, module, section, cursor, end, old);
                }
            }
        }
        result.complete_membership = result.independent_members > 0
            && result.retained_questionable == 0
            && result.new_shared_helpers == 0
            && result.new_conflicts == 0
            && result.new_unresolved == 0;
        result.supported_edges = self
            .unit(unit)
            .into_iter()
            .flat_map(|identification| &identification.candidates)
            .filter(|candidate| candidate.module == module)
            .filter(|candidate| {
                let start = parse_hex(&candidate.start);
                let end = parse_hex(&candidate.end);
                after.get(&candidate.section).is_some_and(|ranges| ranges.contains(&(start, end)))
            })
            .map(|candidate| {
                u32::from(candidate.left_target_edge.supported)
                    + u32::from(candidate.right_target_edge.supported)
            })
            .max()
            .unwrap_or(0);
        result
    }
}

fn validate_body_digest(digest: Option<&str>, name: &str) -> Result<()> {
    if digest.is_some_and(|value| {
        value.len() != 64
            || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        bail!("Function {name} has an invalid normalized-body digest");
    }
    Ok(())
}

pub fn load_reference(
    reference: &ObservationReference,
    source: &str,
    target: &str,
) -> Result<ObservationIndex> {
    if !identification_schema_supported(reference.schema) {
        bail!("Ownership reference uses unsupported schema {}", reference.schema);
    }
    let text = std::fs::read_to_string(&reference.file).map_err(|error| {
        anyhow::anyhow!("Failed to read ownership observations {}: {error}", reference.file)
    })?;
    let report: IdentificationReport = serde_json::from_str(&text)?;
    let observations = ObservationIndex::load_self_contained(report, source, target)?;
    observations.verify_reference(reference)?;
    Ok(observations)
}

fn interval_covered(ranges: &[(u32, u32)], start: u32, end: u32) -> bool {
    ranges.iter().any(|&(left, right)| left <= start && end <= right)
}

fn record_padding(
    assessment: &mut OwnershipAssessment,
    module: &str,
    section: &str,
    start: u32,
    end: u32,
    before: &[(u32, u32)],
) {
    let retained = interval_covered(before, start, end);
    if !retained {
        assessment.padding_bytes += end - start;
    }
    assessment.records.push(ClaimRecord {
        module: module.to_string(),
        section: section.to_string(),
        start: hex(start),
        end: hex(end),
        class: ClaimClass::Padding,
        attribution_id: None,
        attributed_unit: None,
        retained,
    });
}

fn parse_address_checked(value: &str, side: &str, id: &str) -> Result<u32> {
    let digits = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")).unwrap_or(value);
    u32::from_str_radix(digits, 16)
        .map_err(|_| anyhow::anyhow!("Attribution {id} has invalid {side} address {value}"))
}

fn validate_location(location: &FunctionLocation, side: &str, id: &str) -> Result<()> {
    let start = parse_address_checked(&location.address, side, id)?;
    let end = parse_address_checked(&location.end, side, id)?;
    if location.module.is_empty() || location.section.is_empty() || end <= start {
        bail!("Attribution {id} has an invalid {side} extent");
    }
    Ok(())
}

fn validate_source(source: &SourceFunction, id: &str) -> Result<()> {
    validate_location(
        &FunctionLocation {
            module: source.module.clone(),
            section: source.section.clone(),
            address: source.address.clone(),
            end: source.end.clone(),
        },
        "source",
        id,
    )
}

fn decisive(item: &FunctionAttribution) -> bool {
    !item.source_weak
        && !item.target_weak
        && !item.template_instantiation
        && !item.ambiguous
        && (item.unique_exact_body
            || item.method == MatchMethod::StringRef
            || (matches!(item.method, MatchMethod::CallSite | MatchMethod::CallerSite)
                && item.evidence_count >= 2))
}

fn canonical_edge(
    unit: &str,
    module: &str,
    section: &str,
    neighbor: Option<&TargetFunctionObservation>,
    section_boundary_reason: &str,
    all: &[FunctionAttribution],
) -> EdgeEvidence {
    let Some(neighbor) = neighbor else {
        return EdgeEvidence {
            supported: true,
            reason: section_boundary_reason.into(),
            adjacent_attribution_id: None,
        };
    };
    let address = parse_hex(&neighbor.address);
    let Some(attribution) = all.iter().find(|item| {
        item.target.module == module
            && item.target.section == section
            && parse_hex(&item.target.address) == address
    }) else {
        return EdgeEvidence {
            supported: false,
            reason: format!("adjacent target function {} is not attributed", neighbor.address),
            adjacent_attribution_id: None,
        };
    };
    if attribution.source.unit == unit {
        return EdgeEvidence {
            supported: false,
            reason: "the adjacent target function is attributed to the same source unit".into(),
            adjacent_attribution_id: Some(attribution.id.clone()),
        };
    }
    EdgeEvidence {
        supported: attribution.independent,
        reason: if attribution.independent {
            format!(
                "adjacent target function is independently attributed to {}",
                attribution.source.unit
            )
        } else {
            "adjacent attribution is not an independent foreign boundary".into()
        },
        adjacent_attribution_id: Some(attribution.id.clone()),
    }
}

fn canonical_unit(
    mut unit: UnitIdentification,
    items: &[&FunctionAttribution],
    all: &[FunctionAttribution],
    source_functions: &[SourceFunctionObservation],
    target_functions: &[TargetFunctionObservation],
) -> UnitIdentification {
    let matched = items.len() as u32;
    let source_members: Vec<&SourceFunctionObservation> =
        source_functions.iter().filter(|function| function.unit == unit.unit).collect();
    unit.source_functions = source_members.len() as u32;
    unit.matched_functions = matched;
    unit.strong_functions = items
        .iter()
        .filter(|item| item.binary_supported && item.tier != MatchTier::Candidate)
        .count() as u32;
    unit.binary_functions = items.iter().filter(|item| item.binary_supported).count() as u32;
    unit.independently_supported_functions =
        items.iter().filter(|item| item.independent).count() as u32;
    unit.name_only_functions = items
        .iter()
        .filter(|item| item.origin == AttributionOrigin::InputName && !item.binary_supported)
        .count() as u32;
    let named = items.iter().filter(|item| item.origin == AttributionOrigin::InputName).count();
    unit.basis = match (unit.binary_functions, named) {
        (0, 0) => IdentificationBasis::None,
        (0, _) => IdentificationBasis::NamesOnly,
        (_, 0) => IdentificationBasis::Binary,
        _ => IdentificationBasis::Mixed,
    };
    unit.confidence = confidence_for(
        items.len(),
        unit.independently_supported_functions,
        items.iter().any(|item| item.ambiguous),
    );
    unit.evidence = items.iter().map(|item| item.id.clone()).collect();
    unit.unresolved_helpers = items
        .iter()
        .filter(|item| item.source_weak || item.target_weak || item.template_instantiation)
        .map(|item| item.id.clone())
        .collect();
    unit.competing_explanations = items
        .iter()
        .filter_map(|item| {
            let competing = item.competing.as_ref()?;
            Some(CompetingExplanation {
                target_address: item.target.address.clone(),
                source_name: competing.source_name.clone(),
                source_unit: competing.source_unit.clone(),
                relative_score: competing.relative_score,
            })
        })
        .collect();
    let attributed_source: BTreeSet<(&str, &str, &str)> = items
        .iter()
        .map(|item| {
            (
                item.source.module.as_str(),
                item.source.section.as_str(),
                item.source.address.as_str(),
            )
        })
        .collect();
    unit.missing_members = source_members
        .iter()
        .filter(|function| {
            !attributed_source.contains(&(
                function.module.as_str(),
                function.section.as_str(),
                function.address.as_str(),
            ))
        })
        .map(|function| MissingMember {
            source_name: function.name.clone(),
            section: function.section.clone(),
            address: function.address.clone(),
        })
        .collect();

    // Candidate membership and edges are derived diagnostics. Rebuild the
    // groups from the attributions so a serialized candidate cannot omit,
    // duplicate or repartition evidence to manufacture better boundaries.
    let mut groups: BTreeMap<(&str, &str, &str), Vec<&FunctionAttribution>> = BTreeMap::new();
    for item in items {
        groups
            .entry((&item.target.module, &item.source.section, &item.target.section))
            .or_default()
            .push(item);
    }
    let mut candidates = Vec::with_capacity(groups.len());
    for ((module, source_section, section), mut members) in groups {
        members.sort_by_key(|item| parse_hex(&item.target.address));
        let start = parse_hex(&members[0].target.address);
        let end = parse_hex(&members[members.len() - 1].target.end);
        let matched_addresses: BTreeSet<u32> =
            members.iter().map(|item| parse_hex(&item.target.address)).collect();
        let envelope: Vec<&TargetFunctionObservation> = target_functions
            .iter()
            .filter(|function| {
                function.module == module && function.section == section && {
                    let address = parse_hex(&function.address);
                    start <= address && address < end
                }
            })
            .collect();
        let unexplained_target_members: Vec<TargetMember> = envelope
            .iter()
            .filter(|function| !matched_addresses.contains(&parse_hex(&function.address)))
            .map(|function| TargetMember {
                name: function.name.clone(),
                address: function.address.clone(),
                end: function.end.clone(),
            })
            .collect();
        let mut source_section_members: Vec<&SourceFunctionObservation> = source_members
            .iter()
            .copied()
            .filter(|function| function.section == source_section)
            .collect();
        source_section_members.sort_by_key(|function| parse_hex(&function.address));
        let attributed_source: BTreeSet<u32> =
            members.iter().map(|item| parse_hex(&item.source.address)).collect();
        let left_source_edge_observed = source_section_members
            .first()
            .is_some_and(|function| attributed_source.contains(&parse_hex(&function.address)));
        let right_source_edge_observed = source_section_members
            .last()
            .is_some_and(|function| attributed_source.contains(&parse_hex(&function.address)));

        let mut target_section_members: Vec<&TargetFunctionObservation> = target_functions
            .iter()
            .filter(|function| function.module == module && function.section == section)
            .collect();
        target_section_members.sort_by_key(|function| parse_hex(&function.address));
        let left = target_section_members
            .iter()
            .rev()
            .find(|function| parse_hex(&function.address) < start)
            .copied();
        let right = target_section_members
            .iter()
            .find(|function| parse_hex(&function.address) >= end)
            .copied();
        let left_target_edge = canonical_edge(
            &unit.unit,
            module,
            section,
            left,
            "candidate starts at the beginning of the target section",
            all,
        );
        let right_target_edge = canonical_edge(
            &unit.unit,
            module,
            section,
            right,
            "candidate ends at the end of the target section",
            all,
        );
        candidates.push(CandidateSequence {
            module: module.to_string(),
            source_section: source_section.to_string(),
            section: section.to_string(),
            start: hex(start),
            end: hex(end),
            attribution_ids: members.iter().map(|item| item.id.clone()).collect(),
            matched_members: members.len() as u32,
            target_functions_in_envelope: envelope.len() as u32,
            contiguous_target_members: unexplained_target_members.is_empty()
                && envelope.len() == members.len(),
            left_source_edge_observed,
            right_source_edge_observed,
            left_target_edge,
            right_target_edge,
            unexplained_target_members,
            current_owners: envelope
                .iter()
                .filter_map(|item| item.current_owner.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        });
    }
    unit.candidates = candidates;

    unit.boundary_blockers.clear();
    if items.is_empty() {
        unit.boundary_blockers.push("no target function is attributed to this source unit".into());
    }
    if unit.basis == IdentificationBasis::NamesOnly {
        unit.boundary_blockers.push("identity is supported only by pre-existing names".into());
    }
    if items.iter().any(|item| item.ambiguous) {
        unit.boundary_blockers
            .push("one or more function identities have a competing explanation".into());
    }
    if !unit.missing_members.is_empty() {
        unit.boundary_blockers.push("some source members have no target attribution".into());
    }
    for candidate in &unit.candidates {
        if !candidate.contiguous_target_members {
            unit.boundary_blockers.push(format!(
                "{} has unmatched target functions inside the observed envelope",
                candidate.section
            ));
        }
        if !candidate.left_source_edge_observed {
            unit.boundary_blockers
                .push(format!("{} left source edge is not observed", candidate.section));
        }
        if !candidate.right_source_edge_observed {
            unit.boundary_blockers
                .push(format!("{} right source edge is not observed", candidate.section));
        }
        if !candidate.left_target_edge.supported {
            unit.boundary_blockers.push(format!(
                "{} left target edge is unsupported: {}",
                candidate.section, candidate.left_target_edge.reason
            ));
        }
        if !candidate.right_target_edge.supported {
            unit.boundary_blockers.push(format!(
                "{} right target edge is unsupported: {}",
                candidate.section, candidate.right_target_edge.reason
            ));
        }
    }
    unit.boundary_blockers.sort();
    unit.boundary_blockers.dedup();

    unit.application_blockers.clear();
    if !unit.boundary_blockers.is_empty() {
        unit.application_blockers.push("boundary evidence is incomplete".into());
    }
    let foreign: BTreeSet<&str> = items
        .iter()
        .filter_map(|item| item.current_target_owner.as_deref())
        .filter(|owner| *owner != unit.unit)
        .collect();
    if !foreign.is_empty() {
        unit.application_blockers.push(format!(
            "observed target members are currently owned by {}",
            foreign.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if !unit.unresolved_helpers.is_empty() {
        unit.application_blockers
            .push("weak or template members need emitted-owner evidence".into());
    }
    unit
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionLocation {
    pub module: String,
    pub section: String,
    pub address: String,
    pub end: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFunction {
    pub name: String,
    pub unit: String,
    pub module: String,
    pub section: String,
    pub address: String,
    pub end: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttributionOrigin {
    InputName,
    NormalizedBody,
    StringReference,
    CallGraph,
    LinkOrder,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetingAttribution {
    pub source_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_unit: Option<String>,
    pub relative_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReference {
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitIdentification {
    pub unit: String,
    pub autogenerated: bool,
    pub confidence: IdentificationConfidence,
    pub basis: IdentificationBasis,
    pub source_functions: u32,
    pub matched_functions: u32,
    pub strong_functions: u32,
    pub binary_functions: u32,
    pub independently_supported_functions: u32,
    pub name_only_functions: u32,
    pub candidates: Vec<CandidateSequence>,
    pub evidence: Vec<String>,
    pub competing_explanations: Vec<CompetingExplanation>,
    pub missing_members: Vec<MissingMember>,
    pub unresolved_helpers: Vec<String>,
    pub boundary_blockers: Vec<String>,
    pub application_blockers: Vec<String>,
}

impl UnitIdentification {
    pub fn absent(unit: impl Into<String>, source_functions: u32) -> Self {
        Self {
            unit: unit.into(),
            autogenerated: false,
            confidence: IdentificationConfidence::Absent,
            basis: IdentificationBasis::None,
            source_functions,
            matched_functions: 0,
            strong_functions: 0,
            binary_functions: 0,
            independently_supported_functions: 0,
            name_only_functions: 0,
            candidates: Vec::new(),
            evidence: Vec::new(),
            competing_explanations: Vec::new(),
            missing_members: Vec::new(),
            unresolved_helpers: Vec::new(),
            boundary_blockers: vec!["no target function is attributed to this source unit".into()],
            application_blockers: vec![
                "no target function is attributed to this source unit".into(),
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentificationConfidence {
    Absent,
    Tentative,
    Corroborated,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentificationBasis {
    None,
    NamesOnly,
    Binary,
    Mixed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateSequence {
    pub module: String,
    pub source_section: String,
    pub section: String,
    pub start: String,
    pub end: String,
    pub attribution_ids: Vec<String>,
    pub matched_members: u32,
    pub target_functions_in_envelope: u32,
    pub contiguous_target_members: bool,
    pub left_source_edge_observed: bool,
    pub right_source_edge_observed: bool,
    pub left_target_edge: EdgeEvidence,
    pub right_target_edge: EdgeEvidence,
    pub unexplained_target_members: Vec<TargetMember>,
    pub current_owners: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeEvidence {
    pub supported: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adjacent_attribution_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetMember {
    pub name: String,
    pub address: String,
    pub end: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetingExplanation {
    pub target_address: String,
    pub source_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_unit: Option<String>,
    pub relative_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingMember {
    pub source_name: String,
    pub section: String,
    pub address: String,
}

#[derive(Debug, Clone)]
struct SourceMember {
    name: String,
    section: String,
    address: u32,
    matched: bool,
}

/// Build the complete observation inventory directly from the function matcher.
pub fn identify_units(
    source: &MatchTarget,
    target: &MatchTarget,
    result: &MatchResult,
) -> IdentificationReport {
    let by_source: BTreeMap<NodeIndex, &Match> =
        result.matches.iter().map(|matched| (matched.source, matched)).collect();
    let mut source_members: BTreeMap<String, Vec<SourceMember>> = BTreeMap::new();
    // Seed from split ownership rather than call-graph membership. This keeps
    // data-only and empty code units in the complete identification inventory.
    for (_, _, _, split) in source.obj.sections.all_splits() {
        source_members.entry(split.unit.clone()).or_default();
    }
    for (node, function) in source.graph.iter() {
        let Some(unit) = source.unit_of(node) else { continue };
        source_members.entry(unit.to_string()).or_default().push(SourceMember {
            name: source.symbol_name(node).to_string(),
            section: source.obj.sections[function.section].name.clone(),
            address: function.address,
            matched: by_source.contains_key(&node),
        });
    }
    for members in source_members.values_mut() {
        members.sort_by_key(|member| (member.section.clone(), member.address));
    }

    let source_hash_counts = exact_hash_counts(source);
    let target_hash_counts = exact_hash_counts(target);
    let mut attributions = Vec::new();
    for matched in &result.matches {
        let Some(unit) = source.unit_of(matched.source) else { continue };
        attributions.push(attribution(
            source,
            target,
            matched,
            unit,
            &source_hash_counts,
            &target_hash_counts,
        ));
    }
    attributions.sort_by(|left, right| {
        left.target
            .module
            .cmp(&right.target.module)
            .then(left.target.section.cmp(&right.target.section))
            .then(left.target.address.cmp(&right.target.address))
            .then(left.source.unit.cmp(&right.source.unit))
    });

    let attributions_by_unit: BTreeMap<&str, Vec<&FunctionAttribution>> = source_members
        .keys()
        .map(|unit| {
            (unit.as_str(), attributions.iter().filter(|item| item.source.unit == *unit).collect())
        })
        .collect();
    let attributions_by_target: BTreeMap<(&str, &str, u32), &FunctionAttribution> = attributions
        .iter()
        .map(|item| {
            (
                (
                    item.target.module.as_str(),
                    item.target.section.as_str(),
                    parse_hex(&item.target.address),
                ),
                item,
            )
        })
        .collect();
    let units = source_members
        .iter()
        .map(|(unit, members)| {
            identify_unit(
                unit,
                members,
                attributions_by_unit.get(unit.as_str()).map(Vec::as_slice).unwrap_or_default(),
                target,
                &attributions_by_target,
                source.obj.is_unit_autogenerated(unit),
            )
        })
        .collect();

    let mut report = IdentificationReport {
        schema: IDENTIFICATION_SCHEMA,
        source: source.name.clone(),
        target: target.name.clone(),
        attributions,
        source_functions: source
            .graph
            .iter()
            .filter_map(|(node, function)| {
                Some(SourceFunctionObservation {
                    name: source.symbol_name(node).to_string(),
                    unit: source.unit_of(node)?.to_string(),
                    module: EXECUTABLE_MODULE.into(),
                    section: source.obj.sections[function.section].name.clone(),
                    address: hex(function.address),
                    end: hex(function.address + function.size),
                    normalized_body_sha256: helpers::body_digest(&source.obj, function),
                    weak: source.obj.symbols[function.symbol].flags.is_weak(),
                })
            })
            .collect(),
        target_functions: target
            .graph
            .iter()
            .map(|(node, function)| TargetFunctionObservation {
                name: target.symbol_name(node).to_string(),
                module: EXECUTABLE_MODULE.into(),
                section: target.obj.sections[function.section].name.clone(),
                address: hex(function.address),
                end: hex(function.address + function.size),
                current_owner: target.unit_of(node).map(str::to_string),
                owner_autogenerated: target
                    .unit_of(node)
                    .is_some_and(|unit| target.obj.is_unit_autogenerated(unit)),
                callers: function
                    .callers
                    .iter()
                    .map(|&caller| {
                        let caller = target.graph.node(caller);
                        CallerReference {
                            section: target.obj.sections[caller.section].name.clone(),
                            address: hex(caller.address),
                        }
                    })
                    .collect(),
                normalized_body_sha256: helpers::body_digest(&target.obj, function),
                weak: target.obj.symbols[function.symbol].flags.is_weak(),
            })
            .collect(),
        helper_families: Vec::new(),
        unresolved_target_clusters: Vec::new(),
        units,
    };
    report.helper_families = helpers::families(&report.source_functions, &report.target_functions);
    report.unresolved_target_clusters =
        helpers::unresolved_clusters(&report.target_functions, &report.attributions);
    report
}

fn attribution(
    source: &MatchTarget,
    target: &MatchTarget,
    matched: &Match,
    unit: &str,
    source_hash_counts: &HashMap<u64, u32>,
    target_hash_counts: &HashMap<u64, u32>,
) -> FunctionAttribution {
    let source_node = source.graph.node(matched.source);
    let target_node = target.graph.node(matched.target);
    let source_name = source.symbol_name(matched.source);
    let target_section = target.obj.sections[target_node.section].name.clone();
    let source_section = source.obj.sections[source_node.section].name.clone();
    let competing = matched.runner_up.map(|alternative| CompetingAttribution {
        source_name: source.symbol_name(alternative.source).to_string(),
        source_unit: source.unit_of(alternative.source).map(str::to_string),
        relative_score: round(alternative.relative_score),
    });
    let template = is_template(source, matched.source) || is_template(target, matched.target);
    let source_weak = source.is_weak(matched.source);
    let target_weak = target.is_weak(matched.target);
    let unique_exact =
        unique_exact_body(source, target, matched, source_hash_counts, target_hash_counts);
    let binary_supported = matched.method != MatchMethod::Name || matched.distinctive_body;
    let independent = !source_weak
        && !target_weak
        && !template
        && !matched.is_contested()
        && (unique_exact
            || matched.method == MatchMethod::StringRef
            || (matches!(matched.method, MatchMethod::CallSite | MatchMethod::CallerSite)
                && matched.evidence >= 2));
    let mut evidence = vec![EvidenceReference {
        kind: matched.method.as_str().to_string(),
        detail: method_detail(matched.method).to_string(),
    }];
    if unique_exact && matched.method != MatchMethod::ExactHash {
        evidence.push(EvidenceReference {
            kind: "unique-exact-body".into(),
            detail: "relocation-masked bodies are equal and unique in both binaries".into(),
        });
    } else if matched.distinctive_body && matched.method != MatchMethod::ExactHash {
        evidence.push(EvidenceReference {
            kind: "normalized-body".into(),
            detail: "relocation-masked bodies are equal but do not uniquely identify the pair"
                .into(),
        });
    }
    if matched.evidence > 1 {
        evidence.push(EvidenceReference {
            kind: "corroboration".into(),
            detail: format!("{} independently agreeing neighbours", matched.evidence),
        });
    }
    FunctionAttribution {
        id: format!(
            "{}:{}:{}<-{}:{}:{}",
            EXECUTABLE_MODULE,
            target_section,
            hex(target_node.address),
            EXECUTABLE_MODULE,
            source_section,
            hex(source_node.address)
        ),
        target: FunctionLocation {
            module: EXECUTABLE_MODULE.into(),
            section: target_section,
            address: hex(target_node.address),
            end: hex(target_node.address + target_node.size),
        },
        source: SourceFunction {
            name: source_name.to_string(),
            unit: unit.to_string(),
            module: EXECUTABLE_MODULE.into(),
            section: source_section,
            address: hex(source_node.address),
            end: hex(source_node.address + source_node.size),
        },
        method: matched.method,
        tier: matched.tier(),
        confidence: round(matched.confidence),
        evidence_count: matched.evidence,
        origin: origin(matched.method),
        distinctive_body: matched.distinctive_body,
        unique_exact_body: unique_exact,
        binary_supported,
        independent,
        ambiguous: matched.is_contested(),
        competing,
        source_weak,
        target_weak,
        template_instantiation: template,
        current_target_owner: target.unit_of(matched.target).map(str::to_string),
        evidence,
    }
}

fn identify_unit(
    unit: &str,
    members: &[SourceMember],
    attributions: &[&FunctionAttribution],
    target: &MatchTarget,
    attributions_by_target: &BTreeMap<(&str, &str, u32), &FunctionAttribution>,
    autogenerated: bool,
) -> UnitIdentification {
    let strong_functions = attributions
        .iter()
        .filter(|item| item.binary_supported && item.tier != MatchTier::Candidate)
        .count() as u32;
    let binary_functions = attributions.iter().filter(|item| item.binary_supported).count() as u32;
    let independently_supported_functions =
        attributions.iter().filter(|item| item.independent).count() as u32;
    let named_functions =
        attributions.iter().filter(|item| item.origin == AttributionOrigin::InputName).count()
            as u32;
    let name_only_functions = attributions
        .iter()
        .filter(|item| item.origin == AttributionOrigin::InputName && !item.binary_supported)
        .count() as u32;
    let competing_explanations: Vec<CompetingExplanation> = attributions
        .iter()
        .filter_map(|item| {
            let competing = item.competing.as_ref()?;
            Some(CompetingExplanation {
                target_address: item.target.address.clone(),
                source_name: competing.source_name.clone(),
                source_unit: competing.source_unit.clone(),
                relative_score: competing.relative_score,
            })
        })
        .collect();
    let basis = match (binary_functions, named_functions) {
        (0, 0) => IdentificationBasis::None,
        (0, _) => IdentificationBasis::NamesOnly,
        (_, 0) => IdentificationBasis::Binary,
        _ => IdentificationBasis::Mixed,
    };
    let confidence = confidence_for(
        attributions.len(),
        independently_supported_functions,
        attributions.iter().any(|item| item.ambiguous),
    );

    let missing_members: Vec<MissingMember> = members
        .iter()
        .filter(|member| !member.matched)
        .map(|member| MissingMember {
            source_name: member.name.clone(),
            section: member.section.clone(),
            address: hex(member.address),
        })
        .collect();
    let unresolved_helpers: Vec<String> = attributions
        .iter()
        .filter(|item| item.source_weak || item.target_weak || item.template_instantiation)
        .map(|item| item.id.clone())
        .collect();

    let mut grouped: BTreeMap<(&str, &str, &str), Vec<&FunctionAttribution>> = BTreeMap::new();
    for item in attributions {
        grouped
            .entry((&item.target.module, &item.source.section, &item.target.section))
            .or_default()
            .push(item);
    }
    let candidates: Vec<CandidateSequence> = grouped
        .into_values()
        .map(|items| candidate_sequence(unit, items, members, target, attributions_by_target))
        .collect();

    let mut boundary_blockers = Vec::new();
    if attributions.is_empty() {
        boundary_blockers.push("no target function is attributed to this source unit".into());
    }
    if basis == IdentificationBasis::NamesOnly {
        boundary_blockers.push("identity is supported only by pre-existing names".into());
    }
    if attributions.iter().any(|item| item.ambiguous) {
        boundary_blockers
            .push("one or more function identities have a competing explanation".into());
    }
    if !missing_members.is_empty() {
        boundary_blockers.push("some source members have no target attribution".into());
    }
    for candidate in &candidates {
        if !candidate.contiguous_target_members {
            boundary_blockers.push(format!(
                "{} has unmatched target functions inside the observed envelope",
                candidate.section
            ));
        }
        if !candidate.left_source_edge_observed {
            boundary_blockers
                .push(format!("{} left source edge is not observed", candidate.section));
        }
        if !candidate.right_source_edge_observed {
            boundary_blockers
                .push(format!("{} right source edge is not observed", candidate.section));
        }
        if !candidate.left_target_edge.supported {
            boundary_blockers.push(format!(
                "{} left target edge is unsupported: {}",
                candidate.section, candidate.left_target_edge.reason
            ));
        }
        if !candidate.right_target_edge.supported {
            boundary_blockers.push(format!(
                "{} right target edge is unsupported: {}",
                candidate.section, candidate.right_target_edge.reason
            ));
        }
    }
    boundary_blockers.sort();
    boundary_blockers.dedup();

    let mut application_blockers = Vec::new();
    if !boundary_blockers.is_empty() {
        application_blockers.push("boundary evidence is incomplete".into());
    }
    let foreign: BTreeSet<&str> = attributions
        .iter()
        .filter_map(|item| item.current_target_owner.as_deref())
        .filter(|owner| *owner != unit)
        .collect();
    if !foreign.is_empty() {
        application_blockers.push(format!(
            "observed target members are currently owned by {}",
            foreign.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if !unresolved_helpers.is_empty() {
        application_blockers.push("weak or template members need emitted-owner evidence".into());
    }

    UnitIdentification {
        unit: unit.to_string(),
        autogenerated,
        confidence,
        basis,
        source_functions: members.len() as u32,
        matched_functions: attributions.len() as u32,
        strong_functions,
        binary_functions,
        independently_supported_functions,
        name_only_functions,
        candidates,
        evidence: attributions.iter().map(|item| item.id.clone()).collect(),
        competing_explanations,
        missing_members,
        unresolved_helpers,
        boundary_blockers,
        application_blockers,
    }
}

fn candidate_sequence(
    unit: &str,
    mut items: Vec<&FunctionAttribution>,
    source_members: &[SourceMember],
    target: &MatchTarget,
    attributions_by_target: &BTreeMap<(&str, &str, u32), &FunctionAttribution>,
) -> CandidateSequence {
    items.sort_by_key(|item| parse_hex(&item.target.address));
    let first = items[0];
    let last = items[items.len() - 1];
    let start = parse_hex(&first.target.address);
    let end = parse_hex(&last.target.end);
    let section = first.target.section.as_str();
    let target_members: Vec<(NodeIndex, _)> = target
        .graph
        .iter()
        .filter(|(_, node)| {
            target.obj.sections[node.section].name == section
                && node.address >= start
                && node.address < end
        })
        .collect();
    let mut section_members: Vec<(NodeIndex, _)> = target
        .graph
        .iter()
        .filter(|(_, node)| target.obj.sections[node.section].name == section)
        .collect();
    section_members.sort_by_key(|(_, node)| node.address);
    let attributed_target: BTreeSet<u32> =
        items.iter().map(|item| parse_hex(&item.target.address)).collect();
    let unexplained_target_members = target_members
        .iter()
        .filter(|(_, node)| !attributed_target.contains(&node.address))
        .map(|(node, function)| TargetMember {
            name: target.symbol_name(*node).to_string(),
            address: hex(function.address),
            end: hex(function.address + function.size),
        })
        .collect::<Vec<_>>();

    let source_section = first.source.section.as_str();
    let edge_members: Vec<&SourceMember> =
        source_members.iter().filter(|member| member.section == source_section).collect();
    let attributed_source: BTreeSet<u32> =
        items.iter().map(|item| parse_hex(&item.source.address)).collect();
    let left_source_edge_observed =
        edge_members.first().is_some_and(|member| attributed_source.contains(&member.address));
    let right_source_edge_observed =
        edge_members.last().is_some_and(|member| attributed_source.contains(&member.address));
    let current_owners: BTreeSet<String> = target_members
        .iter()
        .filter_map(|(node, _)| target.unit_of(*node).map(str::to_string))
        .collect();
    let left_neighbor = section_members.iter().rev().find(|(_, node)| node.address < start);
    let right_neighbor = section_members.iter().find(|(_, node)| node.address >= end);
    let left_target_edge = edge_evidence(
        unit,
        first.target.module.as_str(),
        section,
        left_neighbor,
        "candidate starts at the beginning of the target section",
        attributions_by_target,
    );
    let right_target_edge = edge_evidence(
        unit,
        first.target.module.as_str(),
        section,
        right_neighbor,
        "candidate ends at the end of the target section",
        attributions_by_target,
    );

    CandidateSequence {
        module: first.target.module.clone(),
        source_section: first.source.section.clone(),
        section: first.target.section.clone(),
        start: first.target.address.clone(),
        end: last.target.end.clone(),
        attribution_ids: items.iter().map(|item| item.id.clone()).collect(),
        matched_members: items.len() as u32,
        target_functions_in_envelope: target_members.len() as u32,
        contiguous_target_members: unexplained_target_members.is_empty(),
        left_source_edge_observed,
        right_source_edge_observed,
        left_target_edge,
        right_target_edge,
        unexplained_target_members,
        current_owners: current_owners.into_iter().collect(),
    }
}

fn edge_evidence(
    unit: &str,
    module: &str,
    section: &str,
    neighbor: Option<&(NodeIndex, &crate::analysis::callgraph::FunctionNode)>,
    section_boundary_reason: &str,
    attributions_by_target: &BTreeMap<(&str, &str, u32), &FunctionAttribution>,
) -> EdgeEvidence {
    let Some((_, node)) = neighbor else {
        return EdgeEvidence {
            supported: true,
            reason: section_boundary_reason.into(),
            adjacent_attribution_id: None,
        };
    };
    let Some(attribution) = attributions_by_target.get(&(module, section, node.address)) else {
        return EdgeEvidence {
            supported: false,
            reason: format!("adjacent target function {} is not attributed", hex(node.address)),
            adjacent_attribution_id: None,
        };
    };
    if attribution.source.unit == unit {
        return EdgeEvidence {
            supported: false,
            reason: "the adjacent target function is attributed to the same source unit".into(),
            adjacent_attribution_id: Some(attribution.id.clone()),
        };
    }
    if !attribution.independent || attribution.ambiguous {
        return EdgeEvidence {
            supported: false,
            reason: format!(
                "the adjacent {} attribution is not independent and decisive",
                attribution.source.unit
            ),
            adjacent_attribution_id: Some(attribution.id.clone()),
        };
    }
    EdgeEvidence {
        supported: true,
        reason: format!(
            "adjacent target function is independently attributed to {}",
            attribution.source.unit
        ),
        adjacent_attribution_id: Some(attribution.id.clone()),
    }
}

fn confidence_for(
    matches: usize,
    independently_supported_functions: u32,
    contested: bool,
) -> IdentificationConfidence {
    if matches == 0 {
        IdentificationConfidence::Absent
    } else if contested {
        IdentificationConfidence::Ambiguous
    } else if independently_supported_functions >= 2 {
        IdentificationConfidence::Corroborated
    } else {
        IdentificationConfidence::Tentative
    }
}

fn exact_hash_counts(target: &MatchTarget) -> HashMap<u64, u32> {
    let mut counts = HashMap::new();
    for fingerprint in &target.fingerprints {
        if fingerprint.instruction_count >= 4 {
            *counts.entry(fingerprint.exact_hash).or_default() += 1;
        }
    }
    counts
}

fn unique_exact_body(
    source: &MatchTarget,
    target: &MatchTarget,
    matched: &Match,
    source_hash_counts: &HashMap<u64, u32>,
    target_hash_counts: &HashMap<u64, u32>,
) -> bool {
    let source_fingerprint = &source.fingerprints[matched.source as usize];
    let target_fingerprint = &target.fingerprints[matched.target as usize];
    if source_fingerprint.instruction_count < 4
        || source_fingerprint.exact_hash != target_fingerprint.exact_hash
        || source_hash_counts.get(&source_fingerprint.exact_hash) != Some(&1)
        || target_hash_counts.get(&target_fingerprint.exact_hash) != Some(&1)
    {
        return false;
    }
    let source_node = source.graph.node(matched.source);
    let target_node = target.graph.node(matched.target);
    source.obj.symbols[source_node.symbol].size_known
        && target.obj.symbols[target_node.symbol].size_known
        && source_node.size == target_node.size
        && normalized_body(&source.obj, source_node) == normalized_body(&target.obj, target_node)
}

fn origin(method: MatchMethod) -> AttributionOrigin {
    match method {
        MatchMethod::Name => AttributionOrigin::InputName,
        MatchMethod::ExactHash => AttributionOrigin::NormalizedBody,
        MatchMethod::StringRef => AttributionOrigin::StringReference,
        MatchMethod::CallSite | MatchMethod::CallerSite => AttributionOrigin::CallGraph,
        MatchMethod::Layout => AttributionOrigin::LinkOrder,
    }
}

fn method_detail(method: MatchMethod) -> &'static str {
    match method {
        MatchMethod::Name => "the two input binaries already carry the same name",
        MatchMethod::ExactHash => "relocation-masked instruction bodies are uniquely equal",
        MatchMethod::StringRef => "a uniquely referenced string identifies both functions",
        MatchMethod::CallSite => "position among calls from an already matched function agrees",
        MatchMethod::CallerSite => "matched caller/callee topology leaves one pairing",
        MatchMethod::Layout => "position between already matched link-order anchors agrees",
    }
}

fn is_template(target: &MatchTarget, node: NodeIndex) -> bool {
    let symbol = &target.obj.symbols[target.graph.node(node).symbol];
    let name = symbol.demangled_name.as_deref().unwrap_or(&symbol.name);
    let callable = callable_name(name);
    callable.contains('<') && callable.contains('>')
}

/// Return the qualified callable, excluding a demangler's optional return type.
/// A simple split on `(` is not enough: `rstl::rc_ptr<T> C::Get()` is an
/// ordinary method whose return type happens to be a template. The separator
/// we want is the last space outside angle brackets before the argument list.
fn callable_name(name: &str) -> &str {
    let declaration = name.split_once('(').map_or(name, |(declaration, _)| declaration);
    let mut depth = 0_u32;
    let mut separator = None;
    for (offset, character) in declaration.char_indices() {
        match character {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ' ' if depth == 0 => separator = Some(offset + character.len_utf8()),
            _ => {}
        }
    }
    separator.map_or(declaration, |offset| &declaration[offset..])
}

fn round(value: f32) -> f32 { (value * 1000.0).round() / 1000.0 }

fn hex(value: u32) -> String { format!("{value:#010X}") }

fn parse_hex(value: &str) -> u32 {
    u32::from_str_radix(value.trim_start_matches("0x").trim_start_matches("0X"), 16).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use decomp_toolkit::obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjRelocations, ObjSection, ObjSectionKind, ObjSplit,
        ObjSplits, ObjSymbol, ObjSymbolFlagSet, ObjSymbolFlags, ObjSymbolKind,
    };

    use super::*;

    fn fixture_index(units: Vec<crate::analysis::coverage::CoverageUnit>) -> ObservationIndex {
        let report = crate::analysis::coverage_fixture::report("source", "target", units);
        let expected = report.source_units.iter().map(|unit| unit.name.clone()).collect();
        ObservationIndex::load(report.identifications, "source", "target", &expected).unwrap()
    }

    #[test]
    fn forged_aggregate_and_independent_flags_are_recomputed() {
        let unit = crate::analysis::coverage_fixture::unit("A.cpp", vec![
            crate::analysis::coverage_fixture::anchor("A", 0x8000_1000, 0x8000_1100),
        ]);
        let mut report = crate::analysis::coverage_fixture::report("source", "target", vec![unit]);
        let attribution = &mut report.identifications.attributions[0];
        attribution.method = MatchMethod::Name;
        attribution.distinctive_body = false;
        attribution.unique_exact_body = false;
        attribution.independent = true;
        attribution.tier = MatchTier::Confident;
        attribution.ambiguous = false;
        attribution.competing = Some(CompetingAttribution {
            source_name: "runner_up".into(),
            source_unit: Some("A.cpp".into()),
            relative_score: 0.9,
        });
        let diagnostic = &mut report.identifications.units[0];
        diagnostic.matched_functions = 99;
        diagnostic.independently_supported_functions = 99;
        diagnostic.confidence = IdentificationConfidence::Corroborated;
        diagnostic.candidates.clear();

        let expected = BTreeSet::from(["A.cpp".to_string()]);
        let index =
            ObservationIndex::load(report.identifications, "source", "target", &expected).unwrap();
        assert!(!index.report().attributions[0].independent);
        assert!(index.report().attributions[0].ambiguous);
        assert_eq!(index.report().attributions[0].tier, MatchTier::Candidate);
        assert_eq!(index.unit("A.cpp").unwrap().matched_functions, 1);
        assert_eq!(index.unit("A.cpp").unwrap().independently_supported_functions, 0);
        assert_eq!(index.unit("A.cpp").unwrap().candidates.len(), 1);
        assert_eq!(index.unit("A.cpp").unwrap().confidence, IdentificationConfidence::Ambiguous);
        assert_eq!(index.unit("A.cpp").unwrap().basis, IdentificationBasis::NamesOnly);
    }

    #[test]
    fn a_platform_shaped_claim_cannot_take_sounds_tail() {
        let a = crate::analysis::coverage_fixture::unit("Platform.cpp", vec![
            crate::analysis::coverage_fixture::anchor("Platform", 0x8000_1000, 0x8000_1100),
        ]);
        let b = crate::analysis::coverage_fixture::unit("Sound.cpp", vec![
            crate::analysis::coverage_fixture::anchor("Sound", 0x8000_1180, 0x8000_1280),
        ]);
        let index = fixture_index(vec![a, b]);
        let after = BTreeMap::from([(".text".into(), vec![(0x8000_1000, 0x8000_1280)])]);
        let assessment = index.assess("Platform.cpp", "main", &BTreeMap::new(), &after);
        assert_eq!(assessment.new_conflicts, 1);
        assert!(!assessment.permits_automatic_claim());
        assert!(assessment.records.iter().any(|record| {
            record.class == ClaimClass::ConflictingAttribution
                && record.attributed_unit.as_deref() == Some("Sound.cpp")
        }));
    }

    #[test]
    fn a_player_state_claim_cannot_take_a_timer_cluster() {
        let player = crate::analysis::coverage_fixture::unit("CPlayerState.cpp", vec![
            crate::analysis::coverage_fixture::anchor("Player", 0x8000_2000, 0x8000_2100),
        ]);
        let timer = crate::analysis::coverage_fixture::unit("CTime.cpp", vec![
            crate::analysis::coverage_fixture::anchor("TimerCtor", 0x8000_2200, 0x8000_2300),
        ]);
        let index = fixture_index(vec![player, timer]);
        let after = BTreeMap::from([(".text".into(), vec![(0x8000_2000, 0x8000_2300)])]);
        let assessment = index.assess("CPlayerState.cpp", "main", &BTreeMap::new(), &after);
        assert_eq!(assessment.new_conflicts, 1);
        assert!(!assessment.permits_automatic_claim());
    }

    #[test]
    fn a_weak_foreign_function_is_unresolved_shared_evidence_not_a_hard_conflict() {
        let a = crate::analysis::coverage_fixture::unit("A.cpp", vec![
            crate::analysis::coverage_fixture::anchor("A", 0x8000_3000, 0x8000_3100),
        ]);
        let mut helper =
            crate::analysis::coverage_fixture::anchor("helper", 0x8000_3100, 0x8000_3200);
        helper.target_weak = true;
        let b = crate::analysis::coverage_fixture::unit("B.cpp", vec![helper]);
        let index = fixture_index(vec![a, b]);
        let after = BTreeMap::from([(".text".into(), vec![(0x8000_3000, 0x8000_3200)])]);
        let assessment = index.assess("A.cpp", "main", &BTreeMap::new(), &after);
        assert_eq!(assessment.new_conflicts, 0);
        assert_eq!(assessment.new_shared_helpers, 1);
        assert!(assessment.records.iter().any(|record| record.class == ClaimClass::SharedHelper));
    }

    #[test]
    fn cutting_through_an_attributed_function_is_unresolved() {
        let unit = crate::analysis::coverage_fixture::unit("A.cpp", vec![
            crate::analysis::coverage_fixture::anchor("A", 0x8000_4000, 0x8000_4100),
        ]);
        let index = fixture_index(vec![unit]);
        let after = BTreeMap::from([(".text".into(), vec![(0x8000_4004, 0x8000_4100)])]);
        let assessment = index.assess("A.cpp", "main", &BTreeMap::new(), &after);
        assert_eq!(assessment.new_unresolved, 1);
        assert_eq!(assessment.independent_members, 0);
        assert!(!assessment.permits_automatic_claim());
    }

    #[test]
    fn padding_without_an_attributed_member_is_not_automatic_ownership() {
        let unit = crate::analysis::coverage_fixture::unit("A.cpp", Vec::new());
        let index = fixture_index(vec![unit]);
        let after = BTreeMap::from([(".text".into(), vec![(0x8000_4000, 0x8000_4100)])]);
        let assessment = index.assess("A.cpp", "main", &BTreeMap::new(), &after);
        assert_eq!(assessment.padding_bytes, 0x100);
        assert_eq!(assessment.independent_members, 0);
        assert!(!assessment.complete_membership);
        assert!(!assessment.permits_automatic_claim());
    }

    /// A.cpp holds 0x1000..0x1300 as three functions, with an unattributed
    /// function after them, and B.cpp owns 0x1340..0x1380.
    fn with_helper(callers: &[u32]) -> (IdentificationReport, BTreeSet<String>) {
        use crate::analysis::coverage_fixture::{anchor, report, unit};
        let report = report("source", "target", vec![
            unit("A.cpp", vec![
                anchor("a0", 0x1000, 0x1100),
                anchor("a1", 0x1100, 0x1200),
                anchor("a2", 0x1200, 0x1300),
            ]),
            unit("B.cpp", vec![anchor("b0", 0x1340, 0x1380)]),
        ]);
        let mut identifications = report.identifications;
        identifications.target_functions.push(TargetFunctionObservation {
            name: "fn_1300".into(),
            module: "main".into(),
            section: ".text".into(),
            address: "0x00001300".into(),
            end: "0x00001340".into(),
            current_owner: None,
            owner_autogenerated: false,
            callers: callers
                .iter()
                .map(|address| CallerReference {
                    section: ".text".into(),
                    address: format!("0x{address:08X}"),
                })
                .collect(),
            normalized_body_sha256: None,
            weak: false,
        });
        let expected = report.source_units.iter().map(|unit| unit.name.clone()).collect();
        (identifications, expected)
    }

    fn assess_claim(
        index: &ObservationIndex,
        before: (u32, u32),
        after: (u32, u32),
    ) -> OwnershipAssessment {
        index.assess(
            "A.cpp",
            "main",
            &BTreeMap::from([(".text".into(), vec![before])]),
            &BTreeMap::from([(".text".into(), vec![after])]),
        )
    }

    #[test]
    fn a_helper_only_the_unit_calls_is_explained_new_ground() {
        let (report, expected) = with_helper(&[0x1200]);
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        let assessment = assess_claim(&index, (0x1000, 0x1300), (0x1000, 0x1340));
        assert_eq!(assessment.new_caller_confined_helpers, 1);
        assert_eq!(assessment.new_unresolved, 0);
        assert!(assessment.permits_automatic_claim());
        assert!(assessment.records.iter().any(|record| {
            record.class == ClaimClass::CallerConfinedHelper && record.start == "0x00001300"
        }));
    }

    #[test]
    fn a_helper_is_only_confined_to_callers_the_body_holds() {
        // Its caller is A's, but the claim does not keep that caller.
        let (report, expected) = with_helper(&[0x1200]);
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        let assessment = index.assess(
            "A.cpp",
            "main",
            &BTreeMap::new(),
            &BTreeMap::from([(".text".into(), vec![(0x1000, 0x1100), (0x1300, 0x1340)])]),
        );
        assert_eq!(assessment.new_unresolved, 1);
        assert!(!assessment.permits_automatic_claim());
    }

    #[test]
    fn a_helper_another_unit_calls_is_not_explained() {
        let (report, expected) = with_helper(&[0x1200, 0x1340]);
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        let assessment = assess_claim(&index, (0x1000, 0x1300), (0x1000, 0x1340));
        assert_eq!(assessment.new_unresolved, 1);
        assert_eq!(assessment.new_caller_confined_helpers, 0);
        assert!(!assessment.permits_automatic_claim());
    }

    /// Takes away everything that makes the attribution at `address` decisive.
    fn weaken(report: &mut IdentificationReport, address: &str) {
        let item = report.attributions.iter_mut().find(|item| item.target.address == address);
        let item = item.unwrap();
        item.method = MatchMethod::Layout;
        item.unique_exact_body = false;
        item.distinctive_body = false;
    }

    /// Adds a source function of `unit` that the target does not have.
    fn source_only(report: &mut IdentificationReport, unit: &str, name: &str, address: u32) {
        let mut function =
            report.source_functions.iter().find(|function| function.unit == unit).unwrap().clone();
        function.name = name.into();
        function.address = hex(address);
        function.end = hex(address + 0x40);
        report.source_functions.push(function);
    }

    #[test]
    fn a_helper_at_the_seam_is_placed_at_its_units_tail() {
        let (report, expected) = with_helper(&[0x1200]);
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        assert_eq!(
            index.helper_placement("A.cpp", "main", ".text", 0x1300),
            Some(HelperPlacement {
                position: HelperPosition::Tail,
                members: vec![(0x1200, 0x1300)]
            })
        );
        // The seam admits B too, as B's head: position alone cannot choose
        // between the two units either side of it. The callers choose, and
        // they are A's.
        let placement = index.helper_placement("B.cpp", "main", ".text", 0x1300).unwrap();
        assert_eq!(placement.position, HelperPosition::Head);
        let helper = &index.section_functions("main", ".text")[3];
        assert_eq!(helper.address, "0x00001300");
        assert!(
            !index.helper_callers_confined("B.cpp", "main", helper, &placement, |_, _, _| true)
        );
        let b = BTreeMap::from([(".text".into(), vec![(0x1300, 0x1380)])]);
        let assessment = index.assess("B.cpp", "main", &BTreeMap::new(), &b);
        assert_eq!(assessment.new_unresolved, 1);
    }

    #[test]
    fn callers_alone_do_not_place_a_helper_where_its_unit_continues() {
        // A has a function the target lacks after a2, so a2 is not where A
        // ends and the helper need not be A's. Its callers are A's all the
        // same; they corroborate, they do not decide.
        let (mut report, expected) = with_helper(&[0x1200]);
        source_only(&mut report, "A.cpp", "a3", 0x2000);
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        assert_eq!(index.helper_placement("A.cpp", "main", ".text", 0x1300), None);
        let assessment = assess_claim(&index, (0x1000, 0x1300), (0x1000, 0x1340));
        assert_eq!(assessment.new_caller_confined_helpers, 0);
        assert_eq!(assessment.new_unresolved, 1);
        assert!(!assessment.permits_automatic_claim());
    }

    #[test]
    fn a_helper_is_bounded_only_where_another_unit_independently_begins() {
        // B's function after it is not B's first: B may begin with it.
        let (mut report, expected) = with_helper(&[0x1200]);
        source_only(&mut report, "B.cpp", "b_early", 0x0800);
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        assert_eq!(index.helper_placement("A.cpp", "main", ".text", 0x1300), None);
        assert_eq!(assess_claim(&index, (0x1000, 0x1300), (0x1000, 0x1340)).new_unresolved, 1);

        // B's first function is B's only by name: nothing pins where B starts.
        let (mut report, expected) = with_helper(&[0x1200]);
        weaken(&mut report, "0x00001340");
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        assert_eq!(index.helper_placement("A.cpp", "main", ".text", 0x1300), None);
        assert_eq!(assess_claim(&index, (0x1000, 0x1300), (0x1000, 0x1340)).new_unresolved, 1);
    }

    #[test]
    fn a_weakly_attributed_caller_corroborates_only_from_beside_the_helper() {
        // a2 is A's only by name, but it is the member whose position places
        // the helper, so its call is the same evidence.
        let (mut report, expected) = with_helper(&[0x1200]);
        weaken(&mut report, "0x00001200");
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        let assessment = assess_claim(&index, (0x1000, 0x1300), (0x1000, 0x1340));
        assert_eq!(assessment.new_caller_confined_helpers, 1);
        assert!(assessment.permits_automatic_claim());

        // a1 is A's only by name and calls from elsewhere: the helper would
        // be A's on the strength of that weak attribution alone.
        let (mut report, expected) = with_helper(&[0x1100]);
        weaken(&mut report, "0x00001100");
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        let assessment = assess_claim(&index, (0x1000, 0x1300), (0x1000, 0x1340));
        assert_eq!(assessment.new_caller_confined_helpers, 0);
        assert_eq!(assessment.new_unresolved, 1);
    }

    #[test]
    fn a_helper_between_two_members_in_source_order_is_interior() {
        use crate::analysis::coverage_fixture::{anchor, report, unit};
        let built = report("source", "target", vec![unit("A.cpp", vec![
            anchor("a0", 0x1000, 0x1100),
            anchor("a1", 0x1140, 0x1200),
        ])]);
        let expected = built.source_units.iter().map(|unit| unit.name.clone()).collect();
        let mut identifications = built.identifications;
        identifications.target_functions.push(TargetFunctionObservation {
            name: "fn_1100".into(),
            module: "main".into(),
            section: ".text".into(),
            address: "0x00001100".into(),
            end: "0x00001140".into(),
            current_owner: None,
            owner_autogenerated: false,
            callers: vec![CallerReference {
                section: ".text".into(),
                address: "0x00001140".into(),
            }],
            normalized_body_sha256: None,
            weak: false,
        });
        let index = ObservationIndex::load(identifications, "source", "target", &expected).unwrap();
        assert_eq!(
            index.helper_placement("A.cpp", "main", ".text", 0x1100).map(|p| p.position),
            Some(HelperPosition::Interior)
        );
        let assessment = assess_claim(&index, (0x1000, 0x1100), (0x1000, 0x1200));
        assert_eq!(assessment.new_caller_confined_helpers, 1);
        assert!(assessment.permits_automatic_claim());
    }

    #[test]
    fn an_uncalled_function_is_not_a_helper() {
        let (report, expected) = with_helper(&[]);
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        assert_eq!(assess_claim(&index, (0x1000, 0x1300), (0x1000, 0x1340)).new_unresolved, 1);
    }

    #[test]
    fn a_weakly_attributed_member_is_placed_only_between_independent_neighbours() {
        let (mut report, expected) = with_helper(&[]);
        let middle = report
            .attributions
            .iter_mut()
            .find(|item| item.target.address == "0x00001100")
            .unwrap();
        middle.method = MatchMethod::Layout;
        middle.unique_exact_body = false;
        middle.distinctive_body = false;
        let index = ObservationIndex::load(report.clone(), "source", "target", &expected).unwrap();
        // Both neighbours are held: it is placed by them.
        let assessment = assess_claim(&index, (0x1000, 0x1100), (0x1000, 0x1300));
        assert_eq!(assessment.new_order_bracketed, 1);
        assert!(assessment.permits_automatic_claim());
        // Only the left neighbour is held: nothing places it.
        let assessment = assess_claim(&index, (0x1000, 0x1100), (0x1000, 0x1200));
        assert_eq!(assessment.new_unresolved, 1);

        // Neighbours out of source order do not bracket it.
        let last = report
            .attributions
            .iter_mut()
            .find(|item| item.target.address == "0x00001200")
            .unwrap();
        last.source.address = "0x00000F00".into();
        last.source.end = "0x00001000".into();
        report.source_functions.iter_mut().filter(|function| function.name == "a2").for_each(
            |function| {
                function.address = "0x00000F00".into();
                function.end = "0x00001000".into();
            },
        );
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        let assessment = assess_claim(&index, (0x1000, 0x1100), (0x1000, 0x1300));
        assert_eq!(assessment.new_order_bracketed, 0);
        assert_eq!(assessment.new_unresolved, 1);
    }

    #[test]
    fn schema_two_reports_still_load_and_cannot_claim_callers() {
        let (mut report, expected) = with_helper(&[]);
        report.schema = 2;
        let digest = ObservationIndex::load(report.clone(), "source", "target", &expected)
            .unwrap()
            .digest()
            .to_string();
        // With no callers the report serializes as schema 2 always did, so an
        // older run's recorded digest still verifies.
        assert!(!serde_json::to_string(&report).unwrap().contains("callers"));
        assert!(!digest.is_empty());

        let (mut forged, expected) = with_helper(&[0x1200]);
        forged.schema = 2;
        assert!(ObservationIndex::load(forged, "source", "target", &expected).is_err());
    }

    #[test]
    fn schema_three_keeps_its_caller_inventory_after_helper_schema_bump() {
        let (mut report, expected) = with_helper(&[0x1200]);
        report.schema = 3;
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        assert_eq!(index.section_functions("main", ".text").len(), 5);
        assert!(index.report().helper_families.is_empty());
    }

    #[test]
    fn older_schema_does_not_gain_new_clusters_or_change_its_serialized_shape() {
        let (mut report, expected) = with_helper(&[]);
        for function in &mut report.target_functions {
            function.current_owner = match function.address.as_str() {
                "0x00001000" | "0x00001100" | "0x00001200" => Some("A.cpp".into()),
                "0x00001340" => Some("B.cpp".into()),
                _ => None,
            };
        }
        report.target_functions.last_mut().unwrap().end = "0x00001320".into();
        report.target_functions.push(TargetFunctionObservation {
            name: "fn_1320".into(),
            module: "main".into(),
            section: ".text".into(),
            address: "0x00001320".into(),
            end: "0x00001340".into(),
            current_owner: None,
            owner_autogenerated: false,
            callers: Vec::new(),
            normalized_body_sha256: None,
            weak: false,
        });
        let current =
            ObservationIndex::load(report.clone(), "source", "target", &expected).unwrap();
        assert_eq!(current.report().unresolved_target_clusters.len(), 1);
        report.schema = 3;
        let historical = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        assert!(historical.report().unresolved_target_clusters.is_empty());
        let serialized = serde_json::to_value(historical.report()).unwrap();
        assert!(serialized.get("unresolved_target_clusters").is_none());
    }

    #[test]
    fn helper_summaries_are_rederived_and_do_not_authorize_ownership() {
        let (mut report, expected) = with_helper(&[0x1200]);
        let hash = "a".repeat(64);
        report.source_functions[0].normalized_body_sha256 = Some(hash.clone());
        report.target_functions[0].normalized_body_sha256 = Some(hash);
        report.target_functions[0].name = "__dt__12CInstructionFv".into();
        let first = ObservationIndex::load(report.clone(), "source", "target", &expected).unwrap();
        assert_eq!(first.report().helper_families.len(), 1);
        report.helper_families = first.report().helper_families.clone();
        report.helper_families[0].id = "invented-owner".into();
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        assert_ne!(index.report().helper_families[0].id, "invented-owner");
        let assessment = assess_claim(&index, (0x1000, 0x1300), (0x1000, 0x1340));
        assert_eq!(assessment.new_caller_confined_helpers, 1);
    }

    #[test]
    fn schema_four_keeps_its_target_only_generated_name_classifier() {
        let (mut report, expected) = with_helper(&[]);
        let hash = "b".repeat(64);
        report.source_functions[0].name = "__sinit_CPowerBomb_cpp".into();
        report.source_functions[0].normalized_body_sha256 = Some(hash.clone());
        report.target_functions[0].name = "fn_80145158".into();
        report.target_functions[0].normalized_body_sha256 = Some(hash);
        report.schema = 4;
        let previous =
            ObservationIndex::load(report.clone(), "source", "target", &expected).unwrap();
        assert!(previous.report().helper_families.is_empty());
        report.schema = IDENTIFICATION_SCHEMA;
        let current = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        assert_eq!(current.report().helper_families.len(), 1);
        assert_eq!(current.report().helper_families[0].signals, vec![
            helpers::HelperSignal::StaticInitializerName
        ]);
    }

    #[test]
    fn a_kept_report_is_referenced_by_its_own_schema() {
        let (mut report, expected) = with_helper(&[]);
        report.schema = 2;
        let index = ObservationIndex::load(report, "source", "target", &expected).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut reference = index.persist(directory.path()).unwrap();
        assert_eq!(reference.schema, 2);
        assert!(load_reference(&reference, "source", "target").is_ok());

        // The same artifact advertised as the current schema is refused.
        reference.schema = IDENTIFICATION_SCHEMA;
        let error = load_reference(&reference, "source", "target").unwrap_err();
        assert!(error.to_string().contains("reference states 5"), "{error}");
    }

    #[test]
    fn a_caller_must_be_in_the_inventory() {
        let (report, expected) = with_helper(&[0x1204]);
        assert!(ObservationIndex::load(report, "source", "target", &expected).is_err());
    }

    #[test]
    fn persistence_rejects_a_corrupt_existing_content_address() {
        let first = fixture_index(vec![crate::analysis::coverage_fixture::unit("A.cpp", vec![
            crate::analysis::coverage_fixture::anchor("A", 0x8000_4000, 0x8000_4100),
        ])]);
        let second = fixture_index(vec![crate::analysis::coverage_fixture::unit("A.cpp", vec![
            crate::analysis::coverage_fixture::anchor("A", 0x8000_5000, 0x8000_5100),
        ])]);
        let directory = tempfile::tempdir().unwrap();
        let reference = first.persist(directory.path()).unwrap();
        std::fs::write(&reference.file, serde_json::to_vec_pretty(second.report()).unwrap())
            .unwrap();

        let error = first.persist(directory.path()).unwrap_err();
        assert!(error.to_string().contains("wrong digest"), "{error}");
    }

    fn section(
        name: &str,
        kind: ObjSectionKind,
        index: u32,
        base: u32,
        size: u32,
        unit: &str,
    ) -> ObjSection {
        let mut splits = ObjSplits::default();
        splits.push(base, ObjSplit {
            unit: unit.into(),
            end: base + size,
            align: None,
            common: false,
            autogenerated: false,
            skip: false,
            rename: None,
        });
        ObjSection {
            name: name.into(),
            kind,
            address: u64::from(base),
            size: u64::from(size),
            data: vec![0; size as usize],
            align: 4,
            elf_index: index,
            relocations: ObjRelocations::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits,
        }
    }

    fn function(name: &str, section: u32, address: u32, size: u32) -> ObjSymbol {
        ObjSymbol {
            name: name.into(),
            address: u64::from(address),
            section: Some(section),
            size: u64::from(size),
            size_known: true,
            kind: ObjSymbolKind::Function,
            ..Default::default()
        }
    }

    fn target(name: &str, symbols: Vec<ObjSymbol>, sections: Vec<ObjSection>) -> MatchTarget {
        MatchTarget::new(
            name.into(),
            ObjInfo::new(
                ObjKind::Executable,
                ObjArchitecture::PowerPc,
                name.into(),
                symbols,
                sections,
            ),
        )
    }

    fn matched(
        source: NodeIndex,
        target: NodeIndex,
        method: MatchMethod,
        runner_up: Option<(NodeIndex, f32)>,
    ) -> Match {
        Match {
            source,
            target,
            method,
            confidence: 1.0,
            evidence: 1,
            round: 0,
            distinctive_body: method == MatchMethod::ExactHash,
            runner_up: runner_up.map(|(source, relative_score)| {
                crate::analysis::matching::Alternative { source, relative_score }
            }),
        }
    }

    fn result(matches: Vec<Match>, source_len: usize, target_len: usize) -> MatchResult {
        let mut source_to_target = vec![None; source_len];
        let mut target_to_source = vec![None; target_len];
        for item in &matches {
            source_to_target[item.source as usize] = Some(item.target);
            target_to_source[item.target as usize] = Some(item.source);
        }
        MatchResult { matches, source_to_target, target_to_source, rounds: 1 }
    }

    #[test]
    fn names_alone_are_not_independent_corroboration() {
        assert_eq!(confidence_for(6, 0, false), IdentificationConfidence::Tentative);
    }

    #[test]
    fn a_template_return_type_does_not_make_an_ordinary_method_a_template() {
        assert_eq!(
            callable_name("rstl::rc_ptr<IMetaTrans> CTransitionDatabaseGame::GetMetaTrans() const"),
            "CTransitionDatabaseGame::GetMetaTrans"
        );
        assert!(
            !callable_name(
                "rstl::rc_ptr<IMetaTrans> CTransitionDatabaseGame::GetMetaTrans() const"
            )
            .contains('<')
        );
        assert!(callable_name("void rstl::sort<int>(int*, int*)").contains('<'));
        assert!(callable_name("rstl::vector<int>::size() const").contains('<'));
    }

    #[test]
    fn two_binary_members_can_corroborate_a_unit() {
        assert_eq!(confidence_for(2, 2, false), IdentificationConfidence::Corroborated);
    }

    #[test]
    fn a_competing_explanation_remains_ambiguous() {
        assert_eq!(confidence_for(8, 8, true), IdentificationConfidence::Ambiguous);
    }

    #[test]
    fn a_weak_runner_up_is_retained_without_making_the_unit_ambiguous() {
        let source = target(
            "source",
            vec![function("A", 0, 0x1000, 4), function("Other", 0, 0x1004, 4)],
            vec![section(".text", ObjSectionKind::Code, 0, 0x1000, 8, "A.cpp")],
        );
        let target = target("target", vec![function("fn_2000", 0, 0x2000, 4)], vec![section(
            ".text",
            ObjSectionKind::Code,
            0,
            0x2000,
            4,
            "unknown.cpp",
        )]);
        let report = identify_units(
            &source,
            &target,
            &result(vec![matched(0, 0, MatchMethod::CallSite, Some((1, 0.2)))], 2, 1),
        );
        let unit = report.units.iter().find(|unit| unit.unit == "A.cpp").unwrap();
        assert_ne!(unit.confidence, IdentificationConfidence::Ambiguous);
        assert_eq!(unit.competing_explanations.len(), 1, "the diagnostic runner-up is retained");
        assert!(!report.attributions[0].ambiguous);
    }

    #[test]
    fn source_sections_form_separate_candidate_sequences() {
        let source = target(
            "source",
            vec![function("Init", 0, 0x1000, 4), function("Text", 1, 0x2000, 4)],
            vec![
                section(".init", ObjSectionKind::Code, 0, 0x1000, 4, "A.cpp"),
                section(".text", ObjSectionKind::Code, 1, 0x2000, 4, "A.cpp"),
            ],
        );
        let target = target(
            "target",
            vec![function("fn_3000", 0, 0x3000, 4), function("fn_3004", 0, 0x3004, 4)],
            vec![section(".text", ObjSectionKind::Code, 0, 0x3000, 8, "unknown.cpp")],
        );
        let report = identify_units(
            &source,
            &target,
            &result(
                vec![
                    matched(0, 0, MatchMethod::ExactHash, None),
                    matched(1, 1, MatchMethod::ExactHash, None),
                ],
                2,
                2,
            ),
        );
        let unit = report.units.iter().find(|unit| unit.unit == "A.cpp").unwrap();
        assert_eq!(unit.candidates.len(), 2);
        assert_eq!(
            unit.candidates
                .iter()
                .map(|item| item.source_section.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([".init", ".text"]),
        );
        assert!(
            unit.candidates
                .iter()
                .all(|item| { item.left_source_edge_observed && item.right_source_edge_observed })
        );
    }

    #[test]
    fn a_candidate_cannot_borrow_source_edges_from_another_target_section() {
        let source = target(
            "source",
            vec![function("First", 0, 0x1000, 4), function("Last", 0, 0x1004, 4)],
            vec![section(".text", ObjSectionKind::Code, 0, 0x1000, 8, "A.cpp")],
        );
        let target = target(
            "target",
            vec![function("fn_2000", 0, 0x2000, 4), function("fn_3000", 1, 0x3000, 4)],
            vec![
                section(".init", ObjSectionKind::Code, 0, 0x2000, 4, "unknown.cpp"),
                section(".text", ObjSectionKind::Code, 1, 0x3000, 4, "unknown.cpp"),
            ],
        );
        let report = identify_units(
            &source,
            &target,
            &result(
                vec![
                    matched(0, 0, MatchMethod::ExactHash, None),
                    matched(1, 1, MatchMethod::ExactHash, None),
                ],
                2,
                2,
            ),
        );
        let unit = report.units.iter().find(|unit| unit.unit == "A.cpp").unwrap();
        let init = unit.candidates.iter().find(|candidate| candidate.section == ".init").unwrap();
        assert!(init.left_source_edge_observed);
        assert!(!init.right_source_edge_observed);
        let text = unit.candidates.iter().find(|candidate| candidate.section == ".text").unwrap();
        assert!(!text.left_source_edge_observed);
        assert!(text.right_source_edge_observed);
    }

    #[test]
    fn data_only_units_remain_in_the_complete_inventory() {
        let source = target("source", vec![function("A", 0, 0x1000, 4)], vec![
            section(".text", ObjSectionKind::Code, 0, 0x1000, 4, "A.cpp"),
            section(".data", ObjSectionKind::Data, 1, 0x2000, 4, "Data.cpp"),
        ]);
        let target = target("target", vec![function("A", 0, 0x3000, 4)], vec![section(
            ".text",
            ObjSectionKind::Code,
            0,
            0x3000,
            4,
            "A.cpp",
        )]);
        let report = identify_units(
            &source,
            &target,
            &result(vec![matched(0, 0, MatchMethod::Name, None)], 1, 1),
        );
        let named = report.units.iter().find(|unit| unit.unit == "A.cpp").unwrap();
        assert_eq!(named.basis, IdentificationBasis::NamesOnly);
        assert_eq!(named.strong_functions, 0, "input names are not strong binary evidence");
        let data = report.units.iter().find(|unit| unit.unit == "Data.cpp").unwrap();
        assert_eq!(data.source_functions, 0);
        assert_eq!(data.confidence, IdentificationConfidence::Absent);
    }

    #[test]
    fn a_name_match_retains_independent_exact_body_evidence() {
        let source = target("source", vec![function("A", 0, 0x1000, 16)], vec![section(
            ".text",
            ObjSectionKind::Code,
            0,
            0x1000,
            16,
            "A.cpp",
        )]);
        let target = target("target", vec![function("A", 0, 0x2000, 16)], vec![section(
            ".text",
            ObjSectionKind::Code,
            0,
            0x2000,
            16,
            "A.cpp",
        )]);
        let mut item = matched(0, 0, MatchMethod::Name, None);
        item.distinctive_body = true;
        let report = identify_units(&source, &target, &result(vec![item], 1, 1));
        let attribution = &report.attributions[0];
        assert_eq!(attribution.origin, AttributionOrigin::InputName);
        assert!(attribution.binary_supported);
        assert!(attribution.independent);
        assert_eq!(attribution.target.module, "main");
        assert_eq!(attribution.source.module, "main");
        assert!(attribution.id.starts_with("main:.text:0x00002000<-main:.text:"));
        assert!(attribution.evidence.iter().any(|item| item.kind == "unique-exact-body"));
        let unit = &report.units[0];
        assert_eq!(unit.basis, IdentificationBasis::Mixed);
        assert_eq!(unit.binary_functions, 1);
        assert_eq!(unit.strong_functions, 1);
        assert_eq!(unit.name_only_functions, 0);
    }

    #[test]
    fn a_weak_exact_body_does_not_corroborate_emitted_tu_ownership() {
        let mut source_symbol = function("Weak", 0, 0x1000, 16);
        source_symbol.flags = ObjSymbolFlagSet(ObjSymbolFlags::Weak.into());
        let mut target_symbol = function("Weak", 0, 0x2000, 16);
        target_symbol.flags = ObjSymbolFlagSet(ObjSymbolFlags::Weak.into());
        let source = target("source", vec![source_symbol], vec![section(
            ".text",
            ObjSectionKind::Code,
            0,
            0x1000,
            16,
            "A.cpp",
        )]);
        let target = target("target", vec![target_symbol], vec![section(
            ".text",
            ObjSectionKind::Code,
            0,
            0x2000,
            16,
            "unknown.cpp",
        )]);
        let mut item = matched(0, 0, MatchMethod::Name, None);
        item.distinctive_body = true;
        let report = identify_units(&source, &target, &result(vec![item], 1, 1));
        assert!(report.attributions[0].binary_supported);
        assert!(!report.attributions[0].independent);
        assert_eq!(report.units[0].confidence, IdentificationConfidence::Tentative);
        assert_eq!(report.units[0].unresolved_helpers.len(), 1);
    }
}
