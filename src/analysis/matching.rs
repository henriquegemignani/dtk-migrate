use std::collections::{BTreeMap, HashMap, hash_map};

use decomp_toolkit::{
    obj::{ObjInfo, SectionIndex, SymbolIndex},
    util::config::is_auto_symbol,
};
use serde::{Deserialize, Serialize};

use crate::analysis::{
    callgraph::{CallGraph, NodeIndex},
    fingerprint::{Fingerprint, fingerprint_all},
};

/// One analyzed executable, prepared for matching.
pub struct MatchTarget {
    pub name: String,
    pub obj: ObjInfo,
    pub graph: CallGraph,
    pub fingerprints: Vec<Fingerprint>,
    /// Nodes in link order, i.e. sorted by section then address.
    layout: Vec<NodeIndex>,
    /// Position of each node within [`Self::layout`].
    layout_position: Vec<u32>,
}

impl MatchTarget {
    pub fn new(name: String, obj: ObjInfo) -> Self {
        let graph = CallGraph::build(&obj);
        let fingerprints = fingerprint_all(&obj, &graph);

        let mut layout: Vec<NodeIndex> = (0..graph.len() as NodeIndex).collect();
        layout.sort_by_key(|&node| {
            let node = graph.node(node);
            (node.section, node.address)
        });
        let mut layout_position = vec![0u32; graph.len()];
        for (position, &node) in layout.iter().enumerate() {
            layout_position[node as usize] = position as u32;
        }

        Self { name, obj, graph, fingerprints, layout, layout_position }
    }

    /// A fresh ownership view over the same analysed functions. The caller
    /// must first compare [`same_matching_inputs`]; split-dependent signatures
    /// can change symbols during DOL analysis, so fresh splits alone are not
    /// proof that these derived fields are reusable.
    pub(crate) fn with_cached_analysis(name: String, obj: ObjInfo, cached: &Self) -> Self {
        Self {
            name,
            obj,
            graph: cached.graph.clone(),
            fingerprints: cached.fingerprints.clone(),
            layout: cached.layout.clone(),
            layout_position: cached.layout_position.clone(),
        }
    }

    pub fn symbol_name(&self, node: NodeIndex) -> &str {
        self.symbol_name_at(self.graph.node(node).symbol)
    }

    /// Whether this function carries a real name rather than a `fn_8000XXXX`
    /// placeholder.
    pub fn is_named(&self, node: NodeIndex) -> bool {
        self.is_named_at(self.graph.node(node).symbol)
    }

    /// Whether this function's symbol is marked local scope.
    pub fn is_local(&self, node: NodeIndex) -> bool {
        self.is_local_at(self.graph.node(node).symbol)
    }

    pub fn is_weak(&self, node: NodeIndex) -> bool {
        self.obj.symbols[self.graph.node(node).symbol].flags.is_weak()
    }

    /// The split unit this function currently belongs to, if its section has
    /// a split covering its address.
    pub fn unit_of(&self, node: NodeIndex) -> Option<&str> {
        let n = self.graph.node(node);
        self.unit_of_address(n.section, n.address)
    }

    /// Same as the `NodeIndex`-based accessors above, but for any symbol —
    /// including a data symbol, which has no call-graph node of its own.
    pub fn symbol_name_at(&self, symbol: SymbolIndex) -> &str { &self.obj.symbols[symbol].name }

    pub fn is_named_at(&self, symbol: SymbolIndex) -> bool {
        !is_auto_symbol(&self.obj.symbols[symbol])
    }

    pub fn is_local_at(&self, symbol: SymbolIndex) -> bool {
        self.obj.symbols[symbol].flags.is_local()
    }

    /// The split unit a data symbol currently belongs to, if its section has
    /// a split covering its address.
    pub fn unit_of_symbol(&self, symbol: SymbolIndex) -> Option<&str> {
        let s = &self.obj.symbols[symbol];
        self.unit_of_address(s.section?, s.address as u32)
    }

    fn unit_of_address(&self, section: SectionIndex, address: u32) -> Option<&str> {
        let section = self.obj.sections.get(section)?;
        section.splits.for_address(address).map(|(_, split)| split.unit.as_str())
    }

    /// Nodes in link order, i.e. sorted by section then address.
    pub fn layout(&self) -> &[NodeIndex] { &self.layout }

    /// Position of `node` within [`Self::layout`].
    pub fn layout_position(&self, node: NodeIndex) -> u32 { self.layout_position[node as usize] }
}

/// Exact inputs to call-graph construction, fingerprinting and function/data
/// matching after dtk has fully analysed the DOL. Split ownership and link
/// order are deliberately excluded: later identification and proposals read
/// those from a newly loaded `ObjInfo`, never from the cached target.
///
/// Comparing analysed symbols matters. dtk applies some signatures according
/// to existing splits, so a split edit can change the function inventory even
/// when the DOL bytes and symbols.txt have not changed.
pub(crate) fn same_matching_inputs(left: &ObjInfo, right: &ObjInfo) -> bool {
    if left.kind != right.kind
        || left.architecture != right.architecture
        || left.symbols.count() != right.symbols.count()
        || left.sections.len() != right.sections.len()
        || !left.symbols.iter().zip(right.symbols.iter()).all(|((_, a), (_, b))| a == b)
    {
        return false;
    }
    left.sections.iter().zip(right.sections.iter()).all(|((_, a), (_, b))| {
        a.name == b.name
            && a.kind == b.kind
            && a.address == b.address
            && a.size == b.size
            && a.data == b.data
            && a.align == b.align
            && a.elf_index == b.elf_index
            && a.virtual_address == b.virtual_address
            && a.file_offset == b.file_offset
            && a.section_known == b.section_known
            && a.relocations.len() == b.relocations.len()
            && a.relocations.iter().zip(b.relocations.iter()).all(|((at, a), (bt, b))| {
                at == bt
                    && a.kind == b.kind
                    && a.target_symbol == b.target_symbol
                    && a.addend == b.addend
                    && a.module == b.module
            })
    })
}

/// How a pair of functions was matched, in decreasing order of directness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchMethod {
    /// Both sides already carry the same non-generated name.
    Name,
    /// Relocation-masked instruction hash, unique on both sides.
    ExactHash,
    /// A string literal referenced from exactly one function on each side.
    StringRef,
    /// Position within an already-matched function's call sequence.
    CallSite,
    /// The sole remaining unmatched caller of an already-matched function.
    CallerSite,
    /// Position between two anchors in link order.
    Layout,
}

impl MatchMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            MatchMethod::Name => "name",
            MatchMethod::ExactHash => "exact-hash",
            MatchMethod::StringRef => "string-ref",
            MatchMethod::CallSite => "call-site",
            MatchMethod::CallerSite => "caller-site",
            MatchMethod::Layout => "layout",
        }
    }
}

/// A source function that lost to the one actually matched.
#[derive(Debug, Clone, Copy)]
pub struct Alternative {
    pub source: NodeIndex,
    /// Its vote weight as a fraction of the winner's, in `0.0..=1.0`.
    pub relative_score: f32,
}

/// How much trust a match has earned.
///
/// The distinction exists because a wrong name is worse than no name: it reads
/// as established fact, propagates onward, and nothing prompts anyone to
/// re-check it. Only [`MatchTier::Confident`] may be applied unreviewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchTier {
    /// Decided by content unique to this pair, or by an identical body backed by
    /// structural agreement. Safe to apply without review.
    Confident,
    /// Several independent neighbors agree and nothing else came close, but no
    /// direct content evidence. Very likely right; still wants a glance.
    Probable,
    /// Thin or contested evidence. Presented with its alternatives so a reviewer
    /// can choose, never applied automatically.
    Candidate,
}

impl MatchTier {
    pub fn as_str(self) -> &'static str {
        match self {
            MatchTier::Confident => "confident",
            MatchTier::Probable => "probable",
            MatchTier::Candidate => "candidate",
        }
    }
}

/// A runner-up scoring within this fraction of the winner means the evidence
/// didn't actually single the winner out, whatever its confidence says.
pub(crate) const CONTESTED_MARGIN: f32 = 0.15;

/// Independent agreeing neighbors needed before a propagated match is trusted
/// beyond [`MatchTier::Candidate`].
const CORROBORATION_FOR_PROBABLE: u32 = 2;

/// Instructions a function needs before its body says anything about identity.
/// Below this, bodies collide by coincidence.
const MIN_DISTINCTIVE_INSTRUCTIONS: u32 = 4;

#[derive(Debug, Clone)]
pub struct Match {
    pub source: NodeIndex,
    pub target: NodeIndex,
    pub method: MatchMethod,
    pub confidence: f32,
    /// Number of independent matched neighbors that agreed on this pair.
    pub evidence: u32,
    /// Propagation round that produced the match; `0` for tier 1 anchors.
    pub round: u32,
    /// Whether the two bodies hash identically once relocations are masked out,
    /// *and* are long enough for that to mean anything.
    pub distinctive_body: bool,
    /// The strongest source function that lost to this one, if any competed.
    pub runner_up: Option<Alternative>,
}

impl Match {
    /// Whether another source function was close enough that this pairing did
    /// not actually resolve the identity. We retain weaker runner-ups for
    /// diagnosis, but they must not make an otherwise decisive match ambiguous.
    pub fn is_contested(&self) -> bool {
        self.runner_up.is_some_and(|a| a.relative_score > 1.0 - CONTESTED_MARGIN)
    }

    /// Classifies the match by what kind of evidence produced it.
    ///
    /// Deliberately not a cut on [`Self::confidence`]: that score's distribution
    /// shifts with how similar the two binaries are — tightly bimodal between
    /// close revisions, broadly spread between distant ones — so the same
    /// threshold means different things per pair. The evidence kind doesn't move.
    pub fn tier(&self) -> MatchTier {
        classify_tier(self.method, self.distinctive_body, self.evidence, self.is_contested())
    }
}

pub(crate) fn classify_tier(
    method: MatchMethod,
    distinctive_body: bool,
    evidence: u32,
    contested: bool,
) -> MatchTier {
    if contested {
        return MatchTier::Candidate;
    }
    match method {
        // Tier 1 anchors are decided by content unique on both sides.
        MatchMethod::Name | MatchMethod::ExactHash | MatchMethod::StringRef => MatchTier::Confident,
        // Propagated, but the bodies are byte-identical once relocations are
        // masked. The hash wasn't unique enough to anchor on alone; combined
        // with call-graph agreement and no rival, it's as good as one.
        _ if distinctive_body => MatchTier::Confident,
        _ if evidence >= CORROBORATION_FOR_PROBABLE => MatchTier::Probable,
        _ => MatchTier::Candidate,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MatchOptions {
    /// Propagated matches scoring below this are discarded rather than
    /// accepted. Anchors carry a fixed, high confidence and aren't filtered by
    /// this at all.
    pub min_confidence: f32,
    /// Cap on propagation rounds, as a safety valve against slow convergence.
    pub max_rounds: u32,
    /// Skip name-based anchoring, so that a run against an already-named version
    /// can be scored against the names it wasn't allowed to see.
    pub ignore_names: bool,
    /// Infer matches from link order between anchored functions.
    ///
    /// Two builds of the same source keep translation units contiguous and in
    /// the same order, which makes position between anchors highly predictive.
    /// That assumption weakens across different games, so this can be disabled.
    pub use_layout: bool,
}

impl Default for MatchOptions {
    fn default() -> Self {
        // Propagation converges on its own; the cap only bounds pathological
        // cases. Binaries that share little content need many more rounds than
        // close revisions, since each round only advances one call-graph hop.
        Self { min_confidence: 0.5, max_rounds: 100, ignore_names: false, use_layout: true }
    }
}

pub struct MatchResult {
    pub matches: Vec<Match>,
    pub source_to_target: Vec<Option<NodeIndex>>,
    pub target_to_source: Vec<Option<NodeIndex>>,
    pub rounds: u32,
}

/// A candidate pair accumulated during a propagation round.
#[derive(Default, Clone, Copy)]
struct Vote {
    weight: f32,
    count: u32,
    /// Votes originating from call-site position rather than caller identity.
    call_sites: u32,
    /// Votes originating from link-order position.
    layout: u32,
}

impl Vote {
    /// The strongest kind of evidence backing this pair.
    fn method(&self) -> MatchMethod {
        if self.call_sites > 0 {
            MatchMethod::CallSite
        } else if self.count > self.layout {
            MatchMethod::CallerSite
        } else {
            MatchMethod::Layout
        }
    }
}

pub fn match_functions(
    source: &MatchTarget,
    target: &MatchTarget,
    options: &MatchOptions,
) -> MatchResult {
    let mut state = Matcher {
        source,
        target,
        options,
        source_to_target: vec![None; source.graph.len()],
        target_to_source: vec![None; target.graph.len()],
        matches: Vec::new(),
    };

    if !options.ignore_names {
        state.anchor_by_name();
    }
    state.anchor_by_exact_hash();
    state.anchor_by_string();
    let anchors = state.matches.len();
    tracing::info!(
        "Tier 1: {} anchors ({} by name, {} by hash/string)",
        anchors,
        state.matches.iter().filter(|m| m.method == MatchMethod::Name).count(),
        state.matches.iter().filter(|m| m.method != MatchMethod::Name).count()
    );

    let rounds = state.propagate();
    tracing::info!("Tier 2: {} matches after {} rounds", state.matches.len() - anchors, rounds);

    MatchResult {
        matches: state.matches,
        source_to_target: state.source_to_target,
        target_to_source: state.target_to_source,
        rounds,
    }
}

struct Matcher<'a> {
    source: &'a MatchTarget,
    target: &'a MatchTarget,
    options: &'a MatchOptions,
    source_to_target: Vec<Option<NodeIndex>>,
    target_to_source: Vec<Option<NodeIndex>>,
    matches: Vec<Match>,
}

impl Matcher<'_> {
    /// Whether both sides are still unclaimed and so free to be paired.
    fn is_available(&self, source: NodeIndex, target: NodeIndex) -> bool {
        self.source_to_target[source as usize].is_none()
            && self.target_to_source[target as usize].is_none()
    }

    fn record(&mut self, m: Match) {
        self.source_to_target[m.source as usize] = Some(m.target);
        self.target_to_source[m.target as usize] = Some(m.source);
        self.matches.push(m);
    }

    /// Records a tier 1 anchor, which by construction had no competitor.
    fn record_anchor(
        &mut self,
        source: NodeIndex,
        target: NodeIndex,
        method: MatchMethod,
        confidence: f32,
    ) {
        self.record(Match {
            source,
            target,
            method,
            confidence,
            evidence: 1,
            round: 0,
            distinctive_body: self.distinctive_body(source, target),
            runner_up: None,
        });
    }

    fn distinctive_body(&self, source: NodeIndex, target: NodeIndex) -> bool {
        is_distinctive(
            &self.source.fingerprints[source as usize],
            &self.target.fingerprints[target as usize],
        )
    }

    /// Functions already sharing a real name in both versions.
    ///
    /// These carry no new information, but they seed propagation and let a run
    /// against a fully-named version double as a correctness check.
    fn anchor_by_name(&mut self) {
        let source_names = unique_index(self.source, |t, node| {
            t.is_named(node).then(|| t.symbol_name(node).to_string())
        });
        let target_names = unique_index(self.target, |t, node| {
            t.is_named(node).then(|| t.symbol_name(node).to_string())
        });
        for (name, source_node) in source_names {
            if let Some(&target_node) = target_names.get(&name) {
                if self.is_available(source_node, target_node) {
                    self.record_anchor(source_node, target_node, MatchMethod::Name, 1.0);
                }
            }
        }
    }

    /// Functions whose relocation-masked encoding is identical and unambiguous.
    fn anchor_by_exact_hash(&mut self) {
        let source_hashes = unique_index(self.source, |t, node| {
            let fp = &t.fingerprints[node as usize];
            (fp.instruction_count >= MIN_DISTINCTIVE_INSTRUCTIONS).then_some(fp.exact_hash)
        });
        let target_hashes = unique_index(self.target, |t, node| {
            let fp = &t.fingerprints[node as usize];
            (fp.instruction_count >= MIN_DISTINCTIVE_INSTRUCTIONS).then_some(fp.exact_hash)
        });
        for (hash, source_node) in source_hashes {
            if let Some(&target_node) = target_hashes.get(&hash) {
                if self.is_available(source_node, target_node) {
                    self.record_anchor(source_node, target_node, MatchMethod::ExactHash, 0.97);
                }
            }
        }
    }

    /// Functions referencing a string literal that appears in exactly one
    /// function on each side.
    fn anchor_by_string(&mut self) {
        let source_strings = unique_multi_index(self.source);
        let target_strings = unique_multi_index(self.target);

        // A function can reference several distinctive strings. Accept a pairing
        // only when every one of them agrees, in both directions: disagreement
        // means at least one literal moved between versions, and picking a
        // winner would come down to hash iteration order.
        let mut forward: BTreeMap<NodeIndex, Option<NodeIndex>> = BTreeMap::new();
        let mut backward: BTreeMap<NodeIndex, Option<NodeIndex>> = BTreeMap::new();
        for (string, &source_node) in &source_strings {
            let Some(&target_node) = target_strings.get(string) else { continue };
            merge_proposal(&mut forward, source_node, target_node);
            merge_proposal(&mut backward, target_node, source_node);
        }

        for (source_node, target_node) in forward {
            let Some(target_node) = target_node else { continue };
            if backward.get(&target_node) != Some(&Some(source_node)) {
                continue;
            }
            if !self.is_available(source_node, target_node) {
                continue;
            }
            if !self.source.fingerprints[source_node as usize]
                .plausible_match(&self.target.fingerprints[target_node as usize])
            {
                continue;
            }
            self.record_anchor(source_node, target_node, MatchMethod::StringRef, 0.90);
        }
    }

    /// Iteratively grows the match set outward from the anchors along call edges.
    ///
    /// Content-based anchoring stops working as soon as a function's body
    /// changed between versions; its position in the call graph usually didn't.
    fn propagate(&mut self) -> u32 {
        let mut round = 0;
        while round < self.options.max_rounds {
            round += 1;
            let mut votes: HashMap<(NodeIndex, NodeIndex), Vote> = HashMap::new();

            for m in self.matches.clone() {
                self.vote_call_sites(m.source, m.target, m.confidence, &mut votes);
                self.vote_callers(m.source, m.target, m.confidence, &mut votes);
            }
            if self.options.use_layout {
                self.vote_layout(&mut votes);
            }

            let accepted = self.accept_votes(votes, round);
            if accepted == 0 {
                return round;
            }
            tracing::debug!("Round {}: accepted {} matches", round, accepted);
        }
        // Falling out of the loop means the cap bound the search rather than the
        // search converging, so matches were still being found when it stopped.
        tracing::warn!(
            "Propagation stopped at the {}-round cap while still finding matches; \
             raise --max-rounds for a more complete result",
            round
        );
        round
    }

    /// Votes for callee pairs that occupy corresponding positions in the call
    /// sequences of an already-matched pair.
    fn vote_call_sites(
        &self,
        source: NodeIndex,
        target: NodeIndex,
        confidence: f32,
        votes: &mut HashMap<(NodeIndex, NodeIndex), Vote>,
    ) {
        let source_callees: Vec<NodeIndex> = self.source.graph.node(source).callees().collect();
        let target_callees: Vec<NodeIndex> = self.target.graph.node(target).callees().collect();
        if source_callees.is_empty() || target_callees.is_empty() {
            return;
        }

        for (a, b) in self.align(&source_callees, &target_callees) {
            if !self.is_available(a, b) {
                continue;
            }
            if !self.source.fingerprints[a as usize]
                .plausible_match(&self.target.fingerprints[b as usize])
            {
                continue;
            }
            let entry = votes.entry((a, b)).or_default();
            entry.weight += confidence;
            entry.count += 1;
            entry.call_sites += 1;
        }
    }

    /// Votes for functions that sit at the same position between two
    /// consecutive anchors in link order.
    ///
    /// Anchors pin down the translation unit boundaries; when the stretch of
    /// functions between the same two anchors has the same length in both
    /// builds, nothing was added or removed there and position alone identifies
    /// each function.
    fn vote_layout(&self, votes: &mut HashMap<(NodeIndex, NodeIndex), Vote>) {
        // Anchors in source link order, paired with their target position.
        let mut anchors: Vec<(u32, u32)> = self
            .source_to_target
            .iter()
            .enumerate()
            .filter_map(|(source, &target)| {
                let target = target?;
                Some((
                    self.source.layout_position[source],
                    self.target.layout_position[target as usize],
                ))
            })
            .collect();
        anchors.sort_unstable();

        for window in anchors.windows(2) {
            let ((source_start, target_start), (source_end, target_end)) = (window[0], window[1]);
            // Only trust a gap when it advances on both sides by the same amount;
            // a target position that moved backwards means the two builds
            // reordered here and position says nothing.
            if target_end <= target_start || source_end - source_start != target_end - target_start
            {
                continue;
            }
            for offset in 1..source_end - source_start {
                let a = self.source.layout[(source_start + offset) as usize];
                let b = self.target.layout[(target_start + offset) as usize];
                if !self.is_available(a, b) {
                    continue;
                }
                if !self.source.fingerprints[a as usize]
                    .plausible_match(&self.target.fingerprints[b as usize])
                {
                    continue;
                }
                let entry = votes.entry((a, b)).or_default();
                // Layout is circumstantial on its own, but corroborates strongly.
                entry.weight += 0.5;
                entry.count += 1;
                entry.layout += 1;
            }
        }
    }

    /// Votes for the pair formed when a matched function has exactly one
    /// unmatched caller on each side.
    fn vote_callers(
        &self,
        source: NodeIndex,
        target: NodeIndex,
        confidence: f32,
        votes: &mut HashMap<(NodeIndex, NodeIndex), Vote>,
    ) {
        let mut source_unmatched = self
            .source
            .graph
            .node(source)
            .callers
            .iter()
            .filter(|&&c| self.source_to_target[c as usize].is_none());
        let mut target_unmatched = self
            .target
            .graph
            .node(target)
            .callers
            .iter()
            .filter(|&&c| self.target_to_source[c as usize].is_none());

        let (Some(&a), None) = (source_unmatched.next(), source_unmatched.next()) else { return };
        let (Some(&b), None) = (target_unmatched.next(), target_unmatched.next()) else { return };
        if !self.source.fingerprints[a as usize]
            .plausible_match(&self.target.fingerprints[b as usize])
        {
            return;
        }
        let entry = votes.entry((a, b)).or_default();
        // Caller sets are unordered, so this is weaker evidence than a call site.
        entry.weight += confidence * 0.5;
        entry.count += 1;
    }

    /// Pairs up two call sequences positionally, using already-matched callees
    /// as fixed points so that inserted or removed calls only disturb their own
    /// neighborhood.
    fn align(&self, source: &[NodeIndex], target: &[NodeIndex]) -> Vec<(NodeIndex, NodeIndex)> {
        // Project the source sequence into target space so anchors compare directly.
        let projected: Vec<Option<NodeIndex>> =
            source.iter().map(|&s| self.source_to_target[s as usize]).collect();
        let anchors = longest_common_subsequence(&projected, target);

        let mut pairs = Vec::new();
        let mut prev = (0usize, 0usize);
        for &(i, j) in anchors.iter().chain(std::iter::once(&(source.len(), target.len()))) {
            // Between two anchors, positional correspondence is only trustworthy
            // when both sides have the same number of intervening calls.
            if i - prev.0 == j - prev.1 {
                for offset in 0..i - prev.0 {
                    pairs.push((source[prev.0 + offset], target[prev.1 + offset]));
                }
            }
            prev = (i + 1, j + 1);
        }
        pairs
    }

    /// Commits the unambiguous winners of a voting round.
    fn accept_votes(&mut self, votes: HashMap<(NodeIndex, NodeIndex), Vote>, round: u32) -> usize {
        // Best and runner-up per node, so ambiguous candidates can be deferred
        // to a later round when more context is available.
        let mut best_for_source: HashMap<NodeIndex, Best> = HashMap::new();
        let mut best_for_target: HashMap<NodeIndex, Best> = HashMap::new();
        for (&(a, b), vote) in &votes {
            update_best(&mut best_for_source, a, vote.weight, b);
            update_best(&mut best_for_target, b, vote.weight, a);
        }

        let mut accepted = Vec::new();
        for (&(a, b), vote) in &votes {
            let Some(&source_best) = best_for_source.get(&a) else { continue };
            let Some(&target_best) = best_for_target.get(&b) else { continue };
            // Require mutual agreement: a is b's best candidate and vice versa.
            if source_best.node != b || target_best.node != a {
                continue;
            }
            // An exact tie for best means `node` was decided by whichever
            // candidate happened to be seen first. Defer instead of guessing;
            // a later round usually breaks the tie with more context.
            if source_best.is_tied() || target_best.is_tied() {
                continue;
            }
            let runner_up_weight = source_best.runner_up_weight.max(target_best.runner_up_weight);
            let best_weight = source_best.weight.max(target_best.weight);
            let margin =
                if best_weight > 0.0 { 1.0 - (runner_up_weight / best_weight) } else { 0.0 };

            let source_fingerprint = &self.source.fingerprints[a as usize];
            let target_fingerprint = &self.target.fingerprints[b as usize];
            let distinctive_body = self.distinctive_body(a, b);
            let confidence = confidence_for(
                vote,
                margin,
                source_fingerprint.similarity(target_fingerprint),
                distinctive_body,
            );
            if confidence < self.options.min_confidence {
                continue;
            }
            // Report the rival source name, since that's what a reviewer choosing
            // between two possible names for this target actually needs.
            let runner_up = target_best.runner_up_node.map(|source| Alternative {
                source,
                relative_score: if target_best.weight > 0.0 {
                    target_best.runner_up_weight / target_best.weight
                } else {
                    0.0
                },
            });
            accepted.push(Match {
                source: a,
                target: b,
                method: vote.method(),
                confidence,
                evidence: vote.count,
                round,
                distinctive_body,
                runner_up,
            });
        }

        // Highest confidence first, so the strongest claim wins any node that
        // still ended up contested.
        accepted.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
        let mut count = 0;
        for m in accepted {
            if !self.is_available(m.source, m.target) {
                continue;
            }
            self.record(m);
            count += 1;
        }
        count
    }
}

fn confidence_for(vote: &Vote, margin: f32, similarity: f32, distinctive_body: bool) -> f32 {
    if distinctive_body {
        // Byte-identical once relocations are masked out, and the call graph
        // agrees. Note this must be tested directly rather than inferred from a
        // perfect similarity score: the weighted terms in
        // [`Fingerprint::similarity`] also sum to exactly 1.0 for any two
        // functions sharing an opcode sequence and reference counts, which every
        // trivial accessor in a binary does.
        return 0.98;
    }
    let corroboration = (vote.count as f32 / 3.0).min(1.0);
    (0.45 + 0.20 * similarity + 0.20 * corroboration + 0.15 * margin).min(0.95)
}

/// Whether two bodies hash identically once relocations are masked out, *and*
/// are substantial enough for that to be evidence rather than coincidence.
fn is_distinctive(source: &Fingerprint, target: &Fingerprint) -> bool {
    source.exact_hash == target.exact_hash
        && source.instruction_count >= MIN_DISTINCTIVE_INSTRUCTIONS
        && target.instruction_count >= MIN_DISTINCTIVE_INSTRUCTIONS
}

/// Records a proposed pairing, collapsing to `None` once two proposals for the
/// same key disagree. Also used by [`crate::analysis::data_matching`], which
/// faces the same problem pairing data symbols.
pub(crate) fn merge_proposal(
    proposals: &mut BTreeMap<NodeIndex, Option<NodeIndex>>,
    key: NodeIndex,
    value: NodeIndex,
) {
    proposals
        .entry(key)
        .and_modify(|existing| {
            if *existing != Some(value) {
                *existing = None;
            }
        })
        .or_insert(Some(value));
}

/// The leading candidate for one node, and whatever came closest to it.
#[derive(Debug, Clone, Copy)]
struct Best {
    weight: f32,
    node: NodeIndex,
    runner_up_weight: f32,
    runner_up_node: Option<NodeIndex>,
}

impl Best {
    /// Whether the leader and runner-up scored identically, making `node` an
    /// artifact of iteration order rather than a decision.
    fn is_tied(&self) -> bool {
        self.runner_up_node.is_some() && self.weight == self.runner_up_weight
    }
}

fn update_best(map: &mut HashMap<NodeIndex, Best>, key: NodeIndex, weight: f32, other: NodeIndex) {
    match map.entry(key) {
        hash_map::Entry::Vacant(e) => {
            e.insert(Best { weight, node: other, runner_up_weight: 0.0, runner_up_node: None });
        }
        hash_map::Entry::Occupied(mut e) => {
            let best = e.get_mut();
            if weight > best.weight {
                best.runner_up_weight = best.weight;
                best.runner_up_node = Some(best.node);
                best.weight = weight;
                best.node = other;
            } else if weight > best.runner_up_weight {
                best.runner_up_weight = weight;
                best.runner_up_node = Some(other);
            }
        }
    }
}

/// Indexes nodes by a key, keeping only keys that map to exactly one node.
fn unique_index<K, F>(target: &MatchTarget, key: F) -> HashMap<K, NodeIndex>
where
    K: std::hash::Hash + Eq,
    F: Fn(&MatchTarget, NodeIndex) -> Option<K>,
{
    let mut counts: HashMap<K, (NodeIndex, u32)> = HashMap::new();
    for (node, _) in target.graph.iter() {
        let Some(k) = key(target, node) else { continue };
        let entry = counts.entry(k).or_insert((node, 0));
        entry.1 += 1;
    }
    counts
        .into_iter()
        .filter(|(_, (_, count))| *count == 1)
        .map(|(k, (node, _))| (k, node))
        .collect()
}

/// Indexes nodes by every string they reference, keeping only strings that are
/// referenced from exactly one function.
fn unique_multi_index(target: &MatchTarget) -> HashMap<String, NodeIndex> {
    let mut counts: HashMap<&str, (NodeIndex, u32)> = HashMap::new();
    for (node, _) in target.graph.iter() {
        for string in &target.fingerprints[node as usize].strings {
            let entry = counts.entry(string.as_str()).or_insert((node, 0));
            entry.1 += 1;
        }
    }
    counts
        .into_iter()
        .filter(|(_, (_, count))| *count == 1)
        .map(|(k, (node, _))| (k.to_string(), node))
        .collect()
}

/// Indices of a longest common subsequence between a projected source sequence
/// and a target sequence, as `(source_index, target_index)` pairs.
fn longest_common_subsequence(
    source: &[Option<NodeIndex>],
    target: &[NodeIndex],
) -> Vec<(usize, usize)> {
    let (n, m) = (source.len(), target.len());
    let mut table = vec![0u16; (n + 1) * (m + 1)];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            table[i * (m + 1) + j] = if source[i] == Some(target[j]) {
                table[(i + 1) * (m + 1) + j + 1] + 1
            } else {
                table[(i + 1) * (m + 1) + j].max(table[i * (m + 1) + j + 1])
            };
        }
    }

    let mut result = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if source[i] == Some(target[j]) {
            result.push((i, j));
            i += 1;
            j += 1;
        } else if table[(i + 1) * (m + 1) + j] >= table[i * (m + 1) + j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lcs(source: &[u32], target: &[u32]) -> Vec<(usize, usize)> {
        let projected: Vec<Option<NodeIndex>> = source.iter().map(|&v| Some(v)).collect();
        longest_common_subsequence(&projected, target)
    }

    #[test]
    fn lcs_identical_sequences_align_positionally() {
        assert_eq!(lcs(&[1, 2, 3], &[1, 2, 3]), vec![(0, 0), (1, 1), (2, 2)]);
    }

    #[test]
    fn lcs_skips_an_inserted_element() {
        // A call added to the target only shifts the elements after it.
        assert_eq!(lcs(&[1, 2, 3], &[1, 9, 2, 3]), vec![(0, 0), (1, 2), (2, 3)]);
    }

    #[test]
    fn lcs_skips_a_removed_element() {
        assert_eq!(lcs(&[1, 2, 3], &[1, 3]), vec![(0, 0), (2, 1)]);
    }

    #[test]
    fn lcs_of_disjoint_sequences_is_empty() {
        assert!(lcs(&[1, 2], &[3, 4]).is_empty());
    }

    #[test]
    fn lcs_ignores_unmatched_source_entries() {
        // `None` marks a callee with no counterpart yet, which must never anchor.
        let projected = vec![Some(1), None, Some(3)];
        assert_eq!(longest_common_subsequence(&projected, &[1, 2, 3]), vec![(0, 0), (2, 2)]);
    }

    #[test]
    fn lcs_indices_are_strictly_increasing() {
        let source = [4, 1, 7, 2, 9, 3];
        let target = [1, 4, 2, 7, 3, 9];
        let anchors = lcs(&source, &target);
        for pair in anchors.windows(2) {
            assert!(pair[1].0 > pair[0].0, "source indices must advance");
            assert!(pair[1].1 > pair[0].1, "target indices must advance");
        }
        for &(i, j) in &anchors {
            assert_eq!(source[i], target[j]);
        }
    }

    #[test]
    fn vote_method_prefers_the_strongest_evidence() {
        let call = Vote { weight: 1.0, count: 2, call_sites: 1, layout: 1 };
        assert_eq!(call.method(), MatchMethod::CallSite);
        let caller = Vote { weight: 1.0, count: 2, call_sites: 0, layout: 1 };
        assert_eq!(caller.method(), MatchMethod::CallerSite);
        let layout = Vote { weight: 1.0, count: 1, call_sites: 0, layout: 1 };
        assert_eq!(layout.method(), MatchMethod::Layout);
    }

    #[test]
    fn confidence_rewards_corroboration_and_margin() {
        let weak = Vote { weight: 0.5, count: 1, call_sites: 1, layout: 0 };
        let strong = Vote { weight: 3.0, count: 5, call_sites: 5, layout: 0 };
        assert!(confidence_for(&strong, 1.0, 0.5, false) > confidence_for(&weak, 0.0, 0.5, false));
        // An identical masked encoding short-circuits to near certainty.
        assert!(confidence_for(&weak, 0.0, 0.5, true) > 0.95);
    }

    #[test]
    fn a_perfect_similarity_score_alone_does_not_short_circuit() {
        // `Fingerprint::similarity` reaches exactly 1.0 for any two functions
        // sharing an opcode sequence and reference counts, so only a genuine
        // encoding match may claim the high-confidence path.
        let weak = Vote { weight: 0.5, count: 1, call_sites: 0, layout: 1 };
        assert!(confidence_for(&weak, 0.0, 1.0, false) < 0.95);
        assert!(confidence_for(&weak, 0.0, 1.0, true) > 0.95);
    }

    #[test]
    fn merge_proposal_collapses_on_disagreement() {
        let mut proposals = BTreeMap::new();
        merge_proposal(&mut proposals, 1, 10);
        assert_eq!(proposals[&1], Some(10), "a lone proposal stands");
        merge_proposal(&mut proposals, 1, 10);
        assert_eq!(proposals[&1], Some(10), "agreeing proposals reinforce it");
        merge_proposal(&mut proposals, 1, 11);
        assert_eq!(proposals[&1], None, "a disagreement withdraws it");
        merge_proposal(&mut proposals, 1, 10);
        assert_eq!(proposals[&1], None, "and it stays withdrawn");
    }

    #[test]
    fn update_best_detects_an_exact_tie() {
        let mut best = HashMap::new();
        update_best(&mut best, 1, 2.0, 10);
        assert!(!best[&1].is_tied(), "a lone candidate is not tied");
        update_best(&mut best, 1, 2.0, 11);
        assert!(best[&1].is_tied(), "an exact tie must be detectable by the caller");
    }

    #[test]
    fn update_best_tracks_the_runner_up_identity() {
        let mut best = HashMap::new();
        update_best(&mut best, 1, 1.0, 10);
        update_best(&mut best, 1, 3.0, 11);
        update_best(&mut best, 1, 2.0, 12);
        let entry = best[&1];
        assert_eq!(entry.node, 11, "highest weight leads");
        assert_eq!(entry.runner_up_node, Some(12), "second highest is the runner-up");
        assert_eq!(entry.runner_up_weight, 2.0);
    }

    fn propagated(method: MatchMethod, evidence: u32, runner_up: Option<f32>) -> Match {
        Match {
            source: 0,
            target: 0,
            method,
            confidence: 0.8,
            evidence,
            round: 1,
            distinctive_body: false,
            runner_up: runner_up.map(|relative_score| Alternative { source: 1, relative_score }),
        }
    }

    #[test]
    fn anchors_are_confident() {
        for method in [MatchMethod::Name, MatchMethod::ExactHash, MatchMethod::StringRef] {
            assert_eq!(propagated(method, 1, None).tier(), MatchTier::Confident);
        }
    }

    #[test]
    fn an_identical_body_promotes_a_propagated_match() {
        let mut m = propagated(MatchMethod::Layout, 1, None);
        assert_eq!(m.tier(), MatchTier::Candidate, "position alone is only a candidate");
        m.distinctive_body = true;
        assert_eq!(m.tier(), MatchTier::Confident);
    }

    #[test]
    fn a_stub_sized_body_is_not_distinctive() {
        // `blr` hashes the same as every other stub, so an identical body that
        // short must not buy a promotion.
        let stub = Fingerprint {
            exact_hash: 7,
            opcode_hash: 7,
            instruction_count: MIN_DISTINCTIVE_INSTRUCTIONS - 1,
            call_count: 0,
            data_ref_count: 0,
            strings: Vec::new(),
        };
        let real = Fingerprint { instruction_count: MIN_DISTINCTIVE_INSTRUCTIONS, ..stub.clone() };
        assert!(!is_distinctive(&stub, &stub), "matching stubs carry no information");
        assert!(!is_distinctive(&stub, &real), "one short side is enough to disqualify");
        assert!(is_distinctive(&real, &real));

        // A body that could not be read at all hashes like any other empty one.
        let unread = Fingerprint { instruction_count: 0, exact_hash: 0, ..stub.clone() };
        assert!(!is_distinctive(&unread, &unread));
    }

    #[test]
    fn corroboration_separates_probable_from_candidate() {
        assert_eq!(propagated(MatchMethod::CallSite, 1, None).tier(), MatchTier::Candidate);
        assert_eq!(propagated(MatchMethod::CallSite, 2, None).tier(), MatchTier::Probable);
    }

    #[test]
    fn a_close_runner_up_demotes_everything() {
        // Even an identical body loses its promotion when something else scored
        // nearly as well: the evidence didn't actually single this pair out.
        let mut m = propagated(MatchMethod::ExactHash, 5, Some(0.9));
        assert_eq!(m.tier(), MatchTier::Candidate);
        m.distinctive_body = true;
        assert_eq!(m.tier(), MatchTier::Candidate);
        // A distant runner-up leaves the classification alone.
        assert_eq!(propagated(MatchMethod::ExactHash, 5, Some(0.5)).tier(), MatchTier::Confident);
    }

    #[test]
    fn tiers_order_from_most_to_least_trusted() {
        assert!(MatchTier::Confident < MatchTier::Probable);
        assert!(MatchTier::Probable < MatchTier::Candidate);
    }
}
