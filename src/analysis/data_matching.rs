use std::collections::BTreeMap;

use decomp_toolkit::obj::{ObjSymbolKind, SymbolIndex};

use crate::analysis::{
    callgraph::NodeIndex,
    matching::{MatchResult, MatchTarget, MatchTier, merge_proposal},
};

/// A data symbol correspondence inferred from matched functions' data
/// references — the data-symbol analogue of a function
/// [`Match`](crate::analysis::matching::Match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataMatch {
    pub source: SymbolIndex,
    pub target: SymbolIndex,
    /// Reference positions, across every confidently-matched function pair,
    /// that agreed on this pairing.
    pub evidence: u32,
}

/// Finds data symbol correspondences by aligning the data references of every
/// confidently-matched function pair.
///
/// Only [`MatchTier::Confident`] function pairs are trusted enough to say
/// anything about their data: a function match that isn't itself certain
/// gives no basis for pairing what it reads. Within a pair, alignment is
/// positional and all-or-nothing — the two reference sequences must be the
/// same length, with each position agreeing on relocation kind and addend —
/// rather than an LCS-style alignment like call sites get, since there's no
/// pre-existing partial map of data symbols to anchor on the way matched
/// callees anchor a call sequence.
pub fn match_data(
    source: &MatchTarget,
    target: &MatchTarget,
    result: &MatchResult,
) -> Vec<DataMatch> {
    match_data_pairs(
        source,
        target,
        result
            .matches
            .iter()
            .filter(|m| m.tier() == MatchTier::Confident)
            .map(|m| (m.source, m.target)),
    )
}

/// Finds data correspondences from function pairs whose trust was established
/// by a caller other than the ordinary per-function tiering policy.
///
/// The same strict reference alignment and bidirectional uniqueness checks as
/// [`match_data`] still apply. This is used by coverage's bounded unit-sequence
/// evidence: the complete ordered unit can establish a function pairing even
/// when that individual function changed too much to become `Confident` alone.
pub fn match_data_pairs(
    source: &MatchTarget,
    target: &MatchTarget,
    pairs: impl IntoIterator<Item = (NodeIndex, NodeIndex)>,
) -> Vec<DataMatch> {
    let mut evidence: BTreeMap<(SymbolIndex, SymbolIndex), u32> = BTreeMap::new();
    for (source_node, target_node) in pairs {
        let source_refs: Vec<_> = source.graph.node(source_node).data_refs().collect();
        let target_refs: Vec<_> = target.graph.node(target_node).data_refs().collect();
        if source_refs.is_empty() || source_refs.len() != target_refs.len() {
            continue;
        }
        // A disagreement invalidates the function pair as a positional data
        // witness. Keeping only its agreeing positions can manufacture a
        // unique symbol pairing from a changed reference sequence.
        if source_refs
            .iter()
            .zip(&target_refs)
            .any(|(a, b)| a.kind != b.kind || a.addend != b.addend)
        {
            continue;
        }
        for (a, b) in source_refs.iter().zip(&target_refs) {
            *evidence.entry((a.target_symbol, b.target_symbol)).or_default() += 1;
        }
    }

    // A source symbol counts only if every position it appeared in agreed on
    // the same target, and vice versa: disagreement means the position isn't
    // actually identifying the symbol, and the governing principle is to name
    // nothing rather than risk a wrong pairing.
    let mut forward: BTreeMap<SymbolIndex, Option<SymbolIndex>> = BTreeMap::new();
    let mut backward: BTreeMap<SymbolIndex, Option<SymbolIndex>> = BTreeMap::new();
    for &(a, b) in evidence.keys() {
        merge_proposal(&mut forward, a, b);
        merge_proposal(&mut backward, b, a);
    }

    forward
        .into_iter()
        .filter_map(|(source_symbol, target_symbol)| Some((source_symbol, target_symbol?)))
        .filter(|&(source_symbol, target_symbol)| {
            backward.get(&target_symbol) == Some(&Some(source_symbol))
        })
        // A data ref can also target a function symbol, e.g. a vtable entry
        // or a function pointer; those already have a real match (or don't)
        // from `match_functions`, so only Object symbols are new information.
        .filter(|&(s, t)| {
            source.obj.symbols[s].kind == ObjSymbolKind::Object
                && target.obj.symbols[t].kind == ObjSymbolKind::Object
        })
        .map(|(source, target)| DataMatch {
            source,
            target,
            evidence: evidence.get(&(source, target)).copied().unwrap_or(0),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use decomp_toolkit::obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjReloc, ObjRelocKind, ObjRelocations, ObjSection,
        ObjSectionKind, ObjSplits, ObjSymbol,
    };

    use super::*;
    use crate::analysis::matching::{Match, MatchMethod};

    /// Builds a tiny object with one function and, optionally, one data
    /// object symbol the function loads via a `PpcAddr16Ha`/`PpcAddr16Lo`
    /// pair (the usual two-instruction address load), so `data_refs()` sees
    /// two entries pointing at the same symbol.
    fn object(function_name: &str, data_name: Option<&str>) -> ObjInfo {
        let mut symbols = vec![ObjSymbol {
            name: function_name.to_string(),
            address: 0x1000,
            section: Some(0),
            size: 8,
            size_known: true,
            kind: ObjSymbolKind::Function,
            ..Default::default()
        }];
        let mut relocations = ObjRelocations::default();
        if let Some(data_name) = data_name {
            let data_index = symbols.len() as SymbolIndex;
            symbols.push(ObjSymbol {
                name: data_name.to_string(),
                address: 0x2000,
                section: Some(1),
                size: 4,
                size_known: true,
                kind: ObjSymbolKind::Object,
                ..Default::default()
            });
            relocations = ObjRelocations::new(vec![
                (0x1000, ObjReloc {
                    kind: ObjRelocKind::PpcAddr16Ha,
                    target_symbol: data_index,
                    addend: 0,
                    module: None,
                }),
                (0x1004, ObjReloc {
                    kind: ObjRelocKind::PpcAddr16Lo,
                    target_symbol: data_index,
                    addend: 0,
                    module: None,
                }),
            ])
            .unwrap();
        }

        let code = ObjSection {
            name: ".text".to_string(),
            kind: ObjSectionKind::Code,
            address: 0x1000,
            size: 8,
            data: vec![0; 8],
            align: 4,
            elf_index: 0,
            relocations,
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits: ObjSplits::default(),
        };
        let data = ObjSection {
            name: ".data".to_string(),
            kind: ObjSectionKind::Data,
            address: 0x2000,
            size: 4,
            data: vec![0; 4],
            align: 4,
            elf_index: 1,
            relocations: ObjRelocations::default(),
            virtual_address: None,
            file_offset: 0,
            section_known: true,
            splits: ObjSplits::default(),
        };

        ObjInfo::new(
            ObjKind::Executable,
            ObjArchitecture::PowerPc,
            "test".to_string(),
            symbols,
            vec![code, data],
        )
    }

    fn target(name: &str, data_name: Option<&str>) -> MatchTarget {
        MatchTarget::new(name.to_string(), object(name, data_name))
    }

    fn confident_match(source: SymbolIndex, target: SymbolIndex) -> Match {
        Match {
            source,
            target,
            method: MatchMethod::Name,
            confidence: 1.0,
            evidence: 1,
            round: 0,
            distinctive_body: false,
            runner_up: None,
        }
    }

    #[test]
    fn aligned_data_refs_are_paired() {
        let source = target("Fn", Some("gSourceVar"));
        let target = target("Fn", Some("fn_80002000"));
        let result = MatchResult {
            matches: vec![confident_match(0, 0)],
            source_to_target: vec![Some(0)],
            target_to_source: vec![Some(0)],
            rounds: 1,
        };
        let matches = match_data(&source, &target, &result);
        assert_eq!(matches.len(), 1);
        assert_eq!(source.symbol_name_at(matches[0].source), "gSourceVar");
        assert_eq!(matches[0].evidence, 2);
    }

    #[test]
    fn externally_trusted_function_pair_can_match_data() {
        let source = target("SourceFn", Some("gSourceVar"));
        let target = target("fn_80001000", Some("lbl_80002000"));
        let matches = match_data_pairs(&source, &target, [(0, 0)]);
        assert_eq!(matches.len(), 1);
        assert_eq!(source.symbol_name_at(matches[0].source), "gSourceVar");
        assert_eq!(target.symbol_name_at(matches[0].target), "lbl_80002000");
        assert_eq!(matches[0].evidence, 2);
    }

    #[test]
    fn mismatched_ref_counts_are_skipped() {
        let source = target("Fn", Some("gSourceVar"));
        let target = target("Fn", None);
        let result = MatchResult {
            matches: vec![confident_match(0, 0)],
            source_to_target: vec![Some(0)],
            target_to_source: vec![Some(0)],
            rounds: 1,
        };
        assert!(match_data(&source, &target, &result).is_empty());
    }

    #[test]
    fn one_disagreeing_relocation_invalidates_the_whole_function_pair() {
        let source = target("Fn", Some("gSourceVar"));
        let mut target_obj = object("Fn", Some("gTargetVar"));
        target_obj.sections[0].relocations = ObjRelocations::new(vec![
            (0x1000, ObjReloc {
                kind: ObjRelocKind::PpcAddr16Ha,
                target_symbol: 1,
                addend: 0,
                module: None,
            }),
            (0x1004, ObjReloc {
                kind: ObjRelocKind::PpcAddr16Lo,
                target_symbol: 1,
                addend: 4,
                module: None,
            }),
        ])
        .unwrap();
        let target = MatchTarget::new("target".into(), target_obj);
        let matches = match_data_pairs(&source, &target, [(0, 0)]);
        assert!(matches.is_empty(), "an agreeing position cannot vouch for a changed sequence");
    }
}
