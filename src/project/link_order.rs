//! Predicting the link-order cycle that `dtk dol split` would reject.
//!
//! dtk derives the order units must be linked in from address adjacency in
//! every section, and refuses to split at all if those constraints contradict
//! each other. A batch of candidates can introduce such a contradiction, and
//! discovering that from a failed build costs a full compile of the batch. The
//! same graph can be built from the splits file directly, so a batch that
//! cannot possibly link is bisected before anything is compiled.
//!
//! This is a pre-filter, deliberately more cautious than dtk itself. Where it
//! cannot tell two situations apart it declines to add a constraint, so it can
//! pass a batch dtk will reject — the real build stays the authority — but it
//! will not reject a batch dtk would have accepted.

use std::collections::{BTreeMap, BTreeSet};

use indexmap::IndexMap;

use crate::project::splits::parse_range;

/// The units each unit must be linked before.
pub type Graph = BTreeMap<String, BTreeSet<String>>;

/// Builds the link-order constraints implied by a set of split bodies.
///
/// Mirrors dtk's `resolve_link_order`: per section, sort every declared range
/// by address and add an edge from each unit to the next one that differs.
///
/// Two deliberate departures:
///
/// - `.bss` is skipped entirely. dtk only skips edges entering a *common* BSS
///   split, the CodeWarrior analogue of an ELF common symbol, which the linker
///   packs by its own rules rather than by link order. Which splits are common
///   is decided inside dtk from the target's map file and cannot be read from
///   `splits.txt`, so all of `.bss` is treated as unordered. On Prime's PAL
///   target this is the difference between a reported 386-node cycle and none.
/// - The first split of `.ctors` and `.dtors` is dropped before pairing, as dtk
///   does. Pairing from it invents an edge out of one arbitrary unit into every
///   other owner of those sections, which on its own ties the whole program
///   into one false cycle: 673 nodes, for a baseline dtk builds without
///   complaint.
pub fn build_graph(blocks: &IndexMap<String, Vec<String>>) -> Graph {
    let mut per_section: BTreeMap<String, Vec<(u32, u32, &str)>> = BTreeMap::new();
    for (name, lines) in blocks {
        for line in lines {
            let Some(range) = parse_range(line) else { continue };
            if range.section == ".bss" {
                continue;
            }
            per_section.entry(range.section).or_default().push((
                range.start,
                range.end,
                name.as_str(),
            ));
        }
    }

    let mut graph = Graph::new();
    for (section, mut ranges) in per_section {
        ranges.sort();
        let ranges = if section == ".ctors" || section == ".dtors" {
            &ranges[1.min(ranges.len())..]
        } else {
            &ranges[..]
        };
        for pair in ranges.windows(2) {
            let (a, b) = (pair[0].2, pair[1].2);
            if a != b {
                graph.entry(a.to_string()).or_default().insert(b.to_string());
            }
        }
    }
    graph
}

/// Every strongly connected component, by Tarjan's algorithm.
///
/// A component with more than one member is a set of units that must each be
/// linked before the other, which is exactly what dtk rejects.
pub fn strongly_connected(graph: &Graph) -> Vec<Vec<String>> {
    let nodes: Vec<&str> = graph
        .iter()
        .flat_map(|(from, to)| std::iter::once(from.as_str()).chain(to.iter().map(String::as_str)))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let index_of: BTreeMap<&str, usize> = nodes.iter().enumerate().map(|(i, n)| (*n, i)).collect();
    let edges: Vec<Vec<usize>> = nodes
        .iter()
        .map(|node| {
            graph
                .get(*node)
                .map(|to| to.iter().map(|n| index_of[n.as_str()]).collect())
                .unwrap_or_default()
        })
        .collect();

    // Iterative, because a real project's graph is deep enough to overflow a
    // recursive walk and a stack overflow is not a diagnosis anyone can use.
    const UNVISITED: usize = usize::MAX;
    let mut index = vec![UNVISITED; nodes.len()];
    let mut lowlink = vec![UNVISITED; nodes.len()];
    let mut on_stack = vec![false; nodes.len()];
    let mut stack: Vec<usize> = Vec::new();
    let mut counter = 0usize;
    let mut components: Vec<Vec<String>> = Vec::new();

    for start in 0..nodes.len() {
        if index[start] != UNVISITED {
            continue;
        }
        // Each frame is a node and how far through its edges we have walked.
        let mut work: Vec<(usize, usize)> = vec![(start, 0)];
        index[start] = counter;
        lowlink[start] = counter;
        counter += 1;
        stack.push(start);
        on_stack[start] = true;

        while let Some((node, edge)) = work.pop() {
            if edge < edges[node].len() {
                work.push((node, edge + 1));
                let next = edges[node][edge];
                if index[next] == UNVISITED {
                    index[next] = counter;
                    lowlink[next] = counter;
                    counter += 1;
                    stack.push(next);
                    on_stack[next] = true;
                    work.push((next, 0));
                } else if on_stack[next] {
                    lowlink[node] = lowlink[node].min(index[next]);
                }
                continue;
            }
            // Finished this node: fold its lowlink into its parent's.
            if let Some(&(parent, _)) = work.last() {
                lowlink[parent] = lowlink[parent].min(lowlink[node]);
            }
            if lowlink[node] == index[node] {
                let mut component = Vec::new();
                while let Some(member) = stack.pop() {
                    on_stack[member] = false;
                    component.push(nodes[member].to_string());
                    if member == node {
                        break;
                    }
                }
                components.push(component);
            }
        }
    }
    components
}

/// The units caught in a cycle, by dtk's own graph rules.
pub fn cyclic_units(blocks: &IndexMap<String, Vec<String>>) -> BTreeSet<String> {
    strongly_connected(&build_graph(blocks))
        .into_iter()
        .filter(|component| component.len() > 1)
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocks(entries: &[(&str, &[&str])]) -> IndexMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(name, lines)| {
                ((*name).to_string(), lines.iter().map(|l| (*l).to_string()).collect())
            })
            .collect()
    }

    fn range(section: &str, start: u32, end: u32) -> String {
        format!("\t{section:11} start:0x{start:08X} end:0x{end:08X}")
    }

    #[test]
    fn address_order_in_one_section_gives_one_chain_and_no_cycle() {
        let map = blocks(&[
            ("a", &[&range(".text", 0x100, 0x200)]),
            ("b", &[&range(".text", 0x200, 0x300)]),
        ]);
        let graph = build_graph(&map);
        assert_eq!(graph["a"], BTreeSet::from(["b".to_string()]));
        assert!(cyclic_units(&map).is_empty());
    }

    #[test]
    fn two_sections_that_disagree_are_a_cycle() {
        // `a` before `b` in .text, `b` before `a` in .data: no link order
        // satisfies both.
        let map = blocks(&[
            ("a", &[&range(".text", 0x100, 0x200), &range(".data", 0x900, 0xA00)]),
            ("b", &[&range(".text", 0x200, 0x300), &range(".data", 0x800, 0x900)]),
        ]);
        assert_eq!(cyclic_units(&map), BTreeSet::from(["a".to_string(), "b".to_string()]));
    }

    #[test]
    fn bss_order_never_constrains_anything() {
        let map = blocks(&[
            ("a", &[&range(".text", 0x100, 0x200), &range(".bss", 0x900, 0xA00)]),
            ("b", &[&range(".text", 0x200, 0x300), &range(".bss", 0x800, 0x900)]),
        ]);
        assert!(cyclic_units(&map).is_empty(), "common BSS packing is not link order");
    }

    #[test]
    fn the_first_ctors_split_is_dropped_before_pairing() {
        // Without dropping it, the exception-handling stub at the head of
        // .ctors would order every other owner behind it.
        let map = blocks(&[
            ("stub", &[&range(".ctors", 0x10, 0x14)]),
            ("a", &[&range(".ctors", 0x14, 0x18), &range(".text", 0x300, 0x400)]),
            ("b", &[&range(".ctors", 0x18, 0x1C), &range(".text", 0x100, 0x200)]),
        ]);
        let graph = build_graph(&map);
        assert!(!graph.contains_key("stub"), "{graph:?}");
        // a before b in .ctors, b before a in .text: still a real cycle.
        assert_eq!(cyclic_units(&map), BTreeSet::from(["a".to_string(), "b".to_string()]));
    }

    #[test]
    fn a_three_unit_cycle_is_reported_whole() {
        let map = blocks(&[
            ("a", &[&range(".text", 0x100, 0x200), &range(".data", 0x900, 0xA00)]),
            ("b", &[&range(".text", 0x200, 0x300), &range(".data", 0xA00, 0xB00)]),
            ("c", &[&range(".text", 0x300, 0x400), &range(".data", 0x800, 0x900)]),
        ]);
        assert_eq!(cyclic_units(&map).len(), 3);
    }

    #[test]
    fn a_unit_with_two_ranges_in_one_section_does_not_order_itself() {
        let map = blocks(&[("a", &[&range(".text", 0x100, 0x200), &range(".text", 0x300, 0x400)])]);
        assert!(build_graph(&map).is_empty());
    }

    #[test]
    fn a_deep_chain_does_not_overflow_the_stack() {
        let entries: Vec<(String, Vec<String>)> = (0..20_000u32)
            .map(|i| (format!("u{i:05}"), vec![range(".text", i * 0x10, (i + 1) * 0x10)]))
            .collect();
        let map: IndexMap<String, Vec<String>> = entries.into_iter().collect();
        assert!(cyclic_units(&map).is_empty());
    }
}
