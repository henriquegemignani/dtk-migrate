use std::collections::HashMap;

use decomp_toolkit::obj::{ObjInfo, ObjRelocKind, ObjSymbolKind, SectionIndex, SymbolIndex};

/// Index into [`CallGraph::nodes`].
pub type NodeIndex = u32;

/// An outgoing reference from a function body, derived from a single relocation.
#[derive(Debug, Clone)]
pub struct FunctionRef {
    /// Byte offset from the start of the containing function.
    pub offset: u32,
    pub kind: ObjRelocKind,
    pub target_symbol: SymbolIndex,
    pub addend: i64,
    /// Set when the target resolves to a function tracked by this graph.
    pub target_node: Option<NodeIndex>,
}

impl FunctionRef {
    /// Whether this reference is a direct branch, i.e. a call site.
    pub fn is_call(&self) -> bool {
        matches!(self.kind, ObjRelocKind::PpcRel24 | ObjRelocKind::PpcRel14)
    }
}

#[derive(Debug, Clone)]
pub struct FunctionNode {
    pub symbol: SymbolIndex,
    pub section: SectionIndex,
    pub address: u32,
    pub size: u32,
    /// All outgoing references, ordered by offset.
    pub refs: Vec<FunctionRef>,
    /// Nodes with a call site targeting this function, deduplicated and sorted.
    pub callers: Vec<NodeIndex>,
}

impl FunctionNode {
    /// Call sites in address order. Includes calls whose target is outside the graph.
    pub fn calls(&self) -> impl DoubleEndedIterator<Item = &FunctionRef> {
        self.refs.iter().filter(|r| r.is_call())
    }

    /// Callees in call-site order, skipping calls that leave the object.
    ///
    /// Duplicates are kept: the position of a call within this sequence is the
    /// signal that cross-version propagation relies on.
    pub fn callees(&self) -> impl DoubleEndedIterator<Item = NodeIndex> + '_ {
        self.calls().filter_map(|r| r.target_node)
    }

    /// Non-branch references, i.e. loads of data addresses, in address order.
    pub fn data_refs(&self) -> impl DoubleEndedIterator<Item = &FunctionRef> {
        self.refs.iter().filter(|r| !r.is_call())
    }
}

/// A caller/callee graph over an object's functions.
///
/// This is derived rather than discovered: by the time relocations have been
/// applied (see [`decomp_toolkit::analysis::tracker::Tracker`]), every `bl` in a code
/// section is already a [`ObjRelocKind::PpcRel24`] relocation naming its target
/// symbol, so building the graph is a matter of bucketing relocations by the
/// function that contains them and inverting the edges.
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    pub nodes: Vec<FunctionNode>,
}

impl CallGraph {
    pub fn build(obj: &ObjInfo) -> Self {
        let mut nodes = Vec::new();
        let mut by_symbol = HashMap::new();

        // Sized function symbols become nodes. Zero-sized functions can't be
        // attributed relocations, so they'd only add noise.
        for (symbol_index, symbol) in obj.symbols.by_kind(ObjSymbolKind::Function) {
            let (Some(section), true) = (symbol.section, symbol.size >= 4) else { continue };
            by_symbol.insert(symbol_index, nodes.len() as NodeIndex);
            nodes.push(FunctionNode {
                symbol: symbol_index,
                section,
                address: symbol.address as u32,
                size: symbol.size as u32,
                refs: Vec::new(),
                callers: Vec::new(),
            });
        }

        // Collect outgoing references.
        let refs: Vec<Vec<FunctionRef>> = nodes
            .iter()
            .map(|node| {
                let Some(section) = obj.sections.get(node.section) else { return Vec::new() };
                let start = node.address;
                let end = node.address + node.size;
                section
                    .relocations
                    .range(start..end)
                    .map(|(address, reloc)| FunctionRef {
                        offset: address - start,
                        kind: reloc.kind,
                        target_symbol: reloc.target_symbol,
                        addend: reloc.addend,
                        // Cross-module (REL) references resolve to a symbol index
                        // in *another* object, so they can't name a node here.
                        target_node: if reloc.module.is_some() {
                            None
                        } else {
                            by_symbol.get(&reloc.target_symbol).copied()
                        },
                    })
                    .collect()
            })
            .collect();
        for (node, refs) in nodes.iter_mut().zip(refs) {
            node.refs = refs;
        }

        // Invert call edges.
        let mut callers: Vec<Vec<NodeIndex>> = vec![Vec::new(); nodes.len()];
        for (node_index, node) in nodes.iter().enumerate() {
            for callee in node.callees() {
                callers[callee as usize].push(node_index as NodeIndex);
            }
        }
        for (node, mut callers) in nodes.iter_mut().zip(callers) {
            callers.sort_unstable();
            callers.dedup();
            node.callers = callers;
        }

        Self { nodes }
    }

    #[allow(clippy::len_without_is_empty)] // a call graph is never legitimately empty
    pub fn len(&self) -> usize { self.nodes.len() }

    pub fn node(&self, index: NodeIndex) -> &FunctionNode { &self.nodes[index as usize] }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (NodeIndex, &FunctionNode)> {
        self.nodes.iter().enumerate().map(|(i, n)| (i as NodeIndex, n))
    }
}
