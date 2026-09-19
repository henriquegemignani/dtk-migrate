//! Reading and writing a version's `splits.txt`, and the proposal files that
//! share its syntax.
//!
//! A splits file is a list of units and their address ranges. Non-code sections
//! may have more than one range in a unit, including ordinary and common BSS.
//! It is a project input under version control, so the writer's job is to keep
//! every line it did not deliberately change exactly as it found it: the file is
//! not sorted by address, and re-sorting it would turn every untouched unit into
//! a diff.

use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
    sync::LazyLock,
};

use anyhow::{Context, Result, bail};
use indexmap::IndexMap;
use regex::Regex;

static ENTRY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?P<section>\S+)\s+start:0x(?P<start>[0-9A-Fa-f]+)\s+end:0x(?P<end>[0-9A-Fa-f]+)")
        .unwrap()
});

/// The reason `match --splits` gives for a range that fails its section's own
/// alignment requirement.
///
/// Worth recognising rather than leaving to the build: `dtk dol split` rejects a
/// misaligned boundary outright, and the placeholder chunk that starts after it
/// inherits whatever address the previous split ended at — so one misaligned
/// candidate can manufacture a failure that looks like it is about a completely
/// unrelated unit.
pub const ALIGNMENT_REASON: &str = "split boundary doesn't meet the section's required alignment";

/// One section's address range within a unit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Range {
    pub section: String,
    pub start: u32,
    pub end: u32,
}

impl Range {
    pub fn size(&self) -> u32 { self.end.saturating_sub(self.start) }
}

/// Parses one split entry line, or `None` if the line is not one.
pub fn parse_range(line: &str) -> Option<Range> {
    let captures = ENTRY.captures(line.trim())?;
    Some(Range {
        section: captures["section"].to_string(),
        start: u32::from_str_radix(&captures["start"], 16).ok()?,
        end: u32::from_str_radix(&captures["end"], 16).ok()?,
    })
}

/// The tokens an entry line carries after its address range.
///
/// dtk writes per-block attributes there — `align:4`, `common` — and they are
/// not decoration: `common` says the block is BSS the linker merges, and a
/// migration that rewrote a block without it would change what the project
/// means while leaving every address identical. Scoring compares them
/// separately from the addresses for exactly that reason.
pub fn parse_attributes(line: &str) -> BTreeSet<String> {
    let trimmed = line.trim();
    let Some(captures) = ENTRY.captures(trimmed) else { return BTreeSet::new() };
    trimmed[captures.get(0).map_or(0, |m| m.end())..]
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// The attribute text after an entry's address range, exactly as written.
///
/// [`parse_attributes`] is for comparing; this is for rewriting a range while
/// keeping what followed it, in its original order and spelling.
pub fn entry_suffix(line: &str) -> String {
    let trimmed = line.trim();
    match ENTRY.find(trimmed) {
        Some(found) => trimmed[found.end()..].trim().to_string(),
        None => String::new(),
    }
}

/// An entry line for `section` `start..end`, followed by `suffix` if any.
pub fn entry_line(section: &str, start: u32, end: u32, suffix: &str) -> String {
    let line = format!("\t{section:11} start:0x{start:08X} end:0x{end:08X}");
    if suffix.is_empty() { line } else { format!("{line} {suffix}") }
}

/// Strips a proposal file's leading `#` and trailing `# candidate: ...`
/// annotation. A no-op on an already-clean `splits.txt` line.
pub fn clean_entry_line(line: &str) -> String {
    let line = line.strip_prefix('#').unwrap_or(line);
    match line.find("  # candidate:") {
        Some(index) => line[..index].to_string(),
        None => line.to_string(),
    }
}

/// A parsed splits file: the header block, then one body per unit in file order.
#[derive(Debug, Clone, Default)]
pub struct Splits {
    /// Everything up to and including the first blank line — a real file's
    /// `Sections:` block, or a proposal's banner comment. Kept verbatim and
    /// already ending in that blank line.
    pub header: String,
    /// Unit name to its entry lines, in the order the file lists them.
    pub blocks: IndexMap<String, Vec<String>>,
}

impl Splits {
    /// Parses a `splits.txt` or a `match --splits` proposal. Candidate lines are
    /// uncommented, so a proposal reads as the splits it is proposing.
    pub fn parse(text: &str) -> Result<Self> {
        let (header, bodies) = split_blocks(text, clean_entry_line);
        let mut blocks = IndexMap::new();
        for (name, body) in bodies {
            if blocks.insert(name.clone(), body).is_some() {
                bail!("Split file lists '{name}' more than once");
            }
        }
        Ok(Self { header, blocks })
    }

    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("Failed to parse {}", path.display()))
    }

    /// Renders the file. `header` already ends in the blank line that follows
    /// `Sections:`, so blocks are appended rather than joined.
    pub fn render(&self) -> String {
        let mut text = self.header.clone();
        for (name, lines) in &self.blocks {
            text.push_str(name);
            text.push_str(":\n");
            for line in lines {
                text.push_str(line);
                text.push('\n');
            }
            text.push('\n');
        }
        while text.ends_with("\n\n") {
            text.pop();
        }
        text
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        std::fs::write(path, self.render())
            .with_context(|| format!("Failed to write {}", path.display()))
    }

    /// The first `.text` address a unit owns, if it owns any.
    pub fn text_start(&self, unit: &str) -> Option<u32> {
        self.blocks
            .get(unit)?
            .iter()
            .filter_map(|line| parse_range(line))
            .filter(|range| range.section == ".text")
            .map(|range| range.start)
            .min()
    }

    /// Inserts new code-bearing units by their first `.text` address.
    ///
    /// dtk resolves the final link order from address adjacency in every
    /// section. Migration trials deliberately run its splitter with
    /// `--no-update`, so placement is ours to get right rather than dtk's.
    /// Existing units keep their exact relative order, including data-only and
    /// specially ordered runtime blocks.
    pub fn place_new_units(&mut self, new_names: &[String]) -> Result<()> {
        let mut pending: Vec<String> = Vec::new();
        for name in new_names {
            if !self.blocks.contains_key(name) {
                bail!("Missing split block for {name}");
            }
            if !pending.contains(name) {
                pending.push(name.clone());
            }
        }
        let starts: HashMap<String, Option<u32>> =
            self.blocks.keys().map(|k| (k.clone(), self.text_start(k))).collect();
        pending.sort_by(|a, b| {
            let (sa, sb) = (starts[a], starts[b]);
            // Data-only units have no `.text` address to place by, so they go
            // last, in name order.
            sa.is_none().cmp(&sb.is_none()).then(sa.cmp(&sb)).then_with(|| a.cmp(b))
        });

        let mut order: Vec<String> =
            self.blocks.keys().filter(|k| !pending.contains(k)).cloned().collect();
        for name in pending {
            match starts[&name] {
                None => order.push(name),
                Some(start) => {
                    let index = order
                        .iter()
                        .position(|other| starts[other].is_some_and(|other| other > start))
                        .unwrap_or(order.len());
                    order.insert(index, name);
                }
            }
        }
        self.reorder(&order);
        Ok(())
    }

    fn reorder(&mut self, order: &[String]) {
        let mut blocks = IndexMap::with_capacity(self.blocks.len());
        for name in order {
            if let Some(body) = self.blocks.shift_remove(name) {
                blocks.insert(name.clone(), body);
            }
        }
        // Anything the caller's order forgot keeps its relative position at the
        // end rather than vanishing.
        for (name, body) in std::mem::take(&mut self.blocks) {
            blocks.insert(name, body);
        }
        self.blocks = blocks;
    }
}

/// The same unit-block parsing, keeping each line exactly as written — the `#`
/// prefix and the trailing `# candidate: ...` reason both intact.
///
/// [`dominant_cluster`] and [`drop_misaligned_sections`] need that reason text,
/// which [`Splits::parse`] deliberately discards.
pub fn raw_proposal_lines(text: &str) -> IndexMap<String, Vec<String>> {
    let (_, bodies) = split_blocks(text, |line| line.to_string());
    let mut blocks = IndexMap::new();
    for (name, body) in bodies {
        blocks.entry(name).or_insert_with(Vec::new).extend(body);
    }
    blocks
}

/// Shared block scanner for both readers, parameterised by how a body line is
/// normalised.
fn split_blocks(
    text: &str,
    clean: impl Fn(&str) -> String,
) -> (String, Vec<(String, Vec<String>)>) {
    let normalized = text.replace("\r\n", "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();

    let mut header = String::new();
    let mut index = 0;
    while index < lines.len() {
        header.push_str(lines[index]);
        header.push('\n');
        let blank = lines[index].trim().is_empty();
        index += 1;
        if blank {
            break;
        }
    }

    let mut blocks: Vec<(String, Vec<String>)> = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    let flush = |current: &mut Option<(String, Vec<String>)>,
                 blocks: &mut Vec<(String, Vec<String>)>| {
        if let Some((name, body)) = current.take() {
            // A unit header with no entries is not a unit.
            if !body.is_empty() {
                blocks.push((name, body));
            }
        }
    };

    for line in &lines[index..] {
        if line.trim().is_empty() {
            flush(&mut current, &mut blocks);
            continue;
        }
        let is_header =
            !line.starts_with('\t') && !line.starts_with(' ') && line.trim_end().ends_with(':');
        if is_header {
            flush(&mut current, &mut blocks);
            let name = line.trim_end();
            current = Some((name[..name.len() - 1].to_string(), Vec::new()));
            continue;
        }
        // Banner text before the first real unit.
        if let Some((_, body)) = current.as_mut() {
            body.push(clean(line));
        }
    }
    flush(&mut current, &mut blocks);
    (header, blocks)
}

/// True if a proposed unit puts two or more ranges in one code section.
///
/// A translation unit compiles to one contiguous code chunk per section, so this
/// means the matcher found two separate clusters of functions it believes belong
/// to the same source file with something else's code between them. Staging it
/// asks the unit to sit both before and after whatever is in the gap, which no
/// link order can satisfy. Data may legitimately occupy disjoint ranges.
pub fn is_fragmented(lines: &[String]) -> bool {
    let mut per_section: HashMap<String, usize> = HashMap::new();
    for line in lines {
        if let Some(range) = parse_range(line)
            && matches!(range.section.as_str(), ".text" | ".init")
        {
            *per_section.entry(range.section).or_default() += 1;
        }
    }
    per_section.values().any(|&count| count > 1)
}

/// Drops any range the matcher already flagged as failing its section's
/// alignment requirement.
///
/// [`dominant_cluster`] checks this while reducing a fragmented proposal, but an
/// ordinary single-range candidate's annotation is discarded by cleaning and was
/// never checked at all. A no-op when nothing is flagged.
pub fn drop_misaligned_sections(lines: &[String], raw_lines: &[String]) -> Vec<String> {
    let raw_by_clean: HashMap<String, &String> =
        raw_lines.iter().map(|line| (clean_entry_line(line), line)).collect();
    lines
        .iter()
        .filter(|line| raw_by_clean.get(*line).is_none_or(|raw| !raw.contains(ALIGNMENT_REASON)))
        .cloned()
        .collect()
}

/// Reduces a fragmented code proposal to a stageable one: per code section,
/// keep only the largest aligned range. Preserve aligned data ranges separately.
///
/// This is a bet, not a structural fix. dtk validates that a staged split's
/// compiled object matches its declared range exactly, so keeping only the
/// dominant cluster produces a valid split only when the dropped fragments are
/// someone else's code — typically a small member function the compiler emitted
/// as a local instantiation inside this unit in one version but not the other.
/// Nothing here can tell that apart from a genuinely missing piece of this
/// unit's own code; that is what the build gate is for, and a wrong guess costs
/// one cheap, reversible build.
///
/// Returns `None` only when every section was entirely misaligned, leaving no
/// valid range to pick at all.
pub fn dominant_cluster(raw_lines: &[String]) -> Option<Vec<String>> {
    struct Candidate {
        start: u32,
        end: u32,
        line: String,
        misaligned: bool,
    }

    let mut per_section: IndexMap<String, Vec<Candidate>> = IndexMap::new();
    for raw_line in raw_lines {
        let cleaned = clean_entry_line(raw_line);
        if let Some(range) = parse_range(&cleaned) {
            per_section.entry(range.section).or_default().push(Candidate {
                start: range.start,
                end: range.end,
                line: cleaned,
                misaligned: raw_line.contains(ALIGNMENT_REASON),
            });
        }
    }

    let mut kept = Vec::new();
    for (section, ranges) in per_section {
        if !matches!(section.as_str(), ".text" | ".init") {
            kept.extend(
                ranges.into_iter().filter(|range| !range.misaligned).map(|range| range.line),
            );
            continue;
        }
        if ranges.len() == 1 {
            // Not fragmented, but still do not forward a misaligned single range
            // just because it sits alongside a fragmented section in the same
            // unit — it is the same hard failure.
            if !ranges[0].misaligned {
                kept.push(ranges.into_iter().next().unwrap().line);
            }
            continue;
        }
        let largest = ranges
            .into_iter()
            .filter(|range| !range.misaligned)
            .max_by_key(|range| range.end.saturating_sub(range.start));
        if let Some(largest) = largest {
            kept.push(largest.line);
        }
    }
    (!kept.is_empty()).then_some(kept)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "Sections:\n\
                        \t.text type:code\n\
                        \n\
                        Alpha.cpp:\n\
                        \t.text       start:0x80003100 end:0x80003200\n\
                        \n\
                        Beta.cpp:\n\
                        \t.text       start:0x80003000 end:0x80003100\n\
                        \t.data       start:0x80400000 end:0x80400010\n";

    #[test]
    fn a_file_round_trips_unchanged() {
        let splits = Splits::parse(FILE).unwrap();
        assert_eq!(splits.render(), FILE);
    }

    #[test]
    fn units_keep_the_order_the_file_listed_them_in() {
        // Not address order: Beta owns the lower range but is written second.
        let splits = Splits::parse(FILE).unwrap();
        assert_eq!(splits.blocks.keys().collect::<Vec<_>>(), ["Alpha.cpp", "Beta.cpp"]);
    }

    #[test]
    fn a_proposal_line_is_uncommented_and_stripped_of_its_reason() {
        let proposal = "# banner\n\n\
                        Gamma.cpp:\n\
                        #\t.text       start:0x80005000 end:0x80005100  # candidate: thin evidence\n";
        let splits = Splits::parse(proposal).unwrap();
        assert_eq!(splits.blocks["Gamma.cpp"], ["\t.text       start:0x80005000 end:0x80005100"]);
    }

    #[test]
    fn raw_lines_keep_the_reason_the_cleaned_ones_drop() {
        let proposal = "# banner\n\n\
                        Gamma.cpp:\n\
                        #\t.text       start:0x80005000 end:0x80005100  # candidate: thin evidence\n";
        let raw = raw_proposal_lines(proposal);
        assert!(raw["Gamma.cpp"][0].contains("thin evidence"));
    }

    #[test]
    fn a_unit_listed_twice_is_rejected_rather_than_silently_merged() {
        let text = format!("{FILE}\nAlpha.cpp:\n\t.bss        start:0x80500000 end:0x80500004\n");
        assert!(Splits::parse(&text).unwrap_err().to_string().contains("more than once"));
    }

    #[test]
    fn a_new_unit_lands_before_the_first_unit_that_starts_after_it() {
        let mut splits = Splits::parse(FILE).unwrap();
        splits.blocks.insert("Delta.cpp".to_string(), vec![
            "\t.text       start:0x80003080 end:0x800030c0".to_string(),
        ]);
        splits.place_new_units(&["Delta.cpp".to_string()]).unwrap();
        // Alpha starts at 0x80003100, so Delta (0x80003080) goes ahead of it —
        // and behind Beta, which the file lists after Alpha but which starts
        // lower still.
        assert_eq!(splits.blocks.keys().collect::<Vec<_>>(), [
            "Delta.cpp",
            "Alpha.cpp",
            "Beta.cpp"
        ]);
    }

    #[test]
    fn a_data_only_unit_goes_last_because_nothing_places_it() {
        let mut splits = Splits::parse(FILE).unwrap();
        splits.blocks.insert("Data.cpp".to_string(), vec![
            "\t.data       start:0x80400010 end:0x80400020".to_string(),
        ]);
        splits.place_new_units(&["Data.cpp".to_string()]).unwrap();
        assert_eq!(splits.blocks.keys().last().unwrap(), "Data.cpp");
    }

    #[test]
    fn placing_a_unit_with_no_block_is_an_error() {
        let mut splits = Splits::parse(FILE).unwrap();
        assert!(splits.place_new_units(&["Nope.cpp".to_string()]).is_err());
    }

    #[test]
    fn two_ranges_in_one_section_are_fragmented() {
        let lines = vec![
            "\t.text       start:0x80003000 end:0x80003100".to_string(),
            "\t.text       start:0x80003200 end:0x80003300".to_string(),
        ];
        assert!(is_fragmented(&lines));
    }

    #[test]
    fn one_range_per_section_is_not_fragmented() {
        let lines = vec![
            "\t.text       start:0x80003000 end:0x80003100".to_string(),
            "\t.data       start:0x80400000 end:0x80400010".to_string(),
        ];
        assert!(!is_fragmented(&lines));
    }

    #[test]
    fn ordinary_and_common_bss_ranges_are_not_a_fragmented_code_unit() {
        let raw = vec![
            "#\t.bss        start:0x804025F0 end:0x804026E0".to_string(),
            "#\t.bss        start:0x80468C00 end:0x80468C50 align:4 common".to_string(),
        ];
        let clean: Vec<_> = raw.iter().map(|line| clean_entry_line(line)).collect();
        assert!(!is_fragmented(&clean));
        assert_eq!(dominant_cluster(&raw), Some(clean));
    }

    #[test]
    fn the_dominant_cluster_is_the_largest_aligned_range_in_each_section() {
        let raw = vec![
            "#\t.text       start:0x80003000 end:0x80003100".to_string(),
            "#\t.text       start:0x80003200 end:0x80003400".to_string(),
            "#\t.data       start:0x80400000 end:0x80400010".to_string(),
        ];
        let kept = dominant_cluster(&raw).unwrap();
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().any(|line| line.contains("0x80003200")));
        assert!(kept.iter().any(|line| line.contains(".data")));
    }

    #[test]
    fn a_misaligned_range_never_wins_even_when_it_is_the_largest() {
        let raw = vec![
            "#\t.text       start:0x80003000 end:0x80003100".to_string(),
            format!(
                "#\t.text       start:0x80003200 end:0x80003400  # candidate: {ALIGNMENT_REASON}"
            ),
        ];
        let kept = dominant_cluster(&raw).unwrap();
        assert_eq!(kept.len(), 1);
        assert!(kept[0].contains("0x80003000"));
    }

    #[test]
    fn a_section_whose_every_range_is_misaligned_contributes_nothing() {
        let raw = vec![
            format!(
                "#\t.text       start:0x80003000 end:0x80003100  # candidate: {ALIGNMENT_REASON}"
            ),
            format!(
                "#\t.text       start:0x80003200 end:0x80003400  # candidate: {ALIGNMENT_REASON}"
            ),
        ];
        assert!(dominant_cluster(&raw).is_none());
    }

    #[test]
    fn a_lone_misaligned_range_is_dropped_by_the_unconditional_filter() {
        let raw = vec![format!(
            "#\t.text       start:0x80003000 end:0x80003100  # candidate: {ALIGNMENT_REASON}"
        )];
        let clean: Vec<String> = raw.iter().map(|line| clean_entry_line(line)).collect();
        assert!(drop_misaligned_sections(&clean, &raw).is_empty());
    }

    #[test]
    fn an_unflagged_range_survives_the_filter() {
        let raw = vec!["#\t.text       start:0x80003000 end:0x80003100".to_string()];
        let clean: Vec<String> = raw.iter().map(|line| clean_entry_line(line)).collect();
        assert_eq!(drop_misaligned_sections(&clean, &raw), clean);
    }
}
