use std::collections::BTreeSet;

use anyhow::{Result, anyhow};
use decomp_toolkit::{util::file::buf_writer, vfs::open_file};
use typed_path::Utf8NativePath;

/// One unit's block in a splits file: its header line's name, and the raw
/// body lines exactly as written (so re-emitting an untouched block changes
/// nothing in the diff).
#[derive(Debug, Clone)]
struct Block {
    name: String,
    lines: Vec<String>,
    /// The lowest `start:` address among the block's lines, for ordering.
    /// `None` for a block with no address at all, which sorts first.
    min_start: Option<u32>,
}

/// What merging a proposal file into a splits file did.
#[derive(Debug, Default)]
pub struct MergeReport {
    pub added: Vec<String>,
    /// A proposed unit that already has a block in the target file. Left
    /// alone rather than overwritten or duplicated; reconciling it is a
    /// human decision.
    pub already_present: Vec<String>,
}

/// Merges the confident entries from a `dtk match --splits` proposal file
/// into an existing splits file, in address order, or reports what it would
/// add when `dry_run` is set.
///
/// The proposal file's own `#`-commented candidate lines are never applied —
/// only whole units with at least one uncommented line are considered, and
/// only when nothing already covers that unit's name.
pub fn merge_splits(
    splits_path: &Utf8NativePath,
    proposal_path: &Utf8NativePath,
    dry_run: bool,
) -> Result<MergeReport> {
    let existing_text = read_utf8(splits_path)?;
    let proposal_text = read_utf8(proposal_path)?;

    let eol = if existing_text.contains("\r\n") { "\r\n" } else { "\n" };
    let (header, mut blocks) = parse_splits(&existing_text)?;
    let existing_names: BTreeSet<String> = blocks.iter().map(|b| b.name.clone()).collect();

    let proposed = parse_confident_blocks(&proposal_text);

    let mut report = MergeReport::default();
    for block in proposed {
        if existing_names.contains(block.name.as_str()) {
            report.already_present.push(block.name);
            continue;
        }
        report.added.push(block.name.clone());
        blocks.push(block);
    }

    if report.added.is_empty() {
        return Ok(report);
    }
    blocks.sort_by_key(|b| b.min_start.unwrap_or(0));

    if !dry_run {
        let mut out = String::new();
        // header uses bare `\n` from parsing the normalized text; match the file's actual eol.
        out.push_str(&header.replace('\n', eol));
        for block in &blocks {
            out.push_str(&block.name);
            out.push(':');
            out.push_str(eol);
            for line in &block.lines {
                out.push_str(line);
                out.push_str(eol);
            }
            out.push_str(eol);
        }
        // A single trailing blank line, not two.
        while out.ends_with(&format!("{eol}{eol}")) {
            out.truncate(out.len() - eol.len());
        }

        let mut file = buf_writer(splits_path)?;
        std::io::Write::write_all(&mut file, out.as_bytes())?;
        std::io::Write::flush(&mut file)?;
    }
    Ok(report)
}

fn read_utf8(path: &Utf8NativePath) -> Result<String> {
    let mut file = open_file(path, true)?;
    let data = file.map()?;
    Ok(std::str::from_utf8(data)
        .map_err(|e| anyhow!("{path} is not valid UTF-8: {e}"))?
        .to_string())
}

/// Splits a splits file into its `Sections:` header (kept verbatim, including
/// its trailing blank line) and the unit blocks that follow.
fn parse_splits(text: &str) -> Result<(String, Vec<Block>)> {
    let normalized = text.replace("\r\n", "\n");
    let mut lines = normalized.split('\n').peekable();

    let mut header = String::new();
    let Some(first) = lines.next() else {
        return Err(anyhow!("Empty splits file"));
    };
    if first.trim() != "Sections:" {
        return Err(anyhow!("Expected a 'Sections:' header, got '{first}'"));
    }
    header.push_str(first);
    header.push('\n');
    for line in lines.by_ref() {
        header.push_str(line);
        header.push('\n');
        if line.trim().is_empty() {
            break;
        }
    }

    let blocks = parse_blocks(lines);
    Ok((header, blocks))
}

/// Parses unit blocks from an iterator of lines, stopping at each blank line.
/// A block left with no lines at all (every line in it was filtered out
/// upstream) is dropped rather than emitted empty.
fn parse_blocks<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;

    let flush = |current: &mut Option<(String, Vec<String>)>, blocks: &mut Vec<Block>| {
        if let Some((name, body_lines)) = current.take() {
            if !body_lines.is_empty() {
                let min_start = body_lines.iter().filter_map(|l| start_address(l)).min();
                blocks.push(Block { name, lines: body_lines, min_start });
            }
        }
    };

    for line in lines {
        if line.trim().is_empty() {
            flush(&mut current, &mut blocks);
            continue;
        }
        let is_header = !line.starts_with(['\t', ' ']) && line.trim_end().ends_with(':');
        if is_header {
            flush(&mut current, &mut blocks);
            current = Some((line.trim_end().trim_end_matches(':').to_string(), Vec::new()));
            continue;
        }
        if let Some((_, body)) = current.as_mut() {
            body.push(line.to_string());
        }
    }
    flush(&mut current, &mut blocks);
    blocks
}

/// Parses only the units a proposal file left uncommented: every `#`-prefixed
/// line — the banner, and every candidate line `write_unit_proposals`
/// commented out — is dropped before block boundaries are even found.
fn parse_confident_blocks(text: &str) -> Vec<Block> {
    let normalized = text.replace("\r\n", "\n");
    let lines = normalized.split('\n').filter(|l| !l.starts_with('#'));
    parse_blocks(lines)
}

fn start_address(line: &str) -> Option<u32> {
    let idx = line.find("start:0x")?;
    let rest = &line[idx + "start:0x".len()..];
    let hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    u32::from_str_radix(&hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_confident_only_unit() {
        let text = "\
CPlayer:
\t.text       start:0x80003100 end:0x80003354
#\t.text       start:0x80003354 end:0x800033A8  # candidate: reason
";
        let blocks = parse_confident_blocks(text);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].name, "CPlayer");
        assert_eq!(blocks[0].lines.len(), 1);
        assert_eq!(blocks[0].min_start, Some(0x80003100));
    }

    #[test]
    fn a_fully_candidate_unit_is_dropped() {
        let text = "\
CPlayer:
#\t.text       start:0x80003100 end:0x80003354  # candidate: reason
";
        assert!(parse_confident_blocks(text).is_empty());
    }

    #[test]
    fn parses_the_sections_header_verbatim() {
        let text = "\
Sections:
\t.text       type:code align:32

CPlayer:
\t.text       start:0x80003100 end:0x80003354
";
        let (header, blocks) = parse_splits(text).unwrap();
        assert_eq!(header, "Sections:\n\t.text       type:code align:32\n\n");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].name, "CPlayer");
    }

    #[test]
    fn start_address_reads_the_first_hex_run() {
        assert_eq!(start_address("\t.text start:0x80003100 end:0x80003354"), Some(0x8000_3100));
        assert_eq!(start_address("\t.text end:0x80003354"), None);
    }
}
