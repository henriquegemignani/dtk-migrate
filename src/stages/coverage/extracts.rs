//! Adding asset extraction entries to a version's `config.yml`.
//!
//! When a boundary sequence identifies data symbols that the source version
//! extracts as assets — a font, a ROM image, a texture — the target needs the
//! same entries or its build cannot produce the files the source includes.
//!
//! The file is a hand-maintained configuration, so this appends lines rather
//! than reserialising YAML: a round-trip through a YAML library would reorder
//! keys, drop comments, and rewrite quoting across a file nobody asked us to
//! touch. Only the `extract:` block is edited, and only by adding to it.

use std::collections::BTreeSet;

use anyhow::{Result, bail};
use regex::Regex;

use crate::analysis::coverage::RequiredExtract;

/// Rejects an output path that could escape the build directory.
///
/// These come from the source version's configuration and end up as filesystem
/// paths under `build/<version>/`, so a `..` in one would write outside it.
pub fn check_path(value: &str) -> Result<()> {
    let bad = value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.split('/').any(|part| part == "." || part == ".." || part.contains(':'));
    if bad {
        bail!("Unsafe required extract path: {value:?}");
    }
    Ok(())
}

fn yaml_value(text: &str) -> String {
    // JSON string syntax is valid YAML and quotes anything that needs it.
    serde_json::to_string(text).unwrap_or_else(|_| format!("{text:?}"))
}

/// Finds the `extract:` block, as a half-open line range.
fn extract_block(lines: &[String]) -> Option<(usize, usize)> {
    let header = Regex::new(r"^extract:\s*(?:#.*)?$").unwrap();
    let key = Regex::new(r"^[A-Za-z_][^:]*:").unwrap();
    let start =
        lines.iter().position(|line| header.is_match(line.trim_end_matches(['\r', '\n'])))?;
    let mut end = start + 1;
    while end < lines.len() {
        let line = lines[end].trim_end_matches(['\r', '\n']);
        if !line.trim().is_empty() && !line.trim_start().starts_with('#') && key.is_match(line) {
            break;
        }
        end += 1;
    }
    Some((start, end))
}

/// The symbols the block already extracts.
fn configured_symbols(lines: &[String], start: usize, end: usize) -> BTreeSet<String> {
    let entry = Regex::new(r"^\s*-\s+symbol:\s*(.*?)\s*$").unwrap();
    lines[start + 1..end]
        .iter()
        .filter_map(|line| {
            let captures = entry.captures(line.trim_end_matches(['\r', '\n']))?;
            let raw = captures.get(1)?.as_str();
            // Quoted or bare, possibly with a trailing comment.
            Some(match serde_json::from_str::<String>(raw) {
                Ok(value) => value,
                Err(_) => raw
                    .split(" #")
                    .next()
                    .unwrap_or(raw)
                    .trim()
                    .trim_matches(['\'', '"'])
                    .to_string(),
            })
        })
        .collect()
}

/// Adds every extract the target does not already have, preserving all other
/// bytes of the file.
pub fn render(original: &str, extracts: &[RequiredExtract]) -> Result<String> {
    if extracts.is_empty() {
        return Ok(original.to_string());
    }
    let newline = if original.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines: Vec<String> = split_keeping_ends(original);

    let (block, created) = match extract_block(&lines) {
        Some(block) => (block, false),
        None => {
            // A new block goes before `modules:`, which must stay last for the
            // module entries to keep their position.
            let modules = Regex::new(r"^modules:\s*").unwrap();
            let insert = lines
                .iter()
                .position(|line| modules.is_match(line.trim_end_matches(['\r', '\n'])))
                .unwrap_or(lines.len());
            lines.insert(insert, format!("extract:{newline}"));
            ((insert, insert + 1), true)
        }
    };
    let (start, end) = block;

    let mut configured = configured_symbols(&lines, start, end);
    let mut pending: Vec<&RequiredExtract> = Vec::new();
    for extract in extracts {
        if extract.target_symbol.is_empty() {
            bail!("Required extract has no target symbol");
        }
        for path in [&extract.binary, &extract.header, &extract.relocations].into_iter().flatten() {
            check_path(path)?;
        }
        if configured.insert(extract.target_symbol.clone()) {
            pending.push(extract);
        }
    }
    if pending.is_empty() {
        return Ok(original.to_string());
    }

    // Match whatever indentation the existing entries use.
    let list_entry = Regex::new(r"^(\s*)-\s+").unwrap();
    let indent = lines[start + 1..end]
        .iter()
        .find_map(|line| Some(list_entry.captures(line)?.get(1)?.as_str().to_string()))
        .unwrap_or_default();

    let mut rendered: Vec<String> = Vec::new();
    for extract in pending {
        rendered.push(format!("{indent}- symbol: {}{newline}", yaml_value(&extract.target_symbol)));
        for (field, value) in [
            ("rename", &extract.rename),
            ("binary", &extract.binary),
            ("header", &extract.header),
            ("relocations", &extract.relocations),
            ("header_type", &extract.header_type),
            ("custom_type", &extract.custom_type),
        ] {
            if let Some(value) = value {
                rendered.push(format!("{indent}  {field}: {}{newline}", yaml_value(value)));
            }
        }
        if let Some(custom) = &extract.custom_data {
            let text = serde_json::to_string(custom)?;
            rendered.push(format!("{indent}  custom_data: {text}{newline}"));
        }
    }
    // A block we created needs a blank line before whatever followed it.
    if created && end < lines.len() && !lines[end].trim().is_empty() {
        rendered.push(newline.to_string());
    }

    // Insert before the block's trailing blank lines rather than after them.
    let mut insert = end;
    while insert > start + 1 && lines[insert - 1].trim().is_empty() {
        insert -= 1;
    }
    if insert > 0 && !lines[insert - 1].ends_with('\n') && !lines[insert - 1].ends_with('\r') {
        let fixed = format!("{}{newline}", lines[insert - 1]);
        lines[insert - 1] = fixed;
    }
    lines.splice(insert..insert, rendered);
    Ok(lines.concat())
}

fn split_keeping_ends(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for character in text.chars() {
        current.push(character);
        if character == '\n' {
            lines.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(symbol: &str) -> RequiredExtract {
        RequiredExtract {
            source_symbol: "sSource".into(),
            target_symbol: symbol.into(),
            target_address: "0x80400000".into(),
            target_size: 64,
            rename: Some("sRenamed".into()),
            binary: Some("Assets/Thing.bin".into()),
            header: Some("Assets/Thing.inc".into()),
            relocations: None,
            header_type: None,
            custom_type: None,
            custom_data: None,
            reference_evidence: 3,
            evidence: "boundary-sequence-data-reference".into(),
        }
    }

    const CONFIG: &str = "object: sys/main.dol\n\
                          splits: config/PAL/splits.txt\n\
                          \n\
                          extract:\n\
                          - symbol: sExisting\n  \
                            binary: Existing.bin\n\
                          \n\
                          modules:\n\
                          - object: files/Rel.rel\n";

    #[test]
    fn a_new_extract_joins_the_existing_block() {
        let out = render(CONFIG, &[extract("sNew")]).unwrap();
        assert!(out.contains("- symbol: \"sNew\""), "{out}");
        assert!(out.contains("  rename: \"sRenamed\""), "{out}");
        assert!(out.contains("- symbol: sExisting"), "the existing entry is untouched");
        // The new entry goes inside the block, before the blank line.
        let new = out.find("sNew").unwrap();
        let modules = out.find("modules:").unwrap();
        assert!(new < modules, "{out}");
    }

    #[test]
    fn an_already_configured_symbol_is_not_added_again() {
        let mut already = extract("sExisting");
        already.rename = None;
        assert_eq!(render(CONFIG, &[already]).unwrap(), CONFIG);
    }

    #[test]
    fn nothing_to_add_leaves_the_file_byte_for_byte() {
        assert_eq!(render(CONFIG, &[]).unwrap(), CONFIG);
    }

    #[test]
    fn a_file_with_no_extract_block_gains_one_before_modules() {
        let config = "object: sys/main.dol\n\nmodules:\n- object: files/Rel.rel\n";
        let out = render(config, &[extract("sNew")]).unwrap();
        let block = out.find("extract:").unwrap();
        let modules = out.find("modules:").unwrap();
        assert!(block < modules, "{out}");
        assert!(out.contains("- symbol: \"sNew\""), "{out}");
    }

    #[test]
    fn a_file_with_no_modules_gains_the_block_at_the_end() {
        let config = "object: sys/main.dol\n";
        let out = render(config, &[extract("sNew")]).unwrap();
        assert!(out.starts_with("object: sys/main.dol\n"), "{out}");
        assert!(out.contains("extract:"), "{out}");
    }

    #[test]
    fn crlf_input_keeps_crlf() {
        let config = CONFIG.replace('\n', "\r\n");
        let out = render(&config, &[extract("sNew")]).unwrap();
        assert!(out.contains("- symbol: \"sNew\"\r\n"), "{out:?}");
    }

    #[test]
    fn an_escaping_output_path_is_refused() {
        for bad in ["../outside.bin", "/absolute.bin", "a\\b.bin", "", "./a.bin", "C:/x.bin"] {
            assert!(check_path(bad).is_err(), "{bad} should be refused");
        }
        assert!(check_path("Assets/Thing.bin").is_ok());
    }

    #[test]
    fn an_extract_with_an_escaping_path_stops_the_whole_render() {
        let mut bad = extract("sNew");
        bad.binary = Some("../escape.bin".into());
        assert!(render(CONFIG, &[bad]).is_err());
    }

    #[test]
    fn the_existing_indentation_style_is_matched() {
        let config = "extract:\n  - symbol: sExisting\n\nmodules:\n";
        let out = render(config, &[extract("sNew")]).unwrap();
        assert!(out.contains("  - symbol: \"sNew\""), "{out}");
    }
}
