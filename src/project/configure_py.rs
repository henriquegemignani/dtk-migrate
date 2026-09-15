//! Reading and rewriting the matching status of a project's `configure.py`.
//!
//! This is the one place the tool edits a file people also edit by hand, and
//! the only edit it makes is widening an object's matching status to include a
//! version whose compiled object has been shown to link and produce retail
//! bytes. Everything else in the file — comments, formatting, the order of
//! anything — comes out exactly as it went in.
//!
//! The statuses it understands are `Matching`/`True`, `MatchingFor(...)`, and
//! the flat negatives `NonMatching`/`Equivalent`/`False`. Anything else is
//! reported and left alone. `EquivalentFor(...)` is the reason that matters:
//! it means "links from source for these versions, but only in a
//! `--non-matching` build". Promoting `EquivalentFor("A", "B")` to
//! `MatchingFor("A", "B", "C")` would silently claim A and B are byte-identical
//! when they are only equivalent.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};

use crate::project::pysyntax::{
    Mask, find_identifier, matching_delimiter, skip_space, split_arguments, string_literal,
    strip_comments,
};

const BEGIN: &str = "# BEGIN AUTOMATED SOURCE VERIFICATION";
const END: &str = "# END AUTOMATED SOURCE VERIFICATION";

/// How an object's matching status is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// `Matching` or `True`: already enabled for every version.
    Universal,
    /// `MatchingFor(...)` with the versions it names.
    For(Vec<String>),
    /// `NonMatching`, `Equivalent` or `False`: enabled for no version.
    None,
    /// Something this tool will not rewrite, described for the report.
    Unrewritable(String),
}

/// One `Object(<status>, "<path>")` declaration.
#[derive(Debug, Clone)]
pub struct Declaration {
    pub name: String,
    pub status: Status,
    /// Byte range of the status expression in the normalised text.
    status_span: (usize, usize),
}

/// A legacy `BEGIN AUTOMATED SOURCE VERIFICATION` override block.
#[derive(Debug, Clone)]
pub struct LegacyBlock {
    pub version: String,
    pub names: BTreeSet<String>,
    span: (usize, usize),
}

/// A parsed `configure.py`, ready to be asked what it declares or to render a
/// variant of itself.
#[derive(Debug, Clone)]
pub struct Configure {
    /// Line endings normalised to `\n`; [`render`](Self::render) puts CRLF back.
    text: String,
    crlf: bool,
    versions: Vec<String>,
    declarations: Vec<Declaration>,
    legacy: Vec<LegacyBlock>,
}

impl Configure {
    pub fn parse(original: &str) -> Result<Self> {
        let crlf = original.contains("\r\n");
        let text = original.replace("\r\n", "\n");
        let mask = Mask::of(&text);
        let versions = parse_versions(&text, &mask)?;
        let declarations = parse_declarations(&text, &mask)?;
        let legacy = parse_legacy_blocks(&text)?;

        let mut seen = BTreeSet::new();
        for declaration in &declarations {
            if !seen.insert(declaration.name.clone()) {
                bail!("Multiple Object declarations for {}", declaration.name);
            }
        }
        Ok(Self { text, crlf, versions, declarations, legacy })
    }

    pub fn versions(&self) -> &[String] { &self.versions }

    pub fn declarations(&self) -> &[Declaration] { &self.declarations }

    pub fn legacy_blocks(&self) -> &[LegacyBlock] { &self.legacy }

    fn declaration(&self, name: &str) -> Option<&Declaration> {
        self.declarations.iter().find(|d| d.name == name)
    }

    /// Objects whose matching expression [`render`](Self::render) must not touch.
    ///
    /// A stage picks its candidates from the build report, which says nothing
    /// about how an object is declared. Without asking first it can choose one
    /// it cannot then express — a whole batch lost long after the work is done.
    pub fn unrewritable_names(&self) -> BTreeMap<String, String> {
        self.declarations
            .iter()
            .filter_map(|d| match &d.status {
                Status::Unrewritable(kind) => Some((d.name.clone(), kind.clone())),
                _ => None,
            })
            .collect()
    }

    /// Units this file already enables for `version`, so a resumed run rechecks
    /// what an earlier one migrated.
    pub fn configured_names(&self, version: &str) -> BTreeSet<String> {
        let mut names: BTreeSet<String> = self
            .declarations
            .iter()
            .filter(|d| matches!(&d.status, Status::For(versions) if versions.iter().any(|v| v == version)))
            .map(|d| d.name.clone())
            .collect();
        for block in &self.legacy {
            if block.version == version {
                names.extend(block.names.iter().cloned());
            }
        }
        names
    }

    /// Renders the file with `names` additionally enabled for `version`.
    ///
    /// Legacy override blocks are removed and folded into ordinary statuses, so
    /// a successful run migrates them. Each call renders from the unchanged
    /// input, which is what makes a failed trial disappear: the caller simply
    /// renders the accepted set again.
    pub fn render(&self, version: &str, names: &BTreeSet<String>) -> Result<String> {
        let rank: BTreeMap<&str, usize> =
            self.versions.iter().enumerate().map(|(i, v)| (v.as_str(), i)).collect();
        if !rank.contains_key(version) {
            bail!("Unknown target version: {version}");
        }

        let mut wanted: BTreeMap<String, BTreeSet<String>> = names
            .iter()
            .map(|name| (name.clone(), BTreeSet::from([version.to_string()])))
            .collect();
        let mut edits: Vec<(usize, usize, String)> = Vec::new();
        for block in &self.legacy {
            if !rank.contains_key(block.version.as_str()) {
                bail!("Unknown legacy version: {}", block.version);
            }
            for name in &block.names {
                wanted.entry(name.clone()).or_default().insert(block.version.clone());
            }
            edits.push((block.span.0, block.span.1, String::new()));
        }

        for (name, add) in &wanted {
            let Some(declaration) = self.declaration(name) else {
                bail!("Missing Object declaration: {name}");
            };
            let existing = match &declaration.status {
                // Already enabled everywhere; never narrow it to a list.
                Status::Universal => continue,
                Status::For(versions) => versions.clone(),
                Status::None => Vec::new(),
                Status::Unrewritable(kind) => {
                    bail!("Unsupported matching expression for {name}: {kind}")
                }
            };
            for value in &existing {
                if !rank.contains_key(value.as_str()) {
                    bail!("Unknown MatchingFor version in {name}: {value}");
                }
            }
            let mut values: Vec<&str> =
                existing.iter().map(String::as_str).chain(add.iter().map(String::as_str)).collect();
            values.sort_by_key(|value| rank[value]);
            values.dedup();

            let (start, end) = declaration.status_span;
            if self.text[start..end].contains('#') {
                bail!(
                    "Comments inside the matching expression for {name}; refusing to discard them"
                );
            }
            let rendered = format!(
                "MatchingFor({})",
                values.iter().map(|v| format!("{v:?}")).collect::<Vec<_>>().join(", ")
            );
            edits.push((start, end, rendered));
        }

        let mut text = self.text.clone();
        edits.sort_by_key(|(start, _, _)| std::cmp::Reverse(*start));
        for (start, end, replacement) in edits {
            text.replace_range(start..end, &replacement);
        }
        // Re-parsing is the cheapest proof that the edit produced something we
        // could read back, and it catches a span that drifted.
        Self::parse(&text).context("Rewriting configure.py produced something unparseable")?;
        Ok(if self.crlf { text.replace('\n', "\r\n") } else { text })
    }
}

fn parse_versions(text: &str, mask: &Mask) -> Result<Vec<String>> {
    let offsets: Vec<usize> = find_identifier(text, mask, "VERSIONS")
        .into_iter()
        // A top-level assignment only: `VERSIONS` mentioned inside a function
        // or an expression is a use, not the declaration.
        .filter(|&offset| offset == 0 || text.as_bytes()[offset - 1] == b'\n')
        .filter(|&offset| {
            skip_space(text, mask, offset + "VERSIONS".len())
                .is_some_and(|index| text.as_bytes()[index] == b'=')
        })
        .collect();
    let [offset] = offsets[..] else {
        bail!("Expected one top-level VERSIONS assignment in configure.py");
    };
    let equals = skip_space(text, mask, offset + "VERSIONS".len()).unwrap();
    let open = skip_space(text, mask, equals + 1)
        .filter(|&index| text.as_bytes()[index] == b'[')
        .context("VERSIONS must be assigned a literal list")?;
    let close = matching_delimiter(text, mask, open).context("Unterminated VERSIONS list")?;

    let mut versions = Vec::new();
    for (start, end) in split_arguments(text, mask, open, close) {
        let value = string_literal(text, start, end).with_context(|| {
            format!("VERSIONS entry is not a plain string: {}", &text[start..end])
        })?;
        if versions.contains(&value) {
            bail!("VERSIONS lists {value} more than once");
        }
        versions.push(value);
    }
    if versions.is_empty() {
        bail!("VERSIONS is empty");
    }
    Ok(versions)
}

fn parse_declarations(text: &str, mask: &Mask) -> Result<Vec<Declaration>> {
    let mut declarations = Vec::new();
    for offset in find_identifier(text, mask, "Object") {
        let Some(open) = skip_space(text, mask, offset + "Object".len()) else { continue };
        if text.as_bytes()[open] != b'(' {
            continue;
        }
        let Some(close) = matching_delimiter(text, mask, open) else { continue };
        let arguments = split_arguments(text, mask, open, close);
        if arguments.len() < 2 {
            continue;
        }
        let Some(name) = string_literal(text, arguments[1].0, arguments[1].1) else {
            continue;
        };
        let (start, end) = arguments[0];
        declarations.push(Declaration {
            name,
            status: parse_status(text, mask, start, end),
            status_span: (start, end),
        });
    }
    Ok(declarations)
}

fn parse_status(text: &str, mask: &Mask, start: usize, end: usize) -> Status {
    let slice = &text[start..end];
    match slice {
        "Matching" | "True" => return Status::Universal,
        "NonMatching" | "Equivalent" | "False" => return Status::None,
        _ => {}
    }
    // A call: the name up to its opening parenthesis, then positional string
    // arguments. A keyword argument means something this cannot reproduce.
    if let Some(open) = slice.find('(')
        && slice.ends_with(')')
    {
        let function = slice[..open].trim();
        if function == "MatchingFor" {
            let open = start + open;
            if let Some(close) = matching_delimiter(text, mask, open) {
                let mut versions = Vec::new();
                for (a, b) in split_arguments(text, mask, open, close) {
                    match string_literal(text, a, b) {
                        Some(value) => versions.push(value),
                        None => return Status::Unrewritable("MatchingFor".to_string()),
                    }
                }
                return Status::For(versions);
            }
        }
        return Status::Unrewritable(function.to_string());
    }
    Status::Unrewritable(slice.to_string())
}

/// Reads only the exact old override shape, so user-added logic is never
/// discarded.
fn parse_legacy_blocks(text: &str) -> Result<Vec<LegacyBlock>> {
    let starts: Vec<usize> = line_starts_with(text, BEGIN);
    let ends: Vec<usize> = line_starts_with(text, END);
    if starts.len() != ends.len() {
        bail!("Malformed legacy verification block");
    }
    let mut blocks = Vec::new();
    for (&start, &end) in starts.iter().zip(&ends) {
        if end < start {
            bail!("Malformed legacy verification block");
        }
        let mut stop = end + END.len();
        // Absorb the blank line the block was written with, so removing it does
        // not leave a hole.
        for _ in 0..2 {
            if text[stop..].starts_with('\n') {
                stop += 1;
            }
        }
        let body = &text[start + BEGIN.len()..end];
        let version = body
            .lines()
            .find_map(|line| line.trim().strip_prefix("# Version: "))
            .context("Legacy verification block does not name its version")?
            .trim()
            .to_string();
        let (names, literal) = legacy_names(body, &version)?;
        check_legacy_shape(body, &version, &literal)?;
        blocks.push(LegacyBlock { version, names, span: (start, stop) });
    }
    Ok(blocks)
}

fn line_starts_with(text: &str, marker: &str) -> Vec<usize> {
    text.match_indices(marker)
        .filter(|(index, _)| *index == 0 || text.as_bytes()[index - 1] == b'\n')
        .map(|(index, _)| index)
        .collect()
}

/// The names the block enables, and the source text of the set literal itself.
///
/// The literal's own text is what [`check_legacy_shape`] compares, so a set
/// written in a different order than we would write it still reads as unchanged.
fn legacy_names(body: &str, version: &str) -> Result<(BTreeSet<String>, String)> {
    let mask = Mask::of(body);
    let offsets = find_identifier(body, &mask, "_verified_source_units");
    let Some(&offset) = offsets.first() else {
        bail!("Unrecognized legacy verification block for {version}")
    };
    let open = skip_space(body, &mask, offset + "_verified_source_units".len())
        .filter(|&index| body.as_bytes()[index] == b'=')
        .and_then(|equals| skip_space(body, &mask, equals + 1))
        .filter(|&index| body.as_bytes()[index] == b'{')
        .with_context(|| format!("Expected literal unit names in legacy block for {version}"))?;
    let close = matching_delimiter(body, &mask, open)
        .with_context(|| format!("Unterminated unit name set in legacy block for {version}"))?;
    let names = split_arguments(body, &mask, open, close)
        .into_iter()
        .map(|(a, b)| {
            string_literal(body, a, b).with_context(|| {
                format!("Expected literal unit names in legacy block for {version}")
            })
        })
        .collect::<Result<BTreeSet<String>>>()?;
    Ok((names, body[open..=close].to_string()))
}

/// Compares the block against the exact text the old tool generated, ignoring
/// comments and blank lines.
///
/// Anything else — an extra statement, a changed condition, different loop
/// logic — means someone edited it, and it is not ours to remove.
fn check_legacy_shape(body: &str, version: &str, literal: &str) -> Result<()> {
    let expected = format!(
        "if config.version == {version:?}:\n    \
         _verified_source_units = {literal}\n    \
         for _verified_lib in config.libs:\n        \
         for _verified_obj in _verified_lib['objects']:\n            \
         if _verified_obj.name in _verified_source_units:\n                \
         _verified_obj.completed = True"
    );
    if normalize_python(body) != normalize_python(&expected) {
        bail!("Modified legacy verification block for {version}; refusing to remove it");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERSIONS: &str = "VERSIONS = [\n    \"NTSC\",  # first\n    \"PAL\",\n]\n\n";

    fn parse(objects: &str) -> Configure {
        Configure::parse(&format!("{VERSIONS}objects = [\n{objects}]\n")).unwrap()
    }

    fn render(objects: &str, names: &[&str]) -> Result<String> {
        let set = names.iter().map(|n| n.to_string()).collect();
        parse(objects).render("PAL", &set)
    }

    #[test]
    fn versions_come_from_the_top_level_list_in_order() {
        assert_eq!(parse("").versions(), ["NTSC", "PAL"]);
    }

    #[test]
    fn a_negative_status_becomes_a_single_version_list() {
        let out = render("    Object(NonMatching, \"a.cpp\"),\n", &["a.cpp"]).unwrap();
        assert!(out.contains("Object(MatchingFor(\"PAL\"), \"a.cpp\")"), "{out}");
    }

    #[test]
    fn an_existing_list_keeps_its_versions_and_gains_the_new_one_in_versions_order() {
        let out = render("    Object(MatchingFor(\"PAL\"), \"a.cpp\"),\n", &["a.cpp"]).unwrap();
        assert!(out.contains("MatchingFor(\"PAL\")"), "{out}");
        let out = render("    Object(MatchingFor(\"NTSC\"), \"a.cpp\"),\n", &["a.cpp"]).unwrap();
        // VERSIONS lists NTSC first, so it stays first regardless of input order.
        assert!(out.contains("MatchingFor(\"NTSC\", \"PAL\")"), "{out}");
    }

    #[test]
    fn an_already_universal_status_is_never_narrowed() {
        let source = "    Object(Matching, \"a.cpp\"),\n";
        let out = render(source, &["a.cpp"]).unwrap();
        assert!(out.contains("Object(Matching, \"a.cpp\")"), "{out}");
    }

    #[test]
    fn a_multi_line_declaration_is_rewritten_in_place() {
        let source = "    Object(\n        MatchingFor(\"NTSC\"), \"a.cpp\"\n    ),\n";
        let out = render(source, &["a.cpp"]).unwrap();
        assert!(out.contains("        MatchingFor(\"NTSC\", \"PAL\"), \"a.cpp\"\n"), "{out}");
    }

    #[test]
    fn untouched_objects_come_out_byte_for_byte() {
        let source = "    Object(NonMatching, \"a.cpp\"),  # keep this comment\n\
                      \x20   Object(NonMatching, \"b.cpp\"),\n";
        let out = render(source, &["b.cpp"]).unwrap();
        assert!(out.contains("Object(NonMatching, \"a.cpp\"),  # keep this comment"), "{out}");
    }

    #[test]
    fn an_equivalent_for_status_is_reported_rather_than_promoted() {
        let configure = parse("    Object(EquivalentFor(\"NTSC\"), \"a.cpp\"),\n");
        assert_eq!(
            configure.unrewritable_names().get("a.cpp").map(String::as_str),
            Some("EquivalentFor")
        );
        let set = BTreeSet::from(["a.cpp".to_string()]);
        let error = configure.render("PAL", &set).unwrap_err().to_string();
        assert!(error.contains("EquivalentFor"), "{error}");
    }

    #[test]
    fn a_declaration_inside_a_comment_is_not_a_declaration() {
        let configure = parse("    # Object(NonMatching, \"ghost.cpp\"),\n");
        assert!(configure.declarations().is_empty());
    }

    #[test]
    fn a_duplicate_declaration_is_rejected_before_any_edit() {
        let text = format!(
            "{VERSIONS}objects = [\n    Object(NonMatching, \"a.cpp\"),\n    Object(Matching, \"a.cpp\"),\n]\n"
        );
        assert!(Configure::parse(&text).unwrap_err().to_string().contains("Multiple Object"));
    }

    #[test]
    fn a_name_with_no_declaration_is_an_error() {
        let error = render("    Object(NonMatching, \"a.cpp\"),\n", &["b.cpp"]).unwrap_err();
        assert!(error.to_string().contains("Missing Object declaration"), "{error}");
    }

    #[test]
    fn an_unknown_target_version_is_an_error() {
        let configure = parse("    Object(NonMatching, \"a.cpp\"),\n");
        assert!(configure.render("JP", &BTreeSet::new()).is_err());
    }

    #[test]
    fn configured_names_reports_what_is_already_enabled_for_the_target() {
        let configure = parse(
            "    Object(MatchingFor(\"NTSC\", \"PAL\"), \"a.cpp\"),\n\
             \x20   Object(MatchingFor(\"NTSC\"), \"b.cpp\"),\n",
        );
        assert_eq!(configure.configured_names("PAL"), BTreeSet::from(["a.cpp".to_string()]));
    }

    #[test]
    fn crlf_input_produces_crlf_output() {
        let text = format!("{VERSIONS}objects = [\n    Object(NonMatching, \"a.cpp\"),\n]\n")
            .replace('\n', "\r\n");
        let configure = Configure::parse(&text).unwrap();
        let out = configure.render("PAL", &BTreeSet::from(["a.cpp".to_string()])).unwrap();
        assert!(out.contains("\r\n"));
        assert!(!out.contains("\n\n"), "no bare newlines should survive");
    }

    const LEGACY_BODY: &str = "# Version: PAL\n\
                               if config.version == \"PAL\":\n    \
                               _verified_source_units = {\"a.cpp\", \"b.cpp\"}\n    \
                               for _verified_lib in config.libs:\n        \
                               for _verified_obj in _verified_lib['objects']:\n            \
                               if _verified_obj.name in _verified_source_units:\n                \
                               _verified_obj.completed = True\n";

    fn with_legacy(body: &str) -> String {
        format!(
            "{VERSIONS}objects = [\n    Object(NonMatching, \"a.cpp\"),\n    Object(NonMatching, \"b.cpp\"),\n]\n\n{BEGIN}\n{body}{END}\n"
        )
    }

    #[test]
    fn a_legacy_block_is_read_as_the_units_it_enables() {
        let configure = Configure::parse(&with_legacy(LEGACY_BODY)).unwrap();
        assert_eq!(configure.legacy_blocks().len(), 1);
        assert_eq!(configure.configured_names("PAL").len(), 2);
    }

    #[test]
    fn rendering_migrates_a_legacy_block_into_ordinary_statuses() {
        let configure = Configure::parse(&with_legacy(LEGACY_BODY)).unwrap();
        let out = configure.render("PAL", &BTreeSet::new()).unwrap();
        assert!(!out.contains(BEGIN), "{out}");
        assert!(out.contains("Object(MatchingFor(\"PAL\"), \"a.cpp\")"), "{out}");
        assert!(out.contains("Object(MatchingFor(\"PAL\"), \"b.cpp\")"), "{out}");
    }

    #[test]
    fn an_edited_legacy_block_is_refused_rather_than_removed() {
        let edited = LEGACY_BODY.replace("_verified_obj.completed = True", "pass");
        let error = Configure::parse(&with_legacy(&edited)).unwrap_err().to_string();
        assert!(error.contains("Modified legacy verification block"), "{error}");
    }

    #[test]
    fn comments_and_blank_lines_inside_a_legacy_block_are_tolerated() {
        let annotated =
            LEGACY_BODY.replace("if config.version", "# added by hand\n\nif config.version");
        assert!(Configure::parse(&with_legacy(&annotated)).is_ok());
    }

    #[test]
    fn an_unclosed_legacy_block_is_malformed() {
        let text = format!("{VERSIONS}objects = []\n\n{BEGIN}\n{LEGACY_BODY}");
        assert!(Configure::parse(&text).unwrap_err().to_string().contains("Malformed"));
    }
}

/// Drops comments, blank lines and trailing whitespace, and normalises string
/// quoting, so formatting differences do not read as edits.
fn normalize_python(text: &str) -> String {
    strip_comments(text)
        .split('\n')
        // Quote style is not meaning; a literal written with either quote is
        // the same value.
        .map(|line| line.replace('\'', "\"").trim_end().to_string())
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}
