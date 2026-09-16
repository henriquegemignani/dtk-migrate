use std::{
    collections::{BTreeMap, btree_map},
    io::Write,
};

use anyhow::{Context, Result, anyhow, bail};
use decomp_toolkit::{util::file::buf_writer, vfs::open_file};
use typed_path::Utf8NativePath;

/// One rename's destination: the new name, and whether it should carry
/// `scope:local`.
///
/// Copied straight from the source symbol per match rather than inferred at
/// the target: which duplicate of a repeated template instantiation stays
/// global isn't consistent between binaries, so NTSC and PAL can disagree
/// on the same function.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RenameTarget {
    name: String,
    local: bool,
}

/// A set of `target_name = source_name` pairs, as written by `dtk match`.
///
/// Anything from a `#` onward is a comment. That makes the candidates file a
/// valid rename file too: its entries carry a trailing `# tier confidence
/// method` note and its rejected alternatives are already commented out, so a
/// reviewer can delete the lines they don't want and apply what's left.
#[derive(Debug, Default)]
pub struct Renames {
    /// Keyed by the name to replace, since that's what a symbols file is
    /// scanned by.
    entries: BTreeMap<String, RenameTarget>,
}

impl Renames {
    #[allow(clippy::len_without_is_empty)] // callers only ever report the count
    pub fn len(&self) -> usize { self.entries.len() }

    /// Adds one pair, refusing only what would corrupt the set.
    ///
    /// Two entries assigning the same target name are allowed: local template
    /// instantiations repeat a mangled name across translation units, so a set
    /// derived from a one-to-one function matching reproduces the source's own
    /// duplicates. An actual collision between two live symbols is caught in
    /// [`apply_renames`] instead, where the target's existing names are
    /// visible.
    ///
    /// `origin` names the source of the pair for error messages.
    fn insert(&mut self, from: &str, to: &str, local: bool, origin: &str) -> Result<()> {
        match self.entries.entry(from.to_string()) {
            btree_map::Entry::Vacant(e) => {
                e.insert(RenameTarget { name: to.to_string(), local });
            }
            btree_map::Entry::Occupied(e) => {
                bail!("{origin}: '{from}' is renamed twice, to '{}' and '{to}'.", e.get().name)
            }
        }
        Ok(())
    }

    /// Builds a set from pairs already decided in memory.
    ///
    /// Used by symbol derivation, which produces its renames rather than
    /// reading them back from a file it just wrote.
    pub fn from_pairs<'a>(pairs: impl IntoIterator<Item = (&'a String, &'a String)>) -> Self {
        let mut renames = Self::default();
        for (from, to) in pairs {
            renames.entries.insert(from.clone(), RenameTarget { name: to.clone(), local: false });
        }
        renames
    }

    /// Parses `target = source` pairs, one per line, as written by `dtk
    /// match`. Anything from a `#` onward is a comment. A source name may be
    /// followed by the bare word `local` to carry `scope:local` onto the
    /// target when applied.
    pub fn parse(text: &str) -> Result<Self> {
        let mut renames = Self::default();
        for (number, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let (from, to) = line
                .split_once('=')
                .map(|(from, to)| (from.trim(), to.trim()))
                .filter(|(from, to)| !from.is_empty() && !to.is_empty())
                .with_context(|| {
                    format!("Line {}: expected `old_name = new_name`, got '{line}'", number + 1)
                })?;
            let mut words = to.split_whitespace();
            // `to` is non-empty, so a first word always exists.
            let to_name = words.next().unwrap();
            let local = match words.next() {
                None => false,
                Some("local") if words.next().is_none() => true,
                Some(other) => bail!(
                    "Line {}: expected 'local' or nothing after '{to_name}', got '{other}'",
                    number + 1
                ),
            };
            renames.insert(from, to_name, local, &format!("Line {}", number + 1))?;
        }
        Ok(renames)
    }

    pub fn read(path: &Utf8NativePath) -> Result<Self> {
        let mut file = open_file(path, true)?;
        let data = file.map()?;
        let text = std::str::from_utf8(data)
            .map_err(|e| anyhow!("Rename file is not valid UTF-8: {e}"))?;
        Self::parse(text).with_context(|| format!("While reading {path}"))
    }
}

/// What applying a rename set did, and what it declined to do.
#[derive(Debug, Default)]
pub struct RenameReport {
    pub applied: usize,
    /// Names in the rename set that the symbols file doesn't contain.
    pub missing: Vec<String>,
    /// Renames skipped because the new name is already taken by a symbol that
    /// isn't itself being renamed away.
    pub collisions: Vec<(String, String)>,
}

/// Rewrites symbol names in a symbols file, or reports what it would rewrite
/// when `dry_run` is set.
///
/// Operates on lines rather than parsing and regenerating the file, so
/// addresses, attributes, ordering and formatting all survive untouched and the
/// resulting diff shows only the names that changed.
pub fn apply_renames(
    path: &Utf8NativePath,
    renames: &Renames,
    dry_run: bool,
) -> Result<RenameReport> {
    let (rendered, report) = render_renames(&read_symbols(path)?, renames);
    if report.applied > 0 && !dry_run {
        let mut file = buf_writer(path)?;
        file.write_all(rendered.as_bytes())?;
        file.flush()?;
    }
    Ok(report)
}

/// Reads a symbols file as text.
pub fn read_symbols(path: &Utf8NativePath) -> Result<String> {
    let mut file = open_file(path, true)?;
    let data = file.map()?;
    Ok(std::str::from_utf8(data)
        .map_err(|e| anyhow!("Symbols file is not valid UTF-8: {e}"))?
        .to_string())
}

/// Renames without touching the filesystem, for a caller that owns the write.
///
/// A migration trial has to be able to put the file back exactly as it was, so
/// it writes through its own transaction rather than letting this do it.
pub fn render_renames(text: &str, renames: &Renames) -> (String, RenameReport) {
    let text = text.to_string();

    // A name is only free if nothing keeps it. Symbols being renamed away are
    // releasing theirs, so they don't block anyone.
    let mut taken: BTreeMap<&str, ()> = BTreeMap::new();
    for line in text.lines() {
        if let Some(name) = symbol_name(line) {
            if !renames.entries.contains_key(name) {
                taken.insert(name, ());
            }
        }
    }

    let mut report = RenameReport::default();
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    let mut out = String::with_capacity(text.len());

    // Split rather than `lines()` so the original trailing newline (or its
    // absence) is preserved, along with any CRLF, which rides on each line.
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            out.push('\n');
        }
        let Some(name) = symbol_name(line) else {
            out.push_str(line);
            continue;
        };
        let Some(target) = renames.entries.get(name) else {
            out.push_str(line);
            continue;
        };
        // A local rename is exactly the case that's supposed to coexist with
        // whatever else already holds the name: that's what marked it local
        // in the first place. Only a global rename actually collides.
        if !target.local && taken.contains_key(target.name.as_str()) {
            report.collisions.push((name.to_string(), target.name.clone()));
            out.push_str(line);
            continue;
        }
        seen.insert(name, ());
        out.push_str(&target.name);
        let rest = &line[name.len()..];
        if target.local {
            out.push_str(&ensure_scope_local(rest));
        } else {
            out.push_str(rest);
        }
        report.applied += 1;
    }

    report.missing = renames
        .entries
        .keys()
        .filter(|name| !seen.contains_key(name.as_str()))
        .filter(|name| !report.collisions.iter().any(|(from, _)| from == *name))
        .cloned()
        .collect();

    (out, report)
}

/// Adds `scope:local` to a symbol line's attributes, unless it already
/// declares a scope explicitly — a human-authored scope is left alone rather
/// than second-guessed. `rest` is everything from the `=` onward, i.e.
/// ` = .text:0x80000000; // type:function size:0x28`, possibly with a
/// trailing `\r`.
fn ensure_scope_local(rest: &str) -> String {
    if rest.contains("scope:") {
        return rest.to_string();
    }
    let (body, crlf) = match rest.strip_suffix('\r') {
        Some(body) => (body, "\r"),
        None => (rest, ""),
    };
    if body.contains("//") {
        format!("{body} scope:local{crlf}")
    } else {
        format!("{body} // scope:local{crlf}")
    }
}

/// The symbol name a symbols-file line declares, if it declares one.
///
/// Lines look like `name = .section:0x80000000; // attrs`.
fn symbol_name(line: &str) -> Option<&str> {
    let name = line.split_once('=')?.0.trim_end();
    // Preserve leading whitespace by requiring the name to start the line;
    // symbols files don't indent, and anything that does isn't a symbol.
    (!name.is_empty() && !name.starts_with([' ', '\t', '#', '/'])).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_pairs() {
        let renames = Renames::parse("fn_8000 = Foo\nfn_8004 = Bar\n").unwrap();
        assert_eq!(renames.len(), 2);
        assert_eq!(renames.entries["fn_8000"].name, "Foo");
        assert!(!renames.entries["fn_8000"].local);
    }

    #[test]
    fn parses_a_local_marker() {
        let renames = Renames::parse("fn_8000 = Foo local\n").unwrap();
        assert_eq!(renames.entries["fn_8000"].name, "Foo");
        assert!(renames.entries["fn_8000"].local);
    }

    #[test]
    fn rejects_trailing_text_that_isnt_local() {
        assert!(Renames::parse("fn_8000 = Foo bogus\n").is_err());
        assert!(Renames::parse("fn_8000 = Foo local extra\n").is_err());
    }

    #[test]
    fn accepts_a_candidates_file_verbatim() {
        // The candidates file's metadata is a trailing comment and its rejected
        // alternatives are whole-line comments, so it parses as a rename set.
        let renames = Renames::parse(
            "# Candidate names: a -> b\n\
             \n\
             fn_80179620 = RenderMotionBlur__17CPlasmaProjectileCFv  # probable 0.86 call-site\n\
             #       alt = FromEnum__12CPASAnimParmFi  # alternative, 20% as strong\n",
        )
        .unwrap();
        assert_eq!(renames.len(), 1);
        assert_eq!(renames.entries["fn_80179620"].name, "RenderMotionBlur__17CPlasmaProjectileCFv");
    }

    #[test]
    fn allows_two_functions_to_share_a_name() {
        // Local template instantiations repeat across translation units, so a
        // rename set derived from a real binary contains these legitimately.
        let renames = Renames::parse("fn_8000 = Foo\nfn_8004 = Foo\n").unwrap();
        assert_eq!(renames.len(), 2);
        assert_eq!(renames.entries["fn_8000"].name, "Foo");
        assert_eq!(renames.entries["fn_8004"].name, "Foo");
    }

    #[test]
    fn rejects_one_function_renamed_twice() {
        let err = Renames::parse("fn_8000 = Foo\nfn_8000 = Bar\n").unwrap_err();
        assert!(err.to_string().contains("renamed twice"), "{err}");
    }

    #[test]
    fn rejects_a_malformed_line() {
        assert!(Renames::parse("this is not a pair\n").is_err());
        assert!(Renames::parse("fn_8000 =\n").is_err());
    }

    #[test]
    fn ensure_scope_local_adds_the_attribute_once() {
        assert_eq!(
            ensure_scope_local(" = .text:0x80000000; // type:function size:0x28"),
            " = .text:0x80000000; // type:function size:0x28 scope:local"
        );
        // No existing comment to extend: add one.
        assert_eq!(
            ensure_scope_local(" = .text:0x80000000;"),
            " = .text:0x80000000; // scope:local"
        );
    }

    #[test]
    fn ensure_scope_local_leaves_an_explicit_scope_alone() {
        let line = " = .text:0x80000000; // type:function scope:global";
        assert_eq!(ensure_scope_local(line), line);
    }

    #[test]
    fn ensure_scope_local_preserves_a_trailing_cr() {
        assert_eq!(
            ensure_scope_local(" = .text:0x80000000; // type:function\r"),
            " = .text:0x80000000; // type:function scope:local\r"
        );
    }

    #[test]
    fn reads_symbol_names_but_not_comments() {
        assert_eq!(
            symbol_name("__start = .init:0x80003140; // type:function size:0x138"),
            Some("__start")
        );
        assert_eq!(symbol_name("@100 = .text:0x80004000;"), Some("@100"));
        assert_eq!(symbol_name("// a comment = with an equals"), None);
        assert_eq!(symbol_name("  indented = 1"), None);
        assert_eq!(symbol_name(""), None);
    }
}
