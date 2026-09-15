//! Checks the project readers against a real decompilation project rather than
//! a fixture.
//!
//! A hand-written `configure.py` is a thousand declarations of a shape nobody
//! wrote down, and `splits.txt` files run to tens of thousands of lines. The
//! fixtures in the unit tests cover the shapes we know about; this covers the
//! ones we do not.
//!
//! Point `DTK_MIGRATE_TEST_PROJECT` at a dtk-template checkout to run these.
//! Without it they pass trivially, since there is nothing to read.

use std::{collections::BTreeSet, path::PathBuf};

use dtk_migrate::project::{config, configure_py::Configure, splits::Splits};

fn project() -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os("DTK_MIGRATE_TEST_PROJECT")?);
    path.join("configure.py").is_file().then_some(path)
}

macro_rules! project_or_skip {
    () => {
        match project() {
            Some(path) => path,
            None => {
                eprintln!("skipped: set DTK_MIGRATE_TEST_PROJECT to a dtk-template checkout");
                return;
            }
        }
    };
}

#[test]
fn a_real_configure_script_parses_and_declares_every_object_once() {
    let root = project_or_skip!();
    let text = std::fs::read_to_string(root.join("configure.py")).unwrap();
    let configure = Configure::parse(&text).expect("configure.py should parse");

    assert!(configure.versions().len() >= 2, "a migration needs at least two versions");
    let declarations = configure.declarations();
    assert!(declarations.len() > 100, "found only {} declarations", declarations.len());

    // Parse's own duplicate check already ran; this states the expectation.
    let names: BTreeSet<&str> = declarations.iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names.len(), declarations.len());
}

#[test]
fn rewriting_a_real_configure_script_changes_only_the_named_object() {
    let root = project_or_skip!();
    let text = std::fs::read_to_string(root.join("configure.py")).unwrap();
    let configure = Configure::parse(&text).unwrap();
    let target = configure.versions().last().unwrap().clone();

    // Any object this tool could actually promote: rewritable, and not already
    // enabled for the target.
    let blocked = configure.unrewritable_names();
    let already = configure.configured_names(&target);
    let Some(name) = configure
        .declarations()
        .iter()
        .map(|d| d.name.clone())
        .find(|name| !blocked.contains_key(name) && !already.contains(name))
    else {
        return; // Every object is already enabled; nothing to prove here.
    };

    let rendered = configure.render(&target, &BTreeSet::from([name.clone()])).unwrap();
    let before: Vec<&str> = text.lines().collect();
    let after: Vec<&str> = rendered.lines().collect();
    assert_eq!(before.len(), after.len(), "rewriting must not add or remove lines");
    let changed: Vec<usize> =
        (0..before.len()).filter(|&index| before[index] != after[index]).collect();
    assert_eq!(changed.len(), 1, "expected exactly one changed line, got {changed:?}");
    assert!(after[changed[0]].contains(&target), "{}", after[changed[0]]);

    // And the result still parses, with that one object now enabled.
    let reparsed = Configure::parse(&rendered).unwrap();
    assert!(reparsed.configured_names(&target).contains(&name));
}

#[test]
fn every_version_splits_file_round_trips_unchanged() {
    let root = project_or_skip!();
    let versions = root.join("config");
    let (mut checked, mut units) = (0, 0);
    for entry in std::fs::read_dir(&versions).unwrap() {
        let entry = entry.unwrap();
        if !entry.path().is_dir() {
            continue;
        }
        let version = entry.file_name().to_string_lossy().into_owned();
        for module in config::modules(&root, &version).unwrap() {
            if !module.splits.is_file() {
                continue;
            }
            let text = std::fs::read_to_string(&module.splits).unwrap();
            let splits = Splits::parse(&text)
                .unwrap_or_else(|e| panic!("{}: {e:?}", module.splits.display()));
            assert_eq!(
                splits.render(),
                text.replace("\r\n", "\n"),
                "{} did not round-trip",
                module.splits.display()
            );
            // A module nobody has started splitting has a Sections header and
            // no units at all, which is a legitimate file, not an empty one.
            units += splits.blocks.len();
            checked += 1;
        }
    }
    assert!(checked > 0, "no splits files found under {}", versions.display());
    assert!(units > 0, "every splits file was header-only");
}
