//! The cascade: accepting one unit's range is what makes the next unit's
//! evidence exist.
//!
//! This is the behaviour the coverage stage was rebuilt around, and it cannot be
//! seen from either end alone. A unit test can show that `build` produces an
//! alternative from evidence; a run against a real project shows a number
//! changing. Neither shows that accepting A is what *caused* B to become
//! eligible, that B's freshly generated proposal survives worker integration and
//! publication, or that A can then be extended again without losing what it
//! already owned.
//!
//! The evidence is injected rather than derived, because deriving it needs two
//! analysable binaries and nothing else here does. Everything the stage decides
//! — the trials, the ownership gates, batching, publication, resume — is the
//! real thing.
//!
//! Built in steps, each of which must hold before the next means anything:
//!
//! 1. The injected evidence offers exactly `A.cpp` and nothing else.
//! 2. Once `A.cpp` holds a block, it offers `B.cpp`.
//! 3. Once both hold blocks, it offers `A.cpp` again, extended.
//!
//! Only then is it worth running the coordinator over it, since a cascade test
//! that silently proposes nothing looks exactly like one that works.
//!
//! # The coordinator run
//!
//! The rest of the file drives the real pipeline over that evidence in a
//! miniature dtk-template project: preparation, worker batches in their own
//! workspaces, integration, rediscovery between rounds, publication, and resume.
//! The fixture is not the `pipeline.rs` one, which only ever exercises `verify`.
//! What coverage additionally needs:
//!
//! * `config/{NTSC,PAL}/config.yml` declaring **both** `splits` and `symbols`,
//!   since `config::find` requires both, and both `splits.txt` files:
//!   `audit::load_blocks` and `stunted_splits` read them during preparation.
//! * A Ninja graph in which `ninja -t inputs build/PAL/main.elf` lists
//!   `build/PAL/obj/<stem>.o`. The existing fixture links `src/` or `orig/`
//!   objects, so `validate_extracted_inputs` finds nothing to check — this is a
//!   different graph, not an adjustment to that one.
//! * An `objdiff.json` whose `target_path` is the **linked extracted** object
//!   and whose `base_path` is the **unlinked compiled-source** object. Pointing
//!   both at the extracted input would fail coverage validation, correctly:
//!   the stage's whole claim is that the candidate is still linked from its
//!   extracted original rather than from source.
//! * `DTK_MIGRATE_EVIDENCE_DIR` holding `0.json`, `1.json`, `2.json` — the three
//!   worlds above, serialized from [`evidence_for`]. A run using it records a
//!   digest of the directory in its frozen environment, so a resume cannot
//!   quietly mix injected evidence with real.

use std::{collections::BTreeMap, path::PathBuf, process::Command};

use dtk_migrate::{
    analysis::{
        coverage::CoverageReport,
        coverage_fixture::{anchor, report, unit, withheld},
    },
    project::splits::Splits,
    stages::coverage::alternatives,
};
use indexmap::IndexMap;

/// Where each unit's code sits in the fixture's target, and what the evidence
/// says about it at each stage of the cascade.
///
/// `A.cpp` owns 0x1000..0x1200 in the end, but its evidence arrives in two
/// instalments: the first half is matched immediately, the second only once
/// `B.cpp` beside it has a boundary to be bounded by.
const A_FIRST: (u32, u32) = (0x8000_1000, 0x8000_1100);
const A_REST: (u32, u32) = (0x8000_1100, 0x8000_1200);
const B_RANGE: (u32, u32) = (0x8000_1200, 0x8000_1300);

type Blocks = IndexMap<String, Vec<String>>;

fn line(section: &str, start: u32, end: u32) -> String {
    format!("\t{section:11} start:0x{start:08X} end:0x{end:08X}")
}

fn blocks(entries: &[(&str, u32, u32)]) -> Blocks {
    let mut map: Blocks = IndexMap::new();
    for (name, start, end) in entries {
        map.entry((*name).to_string()).or_default().push(line(".text", *start, *end));
    }
    map
}

/// The evidence the fixture's provider hands over when the target's splits name
/// `named` units.
///
/// This is the whole of the cascade's logic, and it is deliberately blunt: the
/// point is not that the rule is clever but that the evidence *changes* when
/// ownership does, which is what the coordinator has to notice.
///
/// Both units and all three anchors are in every report, at the same sizes
/// throughout. What a round changes is only whether an anchor qualifies. That
/// distinction is the point: the source is a fixed body of code being
/// progressively explained, so a summary reporting more source in round two
/// than round one would be reporting a bug. If the units appeared as their
/// evidence did, every such bug would look like correct behaviour here.
fn evidence_for(named: usize) -> CoverageReport {
    let a_one = anchor("A_one", A_FIRST.0, A_FIRST.1);
    let a_two = anchor("A_two", A_REST.0, A_REST.1);
    let b_one = anchor("B_one", B_RANGE.0, B_RANGE.1);
    let units = match named {
        // Nothing owns anything yet, so nothing else has a boundary to be
        // bounded by: only A.cpp's first half is placeable.
        0 => vec![
            unit("A.cpp", vec![a_one, withheld(a_two, "no following boundary")]),
            unit("B.cpp", vec![withheld(b_one, "no preceding boundary")]),
        ],
        // A.cpp has landed, which is what gives B.cpp its lower bound.
        1 => vec![
            unit("A.cpp", vec![a_one, withheld(a_two, "no following boundary")]),
            unit("B.cpp", vec![b_one]),
        ],
        // Both hold blocks, so A.cpp's tail is bounded on both sides at last.
        _ => vec![unit("A.cpp", vec![a_one, a_two]), unit("B.cpp", vec![b_one])],
    };
    report("NTSC", "PAL", units)
}

/// Every unit the policy would offer a candidate for, given what is owned.
fn offered(named: usize, owned: &Blocks) -> BTreeMap<String, Vec<String>> {
    let evidence = evidence_for(named);
    let by_name: BTreeMap<String, &dtk_migrate::analysis::coverage::CoverageUnit> =
        evidence.source_units.iter().map(|u| (u.name.clone(), u)).collect();
    evidence
        .source_units
        .iter()
        .filter_map(|source| {
            let found = alternatives::build(source, owned, &by_name, &IndexMap::new());
            found.first().map(|first| (source.name.clone(), first.lines.clone()))
        })
        .collect()
}

#[test]
fn before_anything_lands_only_a_is_offered() {
    let found = offered(0, &IndexMap::new());
    assert_eq!(found.keys().collect::<Vec<_>>(), ["A.cpp"], "{found:#?}");
    assert_eq!(found["A.cpp"], [line(".text", A_FIRST.0, A_FIRST.1)]);
}

#[test]
fn accepting_a_is_what_makes_b_eligible() {
    let owned = blocks(&[("A.cpp", A_FIRST.0, A_FIRST.1)]);
    // The same world, but with A.cpp's block in it.
    let before = offered(0, &IndexMap::new());
    let after = offered(1, &owned);

    assert!(!before.contains_key("B.cpp"), "B.cpp had no evidence before A.cpp landed");
    assert_eq!(after.keys().collect::<Vec<_>>(), ["B.cpp"], "{after:#?}");
    assert_eq!(after["B.cpp"], [line(".text", B_RANGE.0, B_RANGE.1)]);
    // And A.cpp is not offered again for ground it already holds.
    assert!(!after.contains_key("A.cpp"));
}

#[test]
fn accepting_b_is_what_lets_a_be_extended() {
    let owned = blocks(&[("A.cpp", A_FIRST.0, A_FIRST.1), ("B.cpp", B_RANGE.0, B_RANGE.1)]);
    let found = offered(2, &owned);

    assert_eq!(found.keys().collect::<Vec<_>>(), ["A.cpp"], "{found:#?}");
    // One enlarged range, not the tail alone: the body an alternative writes
    // replaces the block, so a tail-only body would drop the half A.cpp has.
    assert_eq!(found["A.cpp"], [line(".text", A_FIRST.0, A_REST.1)]);
}

#[test]
fn the_cascade_settles_once_everything_is_owned() {
    // The end state: nothing further is offered, so a coordinator looping on
    // rediscovery has a reason to stop that is not the round limit.
    let owned = blocks(&[("A.cpp", A_FIRST.0, A_REST.1), ("B.cpp", B_RANGE.0, B_RANGE.1)]);
    assert!(offered(2, &owned).is_empty());
}

// ---------------------------------------------------------------------------
// The project fixture the coordinator runs against.
// ---------------------------------------------------------------------------

/// The fixture's build script.
///
/// `object` writes a stand-in object file. `link` reproduces retail exactly —
/// this stage's gate is ownership, not bytes, so nothing here should ever make
/// the DOL differ — and appends to a log, which is how a test can tell a
/// workspace that rebuilt from one that was reused.
const BUILD: &str = r#"import json, os, sys
from pathlib import Path

if sys.argv[1] == "object":
    output = Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(b"fixture object")
    raise SystemExit(0)

# Stands in for a machine dying partway through a run. By the time integration
# builds, every worker has written its result, so failing only here leaves
# exactly the state a resume has to pick up from.
if os.environ.get("DTK_MIGRATE_FIXTURE_ABORT") and "integration" in Path.cwd().parts:
    sys.exit("fixture: interrupted during integration")

out = Path("build/PAL")
out.mkdir(parents=True, exist_ok=True)
(out / "main.dol").write_bytes(Path("orig/PAL/sys/main.dol").read_bytes())
(out / "main.elf").write_bytes(b"fixture elf")
(out / "ok").write_text("ok")
report = {
    "measures": {"matched_code": 512, "total_code": 768, "complete_code": 0},
    "units": [
        {
            "name": name,
            # Never complete: coverage keeps candidate source objects disabled,
            # and refuses a candidate whose unit says otherwise.
            "metadata": {"source_path": "src/" + name, "complete": False},
            "measures": {"matched_code": 256},
            "sections": [{"name": ".text", "fuzzy_match_percent": 100}],
        }
        for name in ("A.cpp", "B.cpp")
    ],
}
(out / "report.json").write_text(json.dumps(report))
with (out / "fixture-builds.log").open("a") as stream:
    stream.write("link\n")
"#;

/// The fixture's `configure.py`.
///
/// The graph is the point. `main.elf` links `build/PAL/obj/*.o`, the objects
/// split out of the shipped binary, and the compiled-source objects under
/// `build/PAL/src/` are declared but linked by nothing — which is the shape
/// `validate_extracted_inputs` exists to check, and the shape the `pipeline.rs`
/// fixture does not have.
const CONFIGURE: &str = r#"import argparse, json, sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("mode", nargs="?", default="configure")
parser.add_argument("-v", "--version", required=True)
for flag in ("--dtk", "--ninja", "--compilers", "--objdiff", "--sjiswrap", "--binutils"):
    parser.add_argument(flag)
args = parser.parse_args()

OBJECTS = ["A.cpp", "B.cpp"]

python = sys.executable.replace("$", "$$")
configure_args = " ".join(sys.argv[1:])
lines = [
    f"configure_args = {configure_args}",
    f'python = "{python}"',
    "",
    "rule split",
    "  command = dtk dol split $in $out_dir",
    "rule configure",
    "  command = $python configure.py $configure_args",
    "  generator = 1",
    "rule object",
    f'  command = "{python}" fixture_build.py object $out',
    "rule link",
    f'  command = "{python}" fixture_build.py link',
    "",
]
linked = []
for name in OBJECTS:
    stem = Path(name).stem
    lines.append(f"build build/PAL/obj/{stem}.o: object orig/PAL/sys/main.dol")
    linked.append(f"build/PAL/obj/{stem}.o")
    lines.append(f"build build/PAL/src/{stem}.o: object src/{name}")
outputs = "build/PAL/main.elf build/PAL/main.dol build/PAL/report.json build/PAL/ok"
lines.append(f"build {outputs}: link {' '.join(linked)}")
lines.append("build build.ninja objdiff.json: configure | configure.py")
lines.append("")
Path("build.ninja").write_text("\n".join(lines), encoding="utf-8")

Path("objdiff.json").write_text(
    json.dumps(
        {
            "units": [
                {
                    "name": name,
                    "metadata": {"source_path": "src/" + name},
                    "target_path": f"build/PAL/obj/{Path(name).stem}.o",
                    "base_path": f"build/PAL/src/{Path(name).stem}.o",
                }
                for name in OBJECTS
            ]
        }
    ),
    encoding="utf-8",
)
"#;

const SPLITS_HEADER: &str = "Sections:\n\t.text type:code align:4\n\n";

fn config_yml(version: &str) -> String {
    format!(
        "object: sys/main.dol\n\
         symbols: config/{version}/symbols.txt\n\
         splits: config/{version}/splits.txt\n"
    )
}

/// The source version's splits, at its own addresses and its own sizes.
///
/// Only `stunted_splits` reads these — the cascade's alternatives come from
/// anchors, not from the source layout — but a unit whose source counterpart is
/// missing is audited differently, so the fixture supplies both.
fn source_splits() -> String {
    format!(
        "{SPLITS_HEADER}A.cpp:\n{}\n\nB.cpp:\n{}\n",
        line(".text", 0x8000_0400, 0x8000_0600),
        line(".text", 0x8000_0600, 0x8000_0700)
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    evidence: PathBuf,
    ninja: PathBuf,
    python: PathBuf,
}

fn which(program: &str) -> Option<PathBuf> {
    let suffixes: &[&str] = if cfg!(windows) { &[".exe", ""] } else { &[""] };
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths).find_map(|directory| {
        suffixes.iter().find_map(|suffix| {
            let candidate = directory.join(format!("{program}{suffix}"));
            candidate.is_file().then_some(candidate)
        })
    })
}

/// A whole project plus the evidence directory the stage will read.
///
/// `worlds[n]` is what the matcher would say when the target's splits name `n`
/// units, which is what lets the injected evidence answer differently as the
/// run makes progress.
fn build_fixture(worlds: &[CoverageReport]) -> Option<Fixture> {
    let ninja = which("ninja")?;
    let python = which("python").or_else(|| which("python3"))?;
    let dir = tempfile::Builder::new().prefix("dtk-migrate-cascade").tempdir().ok()?;
    let root = dir.path().join("project");
    let evidence = dir.path().join("evidence");
    for sub in
        ["src", "orig/PAL/sys", "build/compilers", "build/tools", "config/NTSC", "config/PAL"]
    {
        std::fs::create_dir_all(root.join(sub)).ok()?;
    }
    std::fs::create_dir_all(&evidence).ok()?;

    std::fs::write(root.join("configure.py"), CONFIGURE).ok()?;
    std::fs::write(root.join("fixture_build.py"), BUILD).ok()?;
    for name in ["A", "B"] {
        std::fs::write(root.join(format!("src/{name}.cpp")), format!("// {name}\n")).ok()?;
    }
    std::fs::write(root.join("orig/PAL/sys/main.dol"), b"retail fixture").ok()?;
    for version in ["NTSC", "PAL"] {
        std::fs::write(root.join(format!("config/{version}/config.yml")), config_yml(version))
            .ok()?;
        std::fs::write(root.join(format!("config/{version}/symbols.txt")), "// symbols\n").ok()?;
    }
    std::fs::write(root.join("config/NTSC/splits.txt"), source_splits()).ok()?;
    // The target owns nothing yet. Everything it ends up owning, the run put
    // there. Written in exactly the form the writer renders — a file that is
    // merely equivalent would be rewritten the first time a stage saves it, and
    // a test asking whether a no-op run left the project alone would be reading
    // its own formatting back.
    std::fs::write(root.join("config/PAL/splits.txt"), format!("{}\n", SPLITS_HEADER.trim_end()))
        .ok()?;

    let suffix = if cfg!(windows) { ".exe" } else { "" };
    std::fs::write(root.join(format!("build/tools/objdiff-cli{suffix}")), b"tool").ok()?;
    std::fs::write(root.join("build/tools/sjiswrap.exe"), b"tool").ok()?;
    std::fs::write(root.join("build/compilers/fixture"), b"compiler").ok()?;
    std::fs::write(root.join(format!("build/tools/dtk{suffix}")), b"dtk").ok()?;

    for (named, world) in worlds.iter().enumerate() {
        let text = serde_json::to_string_pretty(world).ok()?;
        std::fs::write(evidence.join(format!("{named}.json")), text).ok()?;
    }
    Some(Fixture { _dir: dir, root, evidence, ninja, python })
}

impl Fixture {
    /// Starts a fresh coverage run.
    fn migrate(&self, extra: &[&str]) -> std::process::Output {
        self.invoke(
            &[
                "--source",
                "NTSC",
                "--target",
                "PAL",
                "--stages",
                "coverage",
                "--workers",
                "2",
                "--batch-size",
                "1",
            ],
            extra,
        )
    }

    fn resume(&self, id: &str) -> std::process::Output { self.invoke(&["--resume", id], &[]) }

    fn invoke(&self, args: &[&str], extra: &[&str]) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dtk-migrate"));
        command
            .arg("run")
            .arg("--project-root")
            .arg(&self.root)
            .args(args)
            .args(["--ninja", &self.ninja.display().to_string()])
            .args(["--python", &self.python.display().to_string()])
            .env("DTK_MIGRATE_EVIDENCE_DIR", &self.evidence)
            .env_remove("DTK_MIGRATE_FIXTURE_ABORT");
        for pair in extra.chunks(2) {
            command.env(pair[0], pair[1]);
        }
        command.output().expect("failed to start dtk-migrate")
    }

    fn read(&self, relative: &str) -> String {
        std::fs::read_to_string(self.root.join(relative)).unwrap_or_default()
    }

    fn json(&self, relative: &str) -> serde_json::Value {
        serde_json::from_str(&self.read(relative)).unwrap_or(serde_json::Value::Null)
    }

    fn run_id(&self) -> String {
        let base = self.root.join("build/dtk-migrate/runs");
        let mut found: Vec<String> = std::fs::read_dir(base)
            .expect("no run directory")
            .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
            .collect();
        found.sort();
        assert_eq!(found.len(), 1, "expected exactly one run: {found:?}");
        found.pop().unwrap()
    }

    /// Each worker lane's build log, which grows only when that lane builds.
    fn worker_builds(&self, id: &str) -> BTreeMap<String, String> {
        let pool = self.root.join(format!("build/dtk-migrate/runs/{id}/pool"));
        let Ok(entries) = std::fs::read_dir(&pool) else { return BTreeMap::new() };
        entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let log = entry.path().join("build/PAL/fixture-builds.log");
                Some((
                    entry.file_name().to_string_lossy().into_owned(),
                    std::fs::read_to_string(log).ok()?,
                ))
            })
            .collect()
    }

    /// The target's splits as the run left them in the owner's checkout.
    fn published_splits(&self) -> IndexMap<String, Vec<String>> {
        Splits::parse(&self.read("config/PAL/splits.txt")).expect("unparsable splits").blocks
    }
}

fn describe(output: &std::process::Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn names(candidates: &serde_json::Value) -> Vec<String> {
    candidates
        .as_array()
        .map(|all| all.iter().map(|c| c["name"].as_str().unwrap_or("?").to_string()).collect())
        .unwrap_or_default()
}

/// The three worlds of the cascade, as files.
fn cascade_worlds() -> Vec<CoverageReport> { (0..=2).map(evidence_for).collect() }

/// The same units, with nothing the policy will believe about any of them.
fn nothing_believable() -> Vec<CoverageReport> {
    let units = || {
        vec![
            unit("A.cpp", vec![
                withheld(anchor("A_one", A_FIRST.0, A_FIRST.1), "no boundary either side"),
                withheld(anchor("A_two", A_REST.0, A_REST.1), "no boundary either side"),
            ]),
            unit("B.cpp", vec![withheld(
                anchor("B_one", B_RANGE.0, B_RANGE.1),
                "no boundary either side",
            )]),
        ]
    };
    (0..=2).map(|_| report("NTSC", "PAL", units())).collect()
}

/// Evidence for a unit the project does not link from an extracted object.
///
/// The proposal is perfectly well-formed and the build succeeds; what fails is
/// the check that the range was proved about the extracted original rather than
/// about compiled source. That is a rejection the stage is supposed to make, so
/// it is the honest way to produce a run whose every candidate is refused.
fn only_an_unlinked_unit() -> Vec<CoverageReport> {
    let units = || {
        vec![
            unit("A.cpp", vec![
                withheld(anchor("A_one", A_FIRST.0, A_FIRST.1), "no boundary either side"),
                withheld(anchor("A_two", A_REST.0, A_REST.1), "no boundary either side"),
            ]),
            unit("B.cpp", vec![withheld(
                anchor("B_one", B_RANGE.0, B_RANGE.1),
                "no boundary either side",
            )]),
            unit("Unlinked.cpp", vec![anchor("U_one", 0x8000_2000, 0x8000_2100)]),
        ]
    };
    (0..=3).map(|_| report("NTSC", "PAL", units())).collect()
}

#[test]
fn the_coordinator_follows_the_cascade_it_was_never_told_about() {
    let Some(fixture) = build_fixture(&cascade_worlds()) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let output = fixture.migrate(&[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");

    // Preparation saw one candidate, because at that point one is all the
    // evidence supported.
    let prepared = fixture.json(&format!("{stage}/prepared.json"));
    assert_eq!(names(&prepared["candidates"]), ["A.cpp"], "{prepared:#}");

    // And the run finished holding two. B.cpp was never prepared, never
    // batched, and never handed to a worker: the only way it can be here is
    // that accepting A.cpp made its evidence exist.
    let result = fixture.json(&format!("{stage}/result.json"));
    let mut accepted = names(&result["accepted"]);
    accepted.sort();
    assert_eq!(accepted, ["A.cpp", "B.cpp"], "{result:#}");
    assert!(names(&result["deferred"]).is_empty(), "{result:#}");

    // Each acceptance in the order the rounds reached it: the worker's A.cpp,
    // integration re-proving it, B.cpp once A.cpp had landed, then A.cpp again
    // extended into the gap B.cpp's boundary opened up.
    let taken: Vec<String> = result["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["status"] == "accepted")
        .map(|event| event["unit"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(taken, ["A.cpp", "A.cpp", "B.cpp", "A.cpp"], "{result:#}");

    // Twice, and no more: the third look found nothing, which is why the run
    // stopped for a reason rather than on the round budget.
    let rediscovered = result["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["status"] == "rediscovered")
        .count();
    assert_eq!(rediscovered, 2, "{result:#}");
    assert!(
        !result["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["status"] == "rediscovery-limit-reached"),
        "{result:#}"
    );
}

#[test]
fn what_the_cascade_settled_on_is_what_gets_published() {
    let Some(fixture) = build_fixture(&cascade_worlds()) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let output = fixture.migrate(&[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");

    // The exact ranges, in the owner's checkout. A.cpp holds one merged range
    // rather than two fragments, because an alternative replaces a block whole.
    let published = fixture.published_splits();
    assert_eq!(published.keys().collect::<Vec<_>>(), ["A.cpp", "B.cpp"], "{published:#?}");
    assert_eq!(published["A.cpp"], [line(".text", A_FIRST.0, A_REST.1)]);
    assert_eq!(published["B.cpp"], [line(".text", B_RANGE.0, B_RANGE.1)]);

    // Two translation units gained a home, neither of them a refinement of
    // ground the project already had, and the gain is measured against where
    // the stage started rather than against the round before it.
    let summary = fixture.json(&format!("{stage}/coverage.json"));
    assert_eq!(summary["source_units"], 2);
    assert_eq!(summary["baseline_represented"], 0);
    assert_eq!(summary["final_represented"], 2);
    assert_eq!(summary["newly_supported_units"], 2);
    assert_eq!(summary["refined_units"], 0, "A.cpp was extended, but it started with nothing");
    assert_eq!(
        summary["newly_assigned_code_bytes"],
        A_REST.1 - A_FIRST.0 + (B_RANGE.1 - B_RANGE.0),
        "{summary:#}"
    );

    // The proposal and the selection have to be a pair. A.cpp was accepted
    // twice, and the id recorded has to name an alternative of the proposal
    // that is stored beside it — the extended one, not the half-range the
    // worker proved.
    let result = fixture.json(&format!("{stage}/result.json"));
    let stored = result["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["name"] == "A.cpp")
        .expect("A.cpp should be accepted");
    let chosen = result["selections"]["A.cpp"].as_str().expect("A.cpp should have a selection");
    let alternative = stored["evidence"]["alternatives"]
        .as_array()
        .unwrap()
        .iter()
        .find(|alternative| alternative["id"] == chosen)
        .unwrap_or_else(|| panic!("the stored proposal does not contain {chosen}: {result:#}"));
    let lines: Vec<&str> =
        alternative["lines"].as_array().unwrap().iter().map(|l| l.as_str().unwrap()).collect();
    assert_eq!(lines, [line(".text", A_FIRST.0, A_REST.1)]);
    assert_eq!(summary["selected"]["A.cpp"]["id"], chosen);

    let journal = fixture.json(&format!("build/dtk-migrate/runs/{id}/publication.json"));
    assert_eq!(journal["status"], "published", "{journal:#}");
    let changed: Vec<&String> = journal["changes"].as_object().unwrap().keys().collect();
    assert_eq!(changed, ["config/PAL/splits.txt"], "only the splits should have moved");
}

#[test]
fn a_run_interrupted_after_its_workers_finished_does_not_repeat_their_builds() {
    let Some(fixture) = build_fixture(&cascade_worlds()) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let interrupted = fixture.migrate(&["DTK_MIGRATE_FIXTURE_ABORT", "1"]);
    assert!(!interrupted.status.success(), "{}", describe(&interrupted));
    let id = fixture.run_id();

    // The workers got as far as proving A.cpp and writing it down.
    let job = fixture.json(&format!("build/dtk-migrate/runs/{id}/coverage/jobs/00000/result.json"));
    assert_eq!(names(&job["accepted"]), ["A.cpp"], "{job:#}");
    let before = fixture.worker_builds(&id);
    assert!(!before.is_empty(), "the workers should have built something");
    assert_eq!(fixture.published_splits().len(), 0, "nothing should have been published yet");

    let resumed = fixture.resume(&id);
    assert!(resumed.status.success(), "{}", describe(&resumed));
    assert!(
        String::from_utf8_lossy(&resumed.stderr).contains("reused from a previous run"),
        "{}",
        describe(&resumed)
    );
    assert_eq!(
        fixture.worker_builds(&id),
        before,
        "a resumed run should reuse the worker results, not rebuild them"
    );

    // And the resumed half finished the cascade the interrupted half started.
    let published = fixture.published_splits();
    assert_eq!(published["A.cpp"], [line(".text", A_FIRST.0, A_REST.1)]);
    assert_eq!(published["B.cpp"], [line(".text", B_RANGE.0, B_RANGE.1)]);
}

#[test]
fn a_stage_with_nothing_to_offer_finishes_instead_of_failing() {
    let Some(fixture) = build_fixture(&nothing_believable()) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let before = fixture.read("config/PAL/splits.txt");
    let output = fixture.migrate(&[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");

    let prepared = fixture.json(&format!("{stage}/prepared.json"));
    assert!(names(&prepared["candidates"]).is_empty(), "{prepared:#}");

    // A successful result with nothing in it, and a baseline that was measured
    // rather than assumed: the stage still built the project and recorded what
    // it found, which is what makes "no progress" a claim and not a gap.
    let result = fixture.json(&format!("{stage}/result.json"));
    assert!(names(&result["accepted"]).is_empty(), "{result:#}");
    assert!(names(&result["deferred"]).is_empty(), "{result:#}");
    assert_eq!(result["final_measures"], result["baseline"], "{result:#}");
    assert!(result["dol_sha1"].as_str().is_some_and(|hash| !hash.is_empty()), "{result:#}");
    assert_eq!(fixture.read("config/PAL/splits.txt"), before, "the project should be untouched");

    let journal = fixture.json(&format!("build/dtk-migrate/runs/{id}/publication.json"));
    assert_eq!(journal["status"], "published", "{journal:#}");
    assert!(journal["changes"].as_object().unwrap().is_empty(), "{journal:#}");
}

#[test]
fn a_stage_whose_every_candidate_is_refused_finishes_with_them_deferred() {
    let Some(fixture) = build_fixture(&only_an_unlinked_unit()) else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let before = fixture.read("config/PAL/splits.txt");
    let output = fixture.migrate(&[]);
    assert!(output.status.success(), "{}", describe(&output));
    let id = fixture.run_id();
    let stage = format!("build/dtk-migrate/runs/{id}/coverage");

    let prepared = fixture.json(&format!("{stage}/prepared.json"));
    assert_eq!(names(&prepared["candidates"]), ["Unlinked.cpp"], "{prepared:#}");

    // Refused, and deferred rather than condemned — and the run that contains
    // that refusal is a successful run.
    let result = fixture.json(&format!("{stage}/result.json"));
    assert!(names(&result["accepted"]).is_empty(), "{result:#}");
    assert_eq!(names(&result["deferred"]), ["Unlinked.cpp"], "{result:#}");
    let rejection = result["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["unit"] == "Unlinked.cpp" && event["status"] == "rejected")
        .unwrap_or_else(|| panic!("no recorded reason for the refusal: {result:#}"));
    assert!(
        rejection["reason"].as_str().unwrap().contains("source-linkage-violation"),
        "{rejection:#}"
    );
    assert_eq!(result["final_measures"], result["baseline"], "{result:#}");
    assert_eq!(fixture.read("config/PAL/splits.txt"), before, "a refusal leaves nothing behind");

    let summary = fixture.json(&format!("{stage}/coverage.json"));
    assert_eq!(summary["newly_supported_units"], 0);
    assert_eq!(summary["newly_assigned_code_bytes"], 0);
    assert_eq!(summary["dispositions"]["Unlinked.cpp"], "build-failure");
}
