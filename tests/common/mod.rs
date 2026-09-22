//! A miniature dtk-template project the coverage coordinator can run against.
//!
//! Shared by the suites that drive the real pipeline over injected evidence:
//! preparation, worker batches in their own workspaces, integration,
//! rediscovery between rounds, publication, and resume. What the project
//! needs, beyond what `pipeline.rs` provides:
//!
//! * `config/{NTSC,PAL}/config.yml` declaring **both** `splits` and `symbols`,
//!   since `config::find` requires both, and both `splits.txt` files:
//!   `audit::load_blocks` and `stunted_splits` read them during preparation.
//! * A Ninja graph in which `ninja -t inputs build/PAL/main.elf` lists
//!   `build/PAL/obj/<stem>.o` for every unit — the linked, *extracted* object.
//! * An `objdiff.json` whose `target_path` is that extracted object and whose
//!   `base_path` is the **unlinked compiled-source** object. Pointing both at
//!   the extracted input would fail coverage validation, correctly: the
//!   stage's whole claim is that a unit is still linked from its extracted
//!   original rather than from source.
//! * `DTK_MIGRATE_EVIDENCE_DIR` holding `<n>.json`: what the matcher would say
//!   when the target's splits name `n` units. A run using it records a digest
//!   of the directory in its frozen environment, so a resume cannot quietly
//!   mix injected evidence with real.
//!
//! The unit list lives in `fixture_units.json`, which both scripts read, so a
//! suite can choose which objects the project links.

#![allow(dead_code)]

use std::{collections::BTreeMap, path::PathBuf, process::Command};

use dtk_migrate::{
    analysis::coverage::CoverageReport, matching::data_evidence::DataEvidenceReport,
    project::splits::Splits,
};
use indexmap::IndexMap;

pub type Blocks = IndexMap<String, Vec<String>>;

pub fn line(section: &str, start: u32, end: u32) -> String {
    format!("\t{section:11} start:0x{start:08X} end:0x{end:08X}")
}

/// The fixture's build script.
///
/// `object` writes a stand-in object file. `link` reproduces retail exactly —
/// coverage's gate is ownership, not bytes, so nothing here should ever make
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
if os.environ.get("DTK_MIGRATE_FIXTURE_ABORT_DISCOVER") and "discover" in Path.cwd().parts:
    sys.exit("fixture: interrupted before discovery")

# Lets coordinator tests make two worker-proved ownership changes fail only
# when combined. Each name is a split block header. This models a linker
# interaction the candidate footprints did not predict.
rejected = [name for name in os.environ.get("DTK_MIGRATE_FIXTURE_REJECT_COMBINATION", "").split(",") if name]
workspace = Path(os.environ.get("DTK_MIGRATE_WORKSPACE_ROOT", ""))
if rejected and workspace.name == "integration":
    splits = Path("config/PAL/splits.txt").read_text()
    if all(("\n" + name + ":\n") in ("\n" + splits) for name in rejected):
        sys.exit("fixture: rejected combined ownership")

units = json.loads(Path("fixture_units.json").read_text())
source_linked = set(json.loads(Path("build/PAL/fixture_linked.json").read_text()))
rejected_source = set(filter(None, os.environ.get("DTK_MIGRATE_FIXTURE_REJECT_SOURCE", "").split(",")))
if source_linked & rejected_source:
    sys.exit("fixture: rejected source " + ",".join(sorted(source_linked & rejected_source)))
out = Path("build/PAL")
out.mkdir(parents=True, exist_ok=True)
(out / "main.dol").write_bytes(Path("orig/PAL/sys/main.dol").read_bytes())
(out / "main.elf").write_bytes(b"fixture elf")
(out / "ok").write_text("ok")
report = {
    "measures": {"matched_code": 256 * len(units), "total_code": 768,
                 "complete_code": 256 * len(source_linked)},
    "units": [
        {
            "name": name,
            "metadata": {"source_path": "src/" + name,
                         "complete": name in source_linked},
            "measures": {"matched_code": 256},
            "sections": [{"name": ".text", "fuzzy_match_percent": 100}],
        }
        for name in units
    ],
}
(out / "report.json").write_text(json.dumps(report))
with (out / "fixture-builds.log").open("a") as stream:
    stream.write("link\n")
"#;

/// The fixture's `configure.py`, with `__OBJECTS__` standing for the unit
/// declarations.
///
/// Declared in the shape the verification stage's rewriter understands, so a
/// multi-stage run can prepare verification too. The graph is the point.
/// `main.elf` links extracted objects until verification enables a source
/// object. Both object rules exist throughout so the link-input checks can
/// distinguish the two modes.
const CONFIGURE: &str = r#"import argparse, json, sys
from pathlib import Path

VERSIONS = [
    "NTSC",
    "PAL",
]

parser = argparse.ArgumentParser()
parser.add_argument("mode", nargs="?", default="configure")
parser.add_argument("-v", "--version", required=True)
for flag in ("--dtk", "--ninja", "--compilers", "--objdiff", "--sjiswrap", "--binutils"):
    parser.add_argument(flag)
args = parser.parse_args()

Matching = True
NonMatching = False
def MatchingFor(*versions):
    return args.version in versions
def Object(status, name):
    return (name, status)

objects = [
__OBJECTS__]

OBJECTS = [name for name, _ in objects]

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
source_linked = []
for name, status in objects:
    stem = Path(name).stem
    lines.append(f"build build/PAL/obj/{stem}.o: object orig/PAL/sys/main.dol")
    lines.append(f"build build/PAL/src/{stem}.o: object src/{name}")
    linked.append(f"build/PAL/{'src' if status else 'obj'}/{stem}.o")
    if status:
        source_linked.append(name)
Path("build/PAL").mkdir(parents=True, exist_ok=True)
Path("build/PAL/fixture_linked.json").write_text(json.dumps(source_linked))
outputs = "build/PAL/main.elf build/PAL/main.dol build/PAL/report.json build/PAL/ok"
splits_stamp = Path("build/PAL/fixture_splits.stamp")
splits_stamp.write_text(Path("config/PAL/splits.txt").read_text())
lines.append(f"build {outputs}: link {' '.join(linked)} | build/PAL/fixture_splits.stamp")
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

pub const SPLITS_HEADER: &str = "Sections:\n\t.text type:code align:4\n\n";

fn config_yml(version: &str) -> String {
    format!(
        "object: sys/main.dol\n\
         symbols: config/{version}/symbols.txt\n\
         splits: config/{version}/splits.txt\n"
    )
}

/// Renders split blocks exactly as the stage's writer would, so a run that
/// changes nothing leaves the file byte-identical.
pub fn render(blocks: &Blocks) -> String {
    Splits { header: SPLITS_HEADER.to_string(), blocks: blocks.clone() }.render()
}

/// What a fixture project contains.
pub struct Layout {
    /// Units the project links from extracted objects.
    pub units: Vec<String>,
    /// The source version's `splits.txt`, verbatim.
    pub source_splits: String,
    /// The target's `splits.txt` before the run, verbatim.
    pub target_splits: String,
    /// `worlds[n]` is what the matcher says when the target names `n` units.
    /// `None` leaves that world absent.
    pub worlds: Vec<Option<CoverageReport>>,
    /// Typed discovery evidence for a coverage → data → verify fixture.
    pub discover: Option<DiscoverEvidence>,
}

pub struct DiscoverEvidence {
    pub proposals: String,
    pub data: DataEvidenceReport,
}

pub struct Fixture {
    _dir: tempfile::TempDir,
    pub root: PathBuf,
    pub evidence: PathBuf,
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

/// A whole project plus the evidence directory the stage will read, or `None`
/// when `ninja` or `python` is not available.
pub fn build(layout: &Layout) -> Option<Fixture> {
    let ninja = which("ninja")?;
    let python = which("python").or_else(|| which("python3"))?;
    let dir = tempfile::Builder::new().prefix("dtk-migrate-fixture").tempdir().ok()?;
    let root = dir.path().join("project");
    let evidence = dir.path().join("evidence");
    for sub in
        ["src", "orig/PAL/sys", "build/compilers", "build/tools", "config/NTSC", "config/PAL"]
    {
        std::fs::create_dir_all(root.join(sub)).ok()?;
    }
    std::fs::create_dir_all(&evidence).ok()?;

    let objects: String =
        layout.units.iter().map(|name| format!("    Object(NonMatching, \"{name}\"),\n")).collect();
    std::fs::write(root.join("configure.py"), CONFIGURE.replace("__OBJECTS__", &objects)).ok()?;
    std::fs::write(root.join("fixture_build.py"), BUILD).ok()?;
    std::fs::write(root.join("fixture_units.json"), serde_json::to_string(&layout.units).ok()?)
        .ok()?;
    for name in &layout.units {
        std::fs::write(root.join(format!("src/{name}")), format!("// {name}\n")).ok()?;
    }
    std::fs::write(root.join("orig/PAL/sys/main.dol"), b"retail fixture").ok()?;
    for version in ["NTSC", "PAL"] {
        std::fs::write(root.join(format!("config/{version}/config.yml")), config_yml(version))
            .ok()?;
        std::fs::write(root.join(format!("config/{version}/symbols.txt")), "// symbols\n").ok()?;
    }
    std::fs::write(root.join("config/NTSC/splits.txt"), &layout.source_splits).ok()?;
    std::fs::write(root.join("config/PAL/splits.txt"), &layout.target_splits).ok()?;

    let suffix = if cfg!(windows) { ".exe" } else { "" };
    std::fs::write(root.join(format!("build/tools/objdiff-cli{suffix}")), b"tool").ok()?;
    std::fs::write(root.join("build/tools/sjiswrap.exe"), b"tool").ok()?;
    std::fs::write(root.join("build/compilers/fixture"), b"compiler").ok()?;
    std::fs::write(root.join(format!("build/tools/dtk{suffix}")), b"dtk").ok()?;

    for (named, world) in layout.worlds.iter().enumerate() {
        let Some(world) = world else { continue };
        let text = serde_json::to_string_pretty(world).ok()?;
        std::fs::write(evidence.join(format!("{named}.json")), text).ok()?;
    }
    if let Some(discover) = &layout.discover {
        std::fs::write(evidence.join("discover-proposals.txt"), &discover.proposals).ok()?;
        std::fs::write(
            evidence.join("discover-data-evidence.json"),
            serde_json::to_string_pretty(&discover.data).ok()?,
        )
        .ok()?;
        std::fs::write(evidence.join("discover-renames.txt"), "").ok()?;
    }
    Some(Fixture { _dir: dir, root, evidence, ninja, python })
}

impl Fixture {
    /// Starts a fresh coverage run.
    pub fn migrate(&self, extra_args: &[&str], env: &[&str]) -> std::process::Output {
        self.migrate_with_settings("2", "1", extra_args, env)
    }

    pub fn migrate_with_settings(
        &self,
        workers: &str,
        batch_size: &str,
        extra_args: &[&str],
        env: &[&str],
    ) -> std::process::Output {
        self.migrate_stages_with_settings("coverage", workers, batch_size, extra_args, env)
    }

    pub fn migrate_stages_with_settings(
        &self,
        stages: &str,
        workers: &str,
        batch_size: &str,
        extra_args: &[&str],
        env: &[&str],
    ) -> std::process::Output {
        let mut args = vec![
            "--source",
            "NTSC",
            "--target",
            "PAL",
            "--stages",
            stages,
            "--workers",
            workers,
            "--batch-size",
            batch_size,
        ];
        args.extend_from_slice(extra_args);
        self.invoke(&args, env)
    }

    pub fn resume(&self, id: &str) -> std::process::Output { self.invoke(&["--resume", id], &[]) }

    fn invoke(&self, args: &[&str], env: &[&str]) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dtk-migrate"));
        command
            .arg("run")
            .arg("--project-root")
            .arg(&self.root)
            .args(args)
            .args(["--ninja", &self.ninja.display().to_string()])
            .args(["--python", &self.python.display().to_string()])
            .env("DTK_MIGRATE_EVIDENCE_DIR", &self.evidence)
            // Suites assert INFO-level reuse messages. Keep ambient developer
            // logging preferences from changing the test's contract.
            .env("RUST_LOG", "info")
            .env_remove("DTK_MIGRATE_FIXTURE_ABORT");
        for pair in env.chunks(2) {
            command.env(pair[0], pair[1]);
        }
        command.output().expect("failed to start dtk-migrate")
    }

    pub fn read(&self, relative: &str) -> String {
        std::fs::read_to_string(self.root.join(relative)).unwrap_or_default()
    }

    pub fn json(&self, relative: &str) -> serde_json::Value {
        serde_json::from_str(&self.read(relative)).unwrap_or(serde_json::Value::Null)
    }

    pub fn run_id(&self) -> String {
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
    pub fn worker_builds(&self, id: &str) -> BTreeMap<String, String> {
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
    pub fn published_splits(&self) -> Blocks {
        Splits::parse(&self.read("config/PAL/splits.txt")).expect("unparsable splits").blocks
    }
}

pub fn describe(output: &std::process::Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

pub fn names(candidates: &serde_json::Value) -> Vec<String> {
    candidates
        .as_array()
        .map(|all| all.iter().map(|c| c["name"].as_str().unwrap_or("?").to_string()).collect())
        .unwrap_or_default()
}
