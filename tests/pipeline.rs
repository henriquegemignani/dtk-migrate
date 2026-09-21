//! End-to-end exercise of the whole pipeline against a fixture project.
//!
//! The fixture is a real dtk-template-shaped project in miniature: a
//! `configure.py` that generates a real `build.ninja`, a fake compiler and
//! linker, and a retail file to compare against. Real Ninja runs it and the
//! real binary drives it, so this covers the parts unit tests cannot — the
//! build-graph patch surviving regeneration, worker lanes in separate
//! workspaces, bisection deciding between two candidates, publication writing
//! the owner's `configure.py`, and resume doing nothing to an already-published
//! run.
//!
//! The one thing the fixture fakes is the compiler: `B.cpp` is declared to
//! produce a binary that is not retail, which is how a candidate gets rejected
//! without needing a real toolchain.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

/// The fixture's build script. Its link step writes a DOL that only equals
/// retail when `B.cpp` is *not* enabled, and appends a line to a log so a test
/// can count builds.
const BUILD: &str = r#"import json, sys
from pathlib import Path

if sys.argv[1] == "object":
    output = Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(b"compiled fixture")
elif sys.argv[1] == "link":
    enabled = {"A.cpp": sys.argv[2] == "1", "B.cpp": sys.argv[3] == "1"}
    out = Path("build/PAL")
    out.mkdir(parents=True, exist_ok=True)
    # A stale but passing checksum target: only the raw byte comparison rejects B.
    retail = Path("orig/PAL/sys/main.dol").read_bytes()
    (out / "main.dol").write_bytes(b"not retail at all" if enabled["B.cpp"] else retail)
    (out / "main.elf").write_bytes(b"fixture elf")
    (out / "ok").write_text("ok")
    with (out / "fixture-builds.log").open("a") as stream:
        stream.write(json.dumps(enabled) + "\n")
elif sys.argv[1] == "report":
    enabled = {"A.cpp": sys.argv[2] == "1", "B.cpp": sys.argv[3] == "1"}
    out = Path("build/PAL")
    out.mkdir(parents=True, exist_ok=True)
    report = {
        "measures": {"matched_code": "32", "complete_code": str(16 * sum(enabled.values()))},
        "units": [
            {
                "name": name,
                "metadata": {"source_path": "src/" + name, "complete": complete},
                "measures": {"matched_code": "16"},
                "sections": [{"name": ".text", "fuzzy_match_percent": 100}],
            }
            for name, complete in enabled.items()
        ],
    }
    (out / "report.json").write_text(json.dumps(report))
    with (out / "fixture-reports.log").open("a") as stream:
        stream.write(json.dumps(enabled) + "\n")
"#;

/// The fixture's `configure.py`. Declares two objects in the shape the rewriter
/// understands, and generates a build graph with the two rules it patches.
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
    Object(NonMatching, "A.cpp"),
    Object(NonMatching, "B.cpp"),
]

enabled = dict(objects)
python = sys.executable.replace("$", "$$")
configure_args = " ".join(sys.argv[1:])
lines = [
    f'configure_args = {configure_args}',
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
    f'  command = "{python}" fixture_build.py link {int(enabled["A.cpp"])} {int(enabled["B.cpp"])}',
    "rule report",
    f'  command = "{python}" fixture_build.py report {int(enabled["A.cpp"])} {int(enabled["B.cpp"])}',
    "",
]
inputs = []
for name, on in objects:
    stem = Path(name).stem
    output = f"build/PAL/{'src' if on else 'orig'}/{stem}.o"
    lines.append(f"build {output}: object src/{name}")
    inputs.append(output)
outputs = "build/PAL/main.elf build/PAL/main.dol build/PAL/ok"
lines.append(f"build {outputs}: link {' '.join(inputs)}")
lines.append("build build/PAL/report.json: report | build/PAL/main.elf")
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
                for name, _ in objects
            ]
        }
    ),
    encoding="utf-8",
)
"#;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
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

fn build_fixture() -> Option<Fixture> {
    let ninja = which("ninja")?;
    let python = which("python").or_else(|| which("python3"))?;
    let dir = tempfile::Builder::new().prefix("dtk-migrate-e2e").tempdir().ok()?;
    let root = dir.path().join("project");
    for sub in ["src", "orig/PAL/sys", "build/compilers", "build/tools"] {
        std::fs::create_dir_all(root.join(sub)).ok()?;
    }
    std::fs::write(root.join("configure.py"), CONFIGURE).ok()?;
    std::fs::write(root.join("fixture_build.py"), BUILD).ok()?;
    for name in ["A", "B"] {
        std::fs::write(root.join(format!("src/{name}.cpp")), format!("// {name}\n")).ok()?;
    }
    std::fs::write(root.join("orig/PAL/sys/main.dol"), b"retail fixture").ok()?;
    // Installed tools the configure step passes through as inputs.
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    std::fs::write(root.join(format!("build/tools/objdiff-cli{suffix}")), b"tool").ok()?;
    std::fs::write(root.join("build/tools/sjiswrap.exe"), b"tool").ok()?;
    std::fs::write(root.join("build/compilers/fixture"), b"compiler").ok()?;
    // Stand-in for decomp-toolkit: the fixture's split rule never runs, but a
    // run insists the binary exists so it can freeze it.
    std::fs::write(root.join(format!("build/tools/dtk{suffix}")), b"dtk").ok()?;
    Some(Fixture { _dir: dir, root, ninja, python })
}

impl Fixture {
    fn migrate(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_dtk-migrate"))
            .arg("run")
            .arg("--project-root")
            .arg(&self.root)
            .args(args)
            .env("RUST_LOG", "info")
            .output()
            .expect("failed to start dtk-migrate")
    }

    fn read(&self, relative: &str) -> String {
        std::fs::read_to_string(self.root.join(relative)).unwrap_or_default()
    }

    fn runs(&self) -> Vec<PathBuf> {
        let base = self.root.join("build/dtk-migrate/runs");
        let Ok(entries) = std::fs::read_dir(base) else { return Vec::new() };
        entries.filter_map(|e| e.ok()).map(|e| e.path()).collect()
    }

    /// Every fixture build log and its contents, to prove whether builds ran.
    fn build_logs(&self) -> Vec<(PathBuf, String)> {
        let mut found = Vec::new();
        collect(&self.root, &mut found);
        found.sort();
        return found;

        fn collect(directory: &Path, into: &mut Vec<(PathBuf, String)>) {
            let Ok(entries) = std::fs::read_dir(directory) else { return };
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_dir() {
                    collect(&path, into);
                } else if path.file_name().is_some_and(|n| n == "fixture-builds.log") {
                    into.push((path.clone(), std::fs::read_to_string(&path).unwrap_or_default()));
                }
            }
        }
    }

    /// Every coordinator/worker command log written by the migration runner.
    fn command_logs(&self) -> Vec<String> {
        let mut found = Vec::new();
        collect(&self.root.join("build/dtk-migrate/runs"), &mut found);
        return found;

        fn collect(directory: &Path, into: &mut Vec<String>) {
            let Ok(entries) = std::fs::read_dir(directory) else { return };
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_dir() {
                    collect(&path, into);
                } else if path.file_name().is_some_and(|n| n == "build.log") {
                    into.push(std::fs::read_to_string(path).unwrap_or_default());
                }
            }
        }
    }
}

fn report(output: &std::process::Output) -> String {
    format!(
        "status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_run_publishes_only_the_candidate_that_builds_to_retail() {
    let Some(fixture) = build_fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let ninja = fixture.ninja.display().to_string();
    let python = fixture.python.display().to_string();
    let output = fixture.migrate(&[
        "--source",
        "NTSC",
        "--target",
        "PAL",
        "--stages",
        "verify",
        "--workers",
        "2",
        "--batch-size",
        "1",
        "--ninja",
        &ninja,
        "--python",
        &python,
    ]);
    assert!(output.status.success(), "{}", report(&output));

    let runs = fixture.runs();
    assert_eq!(runs.len(), 1, "expected exactly one run directory");
    let run = &runs[0];

    let summary: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run.join("result.json")).unwrap()).unwrap();
    let verify = &summary["stages"]["verify"];
    let accepted: Vec<&str> = verify["accepted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    let deferred: Vec<&str> = verify["deferred"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(accepted, ["A.cpp"], "A builds to retail bytes");
    assert_eq!(deferred, ["B.cpp"], "B does not, and is deferred rather than condemned");
    assert_eq!(verify["validation"], "compiled-link-inputs-and-retail-bytes");

    // The owner's configure.py carries exactly the accepted unit.
    let configure = fixture.read("configure.py");
    assert!(configure.contains(r#"Object(MatchingFor("PAL"), "A.cpp")"#), "{configure}");
    assert!(configure.contains(r#"Object(NonMatching, "B.cpp")"#), "{configure}");

    // And the project it left behind still builds retail bytes.
    assert_eq!(
        std::fs::read(fixture.root.join("build/PAL/main.dol")).unwrap(),
        std::fs::read(fixture.root.join("orig/PAL/sys/main.dol")).unwrap()
    );

    let journal: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run.join("publication.json")).unwrap())
            .unwrap();
    assert_eq!(journal["status"], "published");
    let changed: Vec<&str> =
        journal["changes"].as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(changed, ["configure.py"], "only configure.py should have been published");
    let graph: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(run.join("final-certificates.json")).unwrap(),
    )
    .unwrap();
    assert!(graph["units"]["A.cpp"]["body"].is_null(), "verify-only has no split file");
    assert_eq!(graph["units"]["A.cpp"]["verified_source_link"], true);

    // Several workspaces each ran real builds.
    assert!(fixture.build_logs().len() >= 3, "{:?}", fixture.build_logs());

    // A trial never asks Ninja to generate the expensive report before it has
    // proved the link and retail bytes. Each invocation names one phase; a
    // successful state reaches both phases, while a rejected link stops after
    // `ok`.
    let logs = fixture.command_logs();
    let mut invocations = Vec::new();
    for log in &logs {
        let mut linked = false;
        for line in log.lines().filter(|line| {
            line.starts_with("+ ") && line.contains("ninja") && line.contains(" -j ")
        }) {
            if line.ends_with("build/PAL/ok") {
                linked = true;
            } else if line.ends_with("build/PAL/report.json") {
                assert!(linked, "report requested before link/hash: {log}");
                linked = false;
            }
            invocations.push(line);
        }
    }
    assert!(invocations.iter().any(|line| line.ends_with("build/PAL/ok")));
    assert!(invocations.iter().any(|line| line.ends_with("build/PAL/report.json")));
    assert!(
        invocations.iter().all(|line| !(line.contains("report.json") && line.contains("/ok"))),
        "{invocations:#?}"
    );
    let rejected = std::fs::read_dir(run.join("verify/jobs"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|entry| {
            let job: serde_json::Value =
                serde_json::from_slice(&std::fs::read(entry.path().join("job.json")).unwrap())
                    .unwrap();
            job["candidates"][0]["name"] == "B.cpp"
        })
        .unwrap();
    let worker = rejected.path().join("process/build.log");
    let commands = std::fs::read_to_string(&worker).unwrap();
    let rejected_link = commands.lines().filter(|line| line.ends_with("build/PAL/ok")).count();
    let reports = commands.lines().filter(|line| line.ends_with("build/PAL/report.json")).count();
    assert_eq!(rejected_link, reports + 1, "{commands}");
}

#[test]
fn resuming_a_published_run_does_no_work() {
    let Some(fixture) = build_fixture() else {
        eprintln!("skipped: needs ninja and python on PATH");
        return;
    };
    let ninja = fixture.ninja.display().to_string();
    let python = fixture.python.display().to_string();
    let first = fixture.migrate(&[
        "--source",
        "NTSC",
        "--target",
        "PAL",
        "--stages",
        "verify",
        "--workers",
        "1",
        "--batch-size",
        "1",
        "--ninja",
        &ninja,
        "--python",
        &python,
    ]);
    assert!(first.status.success(), "{}", report(&first));
    assert!(
        !fixture.read("build.ninja").contains("configure-hook"),
        "publication should return an ordinary build graph to the project owner"
    );

    let run = fixture.runs().pop().unwrap();
    let id = run.file_name().unwrap().to_string_lossy().into_owned();
    let before = fixture.build_logs();
    let configure_before = fixture.read("configure.py");
    let result = std::fs::read(run.join("result.json")).unwrap();
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(run.join("publication.json")).unwrap()).unwrap();
    use sha2::{Digest, Sha256};
    assert_eq!(
        journal["result_sha256"],
        format!("{:x}", Sha256::digest(&result)),
        "publication must commit the complete result with its certificates"
    );

    let resumed = fixture.migrate(&["--resume", &id]);
    assert!(resumed.status.success(), "{}", report(&resumed));
    assert!(
        String::from_utf8_lossy(&resumed.stderr).contains("already published"),
        "{}",
        report(&resumed)
    );
    assert_eq!(fixture.build_logs(), before, "a published run should rebuild nothing");
    assert_eq!(fixture.read("configure.py"), configure_before);
    assert_eq!(std::fs::read(run.join("result.json")).unwrap(), result);

    std::fs::remove_file(run.join("result.json")).unwrap();
    let missing = fixture.migrate(&["--resume", &id]);
    assert!(!missing.status.success(), "{}", report(&missing));
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("Run result changed since publication"),
        "{}",
        report(&missing)
    );
    std::fs::write(run.join("result.json"), result).unwrap();
    let resumed_again = fixture.migrate(&["--resume", &id]);
    assert!(resumed_again.status.success(), "{}", report(&resumed_again));
    assert_eq!(fixture.build_logs(), before);
}

#[test]
fn a_run_refuses_to_start_in_a_directory_that_is_not_a_project() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dtk-migrate"))
        .args(["run", "--project-root"])
        .arg(dir.path())
        .args(["--source", "NTSC", "--target", "PAL"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("dtk-template project"),
        "{}",
        report(&output)
    );
}
