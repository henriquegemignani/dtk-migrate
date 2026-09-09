"""Exercise worker processes, real Ninja graphs, publication, and resume together."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CONFIGURE = r"""from pathlib import Path
import json
import sys
from tools.ninja_syntax import Writer

VERSIONS = ["NTSC", "PAL"]
MatchingFor = lambda *versions: "PAL" in versions
NonMatching = False
Object = lambda status, name: (name, status)
objects = [Object(NonMatching, "A.cpp"), Object(NonMatching, "B.cpp")]

flags = dict(objects)
with Path("build.ninja").open("w", encoding="utf-8") as stream:
    writer = Writer(stream)
    python = sys.executable.replace("$", "$$")
    writer.rule("object", f'"{python}" fixture_build.py object $out')
    writer.rule("fixture", f'"{python}" fixture_build.py link {int(flags["A.cpp"])} {int(flags["B.cpp"])}')
    inputs = []
    for name, enabled in objects:
        stem = Path(name).stem
        output = f"build/PAL/{'src' if enabled else 'orig'}/{stem}.o"
        stream.write(f"build {output}: object src/{name}\n")
        inputs.append(output)
    outputs = "build/PAL/main.elf build/PAL/main.dol build/PAL/report.json build/PAL/ok"
    stream.write(f"build {outputs}: fixture {' '.join(inputs)}\n")
Path("objdiff.json").write_text(json.dumps({"units": [
    {"name": name, "metadata": {"source_path": "src/" + name},
     "base_path": "build/PAL/src/" + Path(name).stem + ".o"}
    for name, _ in objects]}), encoding="utf-8")
"""


BUILD = r"""from pathlib import Path
import json
import sys

if sys.argv[1] == "object":
    output = Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(b"compiled fixture")
else:
    flags = dict(zip(("A.cpp", "B.cpp"), map(lambda arg: bool(int(arg)), sys.argv[2:])))
    output = Path("build/PAL")
    output.mkdir(parents=True, exist_ok=True)
    # Simulate a stale/passing checksum target: only the raw byte gate rejects B.
    (output / "main.dol").write_bytes(b"incorrect B source" if flags["B.cpp"] else Path("orig/PAL/sys/main.dol").read_bytes())
    (output / "main.elf").write_bytes(b"fixture elf")
    (output / "ok").write_text("ok")
    report = {"measures": {"matched_code": "32", "complete_code": str(16 * sum(flags.values()))},
              "units": [{"metadata": {"source_path": "src/" + name, "complete": complete},
                         "measures": {"matched_code": "16"},
                         "sections": [{"name": ".text", "fuzzy_match_percent": 100}]}
                        for name, complete in flags.items()]}
    (output / "report.json").write_text(json.dumps(report))
    with (output / "fixture-builds.log").open("a") as stream:
        stream.write(json.dumps(flags) + "\n")
"""


class ParallelEndToEndTests(unittest.TestCase):
    def test_real_workers_publish_verified_subset_and_resume_without_rebuild(self):
        ninja = shutil.which("ninja")
        if not ninja:
            self.skipTest("Ninja is required for the subprocess integration test")
        ninja = Path(ninja)
        actual = ninja.parent.parent / "lib/ninja/tools/ninja.exe"
        if ninja.parent.name.lower() == "bin" and actual.is_file():
            ninja = actual
        with tempfile.TemporaryDirectory(prefix="migration e2e ") as directory:
            container = Path(directory)
            root = container / "project"
            root.mkdir()
            live_ninja = container / ("live-" + ninja.name)
            shutil.copy2(ninja, live_ninja)
            for subdir in (
                "src",
                "tools",
                "orig/PAL/sys",
                "build/compilers",
                "build/tools",
            ):
                (root / subdir).mkdir(parents=True, exist_ok=True)
            (root / "configure.py").write_text(CONFIGURE, encoding="utf-8")
            (root / "fixture_build.py").write_text(BUILD, encoding="utf-8")
            # Minimal real rule writer; migration_configure patches this API.
            (root / "tools/ninja_syntax.py").write_text(
                "class Writer:\n"
                "    def __init__(self, stream): self.stream = stream\n"
                "    def rule(self, name, command, *args, **kwargs):\n"
                '        self.stream.write(f"rule {name}\\n  command = {command}\\n")\n',
                encoding="utf-8",
            )
            for name in ("A", "B"):
                (root / f"src/{name}.cpp").write_text(
                    f"// dirty untracked {name} source\n", encoding="utf-8"
                )
            (root / "orig/PAL/sys/main.dol").write_bytes(b"retail fixture")
            suffix = ".exe" if os.name == "nt" else ""
            for name in (f"objdiff-cli{suffix}", "sjiswrap.exe"):
                (root / "build/tools" / name).write_bytes(
                    b"unused installed tool fixture"
                )
            (root / "build/compilers/fixture").write_bytes(b"unused installed compiler")
            command = [
                sys.executable,
                str(
                    Path(__file__).resolve().parents[1]
                    / "src"
                    / "parallel_migration.py"
                ),
                "--project-root",
                str(root),
            ]

            def invoke(*args):
                return subprocess.run(
                    command + list(args), capture_output=True, text=True, timeout=60
                )

            result = invoke(
                "--source",
                "NTSC",
                "--target",
                "PAL",
                "--dtk",
                sys.executable,
                "--ninja",
                str(live_ninja),
                "--stage",
                "verify",
                "--batch-size",
                "1",
                "--limit",
                "2",
                "--workers",
                "2",
            )
            if result.returncode:
                logs = "\n".join(
                    f"{p.relative_to(root)}:\n{p.read_text(errors='replace')}"
                    for p in root.rglob("build.log")
                )
                self.fail(f"CLI failed:\n{result.stdout}\n{result.stderr}\n{logs}")
            runs = list((root / "build/parallel-migration/runs").iterdir())
            self.assertEqual(len(runs), 1)
            run = runs[0]
            evidence = json.loads((run / "result.json").read_text())
            self.assertEqual(
                evidence["stages"]["verify"]["accepted"], [{"name": "A.cpp"}]
            )
            self.assertEqual(
                evidence["stages"]["verify"]["deferred"], [{"name": "B.cpp"}]
            )
            self.assertEqual(
                evidence["stages"]["verify"]["validation"],
                "compiled-link-inputs-and-retail-bytes",
            )
            self.assertEqual(
                (root / "build/PAL/main.dol").read_bytes(),
                (root / "orig/PAL/sys/main.dol").read_bytes(),
            )
            config = (root / "configure.py").read_text()
            self.assertIn('Object(MatchingFor("PAL"), "A.cpp")', config)
            self.assertIn('Object(NonMatching, "B.cpp")', config)
            journal = json.loads((run / "publication.json").read_text())
            self.assertEqual(journal["status"], "published")
            self.assertEqual(set(journal["changes"]), {"configure.py"})
            # Byte-for-byte logs and timestamps prove published resume invokes no builds.
            build_logs = {
                p: (p.read_bytes(), p.stat().st_mtime_ns)
                for p in root.rglob("fixture-builds.log")
            }
            self.assertGreaterEqual(len(build_logs), 4)
            with live_ninja.open("ab") as stream:
                stream.write(b"changed after publication")
            resumed = invoke("--resume", run.name)
            self.assertEqual(resumed.returncode, 0, resumed.stdout + resumed.stderr)
            self.assertIn("already published", resumed.stdout)
            self.assertEqual(
                build_logs,
                {
                    p: (p.read_bytes(), p.stat().st_mtime_ns)
                    for p in root.rglob("fixture-builds.log")
                },
            )
            (root / "src/A.cpp").write_text(
                "// intervening owner source edit\n", encoding="utf-8"
            )
            stale = invoke("--resume", run.name)
            self.assertNotEqual(stale.returncode, 0)
            self.assertIn("Published project has changed", stale.stderr)
            self.assertEqual(
                (root / "src/A.cpp").read_text(), "// intervening owner source edit\n"
            )
            self.assertEqual((root / "configure.py").read_text(), config)


if __name__ == "__main__":
    unittest.main()
