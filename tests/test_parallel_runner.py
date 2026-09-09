"""Orchestration checks with real isolated Python workers and synthetic trials."""

import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import parallel_migration as runner
from benchmark_parallel import evidence
from migration_workspace import snapshot_manifest

FAKE_ADAPTER = """
import pathlib
import time
def evaluate(ctx, candidates):
    for candidate in candidates:
        if candidate.get("crash_marker") and pathlib.Path(candidate["crash_marker"]).exists():
            raise RuntimeError("simulated worker crash")
    time.sleep(.02)
    p = ctx.root / "owned.txt"
    if p.read_text() != "baseline":
        raise RuntimeError("sibling or previous batch leaked into this workspace")
    p.write_text(",".join(c["name"] for c in candidates))
    dol = ctx.root / "build" / ctx.target / "main.dol"
    dol.parent.mkdir(parents=True, exist_ok=True)
    dol.write_bytes(b"retail")
    return {"accepted": candidates, "deferred": [], "events": [], "report": {"measures": {"matched_code": len(candidates)}}, "validation": "fixture"}
"""


class WorkerTests(unittest.TestCase):
    def fixture(self, base, workers=3):
        baseline = base / "baseline"
        baseline.mkdir(parents=True)
        (baseline / "owned.txt").write_text("baseline")
        tooling = base / "tooling"
        tooling.mkdir()
        for name in (
            "parallel_migration.py",
            "migration_runtime.py",
            "migration_workspace.py",
        ):
            shutil.copy2(Path(runner.__file__).parent / name, tooling / name)
        (tooling / "discovery_adapter.py").write_text(FAKE_ADAPTER)
        run = {
            "workers": workers,
            "build_jobs": 1,
            "batch_size": 1,
            "environment": {"fixture": "v1"},
            "source": "SRC",
            "target": "PAL",
            "frozen_dtk": sys.executable,
            "frozen_ninja": sys.executable,
        }
        return baseline, run

    def test_one_and_three_workers_produce_same_results_and_preserve_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            baseline, run = self.fixture(base)
            manifest = snapshot_manifest(baseline)
            candidates = [{"name": str(i)} for i in range(7)]
            one = runner.execute_jobs(
                base,
                dict(run, workers=1),
                "discover",
                base / "one",
                baseline,
                manifest,
                candidates,
            )
            three = runner.execute_jobs(
                base, run, "discover", base / "three", baseline, manifest, candidates
            )
            for a, b in zip(one, three):
                for key in (
                    "accepted",
                    "deferred",
                    "fingerprint",
                    "validation",
                    "dol_sha1",
                    "report",
                ):
                    self.assertEqual(a[key], b[key])
            self.assertEqual(snapshot_manifest(baseline), manifest)

    def test_resume_preserves_successful_siblings_and_reruns_failed_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            baseline, run = self.fixture(base)
            marker = base / "crash"
            marker.touch()
            candidates = [
                {"name": "A"},
                {"name": "B", "crash_marker": str(marker)},
                {"name": "C"},
            ]
            stage = base / "stage"
            manifest = snapshot_manifest(baseline)
            with self.assertRaisesRegex(RuntimeError, "successful siblings"):
                runner.execute_jobs(
                    base, run, "discover", stage, baseline, manifest, candidates
                )
            cached = stage / "jobs/00000/result.json"
            old = cached.read_bytes()
            modified = cached.stat().st_mtime_ns
            marker.unlink()
            outcomes = runner.execute_jobs(
                base, run, "discover", stage, baseline, manifest, candidates
            )
            self.assertEqual(len(outcomes), 3)
            self.assertEqual(cached.read_bytes(), old)
            self.assertEqual(cached.stat().st_mtime_ns, modified)

    def test_foreign_or_mutated_candidates_are_rejected(self):
        spec = {
            "job_id": "a",
            "fingerprint": "hash",
            "candidates": [{"name": "A", "lines": ["original"]}],
        }
        result = {
            "schema": runner.SCHEMA,
            "job_id": "a",
            "fingerprint": "hash",
            "accepted": [{"name": "A", "lines": ["changed"]}],
            "deferred": [],
        }
        with self.assertRaises(ValueError):
            runner.verify_result(result, spec)

    def test_forged_coverage_selection_is_rejected(self):
        candidate = {"name": "A", "alternatives": [{"id": "real"}]}
        spec = {
            "stage": "coverage",
            "job_id": "a",
            "fingerprint": "hash",
            "candidates": [candidate],
        }
        result = {
            "schema": runner.SCHEMA,
            "job_id": "a",
            "fingerprint": "hash",
            "accepted": [candidate],
            "deferred": [],
            "selected": {"A": "forged"},
        }
        with self.assertRaisesRegex(ValueError, "unknown coverage alternative"):
            runner.verify_result(result, spec)

    def test_cancellation_does_not_launch_the_next_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            baseline, run = self.fixture(base, workers=1)
            started, stopped = threading.Event(), threading.Event()
            calls = []

            from dataclasses import dataclass

            @dataclass(frozen=True)
            class Context:
                cancel_event: object = None

                def run(self, cmd):
                    calls.append(cmd)
                    started.set()
                    stopped.wait(5)
                    raise subprocess.CalledProcessError(-9, cmd)

            def interrupt(futures):
                self.assertTrue(started.wait(5))
                raise KeyboardInterrupt()

            with (
                patch.object(runner, "context", return_value=Context()),
                patch.object(runner, "as_completed", side_effect=interrupt),
                patch.object(runner, "cancel_commands", side_effect=stopped.set),
                self.assertRaises(KeyboardInterrupt),
            ):
                runner.execute_jobs(
                    base,
                    run,
                    "discover",
                    base / "stage",
                    baseline,
                    snapshot_manifest(baseline),
                    [{"name": str(n)} for n in range(3)],
                )
            self.assertEqual(len(calls), 1)


class IntegrationTests(unittest.TestCase):
    def test_benchmark_detects_per_unit_changes_with_identical_totals(self):
        result = {
            "accepted": [],
            "deferred": [],
            "dol_sha1": "retail",
            "validation": "fixture",
            "report": {
                "measures": {"matched_code": 8},
                "units": [
                    {"name": "A", "matched_code": 8},
                    {"name": "B", "matched_code": 0},
                ],
            },
        }
        first = evidence(result)
        result["report"]["units"] = [
            {"name": "A", "matched_code": 0},
            {"name": "B", "matched_code": 8},
        ]
        second = evidence(result)
        self.assertEqual(first["measures"], second["measures"])
        self.assertNotEqual(first["report_sha256"], second["report_sha256"])

    def test_modified_frozen_executable_stops_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = root / "dtk.exe"
            executable.write_bytes(b"frozen")
            expected = runner.digest_file(executable)
            executable.write_bytes(b"changed")
            with self.assertRaisesRegex(RuntimeError, "Frozen dtk binary changed"):
                runner.check_frozen_environment(
                    {"frozen_dtk": str(executable), "environment": {"dtk": expected}}
                )

    def test_failed_owner_build_rolls_back_and_rebuilds_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root, integrated, run_dir = (
                base / "owner",
                base / "integration",
                base / "run",
            )
            root.mkdir()
            integrated.mkdir()
            (root / "configure.py").write_bytes(b"before")
            (integrated / "configure.py").write_bytes(b"after")
            run = {
                "owner_manifest": snapshot_manifest(root),
                "symbol_mappings": {},
                "target": "PAL",
                "build_jobs": 1,
            }
            calls = []

            class Context:
                def build(self):
                    value = (root / "configure.py").read_bytes()
                    calls.append(value)
                    if value == b"after":
                        raise RuntimeError("owner failed")
                    return {"measures": {}}

            with (
                patch.object(runner, "context", return_value=Context()),
                self.assertRaisesRegex(RuntimeError, "owner failed"),
            ):
                runner.publish(root, integrated, run_dir, run, {})
            self.assertEqual(calls, [b"after", b"before"])
            self.assertEqual(
                runner.read_json(run_dir / "publication.json")["status"], "rolled-back"
            )
            self.assertEqual(snapshot_manifest(root), run["owner_manifest"])

    def test_downstream_resume_rejects_changed_upstream(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            owner = base / "owner"
            owner.mkdir()
            (owner / "configure.py").write_text("new upstream")
            runner.write_json(
                base / "verify/prepared.json", {"source_fingerprint": "old"}
            )
            with self.assertRaisesRegex(RuntimeError, "Upstream verify inputs changed"):
                runner.run_stage(base, {}, "verify", owner)

    def test_union_conflicts_and_dependencies_revalidate_in_canonical_order(self):
        class Context:
            def __init__(self):
                self.accepted = set()

            def build(self):
                return {"measures": {"matched_code": len(self.accepted)}}

            def dol_sha1(self):
                return "retail"

        class Adapter:
            def __init__(self):
                self.calls = []

            def evaluate(self, ctx, candidates):
                self.calls.append([c["name"] for c in candidates])
                accepted, deferred = [], []
                for c in candidates:
                    if c["name"] == "B" and "A" in ctx.accepted:
                        deferred.append(c)  # individually valid but conflicts with A
                    elif c["name"] == "D" and "C" not in ctx.accepted:
                        deferred.append(c)  # can succeed only after C is integrated
                    else:
                        ctx.accepted.add(c["name"])
                        accepted.append(c)
                return {
                    "accepted": accepted,
                    "deferred": deferred,
                    "events": [],
                    "report": ctx.build(),
                    "validation": "fixture",
                }

        candidates = [{"name": n} for n in "ADBC"]
        outcomes = [
            {"accepted": [{"name": n}]} for n in "CBA"
        ]  # completion order intentionally differs
        mod, ctx = Adapter(), Context()
        with patch.object(runner, "adapter", return_value=mod):
            result = runner.integrate(ctx, "discover", candidates, outcomes)
        self.assertEqual(mod.calls[0], ["A", "B", "C"])
        self.assertEqual(
            result["accepted"], [c for c in candidates if c["name"] in "ADC"]
        )
        self.assertEqual(result["deferred"], [{"name": "B"}])

    def test_coverage_integration_prefers_worker_selection_and_validates_it(self):
        candidate = {"name": "A", "alternatives": [{"id": "first"}, {"id": "worker"}]}

        class Context:
            def dol_sha1(self):
                return "retail"

        class Adapter:
            def __init__(self):
                self.calls = []

            def evaluate(self, ctx, candidates, preferred=None):
                self.calls.append((candidates, preferred))
                selected = {
                    c["name"]: preferred.get(c["name"], c["alternatives"][0]["id"])
                    for c in candidates
                }
                return {
                    "accepted": candidates,
                    "deferred": [],
                    "selected": selected,
                    "events": [],
                    "report": {"measures": {}},
                    "validation": "coverage",
                }

            def validate(self, ctx, candidates, selected):
                self.validated = (candidates, selected)
                return {"measures": {}}

        mod = Adapter()
        outcomes = [
            {
                "job_id": "00000",
                "accepted": [candidate],
                "deferred": [],
                "selected": {"A": "worker"},
                "events": [{"unit": "A", "status": "accepted"}],
            }
        ]
        with patch.object(runner, "adapter", return_value=mod):
            result = runner.integrate(Context(), "coverage", [candidate], outcomes)
        self.assertEqual(mod.calls[0][1], {"A": "worker"})
        self.assertEqual(result["selected"], {"A": "worker"})
        self.assertEqual(mod.validated, ([candidate], {"A": "worker"}))
        self.assertEqual(result["events"][0]["phase"], "worker")
        self.assertEqual(result["events"][0]["job_id"], "00000")

    def test_rollback_preserves_intervening_user_edits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "configure.py"
            path.write_bytes(b"before")
            before = runner.digest_file(path)
            path.write_bytes(b"after")
            after = runner.digest_file(path)
            journal = {
                "staging": str(root / "build/staging"),
                "changes": {
                    "configure.py": {
                        "before_sha256": before,
                        "after_sha256": after,
                        "before_hex": b"before".hex(),
                    }
                },
            }
            path.write_bytes(b"user edit")
            self.assertEqual(
                runner.restore_publication(root, journal), ["configure.py"]
            )
            self.assertEqual(path.read_bytes(), b"user edit")
            path.write_bytes(b"after")
            self.assertEqual(runner.restore_publication(root, journal), [])
            self.assertEqual(path.read_bytes(), b"before")

    def test_publication_rejects_baseline_drift_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "owner"
            root.mkdir()
            (root / "configure.py").write_text("original")
            manifest = snapshot_manifest(root)
            (root / "configure.py").write_text("user edit")
            with self.assertRaisesRegex(RuntimeError, "Project inputs changed"):
                runner.publish(
                    root,
                    root,
                    Path(tmp),
                    {"owner_manifest": manifest, "symbol_mappings": {}},
                    {},
                )
            self.assertEqual((root / "configure.py").read_text(), "user edit")

    def test_mapping_seed_retains_only_user_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, dest = root / "source", root / "dest"
            source.mkdir()
            runner.write_json(
                source / "objdiff.json",
                {
                    "units": [
                        {
                            "name": "A",
                            "base_path": "owner/build/A.o",
                            "symbol_mappings": {"a": "b"},
                        },
                        {"name": "B", "base_path": "owner/build/B.o"},
                    ]
                },
            )
            runner.seed_objdiff(source, dest)
            self.assertEqual(
                runner.read_json(dest / "objdiff.json"),
                {"units": [{"name": "A", "symbol_mappings": {"a": "b"}}]},
            )


if __name__ == "__main__":
    unittest.main()
