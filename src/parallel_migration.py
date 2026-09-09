#!/usr/bin/env python3
"""Run deterministic migration batches in private processes and publish verified results."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import shutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from migration_runtime import TRIAL_ERRORS, BuildContext
from migration_workspace import (
    cancel_commands,
    copy_snapshot,
    fingerprint,
    preflight_space,
    project_lock,
    reset_workspace,
    snapshot_manifest,
)

SCHEMA = 2
SOURCE_ROOT = Path(__file__).resolve().parent
REPOSITORY_ROOT = SOURCE_ROOT.parent
EXPECTED_OPERATION_ERRORS = TRIAL_ERRORS + (
    OSError,
    ValueError,
    KeyError,
    TypeError,
    RuntimeError,
)


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temp, path)


def digest_file(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def tooling_manifest():
    paths = list(SOURCE_ROOT.glob("*.py")) + [
        REPOSITORY_ROOT / name
        for name in ("pyproject.toml", "uv.lock", ".python-version")
    ]
    return {p.name: digest_file(p) for p in sorted(paths) if p.is_file()}


def tooling_source(name):
    """Locate a source module or repository-level runtime metadata file."""
    source = SOURCE_ROOT / name
    return source if source.is_file() else REPOSITORY_ROOT / name


def symbol_mappings(root):
    path = Path(root) / "objdiff.json"
    if not path.exists():
        return {}
    return {
        u["name"]: u["symbol_mappings"]
        for u in read_json(path).get("units", [])
        if u.get("symbol_mappings")
    }


def seed_objdiff(source, destination):
    # project.py preserves user symbol mappings while regenerating every path.
    mappings = symbol_mappings(source)
    write_json(
        Path(destination) / "objdiff.json",
        {
            "units": [
                {"name": name, "symbol_mappings": mapping}
                for name, mapping in sorted(mappings.items())
            ]
        },
    )


def context(root, run, stage, output, jobs):
    return BuildContext(
        Path(root),
        run["source"],
        run["target"],
        Path(run["frozen_dtk"]),
        Path(output),
        jobs,
        sys.executable,
        run["frozen_ninja"],
        toolchain_root=Path(run["toolchain_root"])
        if run.get("toolchain_root")
        else None,
    )


def check_toolchain(run):
    if (
        run.get("toolchain_root")
        and snapshot_manifest(Path(run["toolchain_root"])) != run["toolchain_manifest"]
    ):
        raise RuntimeError("Frozen compiler tools changed; start a new run")


def check_frozen_environment(run):
    check_toolchain(run)
    environment = run.get("environment", {})
    for field, identity in (("frozen_dtk", "dtk"), ("frozen_ninja", "ninja")):
        if identity in environment and digest_file(run[field]) != environment[identity]:
            raise RuntimeError(f"Frozen {identity} binary changed; start a new run")
    if run.get("tooling_root"):
        for name, checksum in environment["tooling"].items():
            if digest_file(Path(run["tooling_root"]) / name) != checksum:
                raise RuntimeError("Frozen worker scripts changed; start a new run")


def adapter(stage):
    modules = {
        "coverage": "coverage_adapter",
        "discover": "discovery_adapter",
        "verify": "verification_adapter",
    }
    return importlib.import_module(modules[stage])


def candidate_batches(candidates, size):
    return [candidates[i : i + size] for i in range(0, len(candidates), size)]


def job_identity(baseline, candidates, stage, environment):
    return fingerprint(
        {
            "baseline": baseline,
            "candidates": candidates,
            "stage": stage,
            "environment": environment,
        }
    )


def verify_result(result, spec):
    if (
        result.get("schema") != SCHEMA
        or result.get("job_id") != spec["job_id"]
        or result.get("fingerprint") != spec["fingerprint"]
    ):
        raise ValueError("Worker result belongs to a different job or baseline")
    expected = {c["name"]: c for c in spec["candidates"]}
    seen = set()
    for key in ("accepted", "deferred"):
        for candidate in result[key]:
            name = candidate["name"]
            if name in seen or expected.get(name) != candidate:
                raise ValueError("Worker returned duplicate or changed candidates")
            seen.add(name)
    if seen != set(expected):
        raise ValueError("Worker result omits candidates")
    if spec["stage"] == "coverage":
        selected = result.get("selected")
        accepted = {candidate["name"] for candidate in result["accepted"]}
        if not isinstance(selected, dict) or set(selected) != accepted:
            raise ValueError("Coverage selections do not match accepted candidates")
        for name, identity in selected.items():
            if identity not in {
                alternative["id"] for alternative in expected[name]["alternatives"]
            }:
                raise ValueError("Worker selected an unknown coverage alternative")
    return result


def worker(spec_path):
    spec = read_json(spec_path)
    ctx = context(
        spec["workspace"],
        spec["run"],
        spec["stage"],
        spec["output"],
        spec["build_jobs"],
    )
    started = time.monotonic()
    outcome = adapter(spec["stage"]).evaluate(ctx, spec["candidates"])
    outcome.update(
        schema=SCHEMA,
        job_id=spec["job_id"],
        fingerprint=spec["fingerprint"],
        baseline_fingerprint=spec["baseline_fingerprint"],
        seconds=time.monotonic() - started,
        dol_sha1=ctx.dol_sha1(),
    )
    verify_result(outcome, spec)
    write_json(Path(spec["output"]) / "result.json", outcome)


def execute_jobs(
    run_dir,
    run,
    stage,
    stage_dir,
    baseline,
    manifest,
    candidates,
    *,
    epoch="",
    pool_root=None,
):
    check_frozen_environment(run)
    batches = candidate_batches(candidates, run["batch_size"])
    baseline_hash = fingerprint(manifest)
    specs: list[dict[str, Any]] = []
    for index, batch in enumerate(batches):
        job_id = f"{index:05d}"
        output = stage_dir / "jobs" / epoch / job_id
        specs.append(
            {
                "schema": SCHEMA,
                "run": run,
                "stage": stage,
                "job_id": job_id,
                "baseline_fingerprint": baseline_hash,
                "fingerprint": job_identity(
                    baseline_hash, batch, stage, run["environment"]
                ),
                "candidates": batch,
                "output": str(output),
                "build_jobs": run["build_jobs"],
            }
        )
    results = {}
    errors = []
    cancelled = threading.Event()
    pool_root = Path(pool_root) if pool_root is not None else run_dir / "pool"

    def lane(number):
        workspace = pool_root / f"worker-{number}"
        for spec in specs[number :: run["workers"]]:
            if cancelled.is_set():
                return
            result_path = Path(spec["output"]) / "result.json"
            if result_path.exists():
                try:
                    results[spec["job_id"]] = verify_result(
                        read_json(result_path), spec
                    )
                    continue
                except ValueError, KeyError, TypeError:
                    pass  # Incomplete/obsolete artifact is rerun, never integrated.
            reset_workspace(baseline, workspace, manifest)
            seed_objdiff(baseline, workspace)
            if cancelled.is_set():
                return
            spec = dict(spec, workspace=str(workspace))
            spec_path = Path(spec["output"]) / "job.json"
            write_json(spec_path, spec)
            print(
                f"{stage}: worker {number + 1}, batch {spec['job_id']} ({len(spec['candidates'])} candidates)",
                flush=True,
            )
            ctx = context(
                workspace,
                run,
                stage,
                Path(spec["output"]) / "process",
                run["build_jobs"],
            )
            ctx = replace(ctx, cancel_event=cancelled)
            try:
                ctx.run(
                    [
                        sys.executable,
                        run_dir / "tooling" / "parallel_migration.py",
                        "--worker",
                        spec_path,
                    ]
                )
                results[spec["job_id"]] = verify_result(read_json(result_path), spec)
            except EXPECTED_OPERATION_ERRORS as error:
                if cancelled.is_set():
                    return
                write_json(
                    Path(spec["output"]) / "failure.json", {"error": repr(error)}
                )
                errors.append((spec["job_id"], repr(error)))

    pool = ThreadPoolExecutor(max_workers=run["workers"])
    try:
        futures = [
            pool.submit(lane, i) for i in range(min(run["workers"], len(batches)))
        ]
        for future in as_completed(futures):
            future.result()
    except BaseException:
        cancelled.set()
        cancel_commands()
        raise
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    if errors:
        raise RuntimeError(
            f"Worker jobs failed; successful siblings are retained for --resume: {errors}"
        )
    return [results[spec["job_id"]] for spec in specs]


def integrate(ctx, stage, candidates, outcomes):
    """Revalidate the union, then retry deferred candidates only after progress."""
    mod = adapter(stage)
    if stage == "coverage":
        worker_events = [
            {**event, "phase": "worker", "job_id": outcome.get("job_id")}
            for outcome in outcomes
            for event in outcome.get("events", [])
        ]
        preferred = {
            name: identity
            for outcome in outcomes
            for name, identity in outcome.get("selected", {}).items()
        }
        worker_accepted = {
            candidate["name"]
            for outcome in outcomes
            for candidate in outcome["accepted"]
        }
        proposed = [
            candidate
            for candidate in candidates
            if candidate["name"] in worker_accepted
        ]
        outcome = mod.evaluate(ctx, proposed, preferred)
        accepted = {candidate["name"] for candidate in outcome["accepted"]}
        selected = dict(outcome["selected"])
        events = worker_events + [
            {**event, "phase": "integration"} for event in outcome["events"]
        ]
        pending = [
            candidate for candidate in candidates if candidate["name"] not in accepted
        ]
        while pending:
            retry = mod.evaluate(ctx, pending, preferred)
            events.extend(
                {**event, "phase": "integration"} for event in retry["events"]
            )
            added = {candidate["name"] for candidate in retry["accepted"]}
            if not added:
                break
            accepted.update(added)
            selected.update(retry["selected"])
            pending = [
                candidate for candidate in pending if candidate["name"] not in added
            ]
        accepted_candidates = [
            candidate for candidate in candidates if candidate["name"] in accepted
        ]
        report = mod.validate(ctx, accepted_candidates, selected)
        return {
            "accepted": accepted_candidates,
            "deferred": pending,
            "selected": selected,
            "events": events,
            "report": report,
            "dol_sha1": ctx.dol_sha1(),
            "validation": outcome["validation"],
        }
    accepted_names = {c["name"] for outcome in outcomes for c in outcome["accepted"]}
    proposed = [c for c in candidates if c["name"] in accepted_names]
    outcome = mod.evaluate(ctx, proposed)
    accepted = {c["name"] for c in outcome["accepted"]}
    events = list(outcome["events"])
    pending = [c for c in candidates if c["name"] not in accepted]
    # Retry against the integrated state; each new success changes the baseline.
    while pending:
        retry = mod.evaluate(ctx, pending)
        events.extend(retry["events"])
        added = {c["name"] for c in retry["accepted"]}
        outcome = retry
        if not added:
            break
        accepted.update(added)
        pending = [c for c in pending if c["name"] not in added]
    if stage == "verify":
        report = mod.validate(ctx, accepted)
    else:
        report = ctx.build()
    return {
        "accepted": [c for c in candidates if c["name"] in accepted],
        "deferred": pending,
        "events": events,
        "report": report,
        "dol_sha1": ctx.dol_sha1(),
        "validation": outcome["validation"],
    }


def run_stage(run_dir, run, stage, source_root):
    started = time.monotonic()
    stage_dir = run_dir / stage
    baseline = stage_dir / "baseline"
    prepared_path = stage_dir / "prepared.json"
    source_manifest = snapshot_manifest(source_root)
    source_fingerprint = fingerprint(
        {"inputs": source_manifest, "mappings": symbol_mappings(source_root)}
    )
    if prepared_path.exists():
        prepared = read_json(prepared_path)
        if prepared.get("source_fingerprint") != source_fingerprint:
            raise RuntimeError(f"Upstream {stage} inputs changed; start a new run")
        manifest = read_json(stage_dir / "manifest.json")
        if (
            snapshot_manifest(baseline) != manifest
            or symbol_mappings(baseline) != prepared["symbol_mappings"]
        ):
            raise RuntimeError(f"Frozen {stage} baseline changed; start a new run")
    else:
        reset_workspace(
            source_root, baseline, source_manifest
        ) if baseline.exists() else copy_snapshot(
            source_root, baseline, source_manifest
        )
        seed_objdiff(source_root, baseline)
        ctx = context(
            baseline, run, stage, stage_dir / "preparation", run["build_jobs"]
        )
        prepared = adapter(stage).prepare(
            ctx, limit=None if run.get("only") else run["limit"]
        )
        requested = set(run.get("only", []))
        if requested:
            available = {candidate["name"] for candidate in prepared["candidates"]}
            missing = requested - available
            if missing:
                raise RuntimeError(
                    f"Requested {stage} candidates were not proposed: {sorted(missing)}"
                )
            prepared["candidates"] = [
                candidate
                for candidate in prepared["candidates"]
                if candidate["name"] in requested
            ]
        prepared["source_fingerprint"] = source_fingerprint
        prepared["symbol_mappings"] = symbol_mappings(baseline)
        manifest = snapshot_manifest(baseline)
        write_json(stage_dir / "manifest.json", manifest)
        write_json(prepared_path, prepared)
    candidates = prepared["candidates"]
    print(
        f"{stage}: {len(candidates)} candidates in {len(candidate_batches(candidates, run['batch_size']))} batches",
        flush=True,
    )
    outcomes = execute_jobs(
        run_dir, run, stage, stage_dir, baseline, manifest, candidates
    )
    integrated = run_dir / "integration"
    reset_workspace(baseline, integrated, manifest)
    seed_objdiff(baseline, integrated)
    ctx = context(
        integrated, run, stage, stage_dir / "integration-evidence", run["build_jobs"]
    )
    result = integrate(ctx, stage, candidates, outcomes)
    result.update(
        baseline=prepared["baseline"]["measures"],
        preparation_events=prepared.get("events", []),
        seconds=time.monotonic() - started,
        baseline_fingerprint=fingerprint(manifest),
    )
    if stage == "coverage":
        coverage = adapter(stage).summary(prepared, result)
        write_json(stage_dir / "coverage.json", coverage)
        (stage_dir / "coverage.md").write_text(
            adapter(stage).markdown_summary(coverage), encoding="utf-8"
        )
        result["coverage_summary"] = {
            key: coverage[key]
            for key in (
                "source_units",
                "baseline_represented",
                "final_represented",
                "newly_supported_units",
                "newly_assigned_code_bytes",
            )
        }
    write_json(stage_dir / "result.json", result)
    return integrated, result


def restore_publication(root, journal):
    """Rollback only our own bytes, preserving any edits made after publication."""
    conflicts = []
    for name, change in journal["changes"].items():
        path = root / name
        current = digest_file(path) if path.exists() else None
        if current == change["after_sha256"]:
            data = bytes.fromhex(change["before_hex"])
            temp = Path(journal["staging"]) / (
                hashlib.sha256(name.encode()).hexdigest() + ".rollback"
            )
            temp.parent.mkdir(parents=True, exist_ok=True)
            temp.write_bytes(data)
            os.replace(temp, path)
        elif current != change["before_sha256"]:
            conflicts.append(name)
    return conflicts


def publish(root, integrated, run_dir, run, result):
    check_frozen_environment(run)
    expected = run["owner_manifest"]
    if (
        snapshot_manifest(root) != expected
        or symbol_mappings(root) != run["symbol_mappings"]
    ):
        raise RuntimeError(
            "Project inputs changed during migration; publication stopped. Results retained for revalidation."
        )
    final_manifest = snapshot_manifest(integrated)
    changed = {
        n
        for n in set(expected) | set(final_manifest)
        if expected.get(n) != final_manifest.get(n)
    }
    allowed = {
        "configure.py",
        f"config/{run['target']}/splits.txt",
        f"config/{run['target']}/symbols.txt",
    }
    if changed - allowed:
        raise RuntimeError(
            f"Integration changed unexpected inputs: {sorted(changed - allowed)}"
        )
    journal = {
        "status": "publishing",
        "staging": str(run_dir / "publication-staging"),
        "changes": {
            name: {
                "before_sha256": expected[name],
                "before_hex": (root / name).read_bytes().hex(),
                "after_sha256": final_manifest[name],
                "after_hex": (integrated / name).read_bytes().hex(),
            }
            for name in sorted(changed)
        },
    }
    journal_path = run_dir / "publication.json"
    write_json(journal_path, journal)
    ctx = context(root, run, "publish", run_dir / "owner-validation", run["build_jobs"])
    try:
        for name, change in journal["changes"].items():
            path = root / name
            if digest_file(path) != change["before_sha256"]:
                raise RuntimeError(f"User changed {name} during publication")
            temp = Path(journal["staging"]) / hashlib.sha256(name.encode()).hexdigest()
            temp.parent.mkdir(parents=True, exist_ok=True)
            temp.write_bytes(bytes.fromhex(change["after_hex"]))
            os.replace(temp, path)
        report = ctx.build()
        if "coverage" in result:
            coverage = result["coverage"]
            report = adapter("coverage").validate(
                ctx, coverage.get("accepted", []), coverage.get("selected", {})
            )
        if "verify" in result:
            names = {c["name"] for c in result["verify"].get("accepted", [])}
            report = adapter("verify").validate(ctx, names)
        check_frozen_environment(run)
        if snapshot_manifest(root) != final_manifest or symbol_mappings(
            root
        ) != symbol_mappings(integrated):
            raise RuntimeError("Owner inputs changed during final validation")
    except BaseException:
        conflicts = restore_publication(root, journal)
        journal.update(
            status="rolled-back" if not conflicts else "user-edit-conflict",
            conflicts=conflicts,
        )
        write_json(journal_path, journal)
        if not conflicts and snapshot_manifest(root) == expected:
            try:
                ctx.build()
            except EXPECTED_OPERATION_ERRORS as error:
                print(
                    f"Owner inputs were restored, but rebuilding their report failed: {error}",
                    file=sys.stderr,
                )
        raise
    journal["status"] = "published"
    write_json(journal_path, journal)
    return report


def environment_identity(dtk, ninja):
    return {
        "tooling": tooling_manifest(),
        "dtk": digest_file(dtk),
        "ninja": digest_file(ninja),
        "interpreter": sys.version,
        "executable": str(Path(sys.executable).resolve()),
        "interpreter_sha256": digest_file(sys.executable),
        "gil_enabled": getattr(sys, "_is_gil_enabled", lambda: True)(),
        "build_environment": {
            key: os.environ.get(key)
            for key in (
                "PATH",
                "INCLUDE",
                "LIB",
                "CC",
                "CXX",
                "CFLAGS",
                "CXXFLAGS",
                "CPPFLAGS",
                "LDFLAGS",
                "PYTHONPATH",
                "PYTHONHOME",
            )
        },
    }


def ninja_binary(explicit=None):
    path = Path(explicit or shutil.which("ninja") or "").resolve()
    # Chocolatey's PATH entry is a location-dependent launcher, not Ninja itself.
    actual = path.parent.parent / "lib/ninja/tools/ninja.exe"
    if explicit is None and path.parent.name.lower() == "bin" and actual.is_file():
        path = actual
    if not path.is_file():
        raise ValueError("Ninja not found; provide --ninja with its executable path")
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--source", default="GM8E01_00")
    parser.add_argument("--target")
    parser.add_argument("--dtk", type=Path)
    parser.add_argument(
        "--ninja",
        type=Path,
        help="Ninja executable (defaults to PATH, resolving Chocolatey shims)",
    )
    parser.add_argument(
        "--stage",
        choices=("coverage", "discover", "verify", "both", "all"),
        default="both",
    )
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--build-jobs", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=40)
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--only",
        action="append",
        metavar="UNIT",
        help="run only an exact proposed unit name; repeat for multiple units",
    )
    parser.add_argument("--resume", metavar="RUN_ID")
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.worker:
        worker(args.worker)
        return
    if min(args.workers, args.build_jobs, args.batch_size) < 1 or (
        args.limit is not None and args.limit < 1
    ):
        parser.error("workers, build jobs, batch size and limit must be positive")
    root = args.project_root.resolve()
    if not (root / "configure.py").is_file():
        parser.error("project root must contain configure.py")
    runs = root / "build" / "parallel-migration" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    with project_lock(root):
        if args.resume:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", args.resume) or args.resume in (
                ".",
                "..",
            ):
                parser.error("resume must be a run ID, not a path")
            run_dir = runs / args.resume
            run = read_json(run_dir / "run.json")
            if run.get("schema") != SCHEMA:
                raise RuntimeError("Unsupported run schema")
            if str(root) != run["project_root"]:
                raise RuntimeError("Resume project root does not match")
            if (
                digest_file(run["frozen_dtk"]) != run["environment"]["dtk"]
                or digest_file(run["frozen_ninja"]) != run["environment"]["ninja"]
            ):
                raise RuntimeError("Frozen tool binaries changed")
            check_toolchain(run)
            for name, checksum in run["environment"]["tooling"].items():
                if digest_file(run_dir / "tooling" / name) != checksum:
                    raise RuntimeError("Frozen worker scripts changed")
            publication = run_dir / "publication.json"
            if publication.exists():
                journal = read_json(publication)
                if journal["status"] == "published":
                    expected = dict(run["owner_manifest"])
                    expected.update(
                        {n: c["after_sha256"] for n, c in journal["changes"].items()}
                    )
                    if snapshot_manifest(root) != expected:
                        raise RuntimeError(
                            "Published project has changed; start a new run"
                        )
                    if symbol_mappings(root) != run["symbol_mappings"]:
                        raise RuntimeError(
                            "Published objdiff symbol mappings changed; start a new run"
                        )
                    print(f"Run {args.resume} already published; evidence: {run_dir}")
                    return
            if (
                environment_identity(Path(run["dtk"]), Path(run["ninja"]))
                != run["environment"]
            ):
                raise RuntimeError(
                    "Tools, scripts or interpreter changed; start a new run"
                )
            if publication.exists():
                journal = read_json(publication)
                conflicts = restore_publication(root, journal)
                if conflicts:
                    raise RuntimeError(
                        f"Publication recovery preserves intervening user edits: {conflicts}"
                    )
            if snapshot_manifest(root) != run["owner_manifest"]:
                raise RuntimeError("Project baseline changed; start a new run")
            if symbol_mappings(root) != run["symbol_mappings"]:
                raise RuntimeError("Objdiff symbol mappings changed; start a new run")
        else:
            if not args.target or not args.dtk:
                parser.error("--target and --dtk are required for a new run")
            for version in (args.source, args.target):
                if not re.fullmatch(r"[A-Za-z0-9_-]+", version):
                    parser.error("version must be a simple configuration name")
            dtk = args.dtk.resolve(strict=True)
            ninja = ninja_binary(args.ninja)
            run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
            run_dir = runs / run_id
            run_dir.mkdir()
            manifest = snapshot_manifest(root)
            suffix = ".exe" if os.name == "nt" else ""
            required = [
                root / "build/compilers",
                root / f"build/tools/objdiff-cli{suffix}",
                root / "build/tools/sjiswrap.exe",
            ]
            if any(not path.exists() for path in required):
                raise RuntimeError(
                    "Build the project once to install its compiler, objdiff and sjiswrap tools before snapshotting"
                )
            source_bytes = sum((root / name).stat().st_size for name in manifest)
            stage_count = 3 if args.stage == "all" else 2 if args.stage == "both" else 1
            preflight_space(run_dir, source_bytes, (args.workers + 2) * stage_count)
            env = environment_identity(dtk, ninja)
            (run_dir / "tools").mkdir()
            (run_dir / "tooling").mkdir()
            frozen_dtk = run_dir / "tools" / dtk.name
            frozen_ninja = run_dir / "tools" / ninja.name
            shutil.copy2(dtk, frozen_dtk)
            shutil.copy2(ninja, frozen_ninja)
            for name in env["tooling"]:
                shutil.copy2(tooling_source(name), run_dir / "tooling" / name)
            toolchain_manifest = {
                n: h
                for n, h in manifest.items()
                if n.startswith(("build/compilers/", "build/tools/", "build/binutils/"))
            }
            toolchain_root = run_dir / "toolchain"
            copy_snapshot(root, toolchain_root, toolchain_manifest)
            run = {
                "schema": SCHEMA,
                "run_id": run_id,
                "project_root": str(root),
                "owner_manifest": manifest,
                "symbol_mappings": symbol_mappings(root),
                "source": args.source,
                "target": args.target,
                "dtk": str(dtk),
                "ninja": str(ninja),
                "frozen_dtk": str(frozen_dtk),
                "frozen_ninja": str(frozen_ninja),
                "environment": env,
                "toolchain_root": str(toolchain_root),
                "toolchain_manifest": toolchain_manifest,
                "tooling_root": str(run_dir / "tooling"),
                "workers": args.workers,
                "build_jobs": args.build_jobs,
                "batch_size": args.batch_size,
                "limit": args.limit,
                "only": args.only or [],
                "stage": args.stage,
            }
            check_frozen_environment(run)
            write_json(run_dir / "run.json", run)
        print(
            f"Run {run['run_id']}: {run['workers']} workers × {run['build_jobs']} build jobs",
            flush=True,
        )
        started = time.monotonic()
        current = root
        results = {}
        stages = (
            ("coverage", "discover", "verify")
            if run["stage"] == "all"
            else ("discover", "verify")
            if run["stage"] == "both"
            else (run["stage"],)
        )
        for stage in stages:
            current, results[stage] = run_stage(run_dir, run, stage, current)
        report = publish(root, current, run_dir, run, results)
        summary = {
            "schema": SCHEMA,
            "run_id": run["run_id"],
            "final": report["measures"],
            "seconds": time.monotonic() - started,
            "stages": {
                s: {k: v for k, v in r.items() if k != "report"}
                for s, r in results.items()
            },
        }
        write_json(run_dir / "result.json", summary)
        print(json.dumps(summary["final"], indent=2))
        print(f"Verified evidence: {run_dir}")


if __name__ == "__main__":
    main()
