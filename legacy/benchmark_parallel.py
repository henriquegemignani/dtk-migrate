#!/usr/bin/env python3
"""Replay a frozen prepared run without publishing, comparing cold and warm pools."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import parallel_migration as runner
from migration_workspace import (
    copy_snapshot,
    project_lock,
    reset_workspace,
    snapshot_manifest,
)


def evidence(result):
    return {
        "accepted": result["accepted"],
        "deferred": result["deferred"],
        "selected": result.get("selected", {}),
        "measures": result["report"]["measures"],
        "dol_sha1": result["dol_sha1"],
        "validation": result["validation"],
        "report_sha256": hashlib.sha256(
            json.dumps(result["report"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument(
        "--stage", choices=("coverage", "discover", "verify"), default="discover"
    )
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument(
        "--cold-only",
        action="store_true",
        help="run one fresh-pool sample per worker count for equivalence acceptance",
    )
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("repetitions must be positive")
    run_dir = args.run_dir.resolve()
    run: dict[str, Any] = runner.read_json(run_dir / "run.json")
    stage = args.stage
    prepared = runner.read_json(run_dir / stage / "prepared.json")
    baseline = run_dir / stage / "baseline"
    manifest = cast(dict[str, str], runner.read_json(run_dir / stage / "manifest.json"))
    if (
        snapshot_manifest(baseline) != manifest
        or runner.symbol_mappings(baseline) != prepared["symbol_mappings"]
    ):
        raise RuntimeError("Frozen baseline changed")
    for name, expected in (
        (run["frozen_dtk"], run["environment"]["dtk"]),
        (run["frozen_ninja"], run["environment"]["ninja"]),
    ):
        if runner.digest_file(name) != expected:
            raise RuntimeError("Frozen tool changed")
    # Keep legacy compiler working directories short on Windows.
    output = (
        run_dir.parent.parent
        / "benchmarks"
        / datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    )
    # A replay can validate newer tooling against unchanged game inputs. Freeze that
    # revision separately, so workers and the coordinator use the same implementation.
    (output / "tooling").mkdir(parents=True)
    tooling = runner.tooling_manifest()
    for name in tooling:
        shutil.copy2(runner.tooling_source(name), output / "tooling" / name)
    toolchain_manifest = {
        n: h
        for n, h in manifest.items()
        if n.startswith(("build/compilers/", "build/tools/", "build/binutils/"))
    }
    copy_snapshot(baseline, output / "toolchain", toolchain_manifest)
    run = dict(
        run,
        environment=runner.environment_identity(
            Path(run["frozen_dtk"]), Path(run["frozen_ninja"])
        ),
        toolchain_root=str(output / "toolchain"),
        toolchain_manifest=toolchain_manifest,
        tooling_root=str(output / "tooling"),
    )
    samples: list[dict[str, Any]] = []
    canonical = None
    with project_lock(Path(cast(str, run["project_root"]))):
        for repetition in range(args.repetitions):
            # Alternate order to reduce warm OS cache / thermal bias.
            for count in (1, 3) if repetition % 2 == 0 else (3, 1):
                trial = output / f"r{repetition}" / f"w{count}"
                config = dict(run, workers=count)
                for phase in ("cold",) if args.cold_only else ("cold", "warm"):
                    started = time.monotonic()
                    outcomes = runner.execute_jobs(
                        output,
                        config,
                        stage,
                        trial,
                        baseline,
                        manifest,
                        prepared["candidates"],
                        epoch=phase,
                        pool_root=trial / "pool",
                    )
                    integration_started = time.monotonic()
                    integration = trial / "integration"
                    reset_workspace(baseline, integration, manifest)
                    runner.seed_objdiff(baseline, integration)
                    ctx = runner.context(
                        integration,
                        config,
                        stage,
                        trial / f"{phase}-integration",
                        run["build_jobs"],
                    )
                    result = runner.integrate(
                        ctx, stage, prepared["candidates"], outcomes
                    )
                    seconds = time.monotonic() - started
                    current = evidence(result)
                    runner.check_frozen_environment(run)
                    if canonical is None:
                        canonical = current
                    if canonical != current:
                        raise RuntimeError(
                            "One-worker/three-worker integrated evidence differs"
                        )
                    samples.append(
                        {
                            "repetition": repetition,
                            "workers": count,
                            "phase": phase,
                            "seconds": seconds,
                            "integration_seconds": time.monotonic()
                            - integration_started,
                            "accepted_per_minute": 60
                            * len(result["accepted"])
                            / seconds,
                        }
                    )
                    runner.write_json(output / "samples.json", samples)
                    print(f"{phase}: {count} workers, {seconds:.2f}s", flush=True)
        phases = ("cold",) if args.cold_only else ("cold", "warm")
        medians = {
            f"{phase}-{count}": statistics.median(
                s["seconds"]
                for s in samples
                if s["phase"] == phase and s["workers"] == count
            )
            for phase in phases
            for count in (1, 3)
        }
        speedup_phase = "cold" if args.cold_only else "warm"
        result = {
            "run_id": run["run_id"],
            "stage": stage,
            "tooling": tooling,
            "candidates": len(prepared["candidates"]),
            "samples": samples,
            "median_seconds": medians,
            "speedup": medians[f"{speedup_phase}-1"] / medians[f"{speedup_phase}-3"],
            "speedup_phase": speedup_phase,
            "warm_speedup": (
                None if args.cold_only else medians["warm-1"] / medians["warm-3"]
            ),
            "evidence": canonical,
            "disk_bytes": sum(
                p.stat().st_size for p in output.rglob("*") if p.is_file()
            ),
            "measurement": "Private replay including pool setup/reset, builds and union integration; excludes matcher preparation and owner publication",
        }
        runner.write_json(output / "result.json", result)
        print(f"Benchmark evidence: {output / 'result.json'}")


if __name__ == "__main__":
    main()
