"""Explicit build context shared by serial commands and isolated migration jobs."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


class ValidationError(RuntimeError):
    """A successful command produced invalid migration evidence."""


@dataclass(frozen=True)
class BuildContext:
    root: Path
    source: str
    target: str
    dtk: Path
    output: Path
    build_jobs: int = 4
    python: str = sys.executable
    ninja: str = "ninja"
    cancel_event: object = None
    toolchain_root: Path | None = None
    build_timeout: float | None = None

    def run(self, cmd, capture=False, timeout=None):
        from migration_workspace import run_command

        self.output.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env["DTK_MIGRATION_BUILD_JOBS"] = str(self.build_jobs)
        for key in (
            "OMP_NUM_THREADS",
            "OPENBLAS_NUM_THREADS",
            "MKL_NUM_THREADS",
            "RAYON_NUM_THREADS",
        ):
            env[key] = str(self.build_jobs)
        with (self.output / "build.log").open("a", encoding="utf-8") as log:
            log.write("+ " + " ".join(map(str, cmd)) + "\n")
            log.flush()
            try:
                return run_command(
                    list(map(str, cmd)),
                    cwd=self.root,
                    env=env,
                    log=log,
                    capture=capture,
                    cancel_event=self.cancel_event,
                    timeout=timeout,
                )
            except subprocess.CalledProcessError as error:
                log.write(f"! exit status {error.returncode}\n")
                log.flush()
                raise

    def build(self, *, timeout=None):
        command = [
            self.python,
            Path(__file__).with_name("migration_configure.py"),
            "configure",
            "-v",
            self.target,
            "--dtk",
            self.dtk,
            "--ninja",
            self.ninja,
        ]
        # Existing toolchains are inputs, not Ninja download outputs in each copy.
        suffix = ".exe" if os.name == "nt" else ""
        tools = self.toolchain_root or self.root
        for flag, path in (
            ("--compilers", tools / "build/compilers"),
            ("--objdiff", tools / f"build/tools/objdiff-cli{suffix}"),
            ("--sjiswrap", tools / "build/tools/sjiswrap.exe"),
            ("--binutils", tools / "build/binutils"),
        ):
            if path.exists() or (
                self.toolchain_root is not None and flag == "--binutils"
            ):
                command.extend([flag, path])
        self.run(command)
        self.run(
            [
                self.ninja,
                "-j",
                self.build_jobs,
                f"build/{self.target}/report.json",
                f"build/{self.target}/ok",
            ],
            timeout=timeout,
        )
        retail = self.root / "orig" / self.target / "sys/main.dol"
        built = self.root / "build" / self.target / "main.dol"
        if retail.read_bytes() != built.read_bytes():
            raise ValidationError(
                "Retail DOL bytes differ despite passing the checksum target"
            )
        return json.loads(
            (self.root / "build" / self.target / "report.json").read_text(
                encoding="utf-8"
            )
        )

    def trial_build(self):
        """Build a candidate with the run's bounded trial timeout."""
        return self.build(timeout=self.build_timeout)

    def dol_sha1(self):
        return hashlib.sha1(
            (self.root / "build" / self.target / "main.dol").read_bytes()
        ).hexdigest()


def trial_build(ctx):
    """Use bounded candidate builds while retaining small structural test contexts."""
    bounded = getattr(ctx, "trial_build", None)
    return bounded() if bounded is not None else ctx.build()


TRIAL_ERRORS = (
    subprocess.CalledProcessError,
    subprocess.TimeoutExpired,
    ValidationError,
)
