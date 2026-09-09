"""Private snapshots and bounded process trees for local migration workers."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

LOCK_NAME = ".migration.lock"
_CACHE_NAMES = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".cache",
    ".venv",
    "venv",
    ".migration-runs",
    ".parallel-migration",
}
_GENERATED_ROOT = {
    "objdiff.json",
    "build.ninja",
    "compile_commands.json",
    ".ninja_log",
    ".ninja_deps",
    LOCK_NAME,
}


def _included(relative: Path) -> bool:
    parts = relative.parts
    if any(part in _CACHE_NAMES for part in parts):
        return False
    if len(parts) == 1 and parts[0] in _GENERATED_ROOT:
        return False
    if parts[0] == "build":
        return len(parts) == 1 or parts[1] in {"compilers", "tools", "binutils"}
    return True


def _reject_link(path: Path) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError(f"Snapshot paths cannot be symlinks or reparse points: {path}")


def _check_ancestors(path: Path) -> None:
    for parent in reversed((path, *path.parents)):
        if parent.exists() or parent.is_symlink():
            _reject_link(parent)


def _safe_path(root: Path, relative: str) -> Path:
    parts = PurePosixPath(relative).parts
    if (
        not parts
        or PurePosixPath(relative).is_absolute()
        or any(p in {".", ".."} or ":" in p or "\\" in p for p in parts)
    ):
        raise ValueError(f"Unsafe manifest path: {relative}")
    current = root
    _check_ancestors(current)
    for part in parts:
        current = current / part
        if current.exists() or current.is_symlink():
            _reject_link(current)
    return current


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def snapshot_manifest(root: Path) -> dict[str, str]:
    """Hash actual inputs, including untracked files and populated submodules."""
    root = Path(root).absolute()
    _check_ancestors(root)
    if not root.is_dir():
        raise ValueError(f"Snapshot root is not a directory: {root}")
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        dirs[:] = sorted(
            name for name in dirs if _included((base / name).relative_to(root))
        )
        for name in dirs:
            _reject_link(base / name)
        for name in sorted(files):
            path = base / name
            relative = path.relative_to(root)
            if _included(relative):
                _reject_link(path)
                if not path.is_file():
                    raise ValueError(f"Snapshot input is not a regular file: {path}")
                result[relative.as_posix()] = _hash(path)
    return result


def fingerprint(manifest: dict[str, str]) -> str:
    return hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def preflight_space(parent: Path, source_bytes: int, copies: int) -> None:
    """Reserve the copies plus 25% headroom and 256 MiB per private build."""
    if source_bytes < 0 or copies < 1:
        raise ValueError("Source size must be nonnegative and copies must be positive")
    parent = Path(parent).absolute()
    while not parent.exists():
        parent = parent.parent
    required = copies * (source_bytes + max(source_bytes // 4, 256 * 1024 * 1024))
    available = shutil.disk_usage(parent).free
    if available < required:
        raise OSError(
            f"Insufficient disk space: need {required:,} bytes, have {available:,}"
        )


def copy_snapshot(source: Path, dest: Path, manifest: dict[str, str]) -> None:
    source, dest = Path(source).absolute(), Path(dest).absolute()
    _check_ancestors(source)
    _check_ancestors(dest)
    if dest == source or (
        source in dest.parents and _included(dest.relative_to(source))
    ):
        raise ValueError("Snapshot destination must be outside source inputs")
    sources = {relative: _safe_path(source, relative) for relative in manifest}
    preflight_space(
        dest.parent, sum(path.stat().st_size for path in sources.values()), 1
    )
    dest.mkdir(parents=True, exist_ok=True)
    _reject_link(dest)
    for relative, path in sources.items():
        target = _safe_path(dest, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        if _hash(target) != manifest[relative]:
            raise RuntimeError(f"Input changed while snapshotting: {relative}")


def reset_workspace(baseline: Path, workspace: Path, manifest: dict[str, str]) -> None:
    baseline, workspace = Path(baseline).absolute(), Path(workspace).absolute()
    if (
        baseline == workspace
        or baseline in workspace.parents
        or workspace in baseline.parents
    ):
        raise ValueError("Baseline and worker must be separate directories")
    _check_ancestors(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    # Validate both trees before removing anything. Generated outputs are retained.
    current = snapshot_manifest(workspace)
    for relative in manifest:
        source = _safe_path(baseline, relative)
        if _hash(source) != manifest[relative]:
            raise RuntimeError(f"Baseline changed: {relative}")
        _safe_path(workspace, relative)
    for relative in current.keys() - manifest.keys():
        _safe_path(workspace, relative).unlink()
    for relative, expected in manifest.items():
        if current.get(relative) != expected:
            target = _safe_path(workspace, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(_safe_path(baseline, relative), target)
            # Cached outputs may describe a previous trial. Restoring an old
            # timestamp would let Ninja treat different input bytes as up to date.
            os.utime(target, None)
            if _hash(target) != expected:
                raise RuntimeError(f"Baseline changed during reset: {relative}")


@contextmanager
def project_lock(root: Path):
    """Non-blocking OS lock, released automatically if the coordinator dies."""
    root = Path(root).absolute()
    path = _safe_path(root, LOCK_NAME)
    with path.open("a+b") as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeError(
                f"Another migration owns the project lock: {root}"
            ) from error
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class _WindowsJob:
    """Kill-on-close Job Object; child starts suspended until assigned."""

    def __init__(self):
        from ctypes import wintypes as w

        class Basic(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", w.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", w.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", w.DWORD),
                ("SchedulingClass", w.DWORD),
            ]

        class IO(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_uint64)
                for name in (
                    "ReadOperationCount",
                    "WriteOperationCount",
                    "OtherOperationCount",
                    "ReadTransferCount",
                    "WriteTransferCount",
                    "OtherTransferCount",
                )
            ]

        class Extended(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", Basic),
                ("IoInfo", IO),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = w.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [
            w.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            w.DWORD,
        ]
        self.kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        info = Extended()
        info.BasicLimitInformation.LimitFlags = (
            0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        if not self.kernel.SetInformationJobObject(
            self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def assign_and_resume(self, process):
        if not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())
        resume = ctypes.WinDLL("ntdll").NtResumeProcess
        resume.argtypes = [ctypes.c_void_p]
        resume.restype = ctypes.c_long
        status = resume(int(process._handle))
        if status != 0:
            raise OSError(f"NtResumeProcess failed: {status:#x}")

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def run_command(cmd, *, cwd, env, log, capture=False, cancel_event=None):
    """Run in a private process tree and kill all descendants on every exit."""
    job = _WindowsJob() if os.name == "nt" else None
    process = None
    try:
        options = (
            {"creationflags": 0x00000004 | subprocess.CREATE_NO_WINDOW}
            if job
            else {"start_new_session": True}
        )
        with _ACTIVE_LOCK:
            if cancel_event is not None and cancel_event.is_set():
                raise subprocess.CalledProcessError(-9, cmd)
            process = subprocess.Popen(
                cmd,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE if capture else log,
                stderr=log,
                text=True,
                encoding="utf-8",
                errors="replace",
                **options,
            )
            _ACTIVE_COMMANDS[process] = job
            if job:
                job.assign_and_resume(process)
        output, _ = process.communicate()
        if capture and output:
            log.write(output)
            log.flush()
        with _ACTIVE_LOCK:
            cancelled = process in _CANCELLED_COMMANDS
        if process.returncode or cancelled:
            raise subprocess.CalledProcessError(
                process.returncode or -9, cmd, output=output
            )
        return output if capture else None
    finally:
        with _ACTIVE_LOCK:
            if process is not None:
                _terminate(process, job)
                _ACTIVE_COMMANDS.pop(process, None)
                _CANCELLED_COMMANDS.discard(process)
            elif job:
                job.close()
        if process is not None:
            process.wait()


# The coordinator can interrupt calls owned by scheduler threads. Access to process
# registration and Job Object close is serialized, including process creation.
import threading

_ACTIVE_LOCK = threading.RLock()
_ACTIVE_COMMANDS = {}
_CANCELLED_COMMANDS = set()


def _terminate(process, job):
    if job:
        job.close()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if process.poll() is None:
        process.kill()


def cancel_commands():
    """Terminate every command currently owned by this coordinator process."""
    with _ACTIVE_LOCK:
        for process, job in list(_ACTIVE_COMMANDS.items()):
            _CANCELLED_COMMANDS.add(process)
            _terminate(process, job)
