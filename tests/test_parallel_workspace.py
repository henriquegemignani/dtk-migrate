"""Filesystem isolation and real subprocess-tree lifecycle regression tests."""

import ctypes
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import migration_workspace as workspace


def write(root, relative, content="input"):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def alive(pid):
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.OpenProcess(0x00100000, False, pid)
        if not handle:
            return False
        try:
            return kernel.WaitForSingleObject(handle, 0) == 258
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "source"
        self.root.mkdir()

    def test_dirty_untracked_and_submodules_are_isolated(self):
        write(self.root, "src/dirty.cpp", "unsaved commit")
        write(self.root, "new.cpp", "untracked")
        write(self.root, "vendor/library/file", "submodule working state")
        write(self.root, "vendor/library/.git", "gitdir elsewhere")
        write(self.root, "build/compilers/mwcceppc.exe", "compiler")
        write(self.root, "build/tools/dtk.exe", "tool")
        write(self.root, "build/PAL/main.dol", "generated")
        write(self.root, "build.ninja", "generated")
        write(self.root, "objdiff.json", "generated")
        write(self.root, ".migration.lock", "lock")
        manifest = workspace.snapshot_manifest(self.root)
        self.assertEqual(
            set(manifest),
            {
                "src/dirty.cpp",
                "new.cpp",
                "vendor/library/file",
                "build/compilers/mwcceppc.exe",
                "build/tools/dtk.exe",
            },
        )
        destination = self.root.parent / "copy"
        workspace.copy_snapshot(self.root, destination, manifest)
        self.assertEqual(manifest, workspace.snapshot_manifest(destination))
        (destination / "new.cpp").write_text("edited worker")
        self.assertEqual((self.root / "new.cpp").read_text(), "untracked")

    def test_snapshot_inside_excluded_build_artifacts(self):
        write(self.root, "input")
        manifest = workspace.snapshot_manifest(self.root)
        destination = self.root / "build/parallel-migration/runs/run/baseline"
        workspace.copy_snapshot(self.root, destination, manifest)
        self.assertEqual(manifest, workspace.snapshot_manifest(destination))
        self.assertEqual(manifest, workspace.snapshot_manifest(self.root))

    def test_lock_released_after_coordinator_crash(self):
        marker = self.root.parent / "ready"
        source_root = str(Path(workspace.__file__).resolve().parent)
        code = "from pathlib import Path; import sys,time; "
        code += (
            "sys.path.insert(0, "
            + repr(source_root)
            + "); from migration_workspace import project_lock; "
        )
        code += (
            "lock = project_lock(Path("
            + repr(str(self.root))
            + ")); lock.__enter__(); "
        )
        code += "Path(" + repr(str(marker)) + ").write_text('ready'); time.sleep(60)"
        process = subprocess.Popen([sys.executable, "-c", code])
        try:
            deadline = time.monotonic() + 10
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.025)
            self.assertTrue(marker.exists())
            with self.assertRaises(RuntimeError), workspace.project_lock(self.root):
                pass
        finally:
            process.kill()
            process.wait()
        with workspace.project_lock(self.root):
            pass

    def test_hash_detects_source_change(self):
        path = write(self.root, "file")
        manifest = workspace.snapshot_manifest(self.root)
        path.write_text("changed")
        with self.assertRaisesRegex(RuntimeError, "changed"):
            workspace.copy_snapshot(self.root, self.root.parent / "copy", manifest)

    def test_reset_restores_inputs_and_keeps_private_build_outputs(self):
        write(self.root, "src/file")
        manifest = workspace.snapshot_manifest(self.root)
        destination = self.root.parent / "copy"
        workspace.copy_snapshot(self.root, destination, manifest)
        write(destination, "src/file", "modified")
        write(destination, "new/file", "unwanted")
        write(destination, "build/PAL/cache.o", "private cache")
        workspace.reset_workspace(self.root, destination, manifest)
        self.assertEqual(workspace.snapshot_manifest(destination), manifest)
        self.assertEqual(
            (destination / "build/PAL/cache.o").read_text(), "private cache"
        )

    def test_no_copy_into_source(self):
        write(self.root, "file")
        with self.assertRaises(ValueError):
            workspace.copy_snapshot(
                self.root, self.root / "nested", workspace.snapshot_manifest(self.root)
            )

    def test_rejects_path_escape(self):
        with self.assertRaises(ValueError):
            workspace.copy_snapshot(
                self.root, self.root.parent / "copy", {"../escape": "hash"}
            )

    def test_link_is_rejected(self):
        target = write(self.root.parent, "external/file")
        try:
            (self.root / "link").symlink_to(target)
        except OSError:
            self.skipTest("Symlink privilege unavailable")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            workspace.snapshot_manifest(self.root)

    @unittest.skipUnless(os.name == "nt", "Windows junction safety")
    def test_junction_is_rejected(self):
        target = self.root.parent / "external"
        target.mkdir()
        junction = self.root / "junction"
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
            capture_output=True,
            check=False,
        )
        if result.returncode:
            self.skipTest("Junction unavailable")
        try:
            with self.assertRaisesRegex(ValueError, "reparse"):
                workspace.snapshot_manifest(self.root)
        finally:
            junction.rmdir()

    def test_disk_preflight(self):
        with patch.object(workspace.shutil, "disk_usage") as usage:
            usage.return_value.free = 1
            with self.assertRaisesRegex(OSError, "Insufficient disk"):
                workspace.preflight_space(self.root, 100, 3)
            usage.return_value.free = 10**12
            workspace.preflight_space(self.root, 100, 3)

    def test_fingerprint_is_order_independent(self):
        self.assertEqual(
            workspace.fingerprint({"b": "2", "a": "1"}),
            workspace.fingerprint({"a": "1", "b": "2"}),
        )

    def test_project_lock_contention_and_release(self):
        with (
            workspace.project_lock(self.root),
            self.assertRaisesRegex(RuntimeError, "Another migration"),
            workspace.project_lock(self.root),
        ):
            self.fail("Lock should not be acquired")
        with workspace.project_lock(self.root):
            pass
        self.assertNotIn(workspace.LOCK_NAME, workspace.snapshot_manifest(self.root))


class CommandTests(unittest.TestCase):
    def test_cancelled_scope_cannot_start_late_command(self):
        event = threading.Event()
        event.set()
        workspace.cancel_commands()
        with tempfile.TemporaryFile(mode="w+") as log:
            with patch.object(subprocess, "Popen") as popen:
                with self.assertRaises(subprocess.CalledProcessError) as error:
                    workspace.run_command(
                        [sys.executable, "-c", "print('late')"],
                        cwd=Path.cwd(),
                        env=os.environ,
                        log=log,
                        cancel_event=event,
                    )
                popen.assert_not_called()
                self.assertEqual(error.exception.returncode, -9)
            # Cancellation is attached to that scheduler, not globally latched.
            output = workspace.run_command(
                [sys.executable, "-c", "print('unrelated')"],
                cwd=Path.cwd(),
                env=os.environ,
                log=log,
                capture=True,
            )
            self.assertEqual(output.strip(), "unrelated")

    def test_cancel_during_process_creation_cannot_escape_registration(self):
        event = threading.Event()
        creation_entered = threading.Event()
        cancellation_started = threading.Event()
        actual_popen = subprocess.Popen
        errors = []

        def slow_creation(*args, **kwargs):
            creation_entered.set()
            if not cancellation_started.wait(10):
                raise RuntimeError("Cancellation did not start")
            return actual_popen(*args, **kwargs)

        def cancel():
            if not creation_entered.wait(10):
                return
            event.set()
            cancellation_started.set()
            workspace.cancel_commands()

        with tempfile.TemporaryFile(mode="w+") as log:

            def run():
                try:
                    workspace.run_command(
                        [sys.executable, "-c", "import time; time.sleep(60)"],
                        cwd=Path.cwd(),
                        env=os.environ,
                        log=log,
                        cancel_event=event,
                    )
                except subprocess.CalledProcessError as error:
                    errors.append(error)

            with patch.object(subprocess, "Popen", slow_creation):
                runner = threading.Thread(target=run)
                canceller = threading.Thread(target=cancel)
                runner.start()
                canceller.start()
                runner.join(10)
                canceller.join(10)
            if runner.is_alive():
                workspace.cancel_commands()
                runner.join(10)
            self.assertFalse(runner.is_alive())
            self.assertFalse(canceller.is_alive())
            self.assertEqual(len(errors), 1)

    def test_capture_and_failure(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as log:
            output = workspace.run_command(
                [sys.executable, "-c", "print('hello')"],
                cwd=Path.cwd(),
                env=os.environ,
                log=log,
                capture=True,
            )
            self.assertEqual(output.strip(), "hello")
            with self.assertRaises(subprocess.CalledProcessError) as error:
                workspace.run_command(
                    [sys.executable, "-c", "raise SystemExit(7)"],
                    cwd=Path.cwd(),
                    env=os.environ,
                    log=log,
                )
            self.assertEqual(error.exception.returncode, 7)

    def tree_command(self, marker):
        child = (
            "import os,time,pathlib; pathlib.Path("
            + repr(str(marker))
            + ").write_text(str(os.getpid())); time.sleep(60)"
        )
        return [
            sys.executable,
            "-c",
            "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',"
            + repr(child)
            + "]); time.sleep(60)",
        ]

    def await_marker(self, marker):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if marker.exists() and marker.read_text():
                return int(marker.read_text())
            time.sleep(0.025)
        self.fail("Descendant never became ready")

    def assert_dead(self, pid):
        deadline = time.monotonic() + 5
        while alive(pid) and time.monotonic() < deadline:
            time.sleep(0.025)
        self.assertFalse(alive(pid), f"Descendant {pid} survived cancellation")

    def test_coordinator_cancellation_kills_descendants(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            tempfile.TemporaryFile(mode="w+") as log,
        ):
            marker = Path(directory) / "pid"
            errors = []

            def run():
                try:
                    workspace.run_command(
                        self.tree_command(marker),
                        cwd=directory,
                        env=os.environ,
                        log=log,
                    )
                except subprocess.CalledProcessError as error:
                    errors.append(error)

            thread = threading.Thread(target=run)
            thread.start()
            try:
                pid = self.await_marker(marker)
            finally:
                workspace.cancel_commands()
                thread.join(10)
            self.assertFalse(thread.is_alive())
            self.assertEqual(len(errors), 1)
            self.assert_dead(pid)

    def test_keyboard_interrupt_kills_descendants(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            tempfile.TemporaryFile(mode="w+") as log,
        ):
            marker = Path(directory) / "pid"
            descendant = []

            def interrupted(*args, **kwargs):
                descendant.append(self.await_marker(marker))
                raise KeyboardInterrupt

            with (
                patch.object(subprocess.Popen, "communicate", interrupted),
                self.assertRaises(KeyboardInterrupt),
            ):
                workspace.run_command(
                    self.tree_command(marker),
                    cwd=directory,
                    env=os.environ,
                    log=log,
                )
            self.assert_dead(descendant[0])


if __name__ == "__main__":
    unittest.main()
