"""Build-system regressions: input timestamps and regenerated Ninja rules."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import migration_workspace as workspace
from migration_runtime import BuildContext
from parallel_migration import ninja_binary


class BuildContextTests(unittest.TestCase):
    def test_trial_timeout_only_bounds_the_incremental_ninja_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "orig/PAL/sys").mkdir(parents=True)
            (root / "build/PAL").mkdir(parents=True)
            (root / "orig/PAL/sys/main.dol").write_bytes(b"retail")
            (root / "build/PAL/main.dol").write_bytes(b"retail")
            (root / "build/PAL/report.json").write_text('{"measures": {}}')
            ctx = BuildContext(
                root,
                "SRC",
                "PAL",
                Path(sys.executable),
                root / "evidence",
                ninja=sys.executable,
                build_timeout=17,
            )
            with patch("migration_workspace.run_command", return_value=None) as run:
                ctx.trial_build()
            self.assertEqual(len(run.call_args_list), 2)
            self.assertIsNone(run.call_args_list[0].kwargs["timeout"])
            self.assertEqual(run.call_args_list[1].kwargs["timeout"], 17)


class BuildSystemTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("ninja"), "Ninja required")
    def test_reset_invalidates_cached_output_from_previous_trial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline, worker = root / "baseline", root / "worker"
            baseline.mkdir()
            (baseline / "input.txt").write_text("baseline")
            os.utime(baseline / "input.txt", (1, 1))
            manifest = workspace.snapshot_manifest(baseline)
            workspace.reset_workspace(baseline, worker, manifest)
            (worker / "build").mkdir()
            # This generated command copies the current input, like DTK consuming splits.
            command = f"\"{sys.executable}\" -c \"import shutil; shutil.copyfile('input.txt', 'build/output.txt')\""
            ninja_file = worker / "build.ninja"
            ninja_file.write_text(
                f"rule generate\n  command = {command}\nbuild build/output.txt: generate input.txt\n"
            )
            (worker / "input.txt").write_text("trial")
            subprocess.run(
                [str(ninja_binary()), "build/output.txt"],
                cwd=worker,
                check=True,
                capture_output=True,
            )
            self.assertEqual((worker / "build/output.txt").read_text(), "trial")
            workspace.reset_workspace(baseline, worker, manifest)
            subprocess.run(
                [str(ninja_binary()), "build/output.txt"],
                cwd=worker,
                check=True,
                capture_output=True,
            )
            self.assertEqual((worker / "build/output.txt").read_text(), "baseline")

    def test_configure_wrapper_retains_split_policy_on_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tools").mkdir()
            (root / "tools/__init__.py").touch()
            (root / "tools/ninja_syntax.py").write_text(
                "import json\nclass Writer:\n"
                " def rule(self, name, command, *args, **kwargs):\n"
                "  with open('rules.jsonl', 'a') as f: f.write(json.dumps([name,command])+'\\n')\n"
            )
            (root / "configure.py").write_text(
                "from tools.ninja_syntax import Writer\n"
                "w=Writer()\nw.rule('split', 'dtk dol split $in $out_dir')\n"
                "w.rule('configure', '$python configure.py $configure_args')\n"
            )
            wrapper = Path(workspace.__file__).with_name("migration_configure.py")
            subprocess.run(
                [sys.executable, str(wrapper)],
                cwd=root,
                check=True,
                env=dict(os.environ, DTK_MIGRATION_BUILD_JOBS="2"),
                capture_output=True,
            )
            split, configure = [
                json.loads(line)
                for line in (root / "rules.jsonl").read_text().splitlines()
            ]
            self.assertIn("dol split --no-update -j 2", split[1])
            self.assertIn(str(wrapper.resolve()), configure[1])
            self.assertTrue(configure[1].endswith("$configure_args"))


if __name__ == "__main__":
    unittest.main()
