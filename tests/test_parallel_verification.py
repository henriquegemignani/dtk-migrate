import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from migration_runtime import ValidationError
from verification_adapter import (
    ConfigChangedError,
    _replace,
    evaluate,
    prepare,
    validate,
)
from verify_source_units import BEGIN, END

CONFIG = """VERSIONS = ["NTSC", "PAL", "JP"]
objects = [Object(MatchingFor("NTSC", "JP"), "A.cpp"),
           Object(NonMatching, "B.cpp"), Object(NonMatching, "C.cpp")]
"""


class FixtureContext:
    target = "PAL"
    ninja = "ninja"

    def __init__(self, root):
        self.root = root
        self.reject = set()
        self.omit = set()
        self.bad_complete = set()
        self.fatal = False
        self.nonmatching_section = set()
        self.builds = []

    def enabled(self):
        ns = {
            "Object": lambda status, name: (name, status),
            "NonMatching": False,
            "MatchingFor": lambda *versions: self.target in versions,
        }
        exec((self.root / "configure.py").read_text(), ns)
        return dict(ns["objects"])

    def build(self):
        if self.fatal:
            raise OSError("infrastructure failure")
        flags = self.enabled()
        self.builds.append({name for name, enabled in flags.items() if enabled})
        if self.reject & self.builds[-1]:
            raise ValidationError("retail bytes differ")
        return {
            "measures": {"matched_code": "48"},
            "units": [
                {
                    "metadata": {
                        "source_path": f"src/{name}",
                        "complete": enabled and name not in self.bad_complete,
                    },
                    "measures": {"matched_code": "16"},
                    "sections": [
                        {"name": ".text", "fuzzy_match_percent": 100},
                        {
                            "name": ".data",
                            "fuzzy_match_percent": 0
                            if name in self.nonmatching_section
                            else 100,
                        },
                    ],
                }
                for name, enabled in flags.items()
            ],
        }

    def run(self, cmd, capture=False):
        assert cmd == ["ninja", "-t", "inputs", "build/PAL/main.elf"] and capture
        return "\n".join(
            f"build/PAL/src/{Path(name).stem}.o"
            for name, enabled in self.enabled().items()
            if enabled and name not in self.omit
        )


class VerificationAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "configure.py"
        self.path.write_bytes(CONFIG.replace("\n", "\r\n").encode())
        self.ctx = FixtureContext(self.root)
        self.objdiff = {
            "units": [
                {
                    "metadata": {"source_path": f"src/{name}.cpp"},
                    "base_path": f"build/PAL/src/{name}.o",
                }
                for name in "ABC"
            ]
        }
        (self.root / "objdiff.json").write_text(json.dumps(self.objdiff))

    def test_prepare_uses_all_sections_and_stable_ties(self):
        self.ctx.nonmatching_section = {"B.cpp"}
        result = prepare(self.ctx, limit=1)
        self.assertEqual(result["candidates"], [{"name": "A.cpp"}])

    def test_bisection_preserves_order_and_rolls_back_failed_sibling(self):
        prepared = prepare(self.ctx)
        self.ctx.reject = {"B.cpp"}
        result = evaluate(self.ctx, prepared["candidates"])
        self.assertEqual(result["accepted"], [{"name": "A.cpp"}, {"name": "C.cpp"}])
        self.assertEqual(result["deferred"], [{"name": "B.cpp"}])
        self.assertEqual(
            self.ctx.enabled(), {"A.cpp": True, "B.cpp": False, "C.cpp": True}
        )
        self.assertIn(b'MatchingFor("NTSC", "PAL", "JP")', self.path.read_bytes())
        self.assertIn(b"\r\n", self.path.read_bytes())
        self.assertEqual(self.ctx.builds[-1], {"A.cpp", "C.cpp"})

    def test_missing_actual_compiled_input_is_deferred(self):
        self.ctx.omit = {"A.cpp"}
        result = evaluate(self.ctx, [{"name": "A.cpp"}, {"name": "B.cpp"}])
        self.assertEqual(result["accepted"], [{"name": "B.cpp"}])
        self.assertIn("not an input", result["events"][0]["reason"])

    def test_report_flag_is_required_even_when_graph_links_object(self):
        self.ctx.bad_complete = {"A.cpp"}
        result = evaluate(self.ctx, [{"name": "A.cpp"}])
        self.assertEqual(result["accepted"], [])
        self.assertEqual(result["deferred"], [{"name": "A.cpp"}])

    def test_fatal_error_restores_exact_bytes(self):
        original = self.path.read_bytes()
        self.ctx.fatal = True
        with self.assertRaises(OSError):
            evaluate(self.ctx, [{"name": "A.cpp"}])
        self.assertEqual(self.path.read_bytes(), original)

    def test_fatal_build_preserves_intervening_user_edit(self):
        user_edit = CONFIG.encode() + b"# user changed this during build\n"

        def fail():
            self.path.write_bytes(user_edit)
            raise OSError("build failed after user edit")

        for operation in (
            lambda: prepare(self.ctx),
            lambda: evaluate(self.ctx, [{"name": "A.cpp"}]),
        ):
            with (
                self.subTest(operation=operation),
                patch.object(self.ctx, "build", side_effect=fail),
            ):
                self.path.write_bytes(CONFIG.encode())
                with self.assertRaisesRegex(OSError, "after user edit"):
                    operation()
                self.assertEqual(self.path.read_bytes(), user_edit)

    def test_atomic_replace_refuses_unowned_bytes(self):
        expected = self.path.read_bytes()
        user_edit = expected + b"# user edit\n"
        self.path.write_bytes(user_edit)
        with self.assertRaises(ConfigChangedError):
            _replace(self.path, expected, b"replacement")
        self.assertEqual(self.path.read_bytes(), user_edit)

    def test_successful_build_with_intervening_edit_is_not_accepted(self):
        build = self.ctx.build

        def changed():
            report = build()
            self.path.write_bytes(
                self.path.read_bytes() + b"# edited during successful build\n"
            )
            return report

        with patch.object(self.ctx, "build", side_effect=changed):
            with self.assertRaises(ConfigChangedError):
                evaluate(self.ctx, [{"name": "A.cpp"}])
        self.assertIn(b"# edited during successful build", self.path.read_bytes())

    def test_prepare_migrates_and_validates_legacy_baseline(self):
        legacy = (
            BEGIN + "# Version: PAL\nif config.version == 'PAL':\n"
            "    _verified_source_units = {'B.cpp'}\n"
            "    for _verified_lib in config.libs:\n"
            "        for _verified_obj in _verified_lib['objects']:\n"
            "            if _verified_obj.name in _verified_source_units:\n"
            "                _verified_obj.completed = True\n" + END
        )
        self.path.write_text(CONFIG + legacy)
        prepared = prepare(self.ctx)
        self.assertEqual(prepared["migrated_legacy"], {"PAL": ["B.cpp"]})
        self.assertNotIn(BEGIN, self.path.read_text())
        self.ctx.omit = {"B.cpp"}
        with self.assertRaises(ValidationError):
            evaluate(self.ctx, [])

    def test_failed_migration_restores_original(self):
        self.path.write_text(
            CONFIG.replace(
                'Object(NonMatching, "B.cpp")', 'Object(MatchingFor("PAL"), "B.cpp")'
            )
        )
        original = self.path.read_bytes()
        self.ctx.omit = {"B.cpp"}
        with self.assertRaises(ValidationError):
            prepare(self.ctx)
        self.assertEqual(original, self.path.read_bytes())

    def test_ambiguous_objdiff_rejected(self):
        self.objdiff["units"].append(self.objdiff["units"][0])
        (self.root / "objdiff.json").write_text(json.dumps(self.objdiff))
        with self.assertRaisesRegex(ValidationError, "Ambiguous"):
            validate(self.ctx, {"A.cpp"})


if __name__ == "__main__":
    unittest.main()
