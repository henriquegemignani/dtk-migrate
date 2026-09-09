"""Regression tests for migration evidence and reversible configuration generation."""
import unittest
from unittest.mock import patch
from pathlib import Path
import tempfile

import discover_splits as discovery
import split_confidence_loop as scl
from verify_source_units import BEGIN, render_config


def line(start, end, section=".text"):
    return f"\t{section} start:0x{start:08X} end:0x{end:08X}"


class DiscoveryTests(unittest.TestCase):
    def test_keeps_all_code_fragments_for_compiler_comparison(self):
        proposed = {"A.cpp": [line(0x100, 0x120), line(0x140, 0x180), line(0x300, 0x310, ".data")]}
        result = dict(discovery.code_proposals(proposed, {}))
        self.assertEqual([scl.parse_range(l) for l in result["A.cpp"]], [(".text", 0x100, 0x180)])

    def test_extension_preserves_data_and_never_shrinks_existing_code(self):
        existing = {"A.cpp": [line(0x100, 0x160), line(0x300, 0x320, ".data")]}
        proposed = {"A.cpp": [line(0x140, 0x180)]}
        result = dict(discovery.code_proposals(proposed, existing))["A.cpp"]
        self.assertEqual(set(scl.parse_range(l) for l in result),
                         {(".text", 0x100, 0x180), (".data", 0x300, 0x320)})

    def test_cannot_claim_another_existing_unit(self):
        proposed = {"A.cpp": [line(0x100, 0x200)]}
        existing = {"B.cpp": [line(0x180, 0x190)]}
        self.assertEqual(discovery.code_proposals(proposed, existing), [])

    def test_same_range_is_not_a_new_proposal_despite_formatting(self):
        self.assertEqual(discovery.code_proposals({"A.cpp": [line(0x100, 0x120)]},
                         {"A.cpp": ["\t.text start:0x100 end:0x120"]}), [])


class EvidenceTests(unittest.TestCase):
    def test_legacy_failure_restores_symbols_splits_and_skip_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config" / "PAL"
            config.mkdir(parents=True)
            splits = config / "splits.txt"
            symbols = config / "symbols.txt"
            skip = root / "skip.txt"
            splits.write_bytes(b"original splits\r\n")
            symbols.write_bytes(b"original symbols\r\n")

            def fail():
                splits.write_text("trial splits")
                symbols.write_text("trial symbols")
                skip.write_text("wrongly rejected unit")
                raise RuntimeError("trial failure")

            with patch.object(scl, "ROOT_DIR", root), patch.object(scl, "DTK_OVERRIDE", None), \
                 patch.object(scl, "_main", fail), \
                 patch("sys.argv", ["loop", "--target", "PAL", "--skip-file", str(skip)]):
                with self.assertRaisesRegex(RuntimeError, "trial failure"):
                    scl.main()
            self.assertEqual(splits.read_bytes(), b"original splits\r\n")
            self.assertEqual(symbols.read_bytes(), b"original symbols\r\n")
            self.assertFalse(skip.exists())

    def test_empty_comparison_is_not_a_match(self):
        result = scl.classify_built_unit("A", [], {"A": {}}, None, None, None)
        self.assertEqual(result[0], "rejected")

    def test_extracted_retail_bytes_cannot_confirm_compiled_data(self):
        class Reader:
            def read_bytes(self, *args):
                return b"same retail bytes"

        class Neighbors:
            def borders_unclaimed(self, *args):
                return True

        unit = {"sections": [{"name": ".data", "size": "16", "fuzzy_match_percent": 50,
                              "metadata": {"virtual_address": "256"}}]}
        result = scl.classify_built_unit("A", [line(0x100, 0x110, ".data")],
                                        {"A": unit}, Neighbors(), Reader(), Reader())
        self.assertEqual(result[0], "blocked")
        self.assertFalse(result[2])


class ConfigureTests(unittest.TestCase):
    BASE = 'config.libs = []\nif args.mode == "configure":\n    generate_build(config)\n'

    def test_rerun_replaces_only_its_version_even_with_windows_newlines(self):
        text = render_config(self.BASE, "PAL", {"A.cpp"})
        text = render_config(text, "NTSC", {"B.cpp"})
        text = render_config(text.replace("\n", "\r\n"), "PAL", {"C.cpp"})
        self.assertEqual(text.count(BEGIN), 2)
        self.assertNotIn("'A.cpp'", text)
        self.assertIn("'B.cpp'", text)
        self.assertIn("'C.cpp'", text)
        compile(text, "configure.py", "exec")

    def test_empty_trial_restores_original_dispatch(self):
        text = render_config(self.BASE, "PAL", {"A.cpp"})
        self.assertEqual(render_config(text, "PAL", set()), self.BASE)

    def test_unknown_adapter_fails_before_editing(self):
        with self.assertRaises(ValueError):
            render_config("different project\n", "PAL", {"A.cpp"})


if __name__ == "__main__":
    unittest.main()
