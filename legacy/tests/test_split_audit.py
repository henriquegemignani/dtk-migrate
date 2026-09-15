"""Detection of existing splits too small to be the whole translation unit."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import coverage_adapter
import split_audit


def line(start, end, section=".text"):
    return f"\t{section:11} start:0x{start:08X} end:0x{end:08X}"


class SectionBytesTests(unittest.TestCase):
    def test_sums_every_range_in_the_section(self):
        body = [line(0x100, 0x140), line(0x200, 0x280), line(0x0, 0x10, ".data")]
        self.assertEqual(split_audit.section_bytes(body), 0xC0)

    def test_an_absent_section_is_zero(self):
        self.assertEqual(split_audit.section_bytes([line(0x0, 0x10)], ".sbss"), 0)

    def test_an_empty_body_is_zero(self):
        self.assertEqual(split_audit.section_bytes(None), 0)


class StuntedSplitTests(unittest.TestCase):
    def test_flags_a_unit_claiming_a_fraction_of_its_source_split(self):
        # ScriptLoader.cpp: 712 bytes claimed where the source version has 87988,
        # because the range rests on one weak symbol the linkers placed apart.
        found = split_audit.stunted_splits(
            {"A.cpp": [line(0x800A8964, 0x800A8C2C)]},
            {"A.cpp": [line(0x800C527C, 0x800DAA30)]},
        )
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["unit"], "A.cpp")
        self.assertEqual(found[0]["claimed_bytes"], 712)
        self.assertEqual(found[0]["expected_bytes"], 87988)
        self.assertLess(found[0]["ratio"], 0.01)

    def test_leaves_a_unit_of_a_comparable_size_alone(self):
        self.assertEqual(
            split_audit.stunted_splits(
                {"A.cpp": [line(0x100, 0x900)]}, {"A.cpp": [line(0x0, 0x880)]}
            ),
            [],
        )

    def test_ignores_a_unit_the_source_version_has_not_split(self):
        self.assertEqual(
            split_audit.stunted_splits({"A.cpp": [line(0x100, 0x120)]}, {}), []
        )

    def test_ignores_a_unit_with_no_code_of_its_own(self):
        # A data-only unit has nothing to compare and is not stunted.
        self.assertEqual(
            split_audit.stunted_splits(
                {"A.cpp": [line(0x100, 0x140, ".sbss")]},
                {"A.cpp": [line(0x0, 0x8000)]},
            ),
            [],
        )

    def test_orders_the_worst_offender_first(self):
        found = split_audit.stunted_splits(
            {
                "bad.cpp": [line(0x0, 0x10)],
                "worse.cpp": [line(0x0, 0x4)],
            },
            {
                "bad.cpp": [line(0x0, 0x1000)],
                "worse.cpp": [line(0x0, 0x1000)],
            },
        )
        self.assertEqual([e["unit"] for e in found], ["worse.cpp", "bad.cpp"])

    def test_honours_the_ratio_threshold(self):
        blocks = ({"A.cpp": [line(0x0, 0x60)]}, {"A.cpp": [line(0x0, 0x100)]})
        self.assertEqual(split_audit.stunted_splits(*blocks, ratio=0.3), [])
        self.assertEqual(len(split_audit.stunted_splits(*blocks, ratio=0.9)), 1)


class AuditTests(unittest.TestCase):
    def test_reads_both_versions_from_the_project(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for version, body in (
                ("target", line(0x100, 0x120)),
                ("source", line(0x0, 0x8000)),
            ):
                path = root / "config" / version / "splits.txt"
                path.parent.mkdir(parents=True)
                path.write_text(
                    f"Sections:\n\t.text type:code\n\nA.cpp:\n{body}\n",
                    encoding="utf-8",
                )
            found = split_audit.audit(root, "source", "target")
        self.assertEqual([e["unit"] for e in found], ["A.cpp"])

    def test_a_missing_source_splits_file_audits_nothing(self):
        with TemporaryDirectory() as directory:
            self.assertEqual(split_audit.audit(Path(directory), "source", "target"), [])


class ReportRenderingTests(unittest.TestCase):
    def test_renders_a_table_of_the_worst_offenders(self):
        text = "\n".join(
            coverage_adapter._stunted_section(
                [
                    {
                        "unit": "MetroidPrime/ScriptLoader.cpp",
                        "section": ".text",
                        "claimed_bytes": 712,
                        "expected_bytes": 87988,
                        "ratio": 0.008,
                    }
                ]
            )
        )
        self.assertIn("## Stunted splits", text)
        self.assertIn("MetroidPrime/ScriptLoader.cpp", text)
        self.assertIn("0.008", text)
        self.assertIn("not** candidates", text)

    def test_says_nothing_when_every_split_is_a_plausible_size(self):
        self.assertEqual(coverage_adapter._stunted_section([]), [])

    def test_truncates_a_long_list_and_says_where_the_rest_are(self):
        text = "\n".join(
            coverage_adapter._stunted_section(
                [
                    {
                        "unit": f"U{n}.cpp",
                        "section": ".text",
                        "claimed_bytes": 4,
                        "expected_bytes": 4096,
                        "ratio": 0.001,
                    }
                    for n in range(25)
                ]
            )
        )
        self.assertIn("…and 5 more", text)
        self.assertIn("coverage.json", text)


if __name__ == "__main__":
    unittest.main()
