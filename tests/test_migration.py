"""Regression tests for migration evidence and reversible configuration generation."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import discover_splits as discovery
import split_confidence_loop as scl
import verify_source_units as verifier
from verify_source_units import BEGIN, render_config


def line(start, end, section=".text"):
    return f"\t{section} start:0x{start:08X} end:0x{end:08X}"


class DiscoveryTests(unittest.TestCase):
    def test_keeps_all_code_fragments_for_compiler_comparison(self):
        proposed = {
            "A.cpp": [
                line(0x100, 0x120),
                line(0x140, 0x180),
                line(0x300, 0x310, ".data"),
            ]
        }
        result = dict(discovery.code_proposals(proposed, {}))
        self.assertEqual(
            [scl.parse_range(l) for l in result["A.cpp"]], [(".text", 0x100, 0x180)]
        )

    def test_extension_preserves_data_and_never_shrinks_existing_code(self):
        existing = {"A.cpp": [line(0x100, 0x160), line(0x300, 0x320, ".data")]}
        proposed = {"A.cpp": [line(0x140, 0x180)]}
        result = dict(discovery.code_proposals(proposed, existing))["A.cpp"]
        self.assertEqual(
            {scl.parse_range(line) for line in result},
            {(".text", 0x100, 0x180), (".data", 0x300, 0x320)},
        )

    def test_cannot_claim_another_existing_unit(self):
        proposed = {"A.cpp": [line(0x100, 0x200)]}
        existing = {"B.cpp": [line(0x180, 0x190)]}
        self.assertEqual(discovery.code_proposals(proposed, existing), [])

    def test_same_range_is_not_a_new_proposal_despite_formatting(self):
        self.assertEqual(
            discovery.code_proposals(
                {"A.cpp": [line(0x100, 0x120)]},
                {"A.cpp": ["\t.text start:0x100 end:0x120"]},
            ),
            [],
        )


class DataProposalTests(unittest.TestCase):
    def test_extends_already_established_unit_with_named_data(self):
        existing = {"A.cpp": [line(0x100, 0x160)]}
        proposed = {"A.cpp": [line(0x300, 0x308, ".sbss")]}
        result = dict(discovery.data_proposals(proposed, existing))["A.cpp"]
        self.assertEqual(
            {scl.parse_range(l) for l in result},
            {(".text", 0x100, 0x160), (".sbss", 0x300, 0x308)},
        )

    def test_never_creates_a_unit_from_data_alone(self):
        proposed = {"A.cpp": [line(0x300, 0x308, ".sbss")]}
        self.assertEqual(discovery.data_proposals(proposed, {}), [])

    def test_creates_a_unit_that_emits_no_code_in_the_source(self):
        proposed = {"A.cpp": [line(0x300, 0x308, ".sbss")]}
        source = {"A.cpp": [line(0x900, 0x908, ".sbss")]}
        result = dict(discovery.data_proposals(proposed, {}, source))
        self.assertEqual(
            [scl.parse_range(l) for l in result["A.cpp"]], [(".sbss", 0x300, 0x308)]
        )

    def test_still_refuses_a_unit_whose_source_has_code(self):
        # dtk proposing no .text means it could not match the code, not that
        # the unit has none -- placing data alone here would guess a boundary.
        proposed = {"A.cpp": [line(0x300, 0x308, ".sbss")]}
        source = {"A.cpp": [line(0x900, 0x980), line(0x990, 0x998, ".sbss")]}
        self.assertEqual(discovery.data_proposals(proposed, {}, source), [])

    def test_created_unit_still_cannot_claim_another_unit(self):
        proposed = {"A.cpp": [line(0x300, 0x310, ".sbss")]}
        source = {"A.cpp": [line(0x900, 0x910, ".sbss")]}
        existing = {"B.cpp": [line(0x304, 0x308, ".sbss")]}
        self.assertEqual(discovery.data_proposals(proposed, existing, source), [])

    def test_ignores_code_sections(self):
        existing = {"A.cpp": [line(0x100, 0x160)]}
        proposed = {"A.cpp": [line(0x160, 0x180)]}
        self.assertEqual(discovery.data_proposals(proposed, existing), [])

    def test_cannot_claim_another_existing_unit(self):
        existing = {
            "A.cpp": [line(0x100, 0x160)],
            "B.cpp": [line(0x300, 0x310, ".sbss")],
        }
        proposed = {"A.cpp": [line(0x304, 0x30C, ".sbss")]}
        self.assertEqual(discovery.data_proposals(proposed, existing), [])

    def test_same_range_is_not_a_new_proposal(self):
        existing = {"A.cpp": [line(0x100, 0x160), line(0x300, 0x308, ".sbss")]}
        proposed = {"A.cpp": [line(0x300, 0x308, ".sbss")]}
        self.assertEqual(discovery.data_proposals(proposed, existing), [])


class LinkOrderGraphTests(unittest.TestCase):
    def test_first_ctors_split_is_not_an_edge_source(self):
        # dtk drops the first .ctors split before pairing. Keeping it invents
        # an edge from that one unit into the next .ctors owner, which is how
        # a whole program collapses into one false cycle.
        # .ctors deliberately contradicts .text here: keeping the first split
        # yields B -> A on top of .text's A -> B, a cycle dtk never sees.
        blocks = {
            "A.cpp": [line(0x100, 0x200), line(0x904, 0x908, ".ctors")],
            "B.cpp": [line(0x200, 0x300), line(0x900, 0x904, ".ctors")],
        }
        graph = scl.build_link_order_graph(blocks)
        self.assertEqual(graph, {"A.cpp": {"B.cpp"}})
        self.assertEqual([s for s in scl.find_sccs(graph) if len(s) > 1], [])

    def test_contradicting_sections_are_still_a_cycle(self):
        blocks = {
            "A.cpp": [line(0x100, 0x200), line(0x500, 0x600, ".sdata")],
            "B.cpp": [line(0x200, 0x300), line(0x400, 0x500, ".sdata")],
        }
        graph = scl.build_link_order_graph(blocks)
        self.assertEqual(
            [sorted(s) for s in scl.find_sccs(graph) if len(s) > 1],
            [["A.cpp", "B.cpp"]],
        )


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

            with (
                patch.object(scl, "ROOT_DIR", root),
                patch.object(scl, "DTK_OVERRIDE", None),
                patch.object(scl, "_main", fail),
                patch(
                    "sys.argv", ["loop", "--target", "PAL", "--skip-file", str(skip)]
                ),
                self.assertRaisesRegex(RuntimeError, "trial failure"),
            ):
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

        unit = {
            "sections": [
                {
                    "name": ".data",
                    "size": "16",
                    "fuzzy_match_percent": 50,
                    "metadata": {"virtual_address": "256"},
                }
            ]
        }
        result = scl.classify_built_unit(
            "A",
            [line(0x100, 0x110, ".data")],
            {"A": unit},
            Neighbors(),
            Reader(),
            Reader(),
        )
        self.assertEqual(result[0], "blocked")
        self.assertFalse(result[2])


class ConfigureTests(unittest.TestCase):
    BASE = (
        'VERSIONS = ["NTSC", "PAL", "JP"]\n'
        "objects = [\n"
        '    Object(MatchingFor("NTSC", "JP"), "A.cpp"),  # retain this comment\n'
        '    Object(NonMatching, "B.cpp"),\n'
        '    Object(Matching, "C.cpp"),\n'
        "]\n"
    )

    @staticmethod
    def legacy(version, names):
        return (
            BEGIN
            + f"# Version: {version}\n"
            + f"if config.version == {version!r}:\n"
            + f"    _verified_source_units = {names!r}\n"
            + "    for _verified_lib in config.libs:\n"
            + "        for _verified_obj in _verified_lib['objects']:\n"
            + "            if _verified_obj.name in _verified_source_units:\n"
            + "                _verified_obj.completed = True\n"
            + "# END AUTOMATED SOURCE VERIFICATION\n\n"
        )

    def test_orders_arguments_and_preserves_other_versions_and_comments(self):
        text = render_config(self.BASE, "PAL", {"A.cpp", "B.cpp", "C.cpp"})
        self.assertIn('MatchingFor("NTSC", "PAL", "JP"), "A.cpp"', text)
        self.assertIn('MatchingFor("PAL"), "B.cpp"', text)
        self.assertIn('Object(Matching, "C.cpp")', text)
        self.assertIn("# retain this comment", text)
        self.assertNotIn(BEGIN, text)
        for version in ("NTSC", "PAL", "JP"):
            namespace = {
                "NonMatching": False,
                "Matching": True,
                "MatchingFor": lambda *vs, version=version: version in vs,
                "Object": lambda completed, name: (name, completed),
            }
            # Execute the trusted generated fixture to verify its runtime semantics.
            exec(text, namespace)  # noqa: S102
            objects = namespace.get("objects")
            if not isinstance(objects, list):
                self.fail("Generated configuration did not define an object list")
            self.assertEqual(
                dict(objects),
                {"A.cpp": True, "B.cpp": version == "PAL", "C.cpp": True},
            )

    def test_idempotent_with_windows_newlines(self):
        original = self.BASE.replace("\n", "\r\n")
        text = render_config(original, "PAL", {"A.cpp", "B.cpp"})
        self.assertEqual(render_config(text, "PAL", {"A.cpp", "B.cpp"}), text)
        self.assertEqual(text.count("\n"), text.count("\r\n"))

    def test_failed_trial_render_keeps_only_accepted_and_baseline_flags(self):
        accepted = render_config(self.BASE, "PAL", {"A.cpp"})
        trial = render_config(self.BASE, "PAL", {"A.cpp", "B.cpp"})
        self.assertNotEqual(accepted, trial)
        restored = render_config(self.BASE, "PAL", {"A.cpp"})
        self.assertEqual(restored, accepted)
        self.assertIn('Object(NonMatching, "B.cpp")', restored)
        self.assertEqual(render_config(self.BASE, "PAL", set()), self.BASE)

    def test_migrates_legacy_blocks_for_multiple_versions(self):
        original = (
            self.BASE + self.legacy("PAL", {"A.cpp"}) + self.legacy("JP", {"B.cpp"})
        )
        text = render_config(original, "PAL", set())
        self.assertNotIn(BEGIN, text)
        self.assertIn('MatchingFor("NTSC", "PAL", "JP"), "A.cpp"', text)
        self.assertIn('MatchingFor("JP"), "B.cpp"', text)
        self.assertEqual(render_config(text, "PAL", set()), text)

    def test_legacy_migration_survives_failed_new_trial(self):
        original = self.BASE + self.legacy("PAL", {"A.cpp"})
        text = render_config(original, "PAL", {"B.cpp"})
        self.assertIn('MatchingFor("PAL"), "B.cpp"', text)
        restored = render_config(original, "PAL", set())
        self.assertIn('MatchingFor("NTSC", "PAL", "JP"), "A.cpp"', restored)
        self.assertIn('Object(NonMatching, "B.cpp")', restored)
        self.assertNotIn(BEGIN, restored)

    def test_refuses_modified_legacy_logic(self):
        original = self.BASE + self.legacy("PAL", {"A.cpp"}).replace(
            "_verified_obj.completed = True", "_verified_obj.completed = False"
        )
        with self.assertRaisesRegex(ValueError, "Modified legacy"):
            render_config(original, "PAL", set())

    def test_refuses_missing_duplicate_or_unsupported_declarations(self):
        for text, names in (
            (self.BASE, {"Missing.cpp"}),
            (self.BASE + 'extra = Object(NonMatching, "B.cpp")\n', {"B.cpp"}),
            (self.BASE.replace('"JP"), "A.cpp"', '"INVALID"), "A.cpp"'), {"A.cpp"}),
        ):
            with self.subTest(text=text, names=names), self.assertRaises(ValueError):
                render_config(text, "PAL", names)

    def test_equivalent_can_be_promoted_for_one_version(self):
        original = self.BASE.replace(
            'Object(NonMatching, "B.cpp")', 'Object(Equivalent, "B.cpp")'
        )
        result = render_config(original, "PAL", {"B.cpp"})
        self.assertIn('Object(MatchingFor("PAL"), "B.cpp")', result)

    def test_utf8_columns_and_multiline_calls(self):
        text = (
            'VERSIONS = ["NTSC", "PAL", "JP"]\n'
            'label = "é"; objects = [Object(MatchingFor(\n'
            '    "NTSC",\n'
            '    "JP",\n'
            '), "A.cpp")]\n'
        )
        result = render_config(text, "PAL", {"A.cpp"})
        self.assertIn(
            'label = "é"; objects = [Object(MatchingFor("NTSC", "PAL", "JP"), "A.cpp")]',
            result,
        )
        compile(result, "configure.py", "exec")

    def test_unknown_adapter_fails_before_editing(self):
        with self.assertRaises(ValueError):
            render_config("different_project = True\n", "PAL", {"A.cpp"})

    def test_verifier_accepts_direct_call_and_rolls_back_failed_sibling(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "configure.py"
            config.write_text(self.BASE, encoding="utf-8")
            (root / "dtk").write_bytes(b"fixture tool")
            for path in (root / "orig/PAL/sys/main.dol", root / "build/PAL/main.dol"):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"retail fixture")
            (root / "objdiff.json").write_text(
                json.dumps(
                    {
                        "units": [
                            {
                                "metadata": {"source_path": f"src/{name}.cpp"},
                                "base_path": f"build/PAL/src/{name}.o",
                            }
                            for name in "ABC"
                        ]
                    }
                ),
                encoding="utf-8",
            )

            def enabled():
                namespace = {
                    "Matching": True,
                    "NonMatching": False,
                    "MatchingFor": lambda *versions: "PAL" in versions,
                    "Object": lambda status, name: (name, status),
                }
                # Execute the test-owned configure fixture used by the fake builder.
                exec(config.read_text(encoding="utf-8"), namespace)  # noqa: S102
                objects = namespace.get("objects")
                if not isinstance(objects, list):
                    self.fail("Fixture configuration did not define an object list")
                return dict(objects)

            def report():
                flags = enabled()
                return {
                    "measures": {
                        "matched_code": "48",
                        "complete_code": str(16 * sum(flags.values())),
                    },
                    "units": [
                        {
                            "metadata": {
                                "source_path": f"src/{name}",
                                "complete": complete,
                            },
                            "measures": {"matched_code": "16"},
                            "sections": [{"name": ".text", "fuzzy_match_percent": 100}],
                        }
                        for name, complete in flags.items()
                    ],
                }

            class FakeContext:
                target = "PAL"
                ninja = "ninja"

                def __init__(self, project_root, *args):
                    self.root = project_root

                def build(self):
                    if enabled()["B.cpp"]:
                        raise subprocess.CalledProcessError(1, ["ninja"])
                    return report()

                def run(self, cmd, capture=False):
                    return "\n".join(
                        f"build/PAL/src/{Path(name).stem}.o"
                        for name, complete in enabled().items()
                        if complete
                    )

                def dol_sha1(self):
                    return "fixture"

            with (
                patch(
                    "sys.argv",
                    [
                        "verify",
                        "--project-root",
                        str(root),
                        "--target",
                        "PAL",
                        "--dtk",
                        str(root / "dtk"),
                    ],
                ),
                patch.object(verifier, "BuildContext", FakeContext),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                verifier.main()
            result = json.loads(
                (root / "build/PAL/source-verification/result.json").read_text()
            )
            self.assertEqual(result["accepted"], ["A.cpp"])
            self.assertEqual(enabled(), {"A.cpp": True, "B.cpp": False, "C.cpp": True})
            self.assertEqual(
                config.read_text(encoding="utf-8"),
                render_config(self.BASE, "PAL", {"A.cpp"}),
            )
            self.assertNotIn(BEGIN, config.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
