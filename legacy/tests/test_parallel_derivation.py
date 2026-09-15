"""Derivation stage gates exercised without invoking a retail project or compiler."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import derivation_adapter as adapter
from migration_runtime import ValidationError

SYMBOLS = """\
fn_80000000 = .text:0x80000000; // type:function size:0x10
fn_80000010 = .text:0x80000010; // type:function size:0x20
Already__4NameFv = .text:0x80000030; // type:function size:0x8
lbl_803C0000 = .rodata:0x803C0000; // type:object size:0x4
"""


def rename(old, new, method="body-match", tier="confident"):
    return {"name": old, "new": new, "method": method, "tier": tier}


def report(values):
    return {
        "units": [
            {"metadata": {"source_path": "src/" + n}, "measures": {"matched_code": v}}
            for n, v in values.items()
        ],
        "measures": {"matched_code": sum(values.values()), "total_code": 1000},
    }


class FakeContext:
    """Builds succeed unless a named rename is present, standing in for a
    linker that rejects a name another unit already defines."""

    def __init__(self, root, conflicts=(), measures=None):
        self.root, self.target, self.source = root, "target", "source"
        self.output = root / "out"
        self.dtk = root / "dtk"
        self.build_jobs = 1
        self.toolchain_root = None
        self.symbols = root / "config/target/symbols.txt"
        self.symbols.parent.mkdir(parents=True)
        self.symbols.write_text(SYMBOLS, encoding="utf-8")
        self.conflicts = set(conflicts)
        self.measures = measures or (lambda names: {"A.cpp": 10})
        self.builds = 0

    def applied(self):
        text = self.symbols.read_text(encoding="utf-8")
        return {line.split(" = ")[0] for line in text.splitlines() if " = " in line}

    def build(self):
        self.builds += 1
        names = self.applied()
        if names & self.conflicts:
            raise ValidationError("multiply-defined")
        return report(self.measures(names))

    def trial_build(self):
        return self.build()


class ApplyRenamesTests(unittest.TestCase):
    def test_renames_only_the_named_symbols(self):
        out = adapter.apply_renames(SYMBOLS, {"fn_80000000": "Real__4NameFv"})
        self.assertIn("Real__4NameFv = .text:0x80000000;", out)
        self.assertIn("fn_80000010 = .text:0x80000010;", out)

    def test_preserves_the_address_comment_and_trailing_newline(self):
        out = adapter.apply_renames(SYMBOLS, {"fn_80000010": "Other__4NameFv"})
        self.assertIn(
            "Other__4NameFv = .text:0x80000010; // type:function size:0x20", out
        )
        self.assertTrue(out.endswith("\n"))

    def test_leaves_a_file_alone_when_nothing_matches(self):
        self.assertEqual(adapter.apply_renames(SYMBOLS, {"fn_DEADBEEF": "X"}), SYMBOLS)

    def test_renames_data_symbols_too(self):
        out = adapter.apply_renames(SYMBOLS, {"lbl_803C0000": "skTable"})
        self.assertIn("skTable = .rodata:0x803C0000;", out)


class DerivationAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_accepts_a_batch_that_links(self):
        ctx = FakeContext(self.root)
        out = adapter.evaluate(
            ctx,
            [
                rename("fn_80000000", "One__4NameFv"),
                rename("fn_80000010", "Two__4NameFv"),
            ],
        )
        self.assertEqual(len(out["accepted"]), 2)
        self.assertEqual(out["deferred"], [])
        text = ctx.symbols.read_text(encoding="utf-8")
        self.assertIn("One__4NameFv = .text:0x80000000;", text)
        self.assertIn("Two__4NameFv = .text:0x80000010;", text)

    def test_bisects_to_the_single_name_that_will_not_link(self):
        # The real failure this guards: a name a source-linked unit already
        # defines makes the link fail, and only that name should be dropped.
        ctx = FakeContext(self.root, conflicts={"Clash__4NameFv"})
        out = adapter.evaluate(
            ctx,
            [
                rename("fn_80000000", "Good__4NameFv"),
                rename("fn_80000010", "Clash__4NameFv"),
            ],
        )
        self.assertEqual([c["name"] for c in out["accepted"]], ["fn_80000000"])
        self.assertEqual([c["name"] for c in out["deferred"]], ["fn_80000010"])
        self.assertEqual(
            [e["status"] for e in out["events"] if e["unit"] == "fn_80000010"],
            ["name-conflict"],
        )
        self.assertNotIn("Clash__4NameFv", ctx.symbols.read_text(encoding="utf-8"))

    def test_a_rename_that_loses_matched_code_is_rejected(self):
        def measures(names):
            return {"A.cpp": 1 if "Bad__4NameFv" in names else 10}

        ctx = FakeContext(self.root, measures=measures)
        out = adapter.evaluate(ctx, [rename("fn_80000000", "Bad__4NameFv")])
        self.assertEqual(out["accepted"], [])
        self.assertEqual(
            [e["status"] for e in out["events"]], ["regresses-existing-code"]
        )

    def test_restores_the_symbols_file_when_a_trial_raises(self):
        ctx = FakeContext(self.root)
        original = ctx.symbols.read_bytes()
        with self.assertRaises(ValueError):
            adapter.evaluate(
                ctx,
                [
                    rename("fn_80000000", "One__4NameFv"),
                    rename("fn_80000000", "Two__4NameFv"),
                ],
            )
        self.assertEqual(ctx.symbols.read_bytes(), original)

    def test_reports_what_the_names_rest_on(self):
        ctx = FakeContext(self.root)
        out = adapter.evaluate(ctx, [rename("fn_80000000", "One__4NameFv")])
        self.assertIn("objdiff body comparison", out["validation"])
        self.assertIn("not that it is correct", out["validation"])


class ObjdiffPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_returns_none_when_the_binary_is_absent(self):
        ctx = FakeContext(self.root)
        self.assertIsNone(adapter.objdiff_path(ctx))

    def test_prefers_the_frozen_toolchain_copy(self):
        ctx = FakeContext(self.root)
        frozen = self.root / "frozen"
        suffix = ".exe" if adapter.os.name == "nt" else ""
        target = frozen / "build/tools"
        target.mkdir(parents=True)
        (target / f"objdiff-cli{suffix}").write_bytes(b"")
        ctx.toolchain_root = frozen
        self.assertEqual(adapter.objdiff_path(ctx), target / f"objdiff-cli{suffix}")


if __name__ == "__main__":
    unittest.main()
