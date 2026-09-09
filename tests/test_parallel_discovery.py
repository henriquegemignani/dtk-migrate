"""Discovery gates exercised without invoking a retail project or compiler."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import discovery_adapter as adapter
from migration_runtime import ValidationError
import split_confidence_loop as scl


def candidate(name):
    start = 0x100 + ord(name[0]) * 16
    return {"name": name, "lines": [f"\t.text start:0x{start:08X} end:0x{start + 16:08X}"]}


def report(values):
    return {"units": [{"metadata": {"source_path": "src/" + n}, "measures": {"matched_code": v}}
                      for n, v in values.items()],
            "measures": {"matched_code": sum(values.values()), "total_code": 1000}}


class FakeContext:
    def __init__(self, root, behavior=None):
        self.root, self.target, self.source = root, "target", "source"
        self.output = root / "out"
        self.dtk = root / "dtk"
        self.splits = root / "config/target/splits.txt"
        self.splits.parent.mkdir(parents=True)
        self.splits.write_text("Sections:\n\t.text type:code\n\n", encoding="utf-8")
        self.splits.with_name("symbols.txt").write_text("original", encoding="utf-8")
        self.behavior = behavior or (lambda names: {n: 10 for n in names})
        self.last = None

    def build(self):
        names = set(scl.parse_splits(self.splits.read_text(encoding="utf-8"))[1])
        self.last = report(self.behavior(names))
        return self.last

    def run(self, cmd):
        if cmd[1] == "match":
            scl.write_splits(self.output / "proposals.txt", "Sections:\n\t.text type:code\n\n",
                             {"A.cpp": candidate("A.cpp")["lines"]}, ["A.cpp"])
        else:
            self.splits.with_name("symbols.txt").write_text("renamed", encoding="utf-8")


class DiscoveryAdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_gain_filters_and_final_report_matches_restored_state(self):
        ctx = FakeContext(self.root, lambda names: {n: 0 if n == "B.cpp" else 10 for n in names})
        a, b = candidate("A.cpp"), candidate("B.cpp")
        result = adapter.evaluate(ctx, [a, b])
        self.assertEqual(result["accepted"], [a])
        self.assertEqual(result["deferred"], [b])
        self.assertEqual(result["report"], ctx.build())
        self.assertNotIn("B.cpp", ctx.splits.read_text())

    def test_retail_validation_failure_is_bisected(self):
        def behavior(names):
            if "B.cpp" in names:
                raise ValidationError("retail differs")
            return {n: 10 for n in names}
        ctx = FakeContext(self.root, behavior)
        a, b, c = [candidate(n + ".cpp") for n in "ABC"]
        result = adapter.evaluate(ctx, [a, b, c])
        self.assertEqual(result["accepted"], [a, c])
        self.assertEqual(result["deferred"], [b])

    def test_individually_valid_union_conflict_retains_canonical_subset(self):
        def behavior(names):
            if {"A.cpp", "B.cpp"} <= names:
                raise ValidationError("combined conflict")
            return {n: 10 for n in names}
        ctx = FakeContext(self.root, behavior)
        a, b = candidate("A.cpp"), candidate("B.cpp")
        self.assertEqual(adapter.evaluate(ctx, [a])["accepted"], [a])
        self.assertEqual(adapter.evaluate(ctx, [b])["deferred"], [b])
        self.assertEqual(set(adapter.by_path(ctx.build())), {"A.cpp"})

    def test_per_unit_regression_rejects_aggregate_gain(self):
        ctx = FakeContext(self.root, lambda names: {"existing.cpp": 0 if names else 10, **{n: 100 for n in names}})
        a = candidate("A.cpp")
        result = adapter.evaluate(ctx, [a])
        self.assertEqual(result["accepted"], [])
        self.assertEqual(result["events"][0]["status"], "regresses-existing-code")

    def test_fatal_exception_restores_original(self):
        def behavior(names):
            if names:
                raise OSError("disk error")
            return {}
        ctx = FakeContext(self.root, behavior)
        original = ctx.splits.read_bytes()
        with self.assertRaises(OSError):
            adapter.evaluate(ctx, [candidate("A.cpp")])
        self.assertEqual(ctx.splits.read_bytes(), original)

    def test_external_edit_survives_fatal_exception(self):
        ctx = FakeContext(self.root)
        def behavior(names):
            if names:
                ctx.splits.write_text("user edits")
                raise OSError("interrupted")
            return {}
        ctx.behavior = behavior
        with self.assertRaises(OSError):
            adapter.evaluate(ctx, [candidate("A.cpp")])
        self.assertEqual(ctx.splits.read_text(), "user edits")

    def test_prepare_reverts_regressing_renames(self):
        ctx = FakeContext(self.root)
        ctx.behavior = lambda names: {"existing.cpp": 0 if ctx.splits.with_name("symbols.txt").read_text() == "renamed" else 10}
        prepared = adapter.prepare(ctx)
        self.assertEqual(ctx.splits.with_name("symbols.txt").read_text(), "original")
        self.assertEqual(prepared["events"][0]["status"], "rename-batch-reverted")
        self.assertEqual(len(prepared["candidates"]), 1)


if __name__ == "__main__":
    unittest.main()
