"""Discovery of a version's linked modules, and units that move between them."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import project_modules
import split_audit

CONFIG = """\
object: main.dol
modules:
- object: files/{rel}.rel
  hash: deadbeef
  symbols: config/{version}/{directory}/symbols.txt
  splits: config/{version}/{directory}/splits.txt
"""

COMMENTED = """\
object: main.dol
modules:
  #- object: files/Disabled.rel
  #  symbols: config/{version}/Disabled/symbols.txt
  #  splits: config/{version}/Disabled/splits.txt
  - object: files/{rel}.rel
    symbols: config/{version}/{directory}/symbols.txt
    splits: config/{version}/{directory}/splits.txt
"""


def line(start, end, section=".text"):
    return f"\t{section:11} start:0x{start:08X} end:0x{end:08X}"


def write_version(root, version, rel=None, directory=None, template=CONFIG, units=()):
    config = root / "config" / version
    config.mkdir(parents=True, exist_ok=True)
    body = "Sections:\n\t.text type:code\n\n"
    for name, text in units:
        body += f"{name}:\n{text}\n\n"
    (config / "splits.txt").write_text(body, encoding="utf-8")
    (config / "symbols.txt").write_text("", encoding="utf-8")
    text = "object: main.dol\n"
    if rel:
        text = template.format(rel=rel, version=version, directory=directory or rel)
    (config / "config.yml").write_text(text, encoding="utf-8")
    return config


class ModuleDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_a_version_without_modules_has_only_the_dol(self):
        write_version(self.root, "V")
        (found,) = project_modules.modules(self.root, "V")
        self.assertEqual(found.name, project_modules.DOL_NAME)
        self.assertTrue(found.is_dol)
        self.assertEqual(found.splits, self.root / "config/V/splits.txt")

    def test_a_config_directory_need_not_match_the_module_name(self):
        # NTSC keeps NESemuP.rel under config/<version>/NESemu/.
        write_version(self.root, "V", rel="NESemuP", directory="NESemu")
        _, rel = project_modules.modules(self.root, "V")
        self.assertEqual(rel.name, "NESemuP")
        self.assertEqual(rel.splits, self.root / "config/V/NESemu/splits.txt")
        self.assertEqual(rel.build, self.root / "build/V/NESemuP")
        self.assertFalse(rel.is_dol)

    def test_source_objects_are_shared_by_every_module(self):
        write_version(self.root, "V", rel="R")
        dol, rel = project_modules.modules(self.root, "V")
        self.assertEqual(dol.sources, rel.sources)
        self.assertEqual(rel.sources, self.root / "build/V/src")
        self.assertEqual(rel.extracted, self.root / "build/V/R/obj")

    def test_commented_out_modules_are_ignored(self):
        write_version(self.root, "V", rel="R", template=COMMENTED)
        names = [m.name for m in project_modules.modules(self.root, "V")]
        self.assertEqual(names, [project_modules.DOL_NAME, "R"])

    def test_find_reports_what_is_available_for_an_unknown_name(self):
        write_version(self.root, "V", rel="R")
        with self.assertRaises(SystemExit) as raised:
            project_modules.find(self.root, "V", "Nope")
        self.assertIn("R", str(raised.exception))

    def test_modules_pair_across_versions_by_position(self):
        write_version(self.root, "SRC", rel="NESemuP", directory="NESemu")
        write_version(self.root, "TGT", rel="NESPALemuP")
        pairs = project_modules.pair(self.root, "SRC", "TGT")
        self.assertEqual(
            [(t.name, s.name) for t, s in pairs],
            [("main", "main"), ("NESPALemuP", "NESemuP")],
        )

    def test_a_module_the_source_lacks_pairs_with_nothing(self):
        write_version(self.root, "SRC")
        write_version(self.root, "TGT", rel="R")
        pairs = project_modules.pair(self.root, "SRC", "TGT")
        self.assertIsNone(pairs[1][1])


class ModuleAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def rel_splits(self, version, directory, body):
        path = self.root / "config" / version / directory / "splits.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")

    def test_reports_a_module_the_target_has_not_begun_splitting(self):
        # PAL's NES emulator: a splits file holding only a section header.
        write_version(self.root, "SRC", rel="NESemuP", directory="NESemu")
        write_version(self.root, "TGT", rel="NESPALemuP")
        self.rel_splits(
            "SRC",
            "NESemu",
            f"Sections:\n\t.text type:code\n\nemu.cpp:\n{line(0, 0x400)}\n",
        )
        self.rel_splits("TGT", "NESPALemuP", "Sections:\n\t.text type:code\n")
        (found,) = split_audit.unsplit_modules(self.root, "SRC", "TGT")
        self.assertEqual(found["module"], "NESPALemuP")
        self.assertEqual(found["against"], "NESemuP")
        self.assertEqual(found["source_units"], 1)
        self.assertEqual(found["source_code_bytes"], 0x400)
        self.assertFalse(found["built"])

    def test_a_module_with_any_split_is_not_reported_as_unsplit(self):
        write_version(self.root, "SRC", rel="R")
        write_version(self.root, "TGT", rel="R")
        for version in ("SRC", "TGT"):
            self.rel_splits(
                version,
                "R",
                f"Sections:\n\t.text type:code\n\na.cpp:\n{line(0, 0x40)}\n",
            )
        self.assertEqual(split_audit.unsplit_modules(self.root, "SRC", "TGT"), [])

    def test_notices_a_unit_that_moved_between_the_dol_and_a_rel(self):
        write_version(
            self.root, "SRC", rel="R", units=[("moved.cpp", line(0x100, 0x140))]
        )
        write_version(self.root, "TGT", rel="R")
        self.rel_splits("SRC", "R", "Sections:\n\t.text type:code\n")
        self.rel_splits(
            "TGT", "R", f"Sections:\n\t.text type:code\n\nmoved.cpp:\n{line(0, 0x40)}\n"
        )
        (found,) = split_audit.relocated_units(self.root, "SRC", "TGT")
        self.assertEqual(found["unit"], "moved.cpp")
        self.assertEqual(found["source_module"], "main")
        self.assertEqual(found["target_module"], "R")

    def test_a_unit_in_the_same_module_in_both_versions_is_not_relocated(self):
        for version in ("SRC", "TGT"):
            write_version(
                self.root, version, rel="R", units=[("same.cpp", line(0x100, 0x140))]
            )
            self.rel_splits(version, "R", "Sections:\n\t.text type:code\n")
        self.assertEqual(split_audit.relocated_units(self.root, "SRC", "TGT"), [])

    def test_audits_stunted_splits_across_every_module(self):
        write_version(self.root, "SRC", rel="R")
        write_version(self.root, "TGT", rel="R")
        self.rel_splits(
            "SRC", "R", f"Sections:\n\t.text type:code\n\na.cpp:\n{line(0, 0x1000)}\n"
        )
        self.rel_splits(
            "TGT", "R", f"Sections:\n\t.text type:code\n\na.cpp:\n{line(0, 0x10)}\n"
        )
        (found,) = split_audit.audit_modules(self.root, "SRC", "TGT")
        self.assertEqual(found["unit"], "a.cpp")
        self.assertEqual(found["module"], "R")
        self.assertEqual(found["against"], "R")


if __name__ == "__main__":
    unittest.main()
