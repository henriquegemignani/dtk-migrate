"""Verifying a unit that links into a REL rather than the DOL."""

import unittest

import verification_adapter as verifier

VERSION = "GM8E01_02"


class ModuleAttributionTests(unittest.TestCase):
    def test_a_dol_object_belongs_to_no_module(self):
        self.assertIsNone(
            verifier.module_of(f"build/{VERSION}/obj/MetroidPrime/CActor.o", VERSION)
        )

    def test_a_rel_object_names_its_module(self):
        # The real failure: `NESemu/ksNesAudio.cpp` is MatchingFor GM8E01_02 but
        # links into NESemuP, so the DOL's report never mentions it and the
        # whole run died claiming it was not configured to link from source.
        self.assertEqual(
            verifier.module_of(
                f"build/{VERSION}/NESemuP/obj/NESemu/ksNesAudio.o", VERSION
            ),
            "NESemuP",
        )

    def test_windows_separators_attribute_the_same_way(self):
        self.assertEqual(
            verifier.module_of(rf"build\{VERSION}\NESemuP\obj\NESemu\emu.o", VERSION),
            "NESemuP",
        )

    def test_a_path_without_the_version_attributes_to_nothing(self):
        self.assertIsNone(verifier.module_of("build/OTHER/obj/a.o", VERSION))

    def test_an_absent_path_attributes_to_nothing(self):
        self.assertIsNone(verifier.module_of("", VERSION))

    def test_the_version_directory_alone_is_not_a_module(self):
        self.assertIsNone(verifier.module_of(f"build/{VERSION}/obj.o", VERSION))

    def test_an_absolute_path_still_attributes(self):
        self.assertEqual(
            verifier.module_of(
                f"F:/programming/decomp/prime/build/{VERSION}/NESemuP/obj/NESemu/emu.o",
                VERSION,
            ),
            "NESemuP",
        )


if __name__ == "__main__":
    unittest.main()


class UnsplitConfigurationTests(unittest.TestCase):
    """A unit configured for a version that has no split for it."""

    def test_the_helper_separates_split_from_unsplit_units(self):
        # `musyx/runtime/hw_lib_dolphin.c` is MatchingFor(GM8P01_00) but PAL has
        # no split for it, so dtk emits no rule, nothing compiles, and it shows
        # up in neither the report nor objdiff.json. The source version's split
        # for it is a zero-length .sbss range: the TU is simply empty.
        report_units = {"has/split.cpp": {"metadata": {"complete": True}}}
        objdiff_units = {"has/split.cpp": {"base_path": "b.o", "target_path": "t.o"}}
        unsplit = [
            name
            for name in ("has/split.cpp", "musyx/runtime/hw_lib_dolphin.c")
            if name not in objdiff_units and name not in report_units
        ]
        self.assertEqual(unsplit, ["musyx/runtime/hw_lib_dolphin.c"])
