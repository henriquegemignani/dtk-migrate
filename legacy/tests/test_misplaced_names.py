"""A name already in symbols.txt that sits on the wrong function."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import derive_symbol_names as deriver

LIMITS = deriver.BODY_LIMITS


def function(name, value, size):
    return {"name": name, "value": value, "size": size, "relocations": []}


# The real shape, from CFishCloud: `dtk match` propagated `BuildBoidNearList`
# onto the function before the one it belongs to, so the target carries it on a
# 0xE8 body while the source compiles that name to 0x330 and compiles
# `OldBuildBoidNearList` to 0xE8.
CARRIED, TRUE_NAME = (
    "BuildBoidNearList__10CFishCloudFv",
    "OldBuildBoidNearList__10CFishCloudFv",
)
TARGET = {
    "functions": [function(CARRIED, 0x100, 0xE8), function("fn_801C20A4", 0x1E8, 0x330)]
}
SOURCE = {
    "functions": [
        function(TRUE_NAME, 0x0, 0xE8),
        function(CARRIED, 0xE8, 0x330),
    ]
}


def run(scores, target=TARGET, source=SOURCE, limits=LIMITS):
    with patch.object(deriver.objdiff_probe, "score_matrix", return_value=scores):
        return deriver.misplaced_names(
            "objdiff", "CFishCloud.o", "t.o", "s.o", target, source, limits
        )


class DetectionTests(unittest.TestCase):
    def test_a_name_on_a_function_the_source_sizes_differently_is_corrected(self):
        (found,) = run({CARRIED: {TRUE_NAME: 99.83, "Other__Fv": 20.0}})
        self.assertEqual(found["old"], CARRIED)
        self.assertEqual(found["new"], TRUE_NAME)
        self.assertEqual(found["method"], "misplaced-name")
        self.assertEqual(found["tier"], "confident")
        self.assertEqual((found["carried_size"], found["namesake_size"]), (0xE8, 0x330))

    def test_a_name_whose_size_agrees_is_never_suspected(self):
        # No suspicion means no objdiff run at all, so the scores are irrelevant.
        source = {"functions": [function(CARRIED, 0x0, 0xE8)]}
        self.assertEqual(run({CARRIED: {TRUE_NAME: 99.9}}, source=source), [])

    def test_a_merely_good_score_is_not_enough_to_overwrite_a_name(self):
        self.assertEqual(run({CARRIED: {TRUE_NAME: 92.0, "Other__Fv": 10.0}}), [])

    def test_two_near_exact_explanations_correct_nothing(self):
        self.assertEqual(run({CARRIED: {TRUE_NAME: 99.6, "Other__Fv": 99.5}}), [])

    def test_a_name_already_on_another_function_here_would_need_a_swap(self):
        # Correcting this would put `fn_801C20A4`'s current name on two
        # addresses at once, which one rename cannot express.
        target = {
            "functions": [
                function(CARRIED, 0x100, 0xE8),
                function(TRUE_NAME, 0x1E8, 0x330),
            ]
        }
        self.assertEqual(run({CARRIED: {TRUE_NAME: 99.9}}, target=target), [])

    def test_the_replacement_has_to_be_a_plausible_size_too(self):
        source = {
            "functions": [
                function(TRUE_NAME, 0x0, 0x2000),
                function(CARRIED, 0xE8, 0x330),
            ]
        }
        self.assertEqual(run({CARRIED: {TRUE_NAME: 99.9}}, source=source), [])

    def test_a_placeholder_is_never_treated_as_a_misplaced_name(self):
        target = {"functions": [function("fn_801C1FBC", 0x100, 0xE8)]}
        source = {"functions": [function("fn_801C1FBC", 0x0, 0x330)]}
        self.assertEqual(run({"fn_801C1FBC": {TRUE_NAME: 99.9}}, target, source), [])


class ReferenceTests(unittest.TestCase):
    """The other version decides whether a disagreement is ours or the name's."""

    def test_a_reference_that_contradicts_the_placement_confirms_the_fix(self):
        # NTSC sizes `BuildBoidNearList` at 0x330 while the PAL address is 0xE8,
        # so two versions agree the name does not belong on this function.
        (found,) = run({CARRIED: {TRUE_NAME: 99.83}}, limits=LIMITS)
        self.assertFalse(found["contested"])
        self.assertEqual(found["tier"], "confident")

    def test_a_reference_that_agrees_with_the_placement_contests_the_fix(self):
        # CPoseAsTransforms: our source compiles the name to 0x30, but both
        # binaries have it at 0x130. The source failed to inline something --
        # the name is not what is wrong, so it is reported and left alone.
        with patch.object(
            deriver.objdiff_probe,
            "score_matrix",
            return_value={CARRIED: {TRUE_NAME: 99.87}},
        ):
            (found,) = deriver.misplaced_names(
                "objdiff", "u.o", "t.o", "s.o", TARGET, SOURCE, LIMITS, {CARRIED: 0xE8}
            )
        self.assertTrue(found["contested"])
        self.assertEqual(found["tier"], "candidate")
        self.assertEqual(found["reference_size"], 0xE8)

    def test_a_contested_finding_survives_resolution_but_is_not_written_out(self):
        # It stays in the result so the report can show it; the tier is what
        # keeps it out of the rename file, which `--tier probable` cuts at.
        accepted, _ = deriver.resolve(
            [
                {
                    "old": CARRIED,
                    "new": TRUE_NAME,
                    "unit": "u.o",
                    "method": "misplaced-name",
                    "tier": "candidate",
                }
            ],
            {CARRIED: (".text", 0x801C1FBC)},
        )
        self.assertEqual(accepted[CARRIED]["tier"], "candidate")
        kept = {
            old: p
            for old, p in accepted.items()
            if p["tier"] in ("confident", "probable")
        }
        self.assertEqual(deriver.write_renames(Path(self.rename_file()), kept), 0)

    def rename_file(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return Path(directory.name) / "renames.txt"

    def test_a_reference_that_does_not_carry_the_name_contests_nothing(self):
        with patch.object(
            deriver.objdiff_probe,
            "score_matrix",
            return_value={CARRIED: {TRUE_NAME: 99.9}},
        ):
            (found,) = deriver.misplaced_names(
                "objdiff",
                "u.o",
                "t.o",
                "s.o",
                TARGET,
                SOURCE,
                LIMITS,
                {"Unrelated": 0xE8},
            )
        self.assertFalse(found["contested"])

    def test_no_reference_at_all_leaves_every_finding_uncontested(self):
        (found,) = run({CARRIED: {TRUE_NAME: 99.9}})
        self.assertFalse(found["contested"])
        self.assertIsNone(found["reference_size"])


class CorrectionReportTests(unittest.TestCase):
    def proposal(self, **extra):
        return {
            "unit": "CFishCloud.o",
            "new": TRUE_NAME,
            "method": "misplaced-name",
            "percent": 99.83,
            "contested": False,
            "reference_size": None,
            "own_percent": 0.0,
            "carried_size": 0xE8,
            "namesake_size": 0x330,
            **extra,
        }

    def test_a_correction_names_the_rename_it_unblocks(self):
        (entry,) = deriver.corrections(
            {CARRIED: self.proposal()},
            [{"old": "fn_801C20A4", "new": CARRIED, "reason": "name already taken"}],
        )
        self.assertEqual(entry["address_named"], CARRIED)
        self.assertEqual(entry["should_be"], TRUE_NAME)
        self.assertEqual(entry["frees_name_for"], ["fn_801C20A4"])

    def test_a_correction_nothing_is_waiting_on_is_still_reported(self):
        (entry,) = deriver.corrections({CARRIED: self.proposal()}, [])
        self.assertEqual(entry["frees_name_for"], [])

    def test_other_rejections_are_not_mistaken_for_blocked_renames(self):
        (entry,) = deriver.corrections(
            {CARRIED: self.proposal()},
            [{"old": "fn_X", "new": CARRIED, "reason": "units disagree"}],
        )
        self.assertEqual(entry["frees_name_for"], [])

    def test_ordinary_renames_are_not_corrections(self):
        self.assertEqual(
            deriver.corrections(
                {"fn_1": {"unit": "u.o", "new": "N", "method": "body-match"}}, []
            ),
            [],
        )


class ResolutionTests(unittest.TestCase):
    def test_a_correction_survives_resolution_and_can_be_applied_alone(self):
        # The corrected name is free, so the rename collides with nothing --
        # which is why it is emitted without the rename it unblocks.
        symbols = {CARRIED: (".text", 0x801C1FBC), "fn_801C20A4": (".text", 0x801C20A4)}
        accepted, rejected = deriver.resolve(
            [
                {
                    "old": CARRIED,
                    "new": TRUE_NAME,
                    "unit": "CFishCloud.o",
                    "method": "misplaced-name",
                    "tier": "confident",
                },
                {
                    "old": "fn_801C20A4",
                    "new": CARRIED,
                    "unit": "CFishCloud.o",
                    "method": "body-match",
                    "tier": "confident",
                },
            ],
            symbols,
        )
        self.assertEqual(accepted[CARRIED]["new"], TRUE_NAME)
        self.assertNotIn("fn_801C20A4", accepted)
        self.assertEqual(
            [r["reason"] for r in rejected if r["old"] == "fn_801C20A4"],
            ["name already taken"],
        )


if __name__ == "__main__":
    unittest.main()
