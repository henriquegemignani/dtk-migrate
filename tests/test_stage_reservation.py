"""A unit an earlier stage certified is withheld from the later stages."""

import unittest

import parallel_migration as runner


def prepared(*names):
    return {"candidates": [{"name": name, "lines": []} for name in names]}


class ReservationTests(unittest.TestCase):
    def test_withholds_a_unit_an_earlier_stage_certified(self):
        # The real failure: coverage certified ScriptLoader.cpp, discovery then
        # extended the same unit, and publication refused the entire run because
        # coverage could no longer vouch for the range it had selected.
        result = runner.withhold_reserved(
            prepared("A.cpp", "ScriptLoader.cpp", "B.cpp"), {"ScriptLoader.cpp"}
        )
        self.assertEqual([c["name"] for c in result["candidates"]], ["A.cpp", "B.cpp"])
        self.assertEqual(result["reserved_by_earlier_stage"], ["ScriptLoader.cpp"])

    def test_records_only_units_this_stage_actually_proposed(self):
        result = runner.withhold_reserved(prepared("A.cpp"), {"Elsewhere.cpp"})
        self.assertEqual([c["name"] for c in result["candidates"]], ["A.cpp"])
        self.assertEqual(result["reserved_by_earlier_stage"], [])

    def test_nothing_reserved_leaves_the_pool_untouched(self):
        result = runner.withhold_reserved(prepared("A.cpp", "B.cpp"), ())
        self.assertEqual([c["name"] for c in result["candidates"]], ["A.cpp", "B.cpp"])
        self.assertEqual(result["reserved_by_earlier_stage"], [])

    def test_reserving_everything_empties_the_pool(self):
        result = runner.withhold_reserved(
            prepared("A.cpp", "B.cpp"), {"A.cpp", "B.cpp"}
        )
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["reserved_by_earlier_stage"], ["A.cpp", "B.cpp"])

    def test_the_record_is_sorted_for_a_stable_report(self):
        result = runner.withhold_reserved(
            prepared("c.cpp", "a.cpp", "b.cpp"), {"c.cpp", "a.cpp"}
        )
        self.assertEqual(result["reserved_by_earlier_stage"], ["a.cpp", "c.cpp"])


if __name__ == "__main__":
    unittest.main()
