"""The order two objects define their functions in, as corroborating evidence."""

import unittest

import derive_symbol_names as deriver
import match_ordering as ordering
import objdiff_probe


class LongestIncreasingTests(unittest.TestCase):
    def test_an_empty_list_has_no_run(self):
        self.assertEqual(ordering.longest_increasing([]), [])

    def test_an_already_increasing_list_is_its_own_run(self):
        self.assertEqual(ordering.longest_increasing([1, 4, 9]), [0, 1, 2])

    def test_a_single_outlier_is_the_part_left_out(self):
        positions = ordering.longest_increasing([80, 1, 2, 3])
        self.assertEqual(positions, [1, 2, 3])

    def test_equal_values_do_not_extend_a_strictly_increasing_run(self):
        self.assertEqual(len(ordering.longest_increasing([5, 5, 5])), 1)


class SpineTests(unittest.TestCase):
    def test_the_backbone_is_the_pairings_that_agree_on_direction(self):
        # A destructor the target emits first but the source keeps near the end
        # is a real reordering: it stays a pairing, it just does not anchor one.
        decided = [(0, 87), (1, 5), (2, 6), (3, 7)]
        self.assertEqual(ordering.spine(decided), [(1, 5), (2, 6), (3, 7)])

    def test_pairings_off_the_backbone_are_reported_not_dropped(self):
        decided = [(0, 87), (1, 5), (2, 6), (3, 7)]
        backbone = ordering.spine(decided)
        self.assertEqual(ordering.off_spine(decided, backbone), [(0, 87)])

    def test_input_order_does_not_matter(self):
        self.assertEqual(
            ordering.spine([(3, 7), (1, 5), (2, 6)]), [(1, 5), (2, 6), (3, 7)]
        )


ANCHORS = [(10, 100), (20, 200), (30, 300)]


class WindowTests(unittest.TestCase):
    BACKBONE = ANCHORS

    def test_a_target_between_two_anchors_is_bounded_by_both(self):
        self.assertEqual(ordering.window(self.BACKBONE, 25), (200, 300))

    def test_a_target_before_every_anchor_has_no_lower_bound(self):
        self.assertEqual(ordering.window(self.BACKBONE, 5), (None, 100))

    def test_a_target_after_every_anchor_has_no_upper_bound(self):
        self.assertEqual(ordering.window(self.BACKBONE, 99), (300, None))

    def test_a_pairing_outside_the_bounds_contradicts_the_run(self):
        self.assertFalse(ordering.fits(self.BACKBONE, 25, 100))
        self.assertTrue(ordering.fits(self.BACKBONE, 25, 250))

    def test_an_empty_backbone_bounds_nothing(self):
        self.assertTrue(ordering.fits([], 25, 250))


FISH_ANCHORS = [(25, 39), (35, 50)]


class RescueTests(unittest.TestCase):
    BACKBONE = FISH_ANCHORS

    def test_two_targets_wanting_one_pair_of_sources_are_settled_by_order(self):
        # CFishCloud's RemoveRepulsor and RemoveAttractor: each scores within a
        # tenth of a point of the other on both targets, so the scores decide
        # nothing, but only one assignment runs in the same direction as the
        # rest of the unit.
        settled = ordering.rescue(
            [
                (27, [(42, "Repulsor"), (45, "Attractor")]),
                (30, [(45, "Attractor"), (42, "Repulsor")]),
            ],
            self.BACKBONE,
        )
        self.assertEqual(settled, [(27, 42, "Repulsor"), (30, 45, "Attractor")])

    def test_two_targets_that_contradict_each_other_settle_neither(self):
        settled = ordering.rescue(
            [
                (27, [(45, "Attractor")]),
                (30, [(42, "Repulsor")]),
            ],
            self.BACKBONE,
        )
        self.assertEqual(settled, [])

    def test_the_best_candidate_the_backbone_leaves_room_for_wins(self):
        # The top candidate sits before an anchor that already owns that seat,
        # so the runner-up is the one the ordering can actually believe.
        settled = ordering.rescue([(27, [(10, "early"), (44, "fits")])], self.BACKBONE)
        self.assertEqual(settled, [(27, 44, "fits")])

    def test_a_target_with_no_candidate_in_the_window_is_left_alone(self):
        self.assertEqual(ordering.rescue([(27, [(10, "early")])], self.BACKBONE), [])

    def test_nothing_undecided_settles_nothing(self):
        self.assertEqual(ordering.rescue([], self.BACKBONE), [])


class ExactBandTests(unittest.TestCase):
    def test_rank_counts_how_many_candidates_reach_the_near_exact_band(self):
        ranked = objdiff_probe.rank({"fn_1": {"a": 99.7, "b": 99.6, "c": 46.7}}, 99.0)
        self.assertEqual(ranked["fn_1"]["exact"], 2)
        self.assertEqual(ranked["fn_1"]["candidates"], 3)

    def test_a_lone_near_exact_candidate_is_settled_despite_a_thin_lead(self):
        # The real case: a destructor scoring 99.58 against a field of other
        # destructors topping out at 89.79. A lead of 9.79 fails the margin
        # rule, and the pairing is nonetheless unambiguous.
        ranked = objdiff_probe.rank({"fn_1": {"right": 99.58, "other": 89.79}}, 99.0)
        signal, tier = deriver._decide(ranked["fn_1"], deriver.BODY_LIMITS)
        self.assertEqual((signal, tier), ("sole-exact", "confident"))

    def test_two_near_exact_candidates_are_not_settled_by_the_band(self):
        ranked = objdiff_probe.rank({"fn_1": {"a": 99.7, "b": 99.6}}, 99.0)
        self.assertEqual(deriver._decide(ranked["fn_1"], deriver.BODY_LIMITS)[0], None)

    def test_a_clear_lead_below_the_band_is_still_settled_by_the_margin(self):
        ranked = objdiff_probe.rank({"fn_1": {"a": 90.0, "b": 20.0}}, 99.0)
        self.assertEqual(
            deriver._decide(ranked["fn_1"], deriver.BODY_LIMITS)[0], "margin"
        )

    def test_a_poor_field_settles_nothing(self):
        ranked = objdiff_probe.rank({"fn_1": {"a": 40.0, "b": 5.0}}, 99.0)
        self.assertEqual(deriver._decide(ranked["fn_1"], deriver.BODY_LIMITS)[0], None)


if __name__ == "__main__":
    unittest.main()
