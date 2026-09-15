"""Which units are worth spending a build on."""

import unittest

from verification_adapter import matches_on_content


def unit(*sections):
    return {"sections": [{"name": n, "fuzzy_match_percent": p} for n, p in sections]}


class ContentGateTests(unittest.TestCase):
    def test_every_content_section_matching_qualifies(self):
        self.assertTrue(matches_on_content(unit((".text", 100), (".data", 100))))

    def test_a_content_section_short_of_a_full_match_does_not(self):
        self.assertFalse(matches_on_content(unit((".text", 100), (".data", 99))))

    def test_an_empty_section_cannot_disqualify_a_matching_unit(self):
        # GXMisc.c: .text is a byte-identical match, .sbss scores 75% because
        # one symbol there carries a size dtk guessed from the gap to the next
        # one. .sbss holds no bytes, so that score is about our annotations.
        self.assertTrue(matches_on_content(unit((".text", 100), (".sbss", 75))))

    def test_every_flavour_of_empty_section_is_ignored(self):
        for name in (".bss", ".sbss", ".sbss2"):
            self.assertTrue(matches_on_content(unit((".text", 100), (name, 0))), name)

    def test_a_unit_of_nothing_but_empty_sections_is_not_evidence(self):
        self.assertFalse(matches_on_content(unit((".bss", 100))))

    def test_a_unit_with_no_sections_at_all_is_not_evidence(self):
        self.assertFalse(matches_on_content({}))

    def test_a_missing_percent_counts_as_no_match(self):
        self.assertFalse(matches_on_content({"sections": [{"name": ".text"}]}))


if __name__ == "__main__":
    unittest.main()
