"""Object declarations the verification stage must not try to widen."""

import ast
import unittest

from verify_source_units import is_rewritable, render_config, unrewritable_names

VERSIONS = 'VERSIONS = ["A", "B", "C"]\n'


def config(status, name="a.cpp"):
    return f'{VERSIONS}Object({status}, "{name}")\n'


def status_of(source):
    tree = ast.parse(f"Object({source}, 'x')")
    return tree.body[0].value.args[0]


class RewritableTests(unittest.TestCase):
    def test_matching_for_is_a_list_that_can_gain_a_version(self):
        self.assertTrue(is_rewritable(status_of('MatchingFor("A")')))

    def test_the_flat_negatives_can_be_promoted(self):
        for source in ("NonMatching", "Equivalent", "False"):
            self.assertTrue(is_rewritable(status_of(source)), source)

    def test_matching_everywhere_needs_no_change(self):
        for source in ("Matching", "True"):
            self.assertTrue(is_rewritable(status_of(source)), source)

    def test_equivalent_for_states_something_matching_for_cannot(self):
        # `EquivalentFor(*v)` is `config.version in v and config.non_matching`:
        # it links from source only in a --non-matching build. Folding it into
        # MatchingFor("A", "B", "C") would claim A and B are byte-identical.
        self.assertFalse(is_rewritable(status_of('EquivalentFor("A", "B")')))

    def test_an_unrecognised_call_is_not_rewritable(self):
        self.assertFalse(is_rewritable(status_of('SomethingElse("A")')))

    def test_keywords_make_matching_for_unrewritable(self):
        self.assertFalse(is_rewritable(status_of('MatchingFor("A", strict=True)')))


class UnrewritableNamesTests(unittest.TestCase):
    def test_it_names_the_object_and_the_form_that_blocked_it(self):
        found = unrewritable_names(config('EquivalentFor("A", "B")', "swoosh.cpp"))
        self.assertEqual(found, {"swoosh.cpp": "EquivalentFor"})

    def test_ordinary_declarations_are_not_blocked(self):
        self.assertEqual(unrewritable_names(config('MatchingFor("A")')), {})
        self.assertEqual(unrewritable_names(config("NonMatching")), {})

    def test_it_agrees_with_what_render_config_refuses(self):
        # The two must not drift: anything reported here is exactly what
        # render_config would raise on, which is the whole point of the check.
        text = config('EquivalentFor("A", "B")', "swoosh.cpp")
        self.assertIn("swoosh.cpp", unrewritable_names(text))
        with self.assertRaises(ValueError) as raised:
            render_config(text, "C", {"swoosh.cpp"})
        self.assertIn("swoosh.cpp", str(raised.exception))

    def test_a_rewritable_object_really_does_render(self):
        text = config('MatchingFor("A")', "ok.cpp")
        self.assertEqual(unrewritable_names(text), {})
        self.assertIn("MatchingFor", render_config(text, "C", {"ok.cpp"}))


if __name__ == "__main__":
    unittest.main()
