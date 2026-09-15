"""Regression tests for ELF reading and object-to-object symbol derivation."""

import struct
import tempfile
import unittest
from pathlib import Path

import derive_symbol_names as deriver
import elf_objects
import objdiff_probe

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA = 1, 2, 3, 4
R_PPC_REL24, R_PPC_ADDR16_LO = 10, 4


def build_object(functions, relocations=()):
    """Assemble a tiny ELF32 big-endian relocatable object.

    The reader decodes a binary format, so the suite builds real objects rather
    than mocking the parse; a hand-written fixture cannot drift from the layout
    the reader actually has to survive.

    ``functions`` are ``(name, value, size)`` defined in ``.text``;
    ``relocations`` are ``(offset, target, type)`` applied to it. A relocation
    target that is not a listed function becomes an undefined symbol.
    """
    strings = bytearray(b"\0")

    def intern(text):
        offset = len(strings)
        strings.extend(text.encode() + b"\0")
        return offset

    text_index, symtab_index, strtab_index = 1, 3, 4
    symbols = [(0, 0, 0, 0, 0)]
    indices = {}
    for name, value, size in functions:
        indices[name] = len(symbols)
        symbols.append((intern(name), value, size, (1 << 4) | 2, text_index))
    for _, target, _ in relocations:
        if target not in indices:
            indices[target] = len(symbols)
            symbols.append((intern(target), 0, 0, (1 << 4) | 2, 0))

    text = bytes(max((v + s for _, v, s in functions), default=0))
    symtab = b"".join(
        struct.pack(">IIIBBH", n, v, s, i, 0, x) for n, v, s, i, x in symbols
    )
    rela = b"".join(
        struct.pack(">IIi", offset, (indices[target] << 8) | kind, 0)
        for offset, target, kind in relocations
    )
    names = bytearray(b"\0")

    def section_name(text_value):
        offset = len(names)
        names.extend(text_value.encode() + b"\0")
        return offset

    layout = [
        ("", 0, b"", 0, 0, 0),
        (".text", SHT_PROGBITS, text, 0, 0, 0),
        (".rela.text", SHT_RELA, rela, symtab_index, text_index, 12),
        (".symtab", SHT_SYMTAB, symtab, strtab_index, 0, 16),
        (".strtab", SHT_STRTAB, bytes(strings), 0, 0, 0),
        (".shstrtab", SHT_STRTAB, None, 0, 0, 0),
    ]
    name_offsets = [section_name(entry[0]) if entry[0] else 0 for entry in layout]
    layout[-1] = (*layout[-1][:2], bytes(names), *layout[-1][3:])

    blob = bytearray(b"\x7fELF\x01\x02\x01" + b"\0" * 9)
    blob += struct.pack(">HHIIII", 1, 20, 1, 0, 0, 0)  # type, machine, version...
    blob += struct.pack(">IHHHHHH", 0, 52, 0, 0, 40, len(layout), len(layout) - 1)

    offsets = []
    for _, _, payload, _, _, _ in layout:
        if payload:
            blob += b"\0" * (-len(blob) % 4)
            offsets.append(len(blob))
            blob += payload
        else:
            offsets.append(0)
    blob += b"\0" * (-len(blob) % 4)
    table = len(blob)
    for index, (_, kind, payload, link, info, entsize) in enumerate(layout):
        blob += struct.pack(
            ">10I",
            name_offsets[index],
            kind,
            0,
            0,
            offsets[index],
            len(payload or b""),
            link,
            info,
            4,
            entsize,
        )
    struct.pack_into(">I", blob, 32, table)
    return bytes(blob)


def read(functions, relocations=()):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "object.o"
        path.write_bytes(build_object(functions, relocations))
        return elf_objects.read_object(path)


class ElfReaderTests(unittest.TestCase):
    def test_reads_functions_in_address_order(self):
        obj = read([("second", 0x40, 0x10), ("first", 0x0, 0x40)])
        self.assertEqual([f["name"] for f in obj["functions"]], ["first", "second"])
        self.assertEqual([f["size"] for f in obj["functions"]], [0x40, 0x10])

    def test_relocations_land_in_their_enclosing_function(self):
        obj = read(
            [("first", 0x0, 0x40), ("second", 0x40, 0x10)],
            [(0x10, "Callee", R_PPC_REL24), (0x44, "Other", R_PPC_REL24)],
        )
        first, second = obj["functions"]
        self.assertEqual([r["target"] for r in first["relocations"]], ["Callee"])
        self.assertEqual([r["target"] for r in second["relocations"]], ["Other"])
        self.assertTrue(first["relocations"][0]["external"])

    def test_relocations_are_ordered_within_a_function(self):
        obj = read(
            [("only", 0x0, 0x40)],
            [(0x20, "Late", R_PPC_REL24), (0x08, "Early", R_PPC_REL24)],
        )
        self.assertEqual(
            [r["target"] for r in obj["functions"][0]["relocations"]], ["Early", "Late"]
        )

    def test_rejects_a_file_that_is_not_a_big_endian_elf32(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.o"
            path.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 60)
            with self.assertRaises(ValueError):
                elf_objects.read_object(path)


class AlignmentTests(unittest.TestCase):
    def align(self, left, right):
        pairs, anchors = deriver.align(
            [{"name": n} for n in left],
            [{"name": n} for n in right],
            lambda item: item["name"],
        )
        return pairs, anchors

    def test_anchors_pin_an_unnamed_neighbour(self):
        pairs, anchors = self.align(["a", "secret", "b"], ["a", "fn_80000000", "b"])
        self.assertEqual(pairs, [(0, 0), (1, 1), (2, 2)])
        self.assertEqual(anchors, {(0, 0), (2, 2)})

    def test_a_placeholder_never_acts_as_an_anchor(self):
        _, anchors = self.align(["fn_80000000"], ["fn_80000000"])
        self.assertEqual(anchors, set())

    def test_gaps_of_unequal_length_are_left_unpaired(self):
        pairs, _ = self.align(["a", "x", "b"], ["a", "fn_80000000", "fn_80000004", "b"])
        self.assertEqual(pairs, [(0, 0), (2, 3)])

    def test_pairs_positionally_when_nothing_anchors(self):
        pairs, anchors = self.align(["x", "y"], ["fn_80000000", "fn_80000004"])
        self.assertEqual(pairs, [(0, 0), (1, 1)])
        self.assertEqual(anchors, set())


class ProposalTests(unittest.TestCase):
    def proposals(self, source, target):
        return deriver.unit_proposals(source, target, "Unit.cpp")

    def test_derives_a_callee_name_from_an_anchored_call_site(self):
        # The shape that motivated the tool: one function whose name already
        # agrees, whose relocation list pins the single unnamed callee.
        source = read(
            [("Caller", 0x0, 0x40)],
            [(0x08, "Known", R_PPC_REL24), (0x10, "RealName", R_PPC_REL24)],
        )
        target = read(
            [("Caller", 0x0, 0x40)],
            [(0x08, "Known", R_PPC_REL24), (0x10, "fn_80001234", R_PPC_REL24)],
        )
        (found,) = self.proposals(source, target)
        self.assertEqual(found["old"], "fn_80001234")
        self.assertEqual(found["new"], "RealName")
        self.assertEqual(found["method"], "call-site")
        self.assertEqual(found["tier"], "confident")

    def test_never_proposes_a_compiler_local_as_a_name(self):
        source = read(
            [("Caller", 0x0, 0x40)],
            [(0x08, "Known", R_PPC_REL24), (0x10, "@468", R_PPC_ADDR16_LO)],
        )
        target = read(
            [("Caller", 0x0, 0x40)],
            [(0x08, "Known", R_PPC_REL24), (0x10, "lbl_80001234", R_PPC_ADDR16_LO)],
        )
        self.assertEqual(self.proposals(source, target), [])

    def test_ignores_a_call_site_whose_relocation_type_differs(self):
        source = read([("Caller", 0x0, 0x40)], [(0x08, "RealName", R_PPC_REL24)])
        target = read([("Caller", 0x0, 0x40)], [(0x08, "fn_80001234", R_PPC_ADDR16_LO)])
        self.assertEqual(self.proposals(source, target), [])

    def test_names_a_function_by_position_between_anchors(self):
        source = read([("a", 0x0, 0x10), ("Hidden", 0x10, 0x20), ("b", 0x30, 0x10)])
        target = read(
            [("a", 0x0, 0x10), ("fn_80000010", 0x10, 0x20), ("b", 0x30, 0x10)]
        )
        (found,) = self.proposals(source, target)
        self.assertEqual((found["old"], found["new"]), ("fn_80000010", "Hidden"))
        self.assertEqual(found["method"], "function-position")
        self.assertEqual(found["tier"], "probable")

    def test_a_size_disagreement_lowers_a_positional_name_to_candidate(self):
        source = read([("a", 0x0, 0x10), ("Hidden", 0x10, 0x40), ("b", 0x50, 0x10)])
        target = read(
            [("a", 0x0, 0x10), ("fn_80000010", 0x10, 0x20), ("b", 0x30, 0x10)]
        )
        (found,) = self.proposals(source, target)
        self.assertEqual(found["tier"], "candidate")

    def test_refuses_a_unit_where_nothing_agrees(self):
        # Equal function counts would otherwise pair the whole file by position,
        # naming every function on a single coincidence.
        source = read([("First", 0x0, 0x10), ("Second", 0x10, 0x10)])
        target = read([("fn_80000000", 0x0, 0x10), ("fn_80000010", 0x10, 0x10)])
        self.assertEqual(self.proposals(source, target), [])

    def test_records_the_anchor_evidence_behind_a_proposal(self):
        source = read([("a", 0x0, 0x10), ("Hidden", 0x10, 0x20), ("b", 0x30, 0x10)])
        target = read(
            [("a", 0x0, 0x10), ("fn_80000010", 0x10, 0x20), ("b", 0x30, 0x10)]
        )
        (found,) = self.proposals(source, target)
        self.assertEqual((found["anchors"], found["functions"]), (2, 3))

    def test_does_not_mine_call_sites_from_an_unanchored_function(self):
        # `anchor` admits the unit, but the second pairing rests on position
        # alone; a name taken from inside it would rest on that guess too.
        source = read(
            [("anchor", 0x0, 0x10), ("Hidden", 0x10, 0x40)],
            [(0x18, "RealName", R_PPC_REL24)],
        )
        target = read(
            [("anchor", 0x0, 0x10), ("fn_80000010", 0x10, 0x40)],
            [(0x18, "fn_80001234", R_PPC_REL24)],
        )
        found = self.proposals(source, target)
        self.assertEqual([p["method"] for p in found], ["function-position"])


class ResolutionTests(unittest.TestCase):
    def proposal(self, old, new, unit="A.cpp", tier="confident"):
        return {
            "old": old,
            "new": new,
            "unit": unit,
            "method": "call-site",
            "tier": tier,
        }

    def test_keeps_a_rename_every_unit_agrees_on(self):
        accepted, rejected = deriver.resolve(
            [
                self.proposal("fn_80000000", "Real", unit="A.cpp"),
                self.proposal("fn_80000000", "Real", unit="B.cpp"),
            ],
            {"fn_80000000": 0x80000000},
        )
        self.assertEqual(accepted["fn_80000000"]["new"], "Real")
        self.assertEqual(accepted["fn_80000000"]["units"], ["A.cpp", "B.cpp"])
        self.assertEqual(rejected, [])

    def test_drops_a_rename_units_disagree_about(self):
        accepted, rejected = deriver.resolve(
            [
                self.proposal("fn_80000000", "One", unit="A.cpp"),
                self.proposal("fn_80000000", "Two", unit="B.cpp"),
            ],
            {"fn_80000000": 0x80000000},
        )
        self.assertEqual(accepted, {})
        self.assertEqual(rejected[0]["reason"], "units disagree")

    def test_drops_a_name_already_used_at_another_address(self):
        accepted, rejected = deriver.resolve(
            [self.proposal("fn_80000000", "Taken")],
            {"fn_80000000": 0x80000000, "Taken": 0x80009999},
        )
        self.assertEqual(accepted, {})
        self.assertEqual(rejected[0]["reason"], "name already taken")

    def test_drops_one_name_claimed_by_two_symbols(self):
        accepted, rejected = deriver.resolve(
            [
                self.proposal("fn_80000000", "Real"),
                self.proposal("fn_80000004", "Real"),
            ],
            {"fn_80000000": 0x80000000, "fn_80000004": 0x80000004},
        )
        self.assertEqual(accepted, {})
        self.assertEqual(
            {entry["reason"] for entry in rejected}, {"name claimed by several symbols"}
        )

    def test_drops_a_name_a_different_unit_compiles_from_source(self):
        # The shape that broke a real link: the address sits in an auto split,
        # but a source-linked unit already defines the name, so both objects
        # would export it and the linker refuses.
        accepted, rejected = deriver.resolve(
            [self.proposal("fn_80000000", "Defined")],
            {"fn_80000000": (".text", 0x80000000)},
            defined_by={"Defined": {"Gui/CGuiLight"}},
            owner=lambda section, address: None,
        )
        self.assertEqual(accepted, {})
        self.assertEqual(rejected[0]["reason"], "name defined by another unit's source")

    def test_keeps_a_name_the_owning_unit_compiles_from_source(self):
        accepted, _ = deriver.resolve(
            [self.proposal("fn_80000000", "Defined")],
            {"fn_80000000": (".text", 0x80000000)},
            defined_by={"Defined": {"Gui/CGuiLight"}},
            owner=lambda section, address: "Gui/CGuiLight",
        )
        self.assertEqual(accepted["fn_80000000"]["new"], "Defined")

    def test_drops_a_symbol_the_symbols_file_does_not_have(self):
        accepted, rejected = deriver.resolve([self.proposal("fn_80000000", "Real")], {})
        self.assertEqual(accepted, {})
        self.assertEqual(rejected[0]["reason"], "not in symbols file")

    def test_keeps_the_strongest_tier_a_symbol_was_proposed_at(self):
        accepted, _ = deriver.resolve(
            [
                self.proposal("fn_80000000", "Real", unit="A.cpp", tier="candidate"),
                self.proposal("fn_80000000", "Real", unit="B.cpp", tier="confident"),
            ],
            {"fn_80000000": 0x80000000},
        )
        self.assertEqual(accepted["fn_80000000"]["tier"], "confident")


class SymbolPatchTests(unittest.TestCase):
    def test_renaming_a_symbol_in_place_survives_a_reread(self):
        # The probe rewrites names inside .strtab without moving anything, so
        # the patched object has to still parse as the same object.
        blob = build_object(
            [("LongFunctionName", 0x0, 0x20)], [(0x08, "Callee", R_PPC_REL24)]
        )
        patched = objdiff_probe.patch_symbols(blob, {"LongFunctionName": "Q0000"})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "patched.o"
            path.write_bytes(patched)
            obj = elf_objects.read_object(path)
        self.assertEqual([f["name"] for f in obj["functions"]], ["Q0000"])
        self.assertEqual(obj["functions"][0]["size"], 0x20)
        self.assertEqual(
            [r["target"] for r in obj["functions"][0]["relocations"]], ["Callee"]
        )

    def test_refuses_to_overrun_a_shorter_name(self):
        blob = build_object([("ab", 0x0, 0x20)])
        self.assertEqual(objdiff_probe.patch_symbols(blob, {"ab": "Q0000"}), blob)


class PermutationTests(unittest.TestCase):
    def test_every_pairing_is_covered_exactly_once(self):
        pairs = [(t, s) for t in ("t1", "t2") for s in ("s1", "s2", "s3")]
        rounds = list(objdiff_probe._permutations(pairs))
        self.assertEqual(sorted(p for r in rounds for p in r), sorted(pairs))

    def test_no_symbol_appears_twice_within_one_round(self):
        pairs = [(t, s) for t in ("t1", "t2", "t3") for s in ("s1", "s2")]
        for round_ in objdiff_probe._permutations(pairs):
            targets = [t for t, _ in round_]
            sources = [s for _, s in round_]
            self.assertEqual(len(targets), len(set(targets)))
            self.assertEqual(len(sources), len(set(sources)))


class CandidateFilterTests(unittest.TestCase):
    def function(self, name, size):
        return {"name": name, "size": size}

    def test_drops_candidates_whose_sizes_are_far_apart(self):
        pairs = objdiff_probe.candidate_pairs(
            [self.function("fn_80000000", 0x100)],
            [self.function("CloseEnough", 0x180), self.function("FarTooBig", 0x900)],
            size_ratio=2.5,
        )
        self.assertEqual(pairs, [("fn_80000000", "CloseEnough")])

    def test_drops_names_too_short_to_hold_a_token(self):
        pairs = objdiff_probe.candidate_pairs(
            [self.function("fn_80000000", 0x100)],
            [self.function("ab", 0x100)],
            size_ratio=2.5,
        )
        self.assertEqual(pairs, [])


class RankingTests(unittest.TestCase):
    def test_reports_the_lead_over_the_runner_up(self):
        ranked = objdiff_probe.rank({"fn_80000000": {"A": 99.0, "B": 40.0, "C": 5.0}})
        self.assertEqual(ranked["fn_80000000"]["name"], "A")
        self.assertAlmostEqual(ranked["fn_80000000"]["margin"], 59.0)
        self.assertEqual(ranked["fn_80000000"]["candidates"], 3)

    def test_a_lone_candidate_leads_by_its_whole_score(self):
        ranked = objdiff_probe.rank({"fn_80000000": {"A": 80.0}})
        self.assertAlmostEqual(ranked["fn_80000000"]["margin"], 80.0)


class MethodPrecedenceTests(unittest.TestCase):
    def proposal(self, method, new, tier="confident"):
        return {
            "old": "fn_80000000",
            "new": new,
            "unit": "A.cpp",
            "method": method,
            "tier": tier,
        }

    def test_a_body_match_overrides_a_positional_guess(self):
        accepted, rejected = deriver.resolve(
            [
                self.proposal("function-position", "Guessed"),
                self.proposal("body-match", "Measured"),
            ],
            {"fn_80000000": 0x80000000},
        )
        self.assertEqual(accepted["fn_80000000"]["new"], "Measured")
        self.assertEqual(rejected, [])

    def test_two_equally_strong_methods_that_disagree_are_dropped(self):
        accepted, rejected = deriver.resolve(
            [
                self.proposal("call-site", "One"),
                self.proposal("body-match", "Two"),
            ],
            {"fn_80000000": 0x80000000},
        )
        self.assertEqual(accepted, {})
        self.assertEqual(rejected[0]["reason"], "units disagree")


class RenameFileTests(unittest.TestCase):
    def test_writes_the_pairs_dtk_symbols_rename_expects(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "renames.txt"
            written = deriver.write_renames(
                path,
                {
                    "fn_80000004": {"new": "Second"},
                    "fn_80000000": {"new": "First"},
                },
            )
            self.assertEqual(written, 2)
            self.assertEqual(
                path.read_text(encoding="utf-8").splitlines(),
                ["fn_80000000 = First", "fn_80000004 = Second"],
            )

    def test_writes_an_empty_file_when_nothing_was_derived(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "renames.txt"
            self.assertEqual(deriver.write_renames(path, {}), 0)
            self.assertEqual(path.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
