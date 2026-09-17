"""Tests for the describe layer.

This is where the reasoning about a snapshot lives, so it is also where the
interesting assertions belong. Everything here is pure: snapshots in, strings
out, no terminal involved.
"""

import unittest

from heapscope.describe import (
    INFO,
    LIVE,
    TOP,
    UNSORTED,
    WARN,
    bin_facts,
    bin_notes,
    chunk_facts,
    chunk_notes,
    classify_chunk,
    hexfmt,
    snapshot_findings,
    snapshot_states,
)

from tests.support import (
    LIBC_BASE,
    STALE_HEAD,
    UNSORTED_OFF,
    bin_,
    build,
    chunk,
    unsorted_chunk,
)


def facts_dict(rows):
    """``chunk_facts`` output as a plain dict, for readable assertions."""
    return dict(rows)


class TestHexFormatting(unittest.TestCase):
    def test_none_is_a_dash_not_a_zero(self):
        # "no pointer here" and "a pointer to address zero" are different
        # things, and a freed field legitimately holds the latter.
        self.assertEqual(hexfmt(None), "-")
        self.assertEqual(hexfmt(0), "0x0")

    def test_a_large_value_is_exact(self):
        self.assertEqual(hexfmt(STALE_HEAD), "0x4343434616161619")
        self.assertEqual(int(hexfmt(STALE_HEAD), 16), STALE_HEAD)


class TestClassify(unittest.TestCase):
    def test_top_wins_over_everything(self):
        c = chunk(0x1000, 0x100, is_top=True, fd=LIBC_BASE + 0x100)
        snap = build("x", [c])
        self.assertEqual(classify_chunk(snap, c), TOP)

    def test_membership_in_a_chain_is_tcache(self):
        c = chunk(0x1000, 0x70)
        snap = build("x", [c], {5: bin_(5, 1, head=c["addr"],
                                        entries=[c["addr"]])})
        self.assertEqual(classify_chunk(snap, c), "tcache")

    def test_both_pointers_at_the_arena_is_unsorted(self):
        c = unsorted_chunk(0x1000)
        snap = build("x", [c])
        self.assertEqual(classify_chunk(snap, c), UNSORTED)

    def test_one_pointer_outside_libc_is_not_unsorted(self):
        # An allocated chunk whose first 16 bytes happen to look like a
        # freelist. Only a chunk actually sitting in the bin has both.
        c = chunk(0x1000, 0x70, fd=LIBC_BASE + 0x100, bk=0x4141414141414141)
        snap = build("x", [c])
        self.assertEqual(classify_chunk(snap, c), LIVE)

    def test_without_libc_bounds_nothing_is_called_unsorted(self):
        # Refusing to guess beats labelling a live chunk as a bin member.
        c = chunk(0x1000, 0x70, fd=LIBC_BASE + 0x100, bk=LIBC_BASE + 0x100)
        snap = build("x", [c], libc_base=None, libc_end=None)
        self.assertEqual(classify_chunk(snap, c), LIVE)

    def test_a_plain_chunk_is_live(self):
        c = chunk(0x1000, 0x70)
        self.assertEqual(classify_chunk(build("x", [c]), c), LIVE)

    def test_states_are_keyed_by_header(self):
        a, b = chunk(0x1000, 0x70), chunk(0x2000, 0x100, is_top=True)
        snap = build("x", [a, b], {5: bin_(5, 1, head=a["addr"],
                                           entries=[a["addr"]])})
        self.assertEqual(snapshot_states(snap),
                         {a["header"]: "tcache", b["header"]: TOP})


class TestFindings(unittest.TestCase):
    def test_a_clean_snapshot_has_nothing_to_say(self):
        a = chunk(0x1000, 0x70)
        snap = build("x", [a], {5: bin_(5, 1, head=a["addr"],
                                        entries=[a["addr"]])})
        self.assertEqual(snapshot_findings(snap), [])

    def test_a_cyclic_chain_is_reported(self):
        a = chunk(0x1000, 0x70)
        snap = build("x", [a], {5: bin_(5, 2, head=a["addr"],
                                        entries=[a["addr"]], truncated=True)})
        findings = snapshot_findings(snap)
        scopes = [f.scope for f in findings]
        self.assertIn("tcache[5]", scopes)
        self.assertTrue(any("broken or cyclic" in f.message for f in findings))
        self.assertTrue(all(f.level == WARN for f in findings))

    def test_a_count_that_does_not_match_the_walk_is_reported(self):
        a = chunk(0x1000, 0x70)
        snap = build("x", [a], {5: bin_(5, 2, head=a["addr"],
                                        entries=[a["addr"]])})
        self.assertTrue(any("could be walked" in f.message
                            for f in snapshot_findings(snap)))

    def test_an_empty_bin_holding_a_head_is_reported(self):
        snap = build("x", [], {5: bin_(5, 0, head=STALE_HEAD)})
        findings = snapshot_findings(snap)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].scope, "tcache[5]")
        self.assertIn("empty", findings[0].message)

    def test_a_count_with_no_head_is_reported(self):
        snap = build("x", [], {5: bin_(5, 3, head=None, entries=[])})
        self.assertTrue(any("head is NULL" in f.message
                            for f in snapshot_findings(snap)))

    def test_a_truncated_walk_is_reported_at_the_heap_level(self):
        snap = build("x", [], truncated=True)
        findings = snapshot_findings(snap)
        self.assertEqual(findings[0].scope, "heap")
        self.assertIn("incomplete", findings[0].message)

    def test_an_unsorted_chunk_with_neighbours_is_noted(self):
        snap = build("x", [unsorted_chunk(0x1000, alone=False)])
        findings = snapshot_findings(snap)
        self.assertEqual([f.level for f in findings], [INFO])
        self.assertIn("not alone", findings[0].message)

    def test_a_lone_unsorted_chunk_is_not_a_finding(self):
        snap = build("x", [unsorted_chunk(0x1000, alone=True)])
        self.assertEqual(snapshot_findings(snap), [])


class TestChunkFacts(unittest.TestCase):
    def test_the_first_16_bytes_are_named_for_what_they_are(self):
        # fd and bk are freelist pointers only when the chunk is in a bin. On a
        # live chunk they are user data, and calling them fd invites you to read
        # meaning into them.
        live = chunk(0x1000, 0x70, fd=0x41, bk=0x42)
        snap = build("x", [live])
        self.assertIn("user+0", facts_dict(chunk_facts(snap, live)))
        self.assertNotIn("fd", facts_dict(chunk_facts(snap, live)))

        freed = chunk(0x2000, 0x70)
        snap = build("x", [freed], {5: bin_(5, 1, head=freed["addr"],
                                            entries=[freed["addr"]])})
        rows = facts_dict(chunk_facts(snap, freed))
        self.assertIn("fd", rows)
        self.assertIn("bk", rows)

    def test_the_size_row_carries_the_usable_bytes(self):
        c = chunk(0x1000, 0x70)
        rows = facts_dict(chunk_facts(build("x", [c]), c))
        self.assertIn("0x70", rows["size"])
        self.assertIn("96 usable", rows["size"])

    def test_flags_are_decoded_by_name(self):
        c = chunk(0x1000, 0x70)
        c["raw_size"] = 0x70
        self.assertIn("none", facts_dict(chunk_fact_rows(c))["flags"])

        c["raw_size"] = 0x71
        self.assertIn("prev_inuse", facts_dict(chunk_fact_rows(c))["flags"])

        c["raw_size"] = 0x76
        flags = facts_dict(chunk_fact_rows(c))["flags"]
        self.assertIn("mmapped", flags)
        self.assertIn("non_main_arena", flags)

    def test_the_state_row_says_where_the_chunk_is(self):
        freed = chunk(0x1000, 0x70)
        snap = build("x", [freed], {5: bin_(5, 1, head=freed["addr"],
                                            entries=[freed["addr"]])})
        rows = facts_dict(chunk_facts(snap, freed))
        self.assertIn("tcache bin 5", rows["state"])

    def test_a_live_state_admits_what_is_not_covered(self):
        c = chunk(0x1000, 0x70)
        rows = facts_dict(chunk_facts(build("x", [c]), c))
        self.assertIn("do not walk", rows["state"])


def chunk_fact_rows(c):
    """``chunk_facts`` for a chunk that stands alone."""
    return chunk_facts(build("x", [c]), c)


class TestChunkNotes(unittest.TestCase):
    def test_the_top_chunk_explains_the_remaining_space(self):
        top = chunk(0x1000, 0x1000, is_top=True)
        snap = build("x", [top], region_end=0x2000)
        notes = chunk_notes(snap, top)
        self.assertTrue(any("not allocated" in n for n in notes))

    def test_a_tcache_entry_says_where_it_sits_in_the_chain(self):
        a, b = chunk(0x1000, 0x70), chunk(0x2000, 0x70)
        snap = build("x", [a, b], {5: bin_(5, 2, head=b["addr"],
                                           entries=[b["addr"], a["addr"]])})
        notes = chunk_notes(snap, a)
        self.assertTrue(any("Entry 2 of 2" in n for n in notes), notes)

    def test_a_cyclic_bin_mentions_the_double_free(self):
        a = chunk(0x1000, 0x70)
        snap = build("x", [a], {5: bin_(5, 2, head=a["addr"],
                                        entries=[a["addr"]], truncated=True)})
        notes = chunk_notes(snap, a)
        self.assertTrue(any("double free" in n for n in notes), notes)

    def test_the_head_is_called_out_as_the_next_allocation(self):
        a, b = chunk(0x1000, 0x70), chunk(0x2000, 0x70)
        snap = build("x", [a, b], {5: bin_(5, 2, head=b["addr"],
                                           entries=[b["addr"], a["addr"]])})
        notes = chunk_notes(snap, b)
        self.assertTrue(any("next allocation" in n for n in notes), notes)

    def test_a_lone_unsorted_chunk_names_the_arena_pointer(self):
        c = unsorted_chunk(0x1000)
        snap = build("x", [c], offsets={"unsorted_bin": UNSORTED_OFF})
        notes = chunk_notes(snap, c)
        joined = " ".join(notes)
        self.assertIn("bin_at(av, 1)", joined)
        self.assertIn("libc base", joined)
        # fd - offset is exactly the libc base in this fixture, so the note
        # should confirm the arithmetic rather than just print it.
        self.assertIn("matches the libc mapping", joined)

    def test_the_arena_pointer_is_found_even_when_it_is_not_fd(self):
        # With two chunks in the bin, the first one's fd points at the other
        # chunk and only bk reaches the arena. Reading fd blindly would take a
        # heap address for the list head.
        c = unsorted_chunk(0x1000, alone=False)
        snap = build("x", [c], offsets={"unsorted_bin": UNSORTED_OFF})
        notes = chunk_notes(snap, c)
        self.assertTrue(any("other chunks share this bin" in n for n in notes))
        self.assertTrue(any(n.startswith(hexfmt(c["bk"]) + " - ")
                            for n in notes), notes)
        self.assertFalse(any(n.startswith(hexfmt(c["fd"]) + " - ")
                             for n in notes), notes)
        self.assertIn("matches the libc mapping", " ".join(notes))

    def test_a_second_chunk_sharing_the_bin_is_still_unsorted(self):
        # The rule must not require both pointers in libc, or a bin with more
        # than one chunk in it would be invisible.
        c = unsorted_chunk(0x1000, alone=False)
        self.assertEqual(classify_chunk(build("x", [c]), c), UNSORTED)

    def test_a_libc_pointer_in_user_data_is_pointed_out(self):
        c = chunk(0x1000, 0x70, fd=LIBC_BASE + 0x1234)
        snap = build("x", [c])
        joined = " ".join(chunk_notes(snap, c))
        self.assertIn("in libc", joined)

    def test_an_ordinary_live_chunk_gets_no_commentary(self):
        # A note on every chunk is noise. Say something only when there is
        # something to say.
        c = chunk(0x1000, 0x70, fd=0x41, bk=0x0)
        self.assertEqual(chunk_notes(build("x", [c]), c), [])


class TestBinFactsAndNotes(unittest.TestCase):
    def test_a_missing_bin_says_so(self):
        rows = facts_dict(bin_facts(build("x", []), 7))
        self.assertIn("not present", rows["state"])
        self.assertEqual(bin_notes(build("x", []), 7), [])

    def test_a_normal_bin_lists_its_chain(self):
        a = chunk(0x1000, 0x70)
        snap = build("x", [a], {5: bin_(5, 1, head=a["addr"],
                                        entries=[a["addr"]])})
        rows = facts_dict(bin_facts(snap, 5))
        self.assertEqual(rows["count"], "1")
        self.assertEqual(rows["walked"], "1 chunk(s)")
        self.assertEqual(rows["truncated"], "no")
        # Chains hold user pointers, so the address in the chain is the chunk's
        # addr, not its header.
        self.assertEqual(rows["chain"], hexfmt(a["addr"]))
        self.assertEqual(rows["head"], hexfmt(a["addr"]))

    def test_a_cyclic_bin_names_the_double_free(self):
        a = chunk(0x1000, 0x70)
        snap = build("x", [a], {5: bin_(5, 2, head=a["addr"],
                                        entries=[a["addr"]], truncated=True)})
        joined = " ".join(bin_notes(snap, 5))
        self.assertIn("double free", joined)

    def test_an_empty_bin_with_a_head_explains_the_hazard(self):
        snap = build("x", [], {5: bin_(5, 0, head=STALE_HEAD)})
        joined = " ".join(bin_notes(snap, 5))
        self.assertIn("next free", joined)
        self.assertIn("next allocation", joined)

    def test_an_empty_bin_with_no_head_is_just_empty(self):
        snap = build("x", [], {5: bin_(5, 0, head=None)})
        self.assertIn("Empty", " ".join(bin_notes(snap, 5)))


if __name__ == "__main__":
    unittest.main()
