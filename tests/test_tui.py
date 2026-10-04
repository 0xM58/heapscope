"""Tests for the terminal inspector.

The point of the split in ``tui.py`` is that nothing here needs a terminal. The
state object and the renderer are pure functions over a snapshot, so navigation,
key handling and layout can all be asserted on directly. The only curses code
worth testing is the two fallbacks in ``_write``, and those get a fake screen.

The layout invariant that matters is exact width: every line ``render`` returns
is exactly as wide as the terminal it was asked for. That is what makes the
output safe to hand straight to ``addstr``, and it is the property most likely
to break quietly when the panes are resized.
"""

import curses
import io
import unittest
from contextlib import redirect_stderr
from unittest import mock

from heapscope.tui import (
    ASCII_CHARS,
    UTF8_CHARS,
    VIEW_BINS,
    VIEW_CHUNKS,
    VIEW_DIFF,
    VIEWS,
    TuiApp,
    TuiState,
    _fit,
    _labelled,
    _pane_widths,
    _window_top,
    _wrap,
    default_chars,
    render,
    run,
)

from tests.support import STALE_HEAD, bin_, build, chunk, unsorted_chunk


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def one_snapshot():
    """A snapshot with a tcache entry, an unsorted chunk and a top chunk."""
    free = chunk(0x1000, 0x70)
    unsorted = unsorted_chunk(0x2000)
    top = chunk(0x3000, 0x1000, is_top=True)
    return build("after free(0)", [free, unsorted, top],
                 {5: bin_(5, 1, head=free["addr"], entries=[free["addr"]])},
                 region_end=0x4000, pid=4242)


def two_snapshots():
    """Two snapshots where the second grows a chunk and fills a bin."""
    first = build("start", [chunk(0x1000, 0x70)])
    second = one_snapshot()
    return [first, second]


def state_for(snapshots=None):
    return TuiState(snapshots if snapshots is not None else [one_snapshot()])


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

class TestFit(unittest.TestCase):
    def test_pads_to_the_requested_width(self):
        self.assertEqual(_fit("abc", 6), "abc   ")

    def test_truncates_with_an_ellipsis(self):
        self.assertEqual(_fit("abcdefgh", 6), "abc...")

    def test_a_tiny_width_does_not_leave_room_for_an_ellipsis(self):
        # width <= len("...") means an ellipsis would be the whole field, so the
        # text is cut plain instead.
        self.assertEqual(_fit("abcdefgh", 3), "abc")
        self.assertEqual(_fit("abcdefgh", 1), "a")

    def test_zero_and_negative_widths_give_nothing(self):
        self.assertEqual(_fit("abc", 0), "")
        self.assertEqual(_fit("abc", -5), "")

    def test_the_result_is_always_exactly_the_width(self):
        for width in range(1, 30):
            self.assertEqual(len(_fit("some text here", width)), width)


class TestWrap(unittest.TestCase):
    def test_wraps_on_word_boundaries(self):
        self.assertEqual(_wrap("one two three four", 9),
                         ["one two", "three", "four"])

    def test_always_returns_at_least_one_line(self):
        self.assertEqual(_wrap("", 10), [""])

    def test_a_word_longer_than_the_width_is_left_whole(self):
        # Breaking a hex address in half makes it unreadable, and the caller
        # fits each line afterwards anyway.
        self.assertEqual(_wrap("0x4343434616161619", 8),
                         ["0x4343434616161619"])

    def test_a_degenerate_width_returns_the_text_unwrapped(self):
        self.assertEqual(_wrap("one two", 1), ["one two"])


class TestLabelled(unittest.TestCase):
    """Label/value rows have to keep their values in one column.

    Regression test: the padding used to be applied before calling the wrapper,
    which splits on whitespace and rejoins with single spaces, so the padding
    was thrown away and every value sat one space after its own label.
    """

    def test_a_short_row_is_padded_not_collapsed(self):
        lines = _labelled("size", "0x70", 10, 60)
        self.assertEqual(lines, ["size        0x70"])

    def test_two_labels_of_different_length_align(self):
        short = _labelled("size", "0x70", 10, 60)[0]
        long_ = _labelled("size field", "0x71", 10, 60)[0]
        self.assertEqual(short.index("0x70"), long_.index("0x71"))

    def test_the_whole_pane_lines_up(self):
        state = state_for()
        pane = [line.split("\u2502", 1)[1].rstrip()
                for line in render(state, 100, 26, chars=UTF8_CHARS)
                if "\u2502" in line]
        values = [line for line in pane if line and " " in line
                  and not line.startswith(" ")]
        starts = set()
        for line in values:
            # The value begins after the run of spaces that follows the label.
            rest = line.split("  ", 1)
            if len(rest) == 2:
                starts.add(len(rest[0]) + 2 + len(rest[1]) - len(rest[1].lstrip()))
        self.assertLessEqual(len(starts), 1, "values do not share a column")

    def test_a_long_value_wraps_with_a_hanging_indent(self):
        lines = _labelled("state", "one two three four five six", 6, 20)
        self.assertGreater(len(lines), 1)
        self.assertTrue(lines[0].startswith("state   one"))
        # Continuations line up under the value, not under the label.
        for line in lines[1:]:
            self.assertTrue(line.startswith(" " * 8), repr(line))
            self.assertEqual(len(line) - len(line.lstrip()), 8)

    def test_a_row_that_exactly_fits_is_not_wrapped(self):
        self.assertEqual(len(_labelled("ab", "cd", 2, 6)), 1)


class TestWindowTop(unittest.TestCase):
    def test_everything_fits_so_nothing_scrolls(self):
        self.assertEqual(_window_top(3, 5, 10), 0)

    def test_scrolls_to_keep_the_selection_visible(self):
        top = _window_top(20, 40, 10)
        self.assertLessEqual(top, 20)
        self.assertLessEqual(20, top + 10 - 1)

    def test_never_scrolls_past_the_end(self):
        self.assertEqual(_window_top(39, 40, 10), 30)

    def test_a_zero_height_window_starts_at_the_top(self):
        self.assertEqual(_window_top(5, 10, 0), 0)


class TestPaneWidths(unittest.TestCase):
    def test_the_panes_and_the_rule_fit_the_terminal(self):
        for width in range(1, 200):
            left, right = _pane_widths(width)
            self.assertGreaterEqual(left, 1)
            self.assertGreaterEqual(right, 0)
            # The separator only exists when there is a second pane to
            # separate, so it is only counted when right is non-zero.
            span = left + right + (1 if right else 0)
            self.assertLessEqual(span, width)

    def test_the_left_pane_never_takes_the_whole_screen(self):
        left, right = _pane_widths(120)
        self.assertLess(left, 120)
        self.assertGreater(right, 0)

    def test_a_single_column_terminal_gets_the_list_and_no_separator(self):
        left, right = _pane_widths(1)
        self.assertEqual((left, right), (1, 0))


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class TestStateBasics(unittest.TestCase):
    def test_it_opens_on_the_last_snapshot(self):
        # You dump snapshots as a run progresses, so the newest is the one you
        # want to see first.
        state = state_for(two_snapshots())
        self.assertEqual(state.index, 1)
        self.assertEqual(state.position, "2/2")

    def test_no_snapshots_is_a_state_it_can_hold(self):
        state = state_for([])
        self.assertIsNone(state.snapshot)
        self.assertEqual(state.position, "no snapshots")
        self.assertEqual(state.rows(), [])
        self.assertEqual(state.findings(), [])

    def test_the_header_names_the_snapshot_and_the_target(self):
        header = state_for().header_line()
        self.assertIn("after free(0)", header)
        self.assertIn("glibc 2.36", header)
        self.assertIn("pid 4242", header)

    def test_the_header_counts_warnings(self):
        snap = build("x", [], {5: bin_(5, 0, head=STALE_HEAD)})
        self.assertIn("1 warning", state_for([snap]).header_line())

    def test_the_header_says_no_snapshots_rather_than_crashing(self):
        self.assertIn("no snapshots", state_for([]).header_line())

    def test_the_tabs_mark_the_active_view(self):
        state = state_for()
        self.assertIn("[ chunks ]", state.tabs_line())
        state.set_view(VIEW_BINS)
        self.assertIn("[ bins ]", state.tabs_line())
        self.assertNotIn("[ chunks ]", state.tabs_line())


class TestStateNavigation(unittest.TestCase):
    def test_move_clamps_at_both_ends(self):
        state = state_for()
        state.move(-1)
        self.assertEqual(state.selected[VIEW_CHUNKS], 0)
        state.to_bottom()
        self.assertEqual(state.selected[VIEW_CHUNKS], 2)
        state.move(1)
        self.assertEqual(state.selected[VIEW_CHUNKS], 2)

    def test_to_top_and_to_bottom(self):
        state = state_for()
        state.to_bottom()
        self.assertEqual(state.selected[VIEW_CHUNKS], 2)
        state.to_top()
        self.assertEqual(state.selected[VIEW_CHUNKS], 0)

    def test_each_view_keeps_its_own_cursor(self):
        # Switching tabs should not lose your place in the list you left.
        state = state_for()
        state.move(2)
        state.set_view(VIEW_BINS)
        state.move(0)
        self.assertEqual(state.selected[VIEW_CHUNKS], 2)
        self.assertEqual(state.selected[VIEW_BINS], 0)

    def test_cycle_view_wraps_in_both_directions(self):
        state = state_for()
        state.cycle_view(1)
        self.assertEqual(state.view, VIEW_BINS)
        state.cycle_view(-1)
        self.assertEqual(state.view, VIEW_CHUNKS)
        state.cycle_view(-1)
        self.assertEqual(state.view, VIEWS[-1])

    def test_set_view_ignores_a_name_it_does_not_know(self):
        state = state_for()
        state.set_view("nonsense")
        self.assertEqual(state.view, VIEW_CHUNKS)

    def test_snapshot_moves_stop_at_the_ends(self):
        state = state_for(two_snapshots())
        state.next_snapshot()
        self.assertEqual(state.index, 1)
        state.prev_snapshot()
        self.assertEqual(state.index, 0)
        state.prev_snapshot()
        self.assertEqual(state.index, 0)

    def test_changing_snapshot_pulls_the_cursor_back_into_range(self):
        # The lists differ in length between snapshots, so a cursor that was
        # valid on one can point past the end of the next.
        short = build("start", [chunk(0x1000, 0x70)])
        long_ = build("later", [chunk(0x1000 + i * 0x100, 0x70)
                                for i in range(6)])
        state = TuiState([short, long_])      # opens on the later snapshot
        state.to_bottom()
        self.assertEqual(state.selected[VIEW_CHUNKS], 5)
        state.prev_snapshot()
        self.assertEqual(state.index, 0)
        self.assertEqual(state.selected[VIEW_CHUNKS], 0)
        state.next_snapshot()
        self.assertEqual(state.index, 1)
        self.assertEqual(state.selected[VIEW_CHUNKS], 0)

    def test_moving_in_an_empty_list_is_a_no_op(self):
        state = state_for([])
        state.move(1)
        state.to_bottom()
        self.assertEqual(state.selected[VIEW_CHUNKS], 0)


class TestStateRows(unittest.TestCase):
    def test_chunk_rows_show_the_address_size_and_state(self):
        state = state_for()
        rows = state.rows()
        self.assertEqual(len(rows), 3)
        self.assertIn("0x1000", rows[0])
        self.assertIn("0x70", rows[0])
        self.assertIn("tcache", rows[0])
        self.assertIn("unsorted", rows[1])
        self.assertIn("top", rows[2])

    def test_bin_rows_show_the_count_the_size_and_the_head(self):
        state = state_for()
        state.set_view(VIEW_BINS)
        rows = state.rows()
        self.assertEqual(len(rows), 1)
        self.assertIn("[5]", rows[0])
        self.assertIn("x1", rows[0])
        self.assertIn("0x70", rows[0])
        # A chain holds user pointers, so the head is the chunk's addr.
        self.assertIn("0x1010", rows[0])

    def test_bins_are_listed_in_index_order(self):
        snap = build("x", [], {9: bin_(9, 0), 1: bin_(1, 0), 5: bin_(5, 0)})
        state = state_for([snap])
        state.set_view(VIEW_BINS)
        self.assertEqual([r.split("]")[0] + "]" for r in state.rows()],
                         ["[1]", "[5]", "[9]"])

    def test_the_first_snapshot_has_nothing_to_diff_against(self):
        state = state_for()
        state.set_view(VIEW_DIFF)
        rows = state.rows()
        self.assertEqual(len(rows), 1)
        self.assertIn("first snapshot", rows[0])

    def test_the_diff_lists_what_the_next_snapshot_changed(self):
        state = state_for(two_snapshots())
        state.set_view(VIEW_DIFF)
        joined = " ".join(state.rows())
        self.assertIn("new chunk", joined)
        self.assertIn("tcache[5]", joined)

    def test_an_unchanged_pair_says_so(self):
        snap = one_snapshot()
        state = state_for([snap, one_snapshot()])
        state.set_view(VIEW_DIFF)
        self.assertIn("Nothing changed", " ".join(state.rows()))

    def test_rows_can_be_asked_for_a_view_other_than_the_current_one(self):
        state = state_for()
        self.assertEqual(len(state.rows(VIEW_BINS)), 1)
        self.assertEqual(len(state.rows(VIEW_CHUNKS)), 3)

    def test_focus_hides_live_chunks_but_keeps_allocator_state(self):
        live = chunk(0x4000, 0x70)
        state = state_for([build("x", [live, one_snapshot().chunks[0],
                                      one_snapshot().chunks[1],
                                      one_snapshot().chunks[2]],
                                 one_snapshot().tcache)])
        state.toggle_focus()
        rows = state.rows()
        self.assertEqual(len(rows), 3)
        self.assertNotIn("0x4000", " ".join(rows))
        self.assertIn("tcache", " ".join(rows))

    def test_focus_keeps_a_flagged_empty_bin(self):
        state = state_for([build("x", [], {5: bin_(5, 0, head=STALE_HEAD),
                                             7: bin_(7, 0)})])
        state.set_view(VIEW_BINS)
        state.toggle_focus()
        self.assertEqual(len(state.rows()), 1)
        self.assertIn("[5]", state.rows()[0])

    def test_palette_filters_sorts_and_finds(self):
        live = chunk(0x1000, 0x90)
        free = chunk(0x2000, 0x70)
        state = state_for([build("x", [live, free],
                                 {5: bin_(5, 1, head=free["addr"],
                                          entries=[free["addr"]])})])
        self.assertEqual(state.command("filter tcache"), "filter: tcache")
        self.assertEqual(len(state.rows()), 1)
        self.assertIn("0x2000", state.rows()[0])
        self.assertEqual(state.command("sort size"), "sort: size")
        self.assertEqual(state.command("find 0x2010"), "selected 0x2010")
        self.assertEqual(state.selected_chunk()["header"], 0x2000)

    def test_palette_explains_invalid_commands(self):
        state = state_for()
        self.assertIn("filter: all", state.command("filter impossible"))
        self.assertIn("unknown command", state.command("blastoff"))


class TestStateSelection(unittest.TestCase):
    def test_the_selected_chunk_follows_the_cursor(self):
        state = state_for()
        self.assertEqual(state.selected_chunk()["header"], 0x1000)
        state.move(1)
        self.assertEqual(state.selected_chunk()["header"], 0x2000)

    def test_no_chunk_is_selected_in_the_bin_view(self):
        state = state_for()
        state.set_view(VIEW_BINS)
        self.assertIsNone(state.selected_chunk())

    def test_the_selected_bin_is_an_index_not_a_position(self):
        snap = build("x", [], {9: bin_(9, 0), 1: bin_(1, 0)})
        state = state_for([snap])
        state.set_view(VIEW_BINS)
        self.assertEqual(state.selected_bin(), 1)
        state.move(1)
        self.assertEqual(state.selected_bin(), 9)

    def test_no_bin_is_selected_in_the_chunk_view(self):
        state = state_for()
        self.assertIsNone(state.selected_bin())

    def test_an_empty_bin_list_selects_nothing(self):
        state = state_for([build("x", [chunk(0x1000, 0x70)])])
        state.set_view(VIEW_BINS)
        self.assertIsNone(state.selected_bin())
        self.assertEqual(state.facts(), [])
        self.assertEqual(state.notes(), [])


class TestStateDetailPane(unittest.TestCase):
    def test_the_pane_describes_the_selected_chunk(self):
        state = state_for()
        text = "\n".join(state.detail_lines(60))
        self.assertIn("0x1000", text)
        self.assertIn("what it means", text)

    def test_the_pane_describes_the_selected_bin(self):
        state = state_for()
        state.set_view(VIEW_BINS)
        text = "\n".join(state.detail_lines(60))
        self.assertIn("count", text)
        self.assertIn("walked", text)

    def test_the_diff_view_has_no_detail_pane(self):
        state = state_for(two_snapshots())
        state.set_view(VIEW_DIFF)
        self.assertEqual(state.facts(), [])
        self.assertEqual(state.notes(), [])
        self.assertEqual(state.detail_lines(60), ["Nothing selected."])

    def test_local_findings_are_scoped_to_the_selected_bin(self):
        # A warning about tcache[5] should not follow you onto tcache[7].
        state = state_for([build("x", [], {5: bin_(5, 0, head=STALE_HEAD),
                                           7: bin_(7, 0)})])
        state.set_view(VIEW_BINS)
        self.assertEqual([f.scope for f in state.local_findings()], ["tcache[5]"])
        state.move(1)
        self.assertEqual(state.local_findings(), [])

    def test_a_finding_about_the_heap_does_not_attach_to_a_chunk(self):
        # "the walk was truncated" is about the whole snapshot, so there is
        # nothing sensible to pin it to in the list.
        state = state_for([build("x", [chunk(0x1000, 0x70)], truncated=True)])
        self.assertEqual(state.local_findings(), [])

    def test_a_chunk_in_a_flagged_bin_carries_the_finding(self):
        state = state_for()
        self.assertEqual([f.scope for f in state.local_findings()], [])

        # A bin whose count outruns its chain is reported twice: once for the
        # cycle the walk stopped on, once for the count that no longer matches.
        cyclic = chunk(0x1000, 0x70)
        state = state_for([build("x", [cyclic],
                                 {5: bin_(5, 2, head=cyclic["addr"],
                                          entries=[cyclic["addr"]],
                                          truncated=True)})])
        scopes = [f.scope for f in state.local_findings()]
        self.assertTrue(scopes)
        self.assertEqual(set(scopes), {"tcache[5]"})
        self.assertIn("findings", state.detail_lines(60)[0])

    def test_a_chunk_outside_every_bin_has_no_findings(self):
        state = state_for()
        state.move(2)   # the top chunk, in no bin
        self.assertEqual(state.local_findings(), [])


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

class TestRenderLayout(unittest.TestCase):
    def assertExactLayout(self, state, width, height):
        lines = render(state, width, height, chars=ASCII_CHARS)
        self.assertEqual(len(lines), height,
                         "expected %d lines, got %d" % (height, len(lines)))
        for i, line in enumerate(lines):
            self.assertEqual(len(line), width,
                             "line %d is %d wide, wanted %d: %r"
                             % (i, len(line), width, line))

    def test_the_layout_holds_at_awkward_sizes(self):
        # This is the assertion that matters: a line one character too long
        # raises on the last cell of a real terminal.
        state = state_for(two_snapshots())
        for width in (1, 2, 3, 5, 10, 12, 13, 20, 40, 79, 80, 120, 200):
            for height in (1, 2, 3, 4, 5, 6, 10, 24, 50):
                self.assertExactLayout(state, width, height)

    def test_the_layout_holds_in_every_view(self):
        state = state_for(two_snapshots())
        for view in VIEWS:
            state.set_view(view)
            for selected in range(3):
                state.selected[view] = selected
                self.assertExactLayout(state, 80, 24)

    def test_the_layout_holds_on_the_help_screen(self):
        state = state_for()
        state.show_help = True
        for width in (20, 60, 100):
            self.assertExactLayout(state, width, 24)

    def test_the_layout_holds_with_no_snapshots(self):
        self.assertExactLayout(state_for([]), 60, 20)

    def test_the_layout_holds_for_a_bin_with_no_chain(self):
        state = state_for([build("x", [], {5: bin_(5, 0, head=STALE_HEAD)})])
        state.set_view(VIEW_BINS)
        self.assertExactLayout(state, 70, 18)

    def test_a_width_below_the_pane_minimum_is_still_honoured(self):
        # The caller asked for 10 columns, so it gets 10, not a padded-up
        # minimum it did not ask for.
        lines = render(state_for(), 10, 8, chars=ASCII_CHARS)
        self.assertTrue(all(len(line) == 10 for line in lines))


class TestRenderContent(unittest.TestCase):
    def test_the_selected_row_is_marked(self):
        state = state_for()
        lines = render(state, 80, 24, chars=ASCII_CHARS)
        marked = [line for line in lines if line.startswith(">")]
        self.assertEqual(len(marked), 1)
        self.assertIn("0x1000", marked[0])

    def test_the_marker_follows_the_cursor(self):
        state = state_for()
        state.move(1)
        lines = render(state, 80, 24, chars=ASCII_CHARS)
        marked = [line for line in lines if line.startswith(">")]
        self.assertIn("0x2000", marked[0])

    def test_the_panes_are_separated_by_a_rule(self):
        state = state_for()
        body = render(state, 80, 24, chars=ASCII_CHARS)[3]
        self.assertIn("|", body)

    def test_the_footer_lists_the_keys(self):
        lines = render(state_for(), 80, 24, chars=ASCII_CHARS)
        self.assertIn("q quit", lines[-1])

    def test_the_help_screen_replaces_the_body(self):
        state = state_for()
        state.show_help = True
        text = "\n".join(render(state, 80, 24, chars=ASCII_CHARS))
        self.assertIn("heapscope in a terminal", text)
        self.assertIn("switch between chunks, bins and diff", text)

    def test_the_empty_state_tells_you_how_to_make_snapshots(self):
        text = "\n".join(render(state_for([]), 80, 24, chars=ASCII_CHARS))
        self.assertIn("No snapshots loaded", text)
        self.assertIn("HeapSnapshot.capture", text)

    def test_the_box_characters_come_from_the_caller(self):
        state = state_for()
        utf8 = render(state, 80, 24, chars=UTF8_CHARS)
        ascii_ = render(state, 80, 24, chars=ASCII_CHARS)
        self.assertIn("\u2500", utf8[2])
        self.assertIn("-", ascii_[2])
        self.assertNotIn("\u2500", ascii_[2])

    def test_the_diff_view_renders_its_rows(self):
        state = state_for(two_snapshots())
        state.set_view(VIEW_DIFF)
        text = "\n".join(render(state, 90, 24, chars=ASCII_CHARS))
        self.assertIn("new chunk", text)


class TestDefaultChars(unittest.TestCase):
    def test_it_picks_one_of_the_two_sets(self):
        self.assertIn(default_chars(), (UTF8_CHARS, ASCII_CHARS))

    def test_a_broken_locale_falls_back_to_ascii(self):
        with mock.patch("heapscope.tui.locale.getpreferredencoding",
                        side_effect=ValueError("no locale")):
            self.assertIs(default_chars(), ASCII_CHARS)

    def test_a_utf8_locale_gets_the_box_characters(self):
        with mock.patch("heapscope.tui.locale.getpreferredencoding",
                        return_value="UTF-8"):
            self.assertIs(default_chars(), UTF8_CHARS)

    def test_a_c_locale_gets_ascii(self):
        with mock.patch("heapscope.tui.locale.getpreferredencoding",
                        return_value="ANSI_X3.4-1968"):
            self.assertIs(default_chars(), ASCII_CHARS)


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------

class TestKeyHandling(unittest.TestCase):
    def app(self, snapshots=None):
        return TuiApp(state_for(snapshots))

    def test_q_and_escape_quit(self):
        self.assertFalse(self.app().handle(ord("q")))
        self.assertFalse(self.app().handle(27))

    def test_everything_else_keeps_running(self):
        app = self.app()
        for key in (ord("j"), ord("k"), ord("g"), ord("?"), ord("z")):
            self.assertTrue(app.handle(key), "key %r should not quit" % key)

    def test_j_and_k_move_down_and_up(self):
        app = self.app()
        app.handle(ord("j"))
        self.assertEqual(app.state.selected[VIEW_CHUNKS], 1)
        app.handle(ord("k"))
        self.assertEqual(app.state.selected[VIEW_CHUNKS], 0)

    def test_the_arrow_keys_do_the_same(self):
        app = self.app()
        app.handle(curses.KEY_DOWN)
        self.assertEqual(app.state.selected[VIEW_CHUNKS], 1)
        app.handle(curses.KEY_UP)
        self.assertEqual(app.state.selected[VIEW_CHUNKS], 0)

    def test_page_keys_move_by_ten(self):
        chunks = [chunk(0x1000 + i * 0x100, 0x70) for i in range(30)]
        app = self.app([build("x", chunks)])
        app.handle(curses.KEY_NPAGE)
        self.assertEqual(app.state.selected[VIEW_CHUNKS], 10)
        app.handle(curses.KEY_PPAGE)
        self.assertEqual(app.state.selected[VIEW_CHUNKS], 0)

    def test_tab_cycles_forward_and_back(self):
        app = self.app()
        app.handle(ord("\t"))
        self.assertEqual(app.state.view, VIEW_BINS)
        app.handle(curses.KEY_BTAB)
        self.assertEqual(app.state.view, VIEW_CHUNKS)

    def test_the_number_keys_jump_straight_to_a_view(self):
        app = self.app()
        app.handle(ord("3"))
        self.assertEqual(app.state.view, VIEW_DIFF)
        app.handle(ord("1"))
        self.assertEqual(app.state.view, VIEW_CHUNKS)
        app.handle(ord("2"))
        self.assertEqual(app.state.view, VIEW_BINS)

    def test_n_and_p_change_snapshot(self):
        app = self.app(two_snapshots())
        self.assertEqual(app.state.index, 1)
        app.handle(ord("p"))
        self.assertEqual(app.state.index, 0)
        app.handle(ord("n"))
        self.assertEqual(app.state.index, 1)

    def test_g_and_G_jump_to_the_ends(self):
        app = self.app()
        app.handle(ord("G"))
        self.assertEqual(app.state.selected[VIEW_CHUNKS], 2)
        app.handle(ord("g"))
        self.assertEqual(app.state.selected[VIEW_CHUNKS], 0)

    def test_f_toggles_focus_mode(self):
        app = self.app()
        self.assertFalse(app.state.focused)
        app.handle(ord("f"))
        self.assertTrue(app.state.focused)
        self.assertIn("focus", app.state.header_line())

    def test_question_mark_opens_help(self):
        app = self.app()
        app.handle(ord("?"))
        self.assertTrue(app.state.show_help)

    def test_any_key_closes_help_without_acting_on_it(self):
        # Pressing j on the help screen should dismiss it, not scroll the list
        # behind it that you cannot see.
        app = self.app()
        app.handle(ord("?"))
        app.handle(ord("j"))
        self.assertFalse(app.state.show_help)
        self.assertEqual(app.state.selected[VIEW_CHUNKS], 0)

    def test_q_on_the_help_screen_only_closes_the_help(self):
        app = self.app()
        app.handle(ord("?"))
        self.assertTrue(app.handle(ord("q")))
        self.assertFalse(app.state.show_help)


class TestScreenWriting(unittest.TestCase):
    class FakeScreen:
        """Records what was written, and can refuse the last cell."""

        def __init__(self, width=40, height=6, refuse_full_bottom=True,
                     refuse_unicode=False):
            self.width = width
            self.height = height
            self.refuse_full_bottom = refuse_full_bottom
            self.refuse_unicode = refuse_unicode
            self.written = []

        def getmaxyx(self):
            return self.height, self.width

        def addstr(self, y, x, line):
            if self.refuse_unicode:
                raise UnicodeEncodeError("ascii", line, 0, 1, "not ascii")
            if (self.refuse_full_bottom and y == self.height - 1
                    and len(line) >= self.width):
                raise curses.error("addwstr() returned ERR")
            self.written.append((y, line))

    def test_a_full_bottom_line_falls_back_to_one_character_less(self):
        # curses refuses to write the bottom-right cell, which a screenful of
        # exactly-width lines always tries to do.
        screen = self.FakeScreen(width=40, height=6)
        app = TuiApp(state_for())
        app.draw(screen)
        self.assertEqual(len(screen.written), 6)
        last_y, last_line = screen.written[-1]
        self.assertEqual(last_y, 5)
        self.assertEqual(len(last_line), 39)

    def test_a_terminal_that_cannot_encode_the_box_characters_drops_to_ascii(self):
        screen = self.FakeScreen(refuse_unicode=True)
        app = TuiApp(state_for())
        self.assertIs(app.chars, default_chars())
        app.draw(screen)
        self.assertIs(app.chars, ASCII_CHARS)

    def test_a_screen_that_refuses_everything_does_not_raise(self):
        screen = self.FakeScreen(refuse_full_bottom=True)
        screen.addstr = mock.Mock(side_effect=curses.error("nope"))
        TuiApp(state_for()).draw(screen)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

class TestRun(unittest.TestCase):
    def test_no_snapshots_is_an_error_not_an_empty_screen(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            self.assertEqual(run([]), 1)
        self.assertIn("no snapshots", stderr.getvalue())

    def test_without_a_tty_it_says_so(self):
        # Redirected output is the common case in CI and in a pipe, and a
        # curses wrapper there produces an unreadable screen rather than an
        # error. StringIO is not a tty, which is exactly the situation.
        #
        # stdout is redirected too, not just stderr, so this behaves the same
        # whether the suite is run from a terminal or from a pipe.
        stderr = io.StringIO()
        with redirect_stderr(stderr), mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(run([one_snapshot()]), 1)
        message = stderr.getvalue()
        self.assertIn("needs a tty", message)
        self.assertIn("redirected", message)


if __name__ == "__main__":
    unittest.main()
