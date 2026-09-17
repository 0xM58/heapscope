"""A terminal inspector for heap snapshots.

The browser viewer answers "what shape is the heap". This answers "what is this
chunk and why", which is a different job and the one you want more often: you
are in a container or over SSH, there is no browser, and forwarding a port to
look at one pointer is a poor trade.

The layout follows the k9s and lazygit convention. A list you move through on
the left, a pane on the right that describes whatever is selected, and a footer
of keys.

Everything that decides *what to show* lives in :class:`TuiState` and
:func:`render`, both of which are pure. The curses layer only reads keys and
writes out the lines ``render`` produced. That split is what makes this testable
without a terminal, and it is why the layout arithmetic can be asserted on
rather than eyeballed.
"""

from __future__ import annotations

import curses
import locale
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .describe import (
    WARN,
    bin_facts,
    bin_notes,
    chunk_facts,
    chunk_notes,
    hexfmt,
    snapshot_findings,
    snapshot_states,
)
from .view import HeapSnapshot

__all__ = ["TuiState", "render", "run", "ASCII_CHARS", "UTF8_CHARS"]


# ---------------------------------------------------------------------------
# Drawing characters
# ---------------------------------------------------------------------------

#: Box drawing, written as escapes so this file stays pure ASCII. The terminal
#: gets the real characters and the source stays diffable.
UTF8_CHARS = {
    "h": "\u2500",   # box drawings light horizontal
    "v": "\u2502",   # box drawings light vertical
}

ASCII_CHARS = {"h": "-", "v": "|"}

ELLIPSIS = "..."


def _terminal_is_utf8() -> bool:
    try:
        encoding = locale.getpreferredencoding(False) or ""
    except Exception:  # pragma: no cover - locale can be hostile
        return False
    return "utf" in encoding.lower()


def default_chars() -> Dict[str, str]:
    """Box drawing when the terminal can take it, ASCII when it cannot.

    A C or POSIX locale raises on the box characters. A tool that crashes
    because of its borders is worse than one with plain ones.
    """
    return UTF8_CHARS if _terminal_is_utf8() else ASCII_CHARS


def _fit(text: str, width: int) -> str:
    """Pad or truncate *text* to exactly *width* characters."""
    if width <= 0:
        return ""
    if len(text) > width:
        if width <= len(ELLIPSIS):
            return text[:width]
        return text[:width - len(ELLIPSIS)] + ELLIPSIS
    return text + " " * (width - len(text))


def _wrap(text: str, width: int) -> List[str]:
    """Greedy word wrap, always returning at least one line."""
    if width <= 1:
        return [text]
    lines: List[str] = []
    current = ""
    for word in text.split():
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def _labelled(key: str, value: str, key_width: int, width: int) -> List[str]:
    """One label/value row, wrapping the value under itself.

    The padding is applied here rather than handed to :func:`_wrap`, because
    that helper splits on whitespace and rejoins with single spaces. A padded
    label passed through it comes back with the alignment gone, so every value
    in the pane would start one space after its own label and no two would line
    up.
    """
    prefix = key.ljust(key_width) + "  "
    if len(prefix) + len(value) <= width:
        return [prefix + value]
    # Too long for one row: wrap the value and hang the continuations under it,
    # so the column stays readable instead of sliding back to the margin.
    lines = _wrap(value, max(1, width - len(prefix)))
    return [prefix + lines[0]] + [" " * len(prefix) + line for line in lines[1:]]


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

VIEW_CHUNKS = "chunks"
VIEW_BINS = "bins"
VIEW_DIFF = "diff"
VIEWS = (VIEW_CHUNKS, VIEW_BINS, VIEW_DIFF)


class TuiState:
    """What the UI knows, with no terminal attached.

    Every key the app understands maps to a method here, so navigation and the
    text it produces can be exercised without a pty.
    """

    def __init__(self, snapshots: Sequence[HeapSnapshot]) -> None:
        self.snapshots: List[HeapSnapshot] = list(snapshots)
        self.index = max(0, len(self.snapshots) - 1)
        self.view = VIEW_CHUNKS
        self.selected = {view: 0 for view in VIEWS}
        self.show_help = False

    # ---- the current snapshot -------------------------------------------
    @property
    def snapshot(self) -> Optional[HeapSnapshot]:
        if not self.snapshots:
            return None
        return self.snapshots[self.index]

    @property
    def position(self) -> str:
        if not self.snapshots:
            return "no snapshots"
        return "%d/%d" % (self.index + 1, len(self.snapshots))

    def findings(self):
        snap = self.snapshot
        return snapshot_findings(snap) if snap is not None else []

    # ---- selection ------------------------------------------------------
    def bin_indexes(self) -> List[int]:
        snap = self.snapshot
        return sorted(snap.tcache) if snap is not None else []

    def selected_chunk(self) -> Optional[Dict[str, Any]]:
        snap = self.snapshot
        if snap is None or self.view != VIEW_CHUNKS:
            return None
        i = self.selected[VIEW_CHUNKS]
        if not 0 <= i < len(snap.chunks):
            return None
        return snap.chunks[i]

    def selected_bin(self) -> Optional[int]:
        indexes = self.bin_indexes()
        if self.view != VIEW_BINS or not indexes:
            return None
        i = self.selected[VIEW_BINS]
        if not 0 <= i < len(indexes):
            return None
        return indexes[i]

    # ---- rows -----------------------------------------------------------
    def rows(self, view: Optional[str] = None) -> List[str]:
        """The left-hand list, one string per row."""
        view = view or self.view
        snap = self.snapshot
        if snap is None:
            return []
        if view == VIEW_CHUNKS:
            return self._chunk_rows(snap)
        if view == VIEW_BINS:
            return self._bin_rows(snap)
        return self._diff_rows(snap)

    @staticmethod
    def _chunk_rows(snap: HeapSnapshot) -> List[str]:
        states = snapshot_states(snap)
        rows = []
        for chunk in snap.chunks:
            state = states.get(chunk["header"], "live")
            rows.append("%-16s %-8s %s"
                        % (hexfmt(chunk["header"]), "%#x" % chunk["size"], state))
        return rows

    @staticmethod
    def _bin_rows(snap: HeapSnapshot) -> List[str]:
        rows = []
        for index in sorted(snap.tcache):
            b = snap.tcache[index]
            rows.append("[%d]%s x%-3d %-7s %s"
                        % (index,
                           " " * max(0, 2 - len(str(index))),
                           b["count"],
                           "%#x" % (b["size"] or 0),
                           hexfmt(b["head"])))
        return rows

    def _diff_rows(self, snap: HeapSnapshot) -> List[str]:
        if self.index == 0:
            return ["This is the first snapshot, so there is nothing to "
                    "compare it against."]
        diff = self.snapshots[self.index - 1].diff(snap)
        rows: List[str] = []
        for addr in diff.added:
            rows.append("+ %s  new chunk" % hexfmt(addr))
        for addr in diff.removed:
            rows.append("- %s  no longer a chunk" % hexfmt(addr))
        for addr, before, after in diff.changed:
            rows.append("~ %s  %s -> %s" % (hexfmt(addr), before, after))
        for index in diff.tcache_changed:
            b = diff.tcache_before.get(index, (0, None))
            a = diff.tcache_after.get(index, (0, None))
            rows.append("tcache[%d]  count %d -> %d   head %s -> %s"
                        % (index, b[0], a[0], hexfmt(b[1]), hexfmt(a[1])))
        if not rows:
            rows.append("Nothing changed between these two snapshots.")
        return rows

    # ---- detail pane ----------------------------------------------------
    def facts(self) -> List[Tuple[str, str]]:
        snap = self.snapshot
        if snap is None:
            return []
        if self.view == VIEW_CHUNKS:
            chunk = self.selected_chunk()
            return chunk_facts(snap, chunk) if chunk is not None else []
        if self.view == VIEW_BINS:
            index = self.selected_bin()
            return bin_facts(snap, index) if index is not None else []
        return []

    def notes(self) -> List[str]:
        snap = self.snapshot
        if snap is None:
            return []
        if self.view == VIEW_CHUNKS:
            chunk = self.selected_chunk()
            return chunk_notes(snap, chunk) if chunk is not None else []
        if self.view == VIEW_BINS:
            index = self.selected_bin()
            return bin_notes(snap, index) if index is not None else []
        return []

    def local_findings(self):
        """Findings that apply to whatever is selected."""
        snap = self.snapshot
        if snap is None:
            return []
        if self.view == VIEW_BINS:
            index = self.selected_bin()
            if index is None:
                return []
            scope = "tcache[%d]" % index
            return [f for f in self.findings() if f.scope == scope]
        chunk = self.selected_chunk()
        if chunk is None:
            return []
        index = None
        for i, b in snap.tcache.items():
            if chunk["addr"] in b["entries"]:
                index = i
                break
        if index is None:
            return []
        scope = "tcache[%d]" % index
        return [f for f in self.findings() if f.scope == scope]

    def detail_lines(self, width: int) -> List[str]:
        """The right-hand pane, wrapped to *width*, as a flat list of lines."""
        out: List[str] = []

        findings = self.local_findings()
        if findings:
            out.append("findings")
            for finding in findings:
                prefix = "[W]" if finding.level == WARN else "[i]"
                wrapped = _wrap(finding.message, max(1, width - 4))
                out.append("%s %s" % (prefix, wrapped[0]))
                out.extend("    " + line for line in wrapped[1:])
            out.append("")

        facts = self.facts()
        if facts:
            key_width = max(len(key) for key, _ in facts)
            for key, value in facts:
                out.extend(_labelled(key, value, key_width, width))
            out.append("")

        notes = self.notes()
        if notes:
            out.append("what it means")
            for note in notes:
                out.extend(_wrap(note, width))
                out.append("")

        if not out:
            out.append("Nothing selected.")
        return out

    # ---- header and footer ----------------------------------------------
    def tabs_line(self) -> str:
        cells = []
        for view in VIEWS:
            label = " %s " % view
            cells.append("[%s]" % label if view == self.view else " " + label + " ")
        return "".join(cells)

    def header_line(self) -> str:
        snap = self.snapshot
        if snap is None:
            return " heapscope   no snapshots"
        parts = [" heapscope ", snap.label, self.position]
        if snap.glibc:
            parts.append("glibc " + snap.glibc)
        if snap.pid:
            parts.append("pid %d" % snap.pid)
        warnings = sum(1 for f in self.findings() if f.level == WARN)
        if warnings:
            parts.append("%d warning%s" % (warnings, "" if warnings == 1 else "s"))
        return "   ".join(parts)

    def footer_line(self) -> str:
        return (" j/k move   tab view   n/p snapshot   g/G ends   ? help   q quit")

    # ---- navigation -----------------------------------------------------
    def move(self, delta: int) -> None:
        rows = self.rows()
        if not rows:
            return
        current = self.selected[self.view]
        self.selected[self.view] = max(0, min(len(rows) - 1, current + delta))

    def to_top(self) -> None:
        self.selected[self.view] = 0

    def to_bottom(self) -> None:
        rows = self.rows()
        self.selected[self.view] = max(0, len(rows) - 1)

    def set_view(self, view: str) -> None:
        if view in VIEWS:
            self.view = view

    def cycle_view(self, delta: int = 1) -> None:
        i = VIEWS.index(self.view)
        self.view = VIEWS[(i + delta) % len(VIEWS)]

    def next_snapshot(self) -> None:
        if self.index < len(self.snapshots) - 1:
            self.index += 1
            self._clamp()

    def prev_snapshot(self) -> None:
        if self.index > 0:
            self.index -= 1
            self._clamp()

    def _clamp(self) -> None:
        """Keep each view's cursor inside its own list after a snapshot change.

        The lists differ in length between snapshots, so a cursor that was
        valid on one can be past the end on the next.
        """
        for view in VIEWS:
            count = len(self.rows(view))
            self.selected[view] = max(0, min(max(0, count - 1),
                                             self.selected[view]))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _window_top(selected: int, count: int, height: int) -> int:
    """First row to draw, so the selection stays on screen."""
    if count <= height or height <= 0:
        return 0
    top = max(0, selected - height // 2)
    return min(top, count - height)


def _pane_widths(width: int) -> Tuple[int, int]:
    """How much of *width* the list and the detail pane get.

    A right-hand width of zero means there is no room for a second pane at all,
    and the caller must drop the separator too; otherwise a one-column terminal
    would try to draw two columns plus a rule. Never returns a negative width,
    so a terminal narrower than the minimum still produces something drawable
    rather than a crash.
    """
    width = max(1, width)
    left = max(12, min(64, int(width * 0.42)))
    left = min(left, max(1, width - 2))
    right = max(0, width - left - 1)
    if right == 0:
        left = width
    return left, right


def _help_lines() -> List[str]:
    return [
        "heapscope in a terminal.",
        "",
        "The left pane is a list you move through. The right pane describes "
        "whatever is selected: the raw fields, then what they mean.",
        "",
        "j / k, up / down      move the selection",
        "tab, shift-tab        switch between chunks, bins and diff",
        "1 2 3                 jump straight to a view",
        "n / p                 next and previous snapshot",
        "g / G                 first and last row",
        "?                     this help",
        "q, esc                quit",
        "",
        "chunks   every chunk in the heap, with its state",
        "bins     tcache bins, their counts and walked chains",
        "diff     what changed between this snapshot and the one before",
    ]


def render(state: TuiState, width: int, height: int,
           chars: Optional[Dict[str, str]] = None) -> List[str]:
    """The whole screen, as a list of lines each exactly *width* characters.

    Pure: no curses, no terminal, no globals. Tests call this directly, which is
    the only reason the layout can be asserted on.
    """
    drawing = chars if chars is not None else default_chars()
    # No clamping up. A caller asking for 10 columns gets 10, so the output can
    # be handed straight to a terminal of that size. The layout helpers cope
    # with being squeezed; see _pane_widths and _fit.
    width = max(1, width)
    height = max(1, height)

    lines: List[str] = [
        _fit(state.header_line(), width),
        _fit(state.tabs_line(), width),
        drawing["h"] * width,
    ]

    body_height = max(1, height - 4)   # header, tabs, rule, footer

    if state.show_help:
        body = [_fit(line, width) for line in _help_lines()]
    elif state.snapshot is None:
        body = [_fit("No snapshots loaded.", width), "",
                _fit("Dump one at each stage from your exploit script:", width),
                "",
                _fit('  HeapSnapshot.capture(p, label="after free(0)")'
                     '.save("stages/03.json")', width)]
    elif state.view == VIEW_DIFF:
        body = [_fit(row, width) for row in state.rows()]
    else:
        body = _split_body(state, width, body_height, drawing)

    lines.extend(_fit(body[i], width) if i < len(body) else " " * width
                 for i in range(body_height))
    lines.append(_fit(state.footer_line(), width))
    return lines[:height]


def _split_body(state: TuiState, width: int, height: int,
                drawing: Dict[str, str]) -> List[str]:
    """The list-and-detail body, one string per screen row."""
    left_width, right_width = _pane_widths(width)
    rows = state.rows()
    selected = state.selected[state.view]
    top = _window_top(selected, len(rows), height)
    detail = state.detail_lines(right_width)

    out: List[str] = []
    for i in range(height):
        n = top + i
        if n < len(rows):
            left = (">" if n == selected else " ") + rows[n]
        else:
            left = ""
        if right_width == 0:
            out.append(_fit(left, left_width))
            continue
        right = detail[i] if i < len(detail) else ""
        out.append(_fit(left, left_width) + drawing["v"] + _fit(right, right_width))
    return out


# ---------------------------------------------------------------------------
# The curses layer
# ---------------------------------------------------------------------------

class TuiApp:
    """Reads keys, redraws, and does nothing else.

    All the decisions live in :class:`TuiState` and :func:`render`; this class
    exists only because a terminal has to be driven from one place.
    """

    def __init__(self, state: TuiState) -> None:
        self.state = state
        self.chars = default_chars()

    # ---- drawing --------------------------------------------------------
    def draw(self, screen) -> None:
        height, width = screen.getmaxyx()
        for y, line in enumerate(render(self.state, width, height, self.chars)):
            self._write(screen, y, line)

    def _write(self, screen, y: int, line: str) -> None:
        # Writing the bottom-right cell raises, so fall back to one character
        # less. A terminal that cannot encode the box characters falls back to
        # ASCII for good rather than failing every frame.
        try:
            screen.addstr(y, 0, line)
        except curses.error:
            try:
                screen.addstr(y, 0, line[:-1])
            except curses.error:
                pass
        except UnicodeEncodeError:
            self.chars = ASCII_CHARS

    # ---- input ----------------------------------------------------------
    def handle(self, key: int) -> bool:
        """Act on one key. Returns False when the UI should exit."""
        state = self.state

        if state.show_help:
            state.show_help = False
            return True

        if key in (ord("q"), 27):
            return False
        if key in (curses.KEY_UP, ord("k")):
            state.move(-1)
        elif key in (curses.KEY_DOWN, ord("j")):
            state.move(1)
        elif key == curses.KEY_PPAGE:
            state.move(-10)
        elif key == curses.KEY_NPAGE:
            state.move(10)
        elif key == ord("\t"):
            state.cycle_view(1)
        elif key == curses.KEY_BTAB:
            state.cycle_view(-1)
        elif key == ord("1"):
            state.set_view(VIEW_CHUNKS)
        elif key == ord("2"):
            state.set_view(VIEW_BINS)
        elif key == ord("3"):
            state.set_view(VIEW_DIFF)
        elif key == ord("n"):
            state.next_snapshot()
        elif key == ord("p"):
            state.prev_snapshot()
        elif key == ord("g"):
            state.to_top()
        elif key == ord("G"):
            state.to_bottom()
        elif key == ord("?"):
            state.show_help = True
        return True

    def main(self, screen) -> None:
        curses.curs_set(0)
        screen.keypad(True)
        while True:
            self.draw(screen)
            screen.refresh()
            if not self.handle(screen.getch()):
                break


def run(snapshots: Sequence[HeapSnapshot]) -> int:
    """Show *snapshots* in a terminal UI until the user quits."""
    if not snapshots:
        print("error: no snapshots to show", file=sys.stderr)
        return 1
    if not sys.stdout.isatty():
        print("error: the terminal UI needs a tty. Use `heapscope view` for a "
              "browser, or run this from a terminal.", file=sys.stderr)
        return 1

    locale.setlocale(locale.LC_ALL, "")
    try:
        curses.wrapper(TuiApp(TuiState(snapshots)).main)
    except curses.error as exc:
        print("error: cannot use this terminal: %s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0
