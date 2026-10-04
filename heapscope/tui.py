"""A terminal inspector for heap snapshots.

A snapshot is a heap frozen at one moment. The interesting question about one
is "what is this chunk and why", and the place you want to ask it is wherever
the heap actually lives: in a container, over SSH, on a box with no browser to
speak of and no reason to forward a port to look at one pointer.

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
    TCACHE,
    UNSORTED,
    WARN,
    bin_facts,
    bin_notes,
    chunk_facts,
    chunk_notes,
    hexfmt,
    snapshot_findings,
    snapshot_states,
)
from .snapshot import HeapSnapshot

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
        # Focus mode hides ordinary live chunks and empty, healthy bins. Heap
        # dumps can be large, so this makes allocator state easy to find.
        self.focused = False
        self.filter = "all"
        self.sort = "address"
        self.notice = ""

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
        if snap is None:
            return []
        indexes = sorted(snap.tcache)
        if not self.focused:
            return indexes
        flagged = {finding.scope for finding in self.findings()}
        return [index for index in indexes
                if snap.tcache[index]["count"]
                or "tcache[%d]" % index in flagged]

    def chunk_indexes(self) -> List[int]:
        """Indexes visible in the chunk list, respecting focus mode."""
        snap = self.snapshot
        if snap is None:
            return []
        indexes = list(range(len(snap.chunks)))
        states = snapshot_states(snap)
        if self.filter == "tcache":
            indexes = [index for index in indexes
                       if states.get(snap.chunks[index]["header"]) == TCACHE]
        elif self.filter == "free":
            indexes = [index for index in indexes
                       if states.get(snap.chunks[index]["header"]) in (TCACHE, UNSORTED)]
        elif self.filter == "anomalous":
            bad_bins = {f.scope for f in self.findings() if f.level == WARN}
            indexes = [index for index in indexes if any(
                snap.chunks[index]["addr"] in b["entries"]
                and "tcache[%d]" % bindex in bad_bins
                for bindex, b in snap.tcache.items())]
        elif self.focused:
            indexes = [index for index in indexes
                       if states.get(snap.chunks[index]["header"], "live") != "live"]
        if self.sort == "size":
            indexes.sort(key=lambda index: (snap.chunks[index]["size"],
                                             snap.chunks[index]["header"]))
        elif self.sort == "state":
            indexes.sort(key=lambda index: (states.get(snap.chunks[index]["header"]),
                                             snap.chunks[index]["header"]))
        return indexes

    def selected_chunk(self) -> Optional[Dict[str, Any]]:
        snap = self.snapshot
        if snap is None or self.view != VIEW_CHUNKS:
            return None
        indexes = self.chunk_indexes()
        i = self.selected[VIEW_CHUNKS]
        if not 0 <= i < len(indexes):
            return None
        return snap.chunks[indexes[i]]

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

    def _chunk_rows(self, snap: HeapSnapshot) -> List[str]:
        states = snapshot_states(snap)
        rows = []
        for index in self.chunk_indexes():
            chunk = snap.chunks[index]
            state = states.get(chunk["header"], "live")
            rows.append("%-16s %-8s %s"
                        % (hexfmt(chunk["header"]), "%#x" % chunk["size"], state))
        return rows

    def _bin_rows(self, snap: HeapSnapshot) -> List[str]:
        rows = []
        for index in self.bin_indexes():
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

        # This is intentionally global, not selection-dependent: a warning
        # should remain in sight while someone compares rows in the left pane.
        global_warnings = [f for f in self.findings() if f.level == WARN]
        if global_warnings:
            out.append("snapshot findings (%d)" % len(global_warnings))
            for finding in global_warnings[:3]:
                scope = finding.scope + ": "
                wrapped = _wrap(scope + finding.message, max(1, width - 4))
                out.append("[W] " + wrapped[0])
                out.extend("    " + line for line in wrapped[1:])
            if len(global_warnings) > 3:
                out.append("    ... %d more" % (len(global_warnings) - 3))
            out.append("")

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
        if self.focused:
            parts.append("focus")
        if self.filter != "all":
            parts.append("filter=" + self.filter)
        if self.sort != "address":
            parts.append("sort=" + self.sort)
        if self.notice:
            parts.append(self.notice)
        return "   ".join(parts)

    def footer_line(self) -> str:
        return (" j/k move  : command  / find  f focus  n/p snapshot  ? help  q quit")

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

    def toggle_focus(self) -> None:
        """Show only allocator-relevant rows, or restore the complete list."""
        self.focused = not self.focused
        if self.focused:
            self.filter = "all"
        self._clamp()

    def set_filter(self, mode: str) -> bool:
        if mode not in ("all", "free", "tcache", "anomalous"):
            return False
        self.filter, self.focused = mode, False
        self._clamp()
        return True

    def set_sort(self, mode: str) -> bool:
        if mode not in ("address", "size", "state"):
            return False
        self.sort = mode
        self._clamp()
        return True

    def find_address(self, text: str) -> bool:
        """Select a chunk by header or user address; accepts decimal or hex."""
        try:
            needle = int(text.strip(), 0)
        except ValueError:
            return False
        snap = self.snapshot
        if snap is None:
            return False
        self.set_view(VIEW_CHUNKS)
        visible = self.chunk_indexes()
        for position, index in enumerate(visible):
            chunk = snap.chunks[index]
            if needle in (chunk["header"], chunk["addr"]):
                self.selected[VIEW_CHUNKS] = position
                return True
        return False

    def command(self, text: str) -> str:
        """Run one palette command. The result is suitable for a status line."""
        words = text.strip().split(None, 1)
        if not words:
            return ""
        name, argument = words[0].lower(), words[1] if len(words) == 2 else ""
        if name in ("find", "goto"):
            return "selected %s" % argument if self.find_address(argument) else "address not visible: %s" % argument
        if name == "filter":
            return "filter: %s" % argument if self.set_filter(argument) else "filter: all, free, tcache, anomalous"
        if name == "sort":
            return "sort: %s" % argument if self.set_sort(argument) else "sort: address, size, state"
        if name == "focus":
            self.toggle_focus()
            return "focus %s" % ("on" if self.focused else "off")
        if name == "help":
            self.show_help = True
            return ""
        return "unknown command: %s" % name


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
        "f                     focus: hide ordinary live / empty rows",
        ":                     command palette (filter, sort, find, focus)",
        "/                     find a chunk header or user address",
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
        self.colors: Dict[str, int] = {}
        self.status = ""

    # ---- drawing --------------------------------------------------------
    def draw(self, screen) -> None:
        height, width = screen.getmaxyx()
        for y, line in enumerate(render(self.state, width, height, self.chars)):
            self._write(screen, y, line, self._line_style(y, line))

    def _line_style(self, y: int, line: str) -> int:
        """Pick a semantic colour without putting ANSI escapes in render()."""
        if y == 0:
            return self.colors.get("header", 0)
        if line.startswith(">"):
            return self.colors.get("selected", 0)
        if "[W]" in line or "warning" in line:
            return self.colors.get("warning", 0)
        if "tcache" in line or "unsorted" in line:
            return self.colors.get("allocator", 0)
        return 0

    def _write(self, screen, y: int, line: str, style: int = 0) -> None:
        # Writing the bottom-right cell raises, so fall back to one character
        # less. A terminal that cannot encode the box characters falls back to
        # ASCII for good rather than failing every frame.
        try:
            if style and hasattr(screen, "attron"):
                screen.attron(style)
            screen.addstr(y, 0, line)
        except curses.error:
            try:
                screen.addstr(y, 0, line[:-1])
            except curses.error:
                pass
        except UnicodeEncodeError:
            self.chars = ASCII_CHARS
        finally:
            if style and hasattr(screen, "attroff"):
                screen.attroff(style)

    def _prompt(self, screen, prefix: str) -> str:
        """Read a short palette command without contaminating the pure renderer."""
        height, width = screen.getmaxyx()
        try:
            screen.move(max(0, height - 1), 0)
            screen.clrtoeol()
            screen.addstr(max(0, height - 1), 0, _fit(prefix, width - 1))
            curses.echo()
            raw = screen.getstr(max(0, height - 1), min(len(prefix), max(0, width - 1)), 120)
            return raw.decode("utf-8", "replace")
        except curses.error:
            return ""
        finally:
            curses.noecho()

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
        elif key == ord("f"):
            state.toggle_focus()
        elif key == ord(":"):
            state.notice = state.command(self._prompt(self.screen, ":"))
        elif key == ord("/"):
            query = self._prompt(self.screen, "find: ")
            state.notice = ("selected %s" % query if state.find_address(query)
                            else "address not visible: %s" % query)
        elif key == ord("?"):
            state.show_help = True
        return True

    def main(self, screen) -> None:
        self.screen = screen
        curses.curs_set(0)
        screen.keypad(True)
        if curses.has_colors():
            try:
                curses.start_color()
                curses.use_default_colors()
                curses.init_pair(1, curses.COLOR_CYAN, -1)
                curses.init_pair(2, curses.COLOR_YELLOW, -1)
                curses.init_pair(3, curses.COLOR_RED, -1)
                curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_CYAN)
                self.colors = {
                    "header": curses.color_pair(1) | curses.A_BOLD,
                    "allocator": curses.color_pair(2),
                    "warning": curses.color_pair(3) | curses.A_BOLD,
                    "selected": curses.color_pair(4) | curses.A_BOLD,
                }
            except curses.error:
                # Colour is progressive enhancement, never a reason not to
                # inspect a snapshot on an odd or minimal terminal.
                self.colors = {}
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
        # Redirected output is the common case in CI and in a pipe, and a
        # curses wrapper there produces an unreadable screen rather than an
        # error. Saying so is more use than trying anyway.
        print("error: the terminal UI needs a tty, so it cannot run with its "
              "output redirected. Run it from a terminal.", file=sys.stderr)
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
