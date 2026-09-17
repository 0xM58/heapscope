"""Look at the terminal UI without a terminal, and check that it draws right.

Two jobs, both of which need a pty:

``--capture``
    Runs the real app in a pseudo-terminal, sends a key sequence, and prints
    what the screen looked like at each step. Useful for showing someone the UI
    over a chat window, and for eyeballing a layout change.

``--verify``
    Sends the same keys and compares the emulated screen against what
    :func:`heapscope.tui.render` says it should be, at several terminal sizes.
    A mismatch means the curses layer and the renderer disagree, which is the
    class of bug that unit tests cannot see.

    This is the check that found the label/value rows losing their alignment:
    the renderer was wrong in a way that only showed up on a real screen.

Emulating the terminal is the fiddly part. pyte implements the sequences it
implements, and ncurses uses the ones it likes; the gap between them is what
this file works around. See :class:`Emulator`.

Needs ``pyte``, which is not a dependency of heapscope:

    pip install pyte

    python tools/tui_capture.py --capture stages/
    python tools/tui_capture.py --verify  stages/
"""

import argparse
import os
import pty
import select
import signal
import struct
import sys
import time

#: The key sequence both modes walk through. It touches every view, both
#: snapshot directions, the help screen and both ends of the list, because a
#: drawing bug is usually specific to one transition.
KEYS = "p p p p j j \t 3 ? ? \t 1 G g n n j \t ? ? 2 j 3 p 1 G".split()

SIZES = [(100, 26), (80, 24), (120, 40), (60, 18), (40, 12), (30, 8)]


# ---------------------------------------------------------------------------
# Terminal emulation
# ---------------------------------------------------------------------------

_SCROLL_PREFIX = b"\x1b["


def _scroll_match(data):
    """Match ``CSI <n> S`` or ``CSI <n> T`` at the start of *data*.

    Returns ``(digits, final, length)``, or ``None`` when this is not a scroll
    sequence or is not complete yet.
    """
    if not data.startswith(_SCROLL_PREFIX):
        return None
    i = len(_SCROLL_PREFIX)
    digits = b""
    while i < len(data) and data[i:i + 1].isdigit():
        digits += data[i:i + 1]
        i += 1
    if i >= len(data):
        return None
    if data[i:i + 1] not in (b"S", b"T"):
        return None
    return digits, data[i:i + 1], i + 1


def _decodable(data):
    """The longest valid UTF-8 prefix of *data*, and whatever is left over."""
    for cut in range(len(data), max(-1, len(data) - 4), -1):
        try:
            return data[:cut].decode("utf-8"), data[cut:]
        except UnicodeDecodeError:
            continue
    return "", data


class Emulator:
    """A pyte screen that also understands the scroll sequences ncurses emits.

    pyte 0.8.2 has no CSI S (scroll up) or CSI T (scroll down), but it does
    implement delete_lines and insert_lines with margin support. ncurses leans
    on the scroll region whenever a frame is mostly a vertical shift of the
    last one, so without this an emulator reports corruption that is not there.

    The scroll is applied against the live screen rather than by rewriting the
    bytes, because real SU and SD leave the cursor alone while delete_lines and
    insert_lines move it to column zero.
    """

    def __init__(self, columns, lines):
        import pyte

        self.screen = pyte.Screen(columns, lines)
        self.stream = pyte.Stream(self.screen)
        self.pending = b""

    def feed(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.pending += data
        self._consume()

    def _consume(self):
        while self.pending:
            start = self.pending.find(_SCROLL_PREFIX)
            if start < 0:
                text, self.pending = _decodable(self.pending)
                self.stream.feed(text)
                return

            match = _scroll_match(self.pending[start:])
            if match is None:
                if start == len(self.pending) - 1:
                    return                      # a lone ESC: wait for more
                text, leftover = _decodable(self.pending[:start])
                if leftover:
                    self.pending = leftover + self.pending[start:]
                    return
                self.stream.feed(text)
                self.pending = self.pending[start:]
                if len(self.pending) == 1:
                    return
                # Not a scroll: hand the ESC to pyte and carry on scanning.
                self.stream.feed("\x1b")
                self.pending = self.pending[1:]
                continue

            text, leftover = _decodable(self.pending[:start])
            if leftover:
                self.pending = leftover + self.pending[start:]
                return
            self.stream.feed(text)
            digits, final, end = match
            self._apply_scroll(int(digits or 1), final == b"S")
            self.pending = self.pending[start + end:]

    def _apply_scroll(self, count, up):
        cursor = (self.screen.cursor.x, self.screen.cursor.y)
        margins = self.screen.margins
        top = margins.top if margins else 0
        bottom = margins.bottom if margins else self.screen.lines - 1
        if up:
            self.screen.cursor.y, self.screen.cursor.x = top, 0
            self.screen.delete_lines(count)
        else:
            self.screen.cursor.y, self.screen.cursor.x = bottom, 0
            self.screen.insert_lines(count)
        self.screen.cursor.x, self.screen.cursor.y = cursor

    def text(self):
        return [line.rstrip() for line in self.screen.display]


# ---------------------------------------------------------------------------
# Driving the app
# ---------------------------------------------------------------------------

def spawn(argv, columns, lines):
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update(TERM="xterm-256color", LANG="en_US.UTF-8",
                          LC_ALL="en_US.UTF-8")
        os.execvp(argv[0], argv)
        os._exit(127)
    import fcntl
    import termios
    fcntl.ioctl(fd, termios.TIOCSWINSZ,
                struct.pack("HHHH", lines, columns, 0, 0))
    return pid, fd


def pump(fd, emu, timeout=0.35):
    """Read everything the app has written within *timeout*."""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            break
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        emu.feed(data)


def quit(pid, fd):
    try:
        os.write(fd, b"q")
        time.sleep(0.15)
    except OSError:
        pass
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    os.close(fd)


def app_argv(paths):
    return [sys.executable, "-m", "heapscope", "tui"] + list(paths)


def expected_frame(keys, paths, columns, lines):
    """What ``render`` says the screen should be after *keys*."""
    from heapscope.tui import TuiApp, TuiState, UTF8_CHARS, render
    from heapscope.view import load_snapshots

    app = TuiApp(TuiState(load_snapshots(paths)))
    for key in keys:
        app.handle(ord(key))
    return [line.rstrip() for line in render(app.state, columns, lines,
                                            chars=UTF8_CHARS)]


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def capture(paths, columns, lines, keys):
    emu = Emulator(columns, lines)
    pid, fd = spawn(app_argv(paths), columns, lines)
    pump(fd, emu, 1.0)

    print("heapscope tui, %dx%d terminal" % (columns, lines))
    for i, key in enumerate([""] + keys):
        if key:
            os.write(fd, key.encode())
            pump(fd, emu)
        label = "on opening" if not key else "after %s" % repr(key)
        print()
        print("--- %s ---" % label)
        print("+" + "-" * columns + "+")
        for line in emu.text():
            print("|" + line.ljust(columns) + "|")
        print("+" + "-" * columns + "+")

    quit(pid, fd)


def verify(paths, sizes, keys):
    bad = 0
    for columns, lines in sizes:
        emu = Emulator(columns, lines)
        pid, fd = spawn(app_argv(paths), columns, lines)
        pump(fd, emu, 1.0)

        problems = []
        for i, key in enumerate(keys):
            os.write(fd, key.encode())
            pump(fd, emu)
            actual = emu.text()
            want = expected_frame(keys[:i + 1], paths, columns, lines)
            rows = [r for r, (a, e) in enumerate(zip(actual, want)) if a != e]
            if rows:
                problems.append((key, rows, actual, want))

        quit(pid, fd)
        bad += len(problems)
        if problems:
            print("%3dx%-3d  %d bad frame(s): %s"
                  % (columns, lines, len(problems),
                     [p[0] for p in problems]))
            for key, rows, actual, want in problems[:1]:
                for r in rows[:3]:
                    print("      row %d after %r" % (r, key))
                    print("        render:   %r" % want[r])
                    print("        terminal: %r" % actual[r])
        else:
            print("%3dx%-3d  clean (%d frames)" % (columns, lines, len(keys)))

    print()
    print("total bad frames: %d" % bad)
    return 1 if bad else 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Capture or verify the heapscope terminal UI.")
    parser.add_argument("paths", nargs="+", help="snapshot files or directories")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--capture", action="store_true",
                       help="print the screen after each key (default)")
    group.add_argument("--verify", action="store_true",
                       help="compare the terminal against render()")
    parser.add_argument("--size", default="100x26",
                        help="terminal size for --capture (default: 100x26)")
    parser.add_argument("--keys", default=" ".join(KEYS),
                        help="keys to send, separated by spaces")
    args = parser.parse_args(argv)

    try:
        import pyte  # noqa: F401
    except ImportError:
        print("error: this needs pyte to emulate the terminal.\n"
              "       pip install pyte", file=sys.stderr)
        return 1

    columns, lines = (int(part) for part in args.size.lower().split("x"))
    keys = args.keys.split()

    if args.verify:
        return verify(args.paths, SIZES, keys)
    capture(args.paths, columns, lines, keys)
    return 0


if __name__ == "__main__":
    sys.exit(main())
