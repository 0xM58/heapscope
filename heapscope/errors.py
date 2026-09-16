"""Exception hierarchy.

The split matters: ``LeakMismatch`` derives from ``AssertionError`` so it
behaves correctly under pytest, while the rest derive from ``HeapscopeError`` so
a harness can catch library failures without swallowing genuine test failures.
"""

from __future__ import annotations


class HeapscopeError(Exception):
    """Base class for every error raised by heapscope."""


class ProcessDied(HeapscopeError):
    """The target exited (or was killed) before the expected output arrived.

    Carries whatever the process managed to print, which is usually the only
    clue available. See :meth:`heapscope.Probe.explain` for the interpreted
    version of that output.
    """

    def __init__(self, message: str, *, output: bytes = b"", status: int = None,
                 signal: int = None):
        super().__init__(message)
        self.output = output
        self.status = status
        self.signal = signal


class Unmapped(HeapscopeError):
    """A read touched an address the target does not have mapped."""

    def __init__(self, addr: int, size: int, got: int):
        super().__init__(
            "cannot read %#x bytes at %#x (got %d) - address is not mapped"
            % (size, addr, got)
        )
        self.addr = addr
        self.size = size
        self.got = got


class HeapCorrupt(HeapscopeError):
    """The chunk chain did not walk cleanly.

    Usually means the heap has already been corrupted by the exploit under
    development - which is itself information, so the partial walk is attached.
    """

    def __init__(self, message: str, *, at: int = None, walked: int = 0):
        super().__init__(message)
        self.at = at
        self.walked = walked


class LayoutUnknown(HeapscopeError):
    """No offset table is available for the target's libc.

    Either point heapscope at the libc file (``Probe(..., libc="libc.so.6")``)
    so the offsets can be read out of its symbol table, or register the layout
    manually with :meth:`heapscope.glibc.GlibcLayout.register`.
    """


class LayoutDrift(AssertionError):
    """The target's memory layout no longer matches a recorded snapshot.

    This is the assertion that catches a silent environment change - a libc
    update, a different container image, a changed kernel - before it turns
    into a mysterious exploit failure three stages later.
    """

    def __init__(self, changes: dict):
        detail = "; ".join("%s: %s -> %s" % (k, v[0], v[1]) for k, v in changes.items())
        super().__init__("layout drifted: " + detail)
        self.changes = changes


class LeakMismatch(AssertionError):
    """A claimed leak disagreed with ground truth.

    Derives from AssertionError on purpose: this is a *test* failure, not a
    library malfunction.
    """

    def __init__(self, claimed: int, actual: int, kind: str, points_to: int = 0):
        delta = claimed - actual
        super().__init__(
            "leak mismatch for %s: claimed %#x, actual %#x (delta %+#x)%s"
            % (kind, claimed, actual, delta,
               "" if points_to == 0 else " [leak minus %#x]" % points_to)
        )
        self.claimed = claimed
        self.actual = actual
        self.kind = kind
        self.delta = delta
