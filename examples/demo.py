#!/usr/bin/env python3
"""A tour of heapscope, driving the bundled dummy target.

This deliberately does not reproduce any particular challenge. It walks through
what the library is for, against `examples/dummy`, a small program whose only
flaw is two missing assignments (`free` never clears the slot pointer, `edit`
reuses the size recorded at alloc time).

Build the target first:

    cd examples/dummy && make

then:

    python3 examples/demo.py

Stages:

  1. heap view        - chunks and tcache as structured data, not hex
  2. triage           - a glibc abort, explained
  3. the bypass       - defeating the tcache double-free check, and seeing it
  4. leak assertion   - proving an offset against ground truth
  5. layout snapshots - catching environment drift before it bites
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heapscope import LayoutSnapshot, Probe, ProcessDied  # noqa: E402

P64 = lambda x: struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)

HERE = os.path.dirname(os.path.abspath(__file__))
TARGET = os.environ.get("TARGET", os.path.join(HERE, "dummy", "dummy"))


class DummyProbe(Probe):
    """A Probe that speaks the dummy target's menu.

    This is the intended extension pattern: `Probe` stays generic and each
    target gets a thin subclass that knows its own prompts.

    Note the discipline in ``_menu``: every operation *ends* by waiting for the
    target to come back to its prompt. Without that, the next step races the
    target - you read memory before it has finished the operation you just
    asked for, and intermittently observe the state from one step ago. Waiting
    at the end of each operation, rather than at the start of the next, removes
    the race entirely.
    """

    def start(self) -> "DummyProbe":
        self.recvuntil(b"Choice? ")
        return self

    def _menu(self) -> None:
        """Wait until the target is back at its menu prompt."""
        self.recvuntil(b"Choice? ")

    def alloc(self, idx: int, size: int, data: bytes = b"", full: bool = True) -> None:
        self.sendline(b"1")
        self.recvuntil(b"Index: ")
        self.sendline(str(idx).encode())
        self.recvuntil(b"Size: ")
        self.sendline(str(size).encode())
        self.recvuntil(b"Data: ")
        if full and len(data) < size:
            data = data + b"\x00" * (size - len(data))
        self.send(data)
        self._menu()

    def free(self, idx: int) -> None:
        self.sendline(b"2")
        self.recvuntil(b"Index: ")
        self.sendline(str(idx).encode())
        self._menu()

    def edit(self, idx: int, data: bytes, size: int = None) -> None:
        self.sendline(b"3")
        self.recvuntil(b"Index: ")
        self.sendline(str(idx).encode())
        self.recvuntil(b"Data: ")
        if size is not None and len(data) < size:
            data = data + b"\x00" * (size - len(data))
        self.send(data)
        self._menu()


def banner(text: str) -> None:
    print("\n" + "=" * 68)
    print(text)
    print("=" * 68)


def stage_1_heap_view() -> None:
    banner("1. heap view - chunks and tcache as data")

    with DummyProbe([TARGET]) as p:
        p.start()
        print("pid %d   libc %s" % (p.pid, p.glibc.version if p.glibc else "?"))

        before = p.heap()
        print("\nat startup (%d chunk(s)):" % len(before.chunks))
        for c in before.chunks:
            print("   " + str(c))
        print("   note: the 0x1010 chunk is stdin's stdio buffer, allocated by")
        print("         the first fgets() - heapscope surfaces it rather than")
        print("         leaving you to wonder where it came from.")

        p.alloc(0, 0x60, b"A" * 0x60)
        p.free(0)

        after = p.heap()
        print("\nafter alloc(0, 0x60) then free(0):")
        for idx in sorted(after.tcache):
            print("   " + str(after.tcache[idx]))

        print("\ndiff across those two operations:")
        for line in str(before.diff(after)).splitlines():
            print("   " + line)


def stage_2_triage() -> None:
    banner("2. triage - a glibc abort, explained")

    p = DummyProbe([TARGET])
    try:
        p.start()
        p.alloc(0, 0x60, b"A" * 0x60)
        p.free(0)

        print("freeing slot 0 twice with no preparation...")
        p.free(0)                       # aborts inside glibc
        print("target survived (unexpected)")
    except ProcessDied as exc:
        print("\n[!] the target is gone: %s" % exc)
        print("    exit status %s, signal %s" % (p.returncode, p.term_signal))
        print("    its last words: %r" % p.output[-60:])
        print("\nheapscope's reading of it:")
        print(p.explain())
    finally:
        p.close()


def stage_3_bypass() -> None:
    banner("3. the bypass - defeating the tcache double-free check")

    with DummyProbe([TARGET]) as p:
        p.start()

        p.alloc(0, 0x60, b"A" * 0x60)
        p.free(0)

        # glibc 2.29's tcache double-free check only compares e->key against the
        # tcache pointer. The UAF edit can overwrite that key, so the check can
        # be satisfied on a chunk that is already free.
        print("zeroing fd and key through the use-after-free...")
        p.edit(0, P64(0) + P64(0), size=0x60)

        print("freeing slot 0 a second time...")
        p.free(0)

        h = p.heap()
        for idx in sorted(h.tcache):
            print("   " + str(h.tcache[idx]))
        print("\nThe chunk is now in its own freelist twice - a cycle. heapscope")
        print("reports `truncated` rather than looping forever on it.")


def stage_4_leak() -> None:
    banner("4. leak assertion - proving an offset against ground truth")

    with DummyProbe([TARGET]) as p:
        p.start()
        layout = p.glibc
        truth = p.libc_base()
        print("ground-truth libc base (from /proc/%d/maps): %#x" % (p.pid, truth))

        # Two large chunks, then free the first. A chunk freed adjacent to the
        # top chunk is consolidated straight into top and never reaches the
        # unsorted bin, so the free must not be the most recent allocation.
        p.alloc(0, 0x480, b"A" * 0x480)
        p.alloc(1, 0x480, b"B" * 0x480)
        p.free(0)

        # Find the chunk that landed in the unsorted bin: its fd is a libc
        # pointer, whereas live chunks still hold our filler.
        h = p.heap()
        freed = None
        for c in h.chunks:
            if c.is_top:
                continue
            fd = p.u64(c.addr)
            if 0x7F0000000000 <= fd < 0x800000000000:
                freed = c
                break
        if freed is None:
            print("[!] no unsorted chunk found")
            return

        fd = p.u64(freed.addr)
        bk = p.u64(freed.addr + 8)
        print("freed chunk  header=%#x size=%#x" % (freed.header, freed.size))
        print("  fd = %#x" % fd)
        print("  bk = %#x" % bk)
        print("  fd == bk, so it is alone in the unsorted bin, and both are")
        print("  bin_at(av, 1) = main_arena + 0x60 = libc + %#x"
              % layout.unsorted_bin)

        derived = fd - layout.unsorted_bin
        print("\nderived libc base = fd - %#x = %#x" % (layout.unsorted_bin, derived))

        p.assert_leak(derived, kind="libc")
        print("[+] assert_leak passed - the offset arithmetic is exact")


def stage_5_snapshot() -> None:
    banner("5. layout snapshots - catching drift")

    with DummyProbe([TARGET]) as p:
        p.start()
        p.alloc(0, 0x60, b"A" * 0x60)
        p.free(0)

        snap = LayoutSnapshot.capture(p, name="dummy")
        print(snap)

        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            snap.save(path)
            print("\nsaved to %s:" % path)
            with open(path) as fh:
                for line in fh.read().splitlines()[:12]:
                    print("   " + line)

            loaded = LayoutSnapshot.load(path)
            loaded.verify(p)
            print("\n[+] reloaded and verified against a fresh process - no drift")
        finally:
            os.unlink(path)


def main() -> int:
    if not os.path.exists(TARGET):
        print("error: %s not found" % TARGET, file=sys.stderr)
        print("build it first:  cd examples/dummy && make", file=sys.stderr)
        return 2

    stage_1_heap_view()
    stage_2_triage()
    stage_3_bypass()
    stage_4_leak()
    stage_5_snapshot()
    return 0


if __name__ == "__main__":
    sys.exit(main())
