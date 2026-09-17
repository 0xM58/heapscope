"""Tests for libc layout resolution.

The ELF parser is tested against a real libc when one is available (set
``HEAPSCOPE_LIBC``, or the suite looks in a few usual places) and skipped
otherwise - fabricating a valid ELF64 shared object with a .dynsym section
would test the fixture more than the parser.

The layout arithmetic tests need no libc at all and always run.
"""

import os
import struct
import tempfile
import unittest

from heapscope.errors import LayoutUnknown
from heapscope.glibc import (
    GlibcLayout,
    derive_main_arena,
    derive_safe_linked,
    detect_version,
    elf_symbols,
)

CANDIDATE_LIBCS = [
    os.environ.get("HEAPSCOPE_LIBC", ""),
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
]


def find_libc():
    for path in CANDIDATE_LIBCS:
        if path and os.path.exists(path):
            return os.path.realpath(path)
    return None


LIBC = find_libc()


class TestElfRejection(unittest.TestCase):
    def _write(self, blob):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        self.addCleanup(os.unlink, path)
        return path

    def test_non_elf_is_rejected(self):
        with self.assertRaises(ValueError):
            elf_symbols(self._write(b"not an elf at all"))

    def test_elf32_is_rejected(self):
        blob = b"\x7fELF" + bytes([1, 1]) + b"\x00" * 60
        with self.assertRaises(ValueError) as ctx:
            elf_symbols(self._write(blob))
        self.assertIn("ELF64", str(ctx.exception))

    def test_big_endian_is_rejected(self):
        blob = b"\x7fELF" + bytes([2, 2]) + b"\x00" * 60
        with self.assertRaises(ValueError) as ctx:
            elf_symbols(self._write(blob))
        self.assertIn("little-endian", str(ctx.exception))


class TestVersionDetection(unittest.TestCase):
    def test_reads_release_version(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as fh:
            fh.write(b"padding\0GNU C Library (Ubuntu GLIBC 2.29-0ubuntu2) "
                     b"stable release version 2.29.\0more")
        self.addCleanup(os.unlink, path)
        self.assertEqual(detect_version(path), "2.29")

    def test_unknown_returns_none(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as fh:
            fh.write(b"nothing useful here")
        self.addCleanup(os.unlink, path)
        self.assertIsNone(detect_version(path))


class TestMainArenaDerivation(unittest.TestCase):
    def test_derives_from_hook_before_2_34(self):
        self.assertEqual(derive_main_arena("2.29", 0x1E4C30), 0x1E4C40)
        self.assertEqual(derive_main_arena("2.31", 0x1EBB70), 0x1EBB80)

    def test_does_not_derive_from_the_compat_hook_on_2_34_plus(self):
        # Debian/Ubuntu still export __malloc_hook on 2.36, but the hooks were
        # removed from the implementation and the symbol now lives somewhere
        # else. Deriving from it would give 0x1da450 where the real value is
        # 0x1d3c60 - a plausible-looking wrong answer, which is the worst kind.
        derived = derive_main_arena("2.36", 0x1DA440)
        self.assertEqual(derived, 0x1D3C60)
        self.assertNotEqual(derived, 0x1DA440 + 0x10)

    def test_uses_table_when_no_hook_symbol(self):
        self.assertEqual(derive_main_arena("2.36", None), 0x1D3C60)

    def test_returns_none_rather_than_guessing(self):
        # Unknown version: refuse. A wrong arena silently corrupts every
        # downstream bin walk.
        self.assertIsNone(derive_main_arena(None, 0x1E4C30))
        self.assertIsNone(derive_main_arena("3.0", 0x1234))
        self.assertIsNone(derive_main_arena("2.29", None))


class TestSafeLinkingVersion(unittest.TestCase):
    """The 2.32 boundary, which is where the chain walk changes meaning.

    Getting this wrong is not a crash. On a 2.32+ target it makes the walker
    read a mangled ``next`` field as an address and report a chunk that does
    not exist, which is why the boundary is pinned here rather than left to
    the libc fixtures.
    """

    def test_2_31_and_earlier_store_next_verbatim(self):
        for version in ("2.23", "2.27", "2.29", "2.31"):
            self.assertFalse(derive_safe_linked(version), version)

    def test_2_32_and_later_are_safe_linked(self):
        for version in ("2.32", "2.33", "2.34", "2.35", "2.36", "2.39"):
            self.assertTrue(derive_safe_linked(version), version)

    def test_unknown_version_is_not_assumed_safe_linked(self):
        # The conservative direction: reading an unmangled field cannot invent
        # an entry, and the bounds check in the walker stops a wrong guess.
        for version in (None, "", "garbage"):
            self.assertFalse(derive_safe_linked(version), repr(version))

    def test_a_future_version_keeps_safe_linking(self):
        # This is a monotonic rule, not a table lookup. Unlike main_arena,
        # which refuses to guess for a version it has no offset for, a later
        # glibc is expected to still mangle its freelist pointers: dropping
        # safe-linking would be a security regression, not a refactor.
        self.assertTrue(derive_safe_linked("3.0"))

    def test_layout_carries_the_flag(self):
        # The dataclass default stays False; only the constructors derive it.
        self.assertFalse(GlibcLayout(version="2.36").safe_linked)
        self.assertTrue(GlibcLayout.register("2.36").safe_linked)
        self.assertFalse(GlibcLayout.register("2.29").safe_linked)


class TestLayoutArithmetic(unittest.TestCase):
    def test_unsorted_bin_is_arena_plus_0x60(self):
        # bin_at(av, 1) is &bins[0] - 0x10, and bins[] sits at arena+0x70.
        # Verified against a live glibc 2.29 process: the value a freed chunk
        # receives is libc+0x1e4ca0 with main_arena at libc+0x1e4c40.
        layout = GlibcLayout(main_arena=0x1E4C40)
        self.assertEqual(layout.bins, 0x1E4C40 + 0x70)
        self.assertEqual(layout.unsorted_bin, 0x1E4CA0)

    def test_unsorted_bin_is_none_without_arena(self):
        self.assertIsNone(GlibcLayout().unsorted_bin)

    def test_register_builds_a_layout(self):
        layout = GlibcLayout.register("2.35", main_arena=0x219C80,
                                      free_hook=None, system=0x50D60)
        self.assertEqual(layout.version, "2.35")
        self.assertEqual(layout.unsorted_bin, 0x219C80 + 0x60)
        self.assertEqual(layout.system, 0x50D60)

    def test_register_rejects_unknown_field(self):
        with self.assertRaises(TypeError):
            GlibcLayout.register("2.35", not_a_field=1)

    def test_sym_reports_missing_symbol(self):
        with self.assertRaises(LayoutUnknown):
            GlibcLayout().sym("__free_hook")


@unittest.skipUnless(LIBC, "no libc available; set HEAPSCOPE_LIBC")
class TestRealLibc(unittest.TestCase):
    def setUp(self):
        self.syms = elf_symbols(LIBC)
        self.layout = GlibcLayout.from_libc(LIBC)

    def test_parses_a_plausible_number_of_symbols(self):
        self.assertGreater(len(self.syms), 500)

    def test_finds_well_known_symbols(self):
        for name in ("malloc", "free", "system", "setcontext"):
            self.assertIn(name, self.syms)

    def test_main_arena_is_never_derived_from_a_compat_hook(self):
        """The adjacency only holds while __malloc_hook is a real object.

        This is the regression guard for the bug that motivated the version
        check: on Debian glibc 2.36 the symbol still exists, so a naive
        "malloc_hook + 0x10" yields 0x1da450 while the real arena is 0x1d3c60.
        """
        version = self.layout.version or ""
        parts = version.split(".")
        try:
            vt = (int(parts[0]), int(parts[1]))
        except (ValueError, IndexError):
            self.skipTest("unparseable version %r" % version)

        if vt >= (2, 34):
            self.assertIsNotNone(self.layout.malloc_hook,
                                 "expected a compat __malloc_hook on this libc")
            self.assertNotEqual(self.layout.main_arena,
                                self.layout.malloc_hook + 0x10)
        else:
            if self.layout.malloc_hook is None:
                self.skipTest("libc has no __malloc_hook")
            self.assertEqual(self.layout.main_arena, self.layout.malloc_hook + 0x10)

    def test_known_229_offsets(self):
        # Independently confirmed with nm and by disassembling __libc_malloc.
        if self.layout.version != "2.29":
            self.skipTest("offsets asserted for 2.29 only")
        self.assertEqual(self.layout.main_arena, 0x1E4C40)
        self.assertEqual(self.layout.unsorted_bin, 0x1E4CA0)
        self.assertEqual(self.layout.free_hook, 0x1E75A8)
        self.assertEqual(self.layout.stdout, 0x1E5760)
        self.assertEqual(self.layout.setcontext, 0x55E00)

    def test_counts_width_follows_version(self):
        if self.layout.version and self.layout.version.startswith("2.2"):
            self.assertEqual(self.layout.tcache_counts_size, 1)
        else:
            self.assertEqual(self.layout.tcache_counts_size, 2)


if __name__ == "__main__":
    unittest.main()
