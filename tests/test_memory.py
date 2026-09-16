"""Tests for /proc/<pid>/maps parsing and heap-base resolution.

No live process needed - the parser is pure text, which is deliberate: the
maps format is stable and worth testing exhaustively.
"""

import unittest

from heapscope.memory import MemoryMap

# A representative maps file: a PIE binary, an unlabelled anonymous rw-p region
# (the brk heap, which container kernels often do not tag), libc, and a stack.
SAMPLE = """\
555555554000-555555555000 r--p 00000000 08:01 1234       /app/chall
555555555000-555555556000 r-xp 00001000 08:01 1234       /app/chall
555555557000-555555778000 rw-p 00000000 00:00 0
7f2f47d90000-7f2f47db6000 r-xp 00000000 08:01 5678       /usr/lib/libc.so.6
7f2f47db6000-7f2f47dbd000 r--p 001d6000 08:01 5678       /usr/lib/libc.so.6
7f2f47dbd000-7f2f47dc1000 rw-p 001dd000 08:01 5678       /usr/lib/libc.so.6
7ffff7fca000-7ffff7fcc000 rw-p 00000000 00:00 0          [stack]
"""

WITH_HEAP_LABEL = SAMPLE.replace(
    "555555557000-555555778000 rw-p 00000000 00:00 0",
    "555555557000-555555778000 rw-p 00000000 00:00 0          [heap]",
)


class TestMapsParsing(unittest.TestCase):
    def setUp(self):
        self.maps = MemoryMap.parse(SAMPLE)

    def test_parses_every_line(self):
        self.assertEqual(len(self.maps), 7)

    def test_fields(self):
        first = self.maps.regions[0]
        self.assertEqual(first.start, 0x555555554000)
        self.assertEqual(first.end, 0x555555555000)
        self.assertEqual(first.perms, "r--p")
        self.assertEqual(first.offset, 0)
        self.assertEqual(first.inode, 1234)
        self.assertEqual(first.path, "/app/chall")

    def test_anonymous_region_has_empty_path(self):
        anon = [r for r in self.maps if r.is_anon]
        self.assertTrue(any(r.start == 0x555555557000 for r in anon))

    def test_permission_flags(self):
        rx = self.maps.regions[1]
        self.assertTrue(rx.readable and rx.executable)
        self.assertFalse(rx.writable)

    def test_region_size_and_contains(self):
        region = self.maps.regions[1]
        self.assertEqual(region.size, 0x1000)
        self.assertTrue(region.contains(0x555555555000))
        self.assertFalse(region.contains(0x555555556000))

    def test_base_returns_lowest_matching_mapping(self):
        # libc is mapped three times; the base is the first (lowest) one.
        self.assertEqual(self.maps.base("libc"), 0x7F2F47D90000)

    def test_base_missing_returns_none(self):
        self.assertIsNone(self.maps.base("nope.so"))

    def test_containing(self):
        self.assertIsNotNone(self.maps.containing(0x7F2F47D90000))
        self.assertIsNone(self.maps.containing(0x1000))


class TestHeapBase(unittest.TestCase):
    def test_prefers_heap_label_when_present(self):
        maps = MemoryMap.parse(WITH_HEAP_LABEL)
        self.assertEqual(maps.heap_base(exe_path="/app/chall"), 0x555555557000)

    def test_falls_back_when_heap_is_unlabelled(self):
        # This is the case that bites people in containers.
        maps = MemoryMap.parse(SAMPLE)
        self.assertEqual(maps.heap_base(exe_path="/app/chall"), 0x555555557000)

    def test_fallback_ignores_regions_below_the_executable(self):
        # A stack-like region below the exe must not be mistaken for the heap.
        text = (
            "500000000000-500000001000 rw-p 00000000 00:00 0\n"
            "555555554000-555555555000 r--p 00000000 08:01 1234 /app/chall\n"
            "555555557000-555555778000 rw-p 00000000 00:00 0\n"
        )
        maps = MemoryMap.parse(text)
        self.assertEqual(maps.heap_base(exe_path="/app/chall"), 0x555555557000)

    def test_exe_regions_matches_on_basename(self):
        maps = MemoryMap.parse(SAMPLE)
        self.assertEqual(len(maps.exe_regions("/somewhere/else/chall")), 2)


if __name__ == "__main__":
    unittest.main()
