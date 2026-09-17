# heapscope

Headless glibc heap introspection and assertions for exploit development.

Exploit development has debuggers and it has exploit frameworks, but it has no
**test** story. `heapscope` fills that gap. It reads a live heap with no
debugger, no `ptrace` and no `LD_PRELOAD`, and it lets you *assert* the facts
your exploit depends on, so that a libc update or an image rebuild fails loudly
instead of three stages later.

```python
from heapscope import Probe

with Probe(["./chall"], libc="./libc.so.6") as p:
    p.recvuntil(b"Choice? ")

    before = p.heap()                      # chunks, tcache, bins - as data
    run_the_operation_you_are_debugging()

    print(before.diff(p.heap()))           # what did that actually change?
    p.assert_leak(leaked, kind="libc")     # raises unless it is exactly right
```

---

## Why this exists

Every heap-debugging tool in wide use is a **gdb plugin**. pwndbg and gef are
good at what they do, and they are also interactive, heavyweight, and bound to a
debugger session. You cannot put them in a `pytest` run. You cannot put them in
CI. You cannot ask them a question like *"did this operation corrupt a freelist
pointer?"* without a human reading the output.

The other half of the problem is that exploit code breaks **silently**. A libc
bump moves `__free_hook` by eight bytes. Your exploit does not crash, it just
stops working, and you spend an evening bisecting your own heap feng shui when
the real change was in the environment.

`heapscope` is built around two ideas:

1. **Observation should be free.** `/proc/<pid>/mem` is readable by a process's
   parent with no attach step. No preload means no shifted heap layout. No
   ptrace means no visible perturbation. You read the heap without changing it,
   which matters when the thing you are measuring is a freelist.
2. **A leak is either right or wrong.** "That looks plausible" is not
   verification. Comparing against `/proc/<pid>/maps` is.

## Install

No dependencies. Standard library only, Python 3.9+.

```sh
pip install -e .
```

## What it gives you

### Symbolic heap views

```python
h = p.heap()

h.chunks            # chunk chain, flag bits decoded, top chunk identified
h.tcache            # tcache bins: counts, heads, walked chains
h.bin_for(0x80)     # the bin a request of that size would use
h.unsorted(p.reader)  # the unsorted bin, walked
h.allocated()       # chunks neither top nor sitting in tcache
```

`tcache_perthread_struct` decoding is version-aware. glibc 2.29 uses one byte per
count; 2.30+ widened them to `uint16_t`, which shifts `entries[]` and the first
user chunk by 64 bytes. Both layouts are handled and tested.

Freelist pointers are version-aware too. From glibc 2.32 the `next` field of a
tcache entry is stored mangled, as `(address_of_next_field >> 12) ^ next`, so a
raw read of that field is not an address at all. A walker that skips the
demangling does not crash and does not hang; it reports one bogus entry and then
stops, which reads like a corrupted heap and is not one.

The demangling also has to happen *before* the end-of-chain test. The last chunk
in a safe-linked chain stores `pos >> 12`, not `0`, because that is
`(pos >> 12) ^ 0`, so a walker that tests the stored value for zero walks
straight past the end of the chain. `derive_safe_linked()` is pinned by tests at
the 2.32 boundary, and a link that leaves the heap ends the walk rather than
being reported as a chunk.

### Heap diffing

Capture before, capture after, and see what an operation actually changed:

```python
before = p.heap()
run_the_thing_you_are_debugging()
print(before.diff(p.heap()))
```

```
+4 chunk(s): 0x5555557572c0, 0x555555757740, 0x5555557577c0, 0x555555757820
~0x555555757250 size=0x20db0 e02e5782efe4 -> size=0x70 3ac68bfbe5fe
tcache[5] count 0->0 head None->0x7171717171717171
tcache[6] count 0->255 head None->0x7fffff7cc7e3
```

That `tcache[5] head = 0x7171717171717171` is `'q' * 8`, a freelist pointer that
has been overwritten with attacker-controlled filler. You can see it right there
instead of inferring it from a crash three steps later.

### Viewing a heap

A diff tells you something moved. It does not tell you what the heap looks like
now, so you end up rebuilding the layout in your head from four addresses. Dump a
snapshot at each stage and scrub through them instead:

```python
from heapscope import HeapSnapshot

with Probe(["./chall"], libc="./libc.so.6") as p:
    p.recvuntil(b"Choice? ")
    HeapSnapshot.capture(p, label="start").save("stages/01.json")

    free(0)
    HeapSnapshot.capture(p, label="after free(0)").save("stages/02.json")
```

```sh
heapscope view stages/            # or, from a checkout: python -m heapscope view stages/
```

That serves the directory on localhost: a proportional map of the heap, the
tcache bins, the unsorted bin, and a diff against the previous snapshot. A chunk
that has just landed in a bin is drawn red, and anything anomalous gets a chip: a
chain longer than its own count, a chain that cycles, a bin whose head is set
while its count is zero.

The library stays headless. Nothing here reads or writes a process, the server
binds to `127.0.0.1` only, there is no write path, and it works after the target
has crashed. Absolute addresses *are* recorded here, unlike in a layout snapshot,
because a heap snapshot exists to be drawn.

Two details that are easy to get wrong and are handled: chunk states are decided
in Python rather than in the page, and addresses cross into the browser as hex
strings. A JavaScript number is a double, so a 64-bit value above 2^53 is
silently rounded, and a tcache head holding stale chunk data is exactly the
kind of value that exceeds it.

### Browsing a heap in a terminal

The browser view answers "what shape is the heap". The terminal view answers
"what is this chunk and why", which is the question you have more often and the
one you want to ask where the heap actually lives: inside a container, over
SSH, on a box where forwarding a port to look at one pointer is a poor trade.

```sh
heapscope tui stages/            # or, from a checkout: python -m heapscope tui stages/
```

```
 heapscope    free(0)   4/8   glibc 2.36   pid 215
[ chunks ]  bins    diff
────────────────────────────────────────────────────────────────────────────────
 0x555555559290   0x1010   live           │header      0x55555555a2a0
>0x55555555a2a0   0x70     tcache         │user        0x55555555a2b0
 0x55555555a310   0x70     live           │size        0x70  (112 bytes, 96 usable)
 0x55555555a380   0x1fc80  top            │size field  0x71
                                          │flags       P--  (prev_inuse)
                                          │state       in tcache bin 5
                                          │fd          0x55555555a
                                          │bk          0xe50f80be5067375b
                                          │digest      8b940bced62c
                                          │
                                          │what it means
                                          │Entry 1 of 1 walked in tcache[5]. The bin's
                                          │count field says 1.
 j/k move   tab view   n/p snapshot   g/G ends   ? help   q quit
```

`j`/`k` move, `tab` switches between chunks, tcache bins and a diff against the
previous snapshot, `n`/`p` change snapshot, `?` explains the keys. The left pane
is a list; the right pane describes whatever is selected: the raw fields first,
then a sentence about what they mean.

The reasoning lives in `heapscope/describe.py`, shared with the browser viewer,
so the two cannot tell you different things. `TuiState` and `render()` are pure,
which is what makes the layout assertable without a terminal: every line
`render` returns is exactly as wide as the terminal it was asked for, and that
is a test rather than a hope. Only `TuiApp` touches curses, and all it does is
read keys and write lines.

`curses` is in the standard library, so the terminal UI costs no dependencies.
It refuses to start without a tty rather than drawing an unreadable screen into
a pipe, and it falls back to ASCII borders when the locale cannot encode box
characters.

To look at the UI without a terminal, or to check that curses and the renderer
still agree, there is `tools/tui_capture.py`. It runs the real app in a
pseudo-terminal and either prints the screens or compares them against
`render()` at six terminal sizes:

```sh
pip install pyte
python tools/tui_capture.py --capture stages/
python tools/tui_capture.py --verify  stages/
```

### Ground-truth leak assertions

```python
p.assert_leak(leaked_libc_base, kind="libc")
p.assert_leak(ptr_to_stdout, kind="libc", points_to=0x1e5760)  # _IO_2_1_stdout_
p.check_leak(candidate, kind="heap")     # bool, non-raising
```

`kind` accepts `"libc"`, `"heap"`, `"pie"`, or any substring matched against
mapping paths. A mismatch raises `LeakMismatch` (an `AssertionError`, so it
behaves correctly under pytest) carrying the claimed value, the real value and
the delta.

### Layout snapshots

Record the environment facts you rely on, commit the JSON, and assert them on
every run:

```python
snap = LayoutSnapshot.capture(p, name="dummy")
snap.save("layout.json")

# later, or in CI
LayoutSnapshot.load("layout.json").verify(p)
```

```
LayoutDrift: layout drifted: offset.free_hook: 0x1e75a8 -> 0x1e75b0
```

Absolute addresses are deliberately **not** recorded. They change on every run
under ASLR and asserting them would be meaningless. What is recorded is
everything that should be stable: symbol offsets, the chunk-size sequence your
script produces, and tcache occupancy.

### Failure triage

`ProcessDied` carries the target's last output and exit status, and `explain()`
turns it into a cause:

```python
try:
    ...
except ProcessDied as exc:
    print(p.explain())
```

```
the target failed to install its seccomp filter
  hint: Common in containers: the runtime's seccomp profile blocks the syscall,
        so the filter is never installed and the target aborts. Use a debug build
        with the error branch patched out, or run with --security-opt seccomp=unconfined.
  seen: b'PR_SET_SECCOMP'
```

"The target exited before I saw the prompt" is the least useful error message in
this field, and it is almost always something specific and diagnosable.

### Offset resolution from the libc itself

```python
from heapscope import GlibcLayout
print(GlibcLayout.from_libc("./libc.so.6"))
```

```
glibc 2.29 (elf:./libc.so.6)
  main_arena     0x1e4c40
  unsorted_bin   0x1e4ca0
  free_hook      0x1e75a8
  stdout         0x1e5760
  system         0x52fd0
  setcontext     0x55e00
```

Offsets are read out of the libc's `.dynsym` by a small pure-Python ELF64 parser,
with **no hardcoded table**, so it cannot drift out of date and it works for
whatever libc you are facing.

`main_arena` is the exception. It is a local symbol and is never exported. On
glibc **< 2.34** it is recovered from `__malloc_hook`, which the linker places
exactly `0x10` below it.

On 2.34+ that rule is a trap, and a silent one. The hooks were removed from the
implementation, but Debian and Ubuntu still *export* `__malloc_hook` as an
ABI-compatibility symbol, sitting somewhere else entirely. Applying the old rule
there gives you a plausible-looking address that is wrong. Measured on Debian
`2.36-9+deb12u14`: `__malloc_hook + 0x10` is `0x1da450`, while the real
`main_arena` is `0x1d3c60`. Every bin walk downstream of that would be garbage,
and nothing would report an error.

So `derive_main_arena()` guards on the version, falls back to a table of
*measured* values for 2.34+, and returns `None` rather than a guess for a version
it has not seen. When it returns `None`, register your own:

```python
GlibcLayout.register("2.39", main_arena=0x1e3b80, free_hook=0x1e9c08)
```

The table ships `2.36` (measured) and `2.31` / `2.35` (public references, not
verified here). `GlibcLayout.from_libc` reports which source it used, so you
always know whether you are looking at a measurement or a reference.

## Command line

```sh
heapscope offsets ./libc.so.6      # symbol offsets, read from the ELF
heapscope bases  -- ./chall        # resolved pie / libc / heap bases
heapscope maps   -- ./chall        # /proc/<pid>/maps
heapscope heap   -- ./chall        # heap at startup
heapscope view   stages/           # serve heap snapshots on localhost
heapscope tui    stages/           # browse heap snapshots in the terminal
```

## Example

The repo ships a runnable tour against a purpose-built target, so you can see the
library work before pointing it at anything of your own.

```sh
cd examples/dummy && make     # a 120-line deliberately-vulnerable target
cd ../.. && python3 examples/demo.py
```

The target is a Linux ELF, because everything heapscope does rests on `/proc`.
On macOS `make` refuses rather than quietly producing a Mach-O binary that the
demo could never use; build it in a Linux container instead. `make` is only a
convenience for the single file, so `gcc -O0 -g -o dummy dummy.c` is equivalent.

`examples/dummy/dummy.c` has exactly two defects, and both are ones you meet
constantly. `free()` never clears the slot pointer, and `edit()` reuses the size
recorded at allocation time, which `free()` also never clears. That is enough to
reach a use-after-free and a tcache double free. There is no contrived bug here
and nothing specific to any challenge.

The demo walks five stages. The interesting ones:

**Triage.** Free the same slot twice with no preparation and the target dies.
`heapscope` tells you why, and how to get past it:

```
[!] the target is gone: target exited before b'Choice? '
    exit status -6, signal 6
    its last words: b'ex: Choice? Index: free(): double free detected in tcache 2\n'

heapscope's reading of it:
glibc detected a double free
  hint: The tcache check only compares e->key against the tcache pointer, so it
        fires when the freed chunk's key still holds that value. If you intend
        the second free, clear the key first - the use-after-free write is
        usually how.
  seen: b'double free detected'
```

**The bypass, and seeing it.** Zero the key through the use-after-free and the
second free goes through. The heap view shows the result, a freelist that now
points into itself:

```
tcache[5] size=0x70 count=2 head=0x55555555a2b0 chain=[0x55555555a2b0] (truncated)
```

One entry in the chain and a count of two is the signature of the cycle: the
chunk's `next` points back at itself. It says `truncated` rather than hanging,
because a cycle is a normal state for an exploited heap and the walker detects it
instead of looping forever.

Pass `--snapshots DIR` and the demo replays that whole sequence once more,
writing a heap snapshot at each of eight steps for the viewer:

```sh
python3 examples/demo.py --snapshots stages/
heapscope view stages/
```

**Proving a leak.** Free a chunk into the unsorted bin and read the `fd` it
received. That value is `bin_at(av, 1)`, so subtracting the offset recovers the
libc base, and `assert_leak` checks it against `/proc/<pid>/maps`:

```
freed chunk  header=0x55555555a2a0 size=0x490
  fd = 0x7fffff7b6cc0
  bk = 0x7fffff7b6cc0
  fd == bk, so it is alone in the unsorted bin, and both are
  bin_at(av, 1) = main_arena + 0x60 = libc + 0x1d3cc0

derived libc base = fd - 0x1d3cc0 = 0x7fffff5e3000
[+] assert_leak passed - the offset arithmetic is exact
```

The demo also shows the intended extension pattern. `heapscope.Probe` stays
generic, and each target gets a thin subclass that knows its own prompts.
`examples/demo.py` defines a 50-line `DummyProbe` for the bundled target.

## Verified offsets

The layout facts this library encodes were measured, not recalled. Where a number
came from a public reference instead, it says so.

**glibc 2.36**, Debian `2.36-9+deb12u14`, the container the demo runs in:

| Fact | Value | How it was confirmed |
|---|---|---|
| `main_arena` | `0x1d3c60` | freed a chunk into the unsorted bin and read the `fd` it received (`main_arena + 0x60`) |
| `unsorted_bin` (`bin_at(av,1)`) | `0x1d3cc0` | the same observation, cross-checked by `assert_leak` against `/proc/<pid>/maps` |
| `__free_hook` | `0x1da448` | `nm -D` (a compat symbol, not a live hook) |
| `__malloc_hook` | `0x1da440` | `nm -D` (**not** adjacent to `main_arena`) |
| `_IO_2_1_stdout_` | `0x1d4760` | `nm -D` |
| `setcontext` | `0x40fe0` | `nm -D` |
| tcache chunk size | `0x290` | read from a live process via `/proc/<pid>/mem` |
| first user chunk | `heap+0x290` | ditto |
| `counts[]` / `entries[]` | `heap+0x10` / `heap+0x90` | ditto |

**glibc 2.29**, Ubuntu `2.29-0ubuntu2`, md5 `2fb0d6800d4d79ffdc7a388d7fe6aea0`:

| Fact | Value | How it was confirmed |
|---|---|---|
| `main_arena` | `0x1e4c40` | `objdump` of `__libc_malloc`, which loads it into `%rdi` |
| `unsorted_bin` (`bin_at(av,1)`) | `0x1e4ca0` | observed as `fd`/`bk` of a freed unsorted chunk |
| `__free_hook` | `0x1e75a8` | `nm -D` |
| `_IO_2_1_stdout_` | `0x1e5760` | `nm -D` |
| `setcontext` | `0x55e00` | `nm -D` |
| tcache chunk size | `0x250` | read from a live process via `/proc/<pid>/mem` |
| first user chunk | `heap+0x250` | ditto |
| `counts[]` / `entries[]` | `heap+0x10` / `heap+0x50` | ditto |

The two tcache layouts differ because 2.30 widened `counts[]` from one byte per
bin to `uint16_t`, which shifts `entries[]` and the first user chunk by 64 bytes.
The rule is `0x10 + 64 * counts_size + 512`, and both widths are asserted in the
test suite (`tests/test_heap.py`).

The safe-linking boundary was checked against both libcs the same way. Read out
of the files, `2.29` reports `safe_linked=False` and `2.36` reports `True`, so
the demangling is switched on by the version actually detected rather than
assumed. With the 2.29 libc supplied, the suite is green with no skips at all.

Look at the two `__malloc_hook` rows together. On 2.29 it is `0x1e4c30`, exactly
`0x10` below `main_arena`. On 2.36 it is the same symbol, and it is nowhere near.
That is the trap, side by side.

One subtlety that causes a lot of `0x10` confusion: `bin_at(av, 1)` is
`&bins[0] - 0x10`, not `&bins[0]`. So a freed unsorted chunk's `fd` is
`main_arena + 0x60`, even though `bins[]` itself starts at `main_arena + 0x70`.
`GlibcLayout.unsorted_bin` returns the value you will actually observe.

The measurement is reproducible rather than asserted. Point the tool at your own
target and it dumps the heap header region, decodes `tcache_perthread_struct`,
and derives `first_chunk_offset` by scanning for the first valid chunk header. On
the bundled 2.36 target:

```sh
python3 tools/measure_heap_layout.py -- ./examples/dummy/dummy
```

```
glibc       2.36 (counts[] width = 2 byte(s))
tcache chunk header: prev_size=0x0 size=0x291
  (size & ~0xf = 0x290, the tcache chunk's own size)
counts[]  at heap+0x10
entries[] at heap+0x90
non-empty tcache bins: none

first chunk header at heap+0x290
  -> derived first_chunk_offset = 0x290
  -> for comparison, 0x10 + 64*2 + 512 = 0x290
```

The tool derives the offset from the image and then checks it against the
formula, so a layout change shows up as a disagreement instead of a silently
wrong answer.

## Scope and limitations

A tool that overstates itself wastes your time, so these are stated plainly:

- **Linux only.** Everything rests on `/proc`.
- **You must be the target's parent, or root.** This is not a general
  attach-to-any-process tool. That needs `ptrace`, which defeats the point.
- **glibc only.** Not musl, not `hardened_malloc`, not jemalloc.
- **Main arena only.** Non-main arenas from threads are not walked.
- **tcache and unsorted bins only.** fastbins, smallbins and largebins are not
  walked yet.
- **glibc 2.34+ needs a manual layout.** The hooks were removed, so `main_arena`
  cannot be derived. Worse, the compatibility symbols Debian and Ubuntu still
  export will produce a *wrong* answer if you apply the pre-2.34 rule. See the
  measured comparison above. The built-in table covers `2.36` (measured) and
  `2.31` / `2.35` (unverified references); anything else needs
  `GlibcLayout.register(...)` with values you have measured yourself.
- **The bundled demo target is deliberately trivial.** Two missing assignments,
  two slots, no seccomp, no sandbox. It exists to demonstrate the library, not to
  be a puzzle. Real targets need a real subclass.
- **Snapshots catch environment drift, not logic bugs.** They tell you the ground
  moved, not that your reasoning was wrong.

## Tests

228 tests, green against both glibc 2.29 and 2.36. The heap tests run against a
synthetic heap image, the ELF rejection and layout-arithmetic tests fabricate
their own inputs, and the viewer, describe and terminal tests build their
snapshots by hand, so the suite needs no privileges, no target and no libc:

```sh
python -m unittest discover -s tests
```

To exercise the real-`.dynsym` path, point `HEAPSCOPE_LIBC` at a libc:

```sh
HEAPSCOPE_LIBC=/path/to/libc.so.6 python -m unittest discover -s tests
```

Without it those tests skip, because fabricating a valid ELF64 shared object with
a `.dynsym` would test the fixture more than the parser.

The suite does not include the terminal check, because that needs a pty and a
timing budget. Run it separately with `tools/tui_capture.py --verify`; it is the
only thing that can catch the curses layer and the renderer drifting apart.

## License

MIT
