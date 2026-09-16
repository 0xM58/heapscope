"""glibc layout resolution.

The design rule here is that offsets are *read out of the libc you actually
have*, not guessed from a table. A libc's dynamic symbol table contains
``_IO_2_1_stdout_``, ``__free_hook``, ``system`` and friends with their exact
virtual addresses; parsing it takes about forty lines and removes an entire
class of "my exploit works locally but not remotely" bugs, because the remote
libc is often a different build from the one you tested against.

``main_arena`` is the exception: it is a local (non-exported) symbol, so it
never appears in ``.dynsym``. On glibc below 2.34 it is recovered from
``__malloc_hook``, which the linker places exactly ``0x10`` below it.

On 2.34 and later the hooks were removed from the implementation, but Debian and
Ubuntu still export ``__malloc_hook`` as an ABI-compatibility symbol sitting
somewhere else entirely. The old rule still produces an address there, it is
just the wrong one, and nothing reports an error. Those versions therefore need
either the measured fallback table or an explicit
:meth:`GlibcLayout.register` call.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Dict, Optional

from .errors import LayoutUnknown

__all__ = ["GlibcLayout", "elf_symbols", "detect_version"]

#: ``__malloc_hook`` sits this far below ``main_arena`` in glibc releases that
#: still have a *real* hook symbol (< 2.34). Verified against Ubuntu
#: glibc 2.29-0ubuntu2 by disassembling ``__libc_malloc``: it loads
#: ``__malloc_hook+0x10`` into ``%rdi`` as ``&main_arena``.
_MALLOC_HOOK_TO_ARENA = 0x10

#: The last glibc release where ``__malloc_hook`` was a real object adjacent to
#: ``main_arena``. The hooks were removed from the implementation in 2.34, but
#: Debian and Ubuntu still ship them as ABI-compatibility symbols sitting
#: somewhere else entirely - so deriving from them on 2.34+ silently yields a
#: wrong address rather than failing. Do not remove this guard.
_HOOKS_REMOVED_IN = (2, 34)

#: ``bin_at(av, 1)`` - the value a chunk gets in ``fd``/``bk`` when it lands in
#: the unsorted bin - is ``&bins[0] - offsetof(malloc_chunk, fd)``, i.e. the
#: bins array minus 0x10. So the observable pointer is ``main_arena + 0x60``
#: even though ``bins[]`` itself starts at ``main_arena + 0x70``.
_BINS_OFFSET = 0x70
_BIN_AT_SKEW = 0x10

#: ``main_arena`` fallback table, for glibc >= 2.34 where it cannot be derived.
#: Entries marked *measured* were established by freeing a chunk into the
#: unsorted bin and reading the ``fd`` it received (which is ``main_arena+0x60``)
#: on a live process, then cross-checking against the ``&main_arena`` load in
#: ``__libc_malloc``. The rest come from public references and are unverified -
#: confirm them against your own target before relying on them.
_MAIN_ARENA = {
    "2.31": 0x1EBB80,   # public reference, unverified here
    "2.35": 0x219C80,   # public reference, unverified here
    "2.36": 0x1D3C60,   # measured on Debian GLIBC 2.36-9+deb12u14
}

#: Symbols worth pulling out of a libc, and the attribute each maps to.
_WANTED = {
    "_IO_2_1_stdout_": "stdout",
    "_IO_2_1_stderr_": "stderr",
    "_IO_2_1_stdin_": "stdin",
    "__free_hook": "free_hook",
    "__malloc_hook": "malloc_hook",
    "system": "system",
    "__libc_system": "libc_system",
    "setcontext": "setcontext",
    "_IO_file_jumps": "file_jumps",
    "_IO_wfile_jumps": "wfile_jumps",
    "environ": "environ",
}


# ---------------------------------------------------------------------------
# Minimal ELF64 reader - just enough to lift .dynsym out of a shared object.
# ---------------------------------------------------------------------------

_SHT_DYNSYM = 11
_SHDR = struct.Struct("<IIQQQQIIQQ")  # Elf64_Shdr, 64 bytes
_SYM = struct.Struct("<IBBHQQ")       # Elf64_Sym,  24 bytes


def _sections(data: bytes):
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if data[4] != 2:
        raise ValueError("not ELF64 (class %d)" % data[4])
    if data[5] != 1:
        raise ValueError("not little-endian")

    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, = struct.unpack_from("<H", data, 0x3A)
    shnum, = struct.unpack_from("<H", data, 0x3C)
    shstrndx, = struct.unpack_from("<H", data, 0x3E)

    raw = []
    for i in range(shnum):
        off = shoff + i * shentsize
        raw.append(_SHDR.unpack_from(data, off))

    # Resolve section names via the section header string table.
    strtab_off = raw[shstrndx][4]
    strtab_size = raw[shstrndx][5]
    names = data[strtab_off:strtab_off + strtab_size]

    out = []
    for sh in raw:
        end = names.find(b"\x00", sh[0])
        name = names[sh[0]:end].decode("latin-1") if end >= 0 else ""
        out.append((name, sh))
    return out


def elf_symbols(path: str) -> Dict[str, int]:
    """Return ``{symbol_name: virtual_address}`` for a shared object's .dynsym.

    Raises ``ValueError`` if the file is not a readable ELF64 shared object.
    """
    with open(path, "rb") as fh:
        data = fh.read()

    sections = _sections(data)
    dynsym = next((sh for name, sh in sections if name == ".dynsym"), None)
    if dynsym is None:
        raise ValueError("%s has no .dynsym section" % path)

    _, _, _, _, sym_off, sym_size, link, _, _, sym_entsize = dynsym
    strtab = sections[link][1]
    str_off, str_size = strtab[4], strtab[5]
    strings = data[str_off:str_off + str_size]

    entsize = sym_entsize or _SYM.size
    out: Dict[str, int] = {}
    for off in range(sym_off, sym_off + sym_size, entsize):
        if off + _SYM.size > len(data):
            break
        st_name, _info, _other, _shndx, st_value, _size = _SYM.unpack_from(data, off)
        if st_name == 0 or st_value == 0:
            continue
        end = strings.find(b"\x00", st_name)
        name = strings[st_name:end].decode("latin-1") if end >= 0 else ""
        if name and name not in out:
            out[name] = st_value
    return out


_VERSION_RE = re.compile(rb"release version (\d+\.\d+)")


def _version_tuple(version: Optional[str]):
    """``"2.29"`` -> ``(2, 29)``, or ``None`` if unparseable."""
    if not version:
        return None
    try:
        major, minor = version.split(".")[:2]
        return int(major), int(minor)
    except (ValueError, AttributeError):
        return None


def derive_main_arena(version: Optional[str],
                      malloc_hook: Optional[int]) -> Optional[int]:
    """Best-effort ``main_arena`` offset for a glibc version.

    ``__malloc_hook`` is only usable as an anchor when the version is *known* to
    predate 2.34. On 2.34+ Debian and Ubuntu still export the symbol for ABI
    compatibility, but it is no longer adjacent to ``main_arena``, so the
    arithmetic produces a plausible-looking wrong address. Returning ``None`` is
    strictly better than returning that: a wrong arena yields confident nonsense
    downstream, whereas ``None`` is visible.
    """
    vt = _version_tuple(version)
    if vt is not None and vt < _HOOKS_REMOVED_IN and malloc_hook is not None:
        return malloc_hook + _MALLOC_HOOK_TO_ARENA
    if version and version in _MAIN_ARENA:
        return _MAIN_ARENA[version]
    return None


def detect_version(path: str) -> Optional[str]:
    """Best-effort glibc version, e.g. ``"2.29"``."""
    with open(path, "rb") as fh:
        blob = fh.read()
    m = _VERSION_RE.search(blob)
    if m:
        return m.group(1).decode()
    m = re.search(rb"GLIBC (\d+\.\d+)", blob)
    return m.group(1).decode() if m else None


# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------

@dataclass
class GlibcLayout:
    """Symbol offsets for one glibc build, relative to the libc load base."""

    version: Optional[str] = None
    source: str = "unknown"

    main_arena: Optional[int] = None
    free_hook: Optional[int] = None
    malloc_hook: Optional[int] = None
    stdout: Optional[int] = None
    stderr: Optional[int] = None
    stdin: Optional[int] = None
    system: Optional[int] = None
    libc_system: Optional[int] = None
    setcontext: Optional[int] = None
    file_jumps: Optional[int] = None
    wfile_jumps: Optional[int] = None
    environ: Optional[int] = None

    extra: Dict[str, int] = field(default_factory=dict)

    #: How many bytes of ``counts[]`` the tcache struct uses: 1 for glibc 2.29,
    #: 2 for 2.30+. Changes where ``entries[]`` begins.
    tcache_counts_size: int = 1

    # ---- constructors ----------------------------------------------------
    @classmethod
    def from_libc(cls, path: str) -> "GlibcLayout":
        """Read offsets straight out of a libc file.

        This is the preferred path: it works for any libc you can obtain, needs
        no table, and cannot drift out of date.
        """
        syms = elf_symbols(path)
        version = detect_version(path)
        layout = cls(version=version, source="elf:%s" % path)

        for sym, attr in _WANTED.items():
            if sym in syms:
                setattr(layout, attr, syms[sym])

        vt = _version_tuple(version)
        layout.main_arena = derive_main_arena(version, layout.malloc_hook)
        if layout.main_arena is not None and not (
                vt is not None and vt < _HOOKS_REMOVED_IN):
            layout.source += " (main_arena from table, not derived)"

        if vt is not None:
            layout.tcache_counts_size = 1 if vt < (2, 30) else 2

        layout.extra = {k: v for k, v in syms.items() if k not in _WANTED}
        return layout

    @classmethod
    def register(cls, version: str, **offsets) -> "GlibcLayout":
        """Build a layout by hand, for glibc versions that need it (>= 2.34)."""
        layout = cls(version=version, source="manual")
        for key, value in offsets.items():
            if not hasattr(layout, key):
                raise TypeError("unknown layout field %r" % key)
            setattr(layout, key, value)
        return layout

    # ---- derived ---------------------------------------------------------
    @property
    def unsorted_bin(self) -> Optional[int]:
        """The pointer value seen in ``fd``/``bk`` of an unsorted-bin chunk.

        This is ``bin_at(av, 1)``, which is ``&bins[0] - 0x10`` - not the
        address of ``bins[]`` itself. Conflating the two is a common source of
        off-by-0x10 confusion.
        """
        if self.main_arena is None:
            return None
        return self.main_arena + _BINS_OFFSET - _BIN_AT_SKEW

    @property
    def bins(self) -> Optional[int]:
        """Address of ``main_arena.bins[0]``."""
        if self.main_arena is None:
            return None
        return self.main_arena + _BINS_OFFSET

    def sym(self, name: str) -> int:
        """Look up any other exported symbol by name."""
        try:
            return self.extra[name]
        except KeyError:
            raise LayoutUnknown("%r is not in this libc's .dynsym" % name) from None

    def __str__(self) -> str:
        fields = (
            "main_arena", "unsorted_bin", "free_hook", "malloc_hook", "stdout",
            "stderr", "stdin", "system", "setcontext", "file_jumps",
        )
        lines = ["glibc %s (%s)" % (self.version or "?", self.source)]
        for f in fields:
            v = getattr(self, f)
            lines.append("  %-14s %s" % (f, "n/a" if v is None else "%#x" % v))
        return "\n".join(lines)
