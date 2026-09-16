"""The harness: spawn a target, talk to it, and read its memory.

:class:`Probe` is deliberately generic. It knows how to start a process, move
bytes across a pipe, resolve load addresses from ``/proc/<pid>/maps``, read
memory, and explain why a run died. It knows nothing about any particular
menu format - a target-specific wrapper is a small subclass, which is what
``examples/demo.py`` demonstrates.

The one design decision worth explaining: :meth:`Probe.explain` exists because
"the target exited before I saw the prompt" tells you nothing, and the actual
cause is almost always something specific.
"""

from __future__ import annotations

import os
import re
import select
import signal as _signal
import struct
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .errors import LeakMismatch, ProcessDied, Unmapped
from .glibc import GlibcLayout
from .heap import HeapView
from .memory import MemReader, MemoryMap

__all__ = ["Probe", "Diagnosis"]

#: Patterns that explain a dead target far better than an exit status does.
_TRIAGE_PATTERNS = [
    (re.compile(rb"PR_SET_SECCOMP", re.I),
     "the target failed to install its seccomp filter",
     "Common in containers: the runtime's seccomp profile blocks the syscall, so "
     "the filter is never installed and the target aborts. Use a debug build with "
     "the error branch patched out, or run with --security-opt seccomp=unconfined."),
    (re.compile(rb"stack smashing detected", re.I),
     "stack canary tripped (SSP)",
     "Your overwrite reached past a canary. Check the length you sent against the "
     "buffer you intended to hit."),
    (re.compile(rb"double free detected", re.I),
     "glibc detected a double free",
     "The tcache check only compares e->key against the tcache pointer, so it "
     "fires when the freed chunk's key still holds that value. If you intend the "
     "second free, clear the key first - the use-after-free write is usually how."),
    (re.compile(rb"(malloc|free|calloc|realloc)\(\):\s"),
     "glibc's allocator aborted on a consistency check",
     "The heap is corrupted in a way the allocator noticed - often a bad chunk "
     "size, a double free that was not masked, or a corrupted bin chain."),
    (re.compile(rb"corrupted (double-linked list|size|top chunk|unsorted)", re.I),
     "glibc detected a corrupted bin or chunk",
     "Your poisoning reached a bin the allocator then walked. This usually means "
     "an offset is slightly off rather than the technique being wrong."),
    (re.compile(rb"cannot execute binary file|Exec format error", re.I),
     "the binary could not be executed (wrong architecture?)",
     "On an arm64 host this is the classic sign of trying to run an x86-64 ELF "
     "without an emulator. Check you are inside the target's container."),
    (re.compile(rb"No such file or directory.*(ld-|ld\.so|libc)", re.I),
     "the dynamic loader or libc could not be found",
     "PT_INTERP did not resolve. For a challenge binary, the interpreter path is "
     "baked in and usually needs the challenge's own directory layout."),
    (re.compile(rb"Permission denied", re.I),
     "a permission check failed",
     "For a setuid target, running it as a different user or from the wrong path "
     "can change what it is allowed to open."),
    (re.compile(rb"Segmentation fault", re.I),
     "the target segfaulted",
     "See the exit signal below; a SIGSEGV at a non-canonical or unmapped address "
     "usually means a pointer was consumed that was never a valid pointer."),
]

#: Signals worth naming explicitly in a diagnosis.
_SIGNAL_HINTS = {
    int(_signal.SIGSYS): ("SIGSYS", "seccomp killed the process - you called a syscall the filter denies"),
    int(_signal.SIGSEGV): ("SIGSEGV", "invalid memory access"),
    int(_signal.SIGABRT): ("SIGABRT", "glibc aborted the process (allocator check or assert)"),
    int(_signal.SIGILL): ("SIGILL", "illegal instruction - often a failed seccomp filter or a bad gadget"),
    int(_signal.SIGKILL): ("SIGKILL", "killed externally, or the OOM killer"),
}


@dataclass
class Diagnosis:
    """An interpreted explanation of why a run failed."""

    summary: str
    hints: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        lines = [self.summary]
        for h in self.hints:
            lines.append("  hint: " + h)
        for e in self.evidence:
            lines.append("  seen: " + e)
        return "\n".join(lines)


class Probe:
    """A running target process, with memory access.

    :param argv: command to run.
    :param env: extra environment variables (``LD_PRELOAD`` is stripped, since
        a preload would perturb the heap layout you are trying to observe).
    :param libc: path to the target's libc, for offset resolution. If omitted,
        heapscope tries to find it via ``/proc/<pid>/maps``.
    :param no_aslr: disable ASLR for the child via ``personality(2)``. Note
        that this is a no-op in many container runtimes - verify rather than
        assume.
    """

    def __init__(self, argv: Sequence[str], env: Optional[Dict[str, str]] = None,
                 cwd: Optional[str] = None, libc: Optional[str] = None,
                 no_aslr: bool = False, timeout: float = 10.0, bufsize: int = 0):
        self.argv = list(argv)
        self.timeout = timeout
        self._exe = self.argv[0] if self.argv else ""
        self._libc_path = libc
        self._layout: Optional[GlibcLayout] = None
        self._maps: Optional[MemoryMap] = None
        self._reader: Optional[MemReader] = None

        child_env = dict(os.environ)
        child_env.pop("LD_PRELOAD", None)
        if env:
            child_env.update(env)

        preexec = None
        if no_aslr:
            def preexec():  # pragma: no cover - depends on kernel
                import ctypes
                ctypes.CDLL(None, use_errno=True).personality(0x40000)

        self.proc = subprocess.Popen(
            self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=child_env, cwd=cwd,
            bufsize=bufsize, preexec_fn=preexec,
        )
        self._buf = b""
        self._pos = 0
        self._eof = False

    # ---- lifecycle -------------------------------------------------------
    def __enter__(self) -> "Probe":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def pid(self) -> int:
        return self.proc.pid

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    @property
    def output(self) -> bytes:
        """Everything the target has written so far."""
        return self._buf

    def close(self, wait: float = 3.0) -> int:
        """Close stdin, collect the tail, and return the exit code."""
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        self._pump(0.5)
        try:
            rc = self.proc.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            rc = -9
        if self._reader is not None:
            self._reader.close()
            self._reader = None
        return rc

    def kill(self) -> None:
        try:
            self.proc.kill()
        except Exception:
            pass

    @property
    def returncode(self) -> Optional[int]:
        return self.proc.returncode

    def wait_exit(self, timeout: float = 2.0) -> Optional[int]:
        """Wait for the target to exit, draining output as it goes.

        Returns the exit status, or ``None`` if it was still running when
        *timeout* expired. Prefer this over ``proc.poll()`` right after a
        suspicious operation: the kernel has not necessarily reaped the child
        yet, so a bare ``poll()`` can report a dead process as alive - which
        turns "glibc aborted" into "it survived, unexpectedly".
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            self._pump(0.05)
            if self.proc.poll() is not None:
                self._pump(0.1)      # collect anything still in the pipe
                return self.proc.returncode
        return None

    @property
    def term_signal(self) -> Optional[int]:
        """The signal that killed the target, if it was killed by one."""
        rc = self.proc.returncode
        return -rc if rc is not None and rc < 0 else None

    # ---- I/O -------------------------------------------------------------
    def _pump(self, timeout: float) -> bytes:
        """Read until the pipe goes quiet for *timeout* seconds."""
        deadline = time.time() + timeout
        got = False
        while time.time() < deadline:
            try:
                ready, _, _ = select.select([self.proc.stdout], [], [], 0.02)
            except (ValueError, OSError):
                break
            if not ready:
                if got or self.proc.poll() is not None:
                    break
                continue
            try:
                data = os.read(self.proc.stdout.fileno(), 65536)
            except OSError:
                self._eof = True
                break
            if not data:
                self._eof = True
                break
            self._buf += data
            got = True
            deadline = time.time() + timeout
        return self._buf

    def _exhausted(self) -> bool:
        """True when the target has exited and its pipe holds nothing more.

        The EOF case needs an explicit flag: once a pipe reaches EOF, ``select``
        reports it as readable *forever*, so a readiness test alone will never
        conclude that a dead process has nothing left to say. Without this,
        every ``recvuntil`` after a crash stalls for the full timeout instead of
        failing immediately.
        """
        if self._eof:
            return True
        if self.proc.poll() is None:
            return False
        try:
            ready, _, _ = select.select([self.proc.stdout], [], [], 0)
        except (ValueError, OSError):
            return True
        if not ready:
            return True
        try:
            data = os.read(self.proc.stdout.fileno(), 65536)
        except OSError:
            return True
        if not data:
            self._eof = True
            return True
        self._buf += data
        return False

    def send(self, data) -> None:
        if isinstance(data, str):
            data = data.encode()
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def sendline(self, data) -> None:
        if isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def _reap(self, timeout: float = 0.5) -> Optional[int]:
        """Give the child a moment to be reaped so status/signal are populated.

        EOF on the pipe proves the process is gone, but the kernel may not have
        reaped it yet, so ``poll()`` can still return ``None``. Without this,
        the most useful error in the library reports a null exit status.
        """
        if self.proc.poll() is not None:
            return self.proc.returncode
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def recvuntil(self, token: bytes, timeout: Optional[float] = None) -> bytes:
        """Wait for *token*, returning everything up to and including it."""
        if isinstance(token, str):
            token = token.encode()
        deadline = time.time() + (self.timeout if timeout is None else timeout)
        while True:
            idx = self._buf.find(token, self._pos)
            if idx >= 0:
                end = idx + len(token)
                out = self._buf[self._pos:end]
                self._pos = end
                return out
            if self._exhausted():
                self._reap()
                raise ProcessDied(
                    "target exited before %r" % token,
                    output=self._buf[-4096:],
                    status=self.proc.returncode,
                    signal=self.term_signal,
                )
            if time.time() > deadline:
                self._reap(0.1)
                raise ProcessDied(
                    "timed out waiting for %r after %.1fs"
                    % (token, self.timeout if timeout is None else timeout),
                    output=self._buf[-4096:],
                    status=self.proc.returncode,
                    signal=self.term_signal,
                )
            self._pump(0.05)

    def recv(self, quiet: float = 0.4) -> bytes:
        """Read whatever is available, waiting for a quiet period."""
        self._pump(quiet)
        out = self._buf[self._pos:]
        self._pos = len(self._buf)
        return out

    def recvline(self, timeout: Optional[float] = None) -> bytes:
        return self.recvuntil(b"\n", timeout=timeout)

    def recvall(self, wait: float = 0.5) -> bytes:
        """Close stdin and return the remainder of the output."""
        self.close(wait=wait)
        out = self._buf[self._pos:]
        self._pos = len(self._buf)
        return out

    # ---- memory ----------------------------------------------------------
    def maps(self, refresh: bool = True) -> MemoryMap:
        """A snapshot of ``/proc/<pid>/maps``.

        Refreshed by default: the brk heap grows and mappings appear as the
        target runs, so a cached map goes stale in exactly the situation you
        care about.
        """
        if refresh or self._maps is None:
            self._maps = MemoryMap.from_pid(self.pid)
        return self._maps

    @property
    def reader(self) -> MemReader:
        if self._reader is None:
            self._reader = MemReader(self.pid)
        return self._reader

    def mem(self, addr: int, size: int) -> bytes:
        return self.reader.read(addr, size)

    def try_mem(self, addr: int, size: int) -> Optional[bytes]:
        return self.reader.try_read(addr, size)

    def u64(self, addr: int) -> int:
        return self.reader.u64(addr)

    def u32(self, addr: int) -> int:
        return self.reader.u32(addr)

    def u8(self, addr: int) -> int:
        return self.reader.u8(addr)

    def cstring(self, addr: int, maxlen: int = 256) -> bytes:
        return self.reader.cstring(addr, maxlen)

    # ---- load addresses (ground truth) -----------------------------------
    def base(self, name: str) -> Optional[int]:
        """Load base of the first mapping whose path contains *name*."""
        return self.maps().base(name)

    def libc_base(self) -> Optional[int]:
        return self.base("libc")

    def libc_path(self) -> Optional[str]:
        """Path of the libc the target actually loaded, per its own maps."""
        for region in self.maps().find("libc"):
            if region.path:
                return region.path
        return None

    def heap_base(self) -> Optional[int]:
        return self.maps().heap_base(exe_path=self._exe)

    def heap_region(self):
        """The mapping containing the heap base."""
        hb = self.heap_base()
        return self.maps().containing(hb) if hb is not None else None

    def pie_base(self) -> Optional[int]:
        """Load base of the main executable (PIE base)."""
        regions = self.maps().exe_regions(self._exe)
        if not regions:
            return None
        # The executable's first mapping is its ELF header, at file offset 0.
        for region in regions:
            if region.offset == 0 and region.executable:
                return region.start
        return min(r.start for r in regions)

    # ---- glibc -----------------------------------------------------------
    @property
    def glibc(self) -> Optional[GlibcLayout]:
        """Layout of the target's libc.

        Resolved from an explicit ``libc=`` argument, or by reading the libc
        the target actually mapped (which works for local targets and for
        anything inside the same container).
        """
        if self._layout is not None:
            return self._layout
        path = self._libc_path or self.libc_path()
        if path and os.path.exists(path):
            try:
                self._layout = GlibcLayout.from_libc(path)
                return self._layout
            except (OSError, ValueError):
                return None
        return None

    def set_layout(self, layout: GlibcLayout) -> None:
        """Supply a layout directly (needed for a remote target)."""
        self._layout = layout

    # ---- heap ------------------------------------------------------------
    def heap(self, layout: Optional[GlibcLayout] = None, sample: int = 0x1000) -> HeapView:
        """Capture a symbolic view of the heap."""
        base = self.heap_base()
        if base is None:
            raise Unmapped(0, 0, 0)
        region = self.heap_region()
        return HeapView.capture(
            self.reader, base, layout or self.glibc,
            region_end=region.end if region else None, sample=sample,
        )

    # ---- assertions ------------------------------------------------------
    def check_leak(self, value: int, kind: str = "libc",
                   points_to: int = 0, tolerance: int = 0) -> bool:
        """Compare a claimed leak against ground truth, without raising.

        :param value: the address you leaked.
        :param kind: ``"libc"``, ``"pie"``, ``"heap"``, or a substring to match
            against mapping paths.
        :param points_to: if the leak is a pointer *into* a mapping rather than
            its base, the offset it points at (e.g. a ``_lock`` field).
        :param tolerance: allow the leak to be off by up to this many bytes.
        """
        actual = self._ground_truth(kind)
        if actual is None:
            return False
        claimed = value - points_to
        return abs(claimed - actual) <= tolerance

    def assert_leak(self, value: int, kind: str = "libc", points_to: int = 0) -> int:
        """Assert a claimed leak against ground truth; returns the real base.

        This is the primitive the whole library is built around. A blind leak
        is either right or it is not, and "it looked plausible" is not a
        verification - comparing against ``/proc/<pid>/maps`` is.
        """
        actual = self._ground_truth(kind)
        if actual is None:
            raise ProcessDied("no %s mapping to compare against" % kind,
                              output=self._buf[-2048:], status=self.proc.returncode)
        claimed = value - points_to
        if claimed != actual:
            raise LeakMismatch(claimed, actual, kind, points_to)
        return actual

    def _ground_truth(self, kind: str) -> Optional[int]:
        if kind == "libc":
            return self.libc_base()
        if kind == "heap":
            return self.heap_base()
        if kind == "pie":
            return self.pie_base()
        return self.base(kind)

    # ---- triage ----------------------------------------------------------
    def explain(self) -> Diagnosis:
        """Explain why the target stopped, in terms of likely causes.

        Intended to be called from an ``except ProcessDied`` block. It reads
        the target's own output and exit status and names the specific thing
        that usually went wrong, because the alternative - a bare timeout with
        a truncated buffer - costs people whole evenings.
        """
        out = self._buf
        hints: List[str] = []
        evidence: List[str] = []

        for pattern, summary, hint in _TRIAGE_PATTERNS:
            m = pattern.search(out)
            if m:
                hints.append(hint)
                evidence.append(repr(m.group(0)[:120]))
                return Diagnosis(summary, hints, evidence)

        sig = self.term_signal
        if sig is not None:
            name, hint = _SIGNAL_HINTS.get(sig, ("signal %d" % sig, "the target was killed by a signal"))
            if not hints:
                hints.append(hint)
            return Diagnosis("target killed by %s" % name, hints,
                             ["last output: %r" % out[-200:]])

        rc = self.proc.returncode
        if rc is not None:
            return Diagnosis(
                "target exited with status %d before the expected output" % rc,
                ["An invalid menu choice often causes a clean exit by design - "
                 "check whether your last write was interpreted as a command."],
                ["last output: %r" % out[-200:]],
            )

        return Diagnosis("target is still running",
                         ["It never produced the output you waited for. "
                          "The write may have been too short or too long for the "
                          "target's read()."],
                         ["buffered output: %r" % out[-200:]])

    def __repr__(self) -> str:
        state = "running" if self.alive else "exited(%s)" % self.proc.returncode
        return "<Probe pid=%d %s %s>" % (self.pid, state, self._exe)
