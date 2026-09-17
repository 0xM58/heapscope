"""A local viewer for heap snapshots.

``heapscope`` is headless on purpose. The assertions are meant to run in CI,
with no debugger and no display, and that is the whole reason the library
exists. But a heap *diff* is hard to read as text:

    +1 chunk(s): 0x55555555a310
    ~0x55555555a2a0 size=0x1fd60 1ceaf73df40e -> size=0x70 ba94a82a8a5c
    tcache[5] count 0->1 head None->0x55555555a2b0

That tells you something moved. It does not tell you what the heap looks like
now, so you rebuild the layout in your head from four addresses. This module
renders it instead.

The headless property is kept intact. Nothing here reads or writes a process.
Your exploit script dumps a JSON snapshot at each stage it cares about, and
``heapscope view`` serves those files on localhost so you can scrub through them
and see what changed:

    from heapscope import HeapSnapshot

    with Probe(["./chall"]) as p:
        p.recvuntil(b"Choice? ")
        HeapSnapshot.capture(p, label="start").save("stages/01.json")
        ...
        HeapSnapshot.capture(p, label="after free(0)").save("stages/03.json")

    heapscope view stages/

The server binds to 127.0.0.1, serves two routes, and never writes anything.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .asserts import DEFAULT_OFFSETS
from .heap import HeapDiff, tcache_size_for_index

__all__ = ["HeapSnapshot", "load_snapshots", "make_server", "payload", "serve"]

#: Bumped when the on-disk shape changes, so a stale snapshot fails loudly.
FORMAT = "heapscope.heapview/1"


def _libc_bounds(probe) -> "tuple[Optional[int], Optional[int]]":
    """Start and end of the target's libc mapping, for pointer classification.

    The viewer uses these to tell a real freelist pointer from whatever happens
    to sit in the first 16 bytes of an allocated chunk's user data.
    """
    try:
        regions = [r for r in probe.maps().regions if "libc" in (r.path or "")]
    except Exception:
        return None, None
    if not regions:
        return None, None
    return min(r.start for r in regions), max(r.end for r in regions)


def _classify(chunk: Dict[str, Any], members: set,
              libc_base: Optional[int], libc_end: Optional[int]) -> str:
    """Which state a chunk is in, decided here rather than in the browser.

    Doing this in Python keeps 64-bit arithmetic out of JavaScript, where
    integers above 2**53 silently lose precision, and keeps the rule in one
    place instead of two.
    """
    if chunk["is_top"]:
        return "top"
    if chunk["addr"] in members:
        return "tcache"
    fd, bk = chunk["fd"], chunk["bk"]
    # Both pointers have to land in libc, not just fd. An allocated chunk's
    # first 16 bytes are user data, and one libc pointer sitting there is
    # ordinary - a vtable, a FILE *, an arena pointer in a struct. Requiring
    # both halves of the pair cuts those false positives down.
    if (libc_base and libc_end and fd and bk
            and libc_base <= fd < libc_end and libc_base <= bk < libc_end):
        return "unsorted"
    return "live"


@dataclass
class HeapSnapshot:
    """A point-in-time heap, serialised.

    Unlike :class:`~heapscope.asserts.LayoutSnapshot`, this *does* record
    absolute addresses. That is deliberate: a layout snapshot exists to catch
    drift across runs, so addresses would make it useless. A heap snapshot
    exists to be drawn, so the addresses are the point.
    """

    label: str = "snapshot"
    pid: Optional[int] = None
    glibc: Optional[str] = None
    base: int = 0
    region_end: Optional[int] = None
    truncated: bool = False
    libc_base: Optional[int] = None
    libc_end: Optional[int] = None
    offsets: Dict[str, int] = field(default_factory=dict)
    chunks: List[Dict[str, Any]] = field(default_factory=list)
    tcache: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    format: str = FORMAT

    # ---- capture ---------------------------------------------------------
    @classmethod
    def capture(cls, probe, label: str = "snapshot") -> "HeapSnapshot":
        """Read the current heap of *probe* into a serialisable snapshot."""
        heap = probe.heap()

        snap = cls(label=label, pid=getattr(probe, "pid", None))
        snap.base = heap.base
        snap.region_end = heap.region_end
        snap.truncated = heap.truncated

        layout = probe.glibc
        if layout is not None:
            snap.glibc = layout.version
            for key in DEFAULT_OFFSETS:
                value = getattr(layout, key, None)
                if value is not None:
                    snap.offsets[key] = value

        snap.libc_base, snap.libc_end = _libc_bounds(probe)

        for chunk in heap.chunks:
            snap.chunks.append({
                "header": chunk.header,
                "addr": chunk.addr,
                "size": chunk.size,
                "raw_size": chunk.raw_size,
                "digest": chunk.digest(),
                "is_top": chunk.is_top,
                "fd": chunk.fd,
                "bk": chunk.bk,
            })

        for index, bin_ in heap.tcache.items():
            snap.tcache[index] = {
                "count": bin_.count,
                "size": bin_.size,
                "head": bin_.head,
                "entries": list(bin_.entries),
                "truncated": bin_.truncated,
            }
        return snap

    # ---- queries used by the viewer --------------------------------------
    def tcache_members(self) -> set:
        """Every address that sits in some tcache chain."""
        return {e for b in self.tcache.values() for e in b["entries"]}

    def _by_header(self) -> Dict[int, "tuple[int, str]"]:
        return {c["header"]: (c["size"], c["digest"]) for c in self.chunks}

    def diff(self, other: "HeapSnapshot") -> HeapDiff:
        """Compare this (earlier) snapshot against a later one.

        Reuses :class:`~heapscope.heap.HeapDiff` so the text rendering, the
        ``tcache_changed`` helper and the semantics stay identical to the
        library's own diffing.
        """
        before, after = self._by_header(), other._by_header()

        result = HeapDiff()
        result.added = sorted(set(after) - set(before))
        result.removed = sorted(set(before) - set(after))
        for addr in sorted(set(before) & set(after)):
            b_size, b_digest = before[addr]
            a_size, a_digest = after[addr]
            if (b_size, b_digest) != (a_size, a_digest):
                result.changed.append((
                    addr,
                    "size=%#x %s" % (b_size, b_digest),
                    "size=%#x %s" % (a_size, a_digest),
                ))
        result.tcache_before = {i: (b["count"], b["head"]) for i, b in self.tcache.items()}
        result.tcache_after = {i: (b["count"], b["head"]) for i, b in other.tcache.items()}
        return result

    # ---- persistence -----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        data = dict(self.__dict__)
        data["tcache"] = {str(k): v for k, v in self.tcache.items()}
        return data

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "HeapSnapshot":
        if raw.get("format") != FORMAT:
            raise ValueError(
                "unsupported snapshot format %r (this build writes %r)"
                % (raw.get("format"), FORMAT))
        data = dict(raw)
        data["tcache"] = {int(k): v for k, v in raw.get("tcache", {}).items()}
        return cls(**data)

    def save(self, path: str) -> None:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w") as fh:
            json.dump(self.to_dict(), fh, indent=1, sort_keys=True)

    @classmethod
    def load(cls, path: str) -> "HeapSnapshot":
        with open(path) as fh:
            return cls.from_dict(json.load(fh))

    def __str__(self) -> str:
        return "heap %r @ %#x chunks=%d tcache_bins=%d%s" % (
            self.label, self.base, len(self.chunks), len(self.tcache),
            " (truncated)" if self.truncated else "")


# ---------------------------------------------------------------------------
# Loading and serving
# ---------------------------------------------------------------------------

def load_snapshots(paths: Sequence[str]) -> List[HeapSnapshot]:
    """Load snapshots from files and directories, sorted by name.

    Directories are searched for ``*.json``, so ``stages/01.json``,
    ``stages/02.json`` and so on come back in the order you numbered them.
    """
    found: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            found.extend(
                os.path.join(path, name)
                for name in sorted(os.listdir(path))
                if name.endswith(".json")
            )
        else:
            found.append(path)
    return [HeapSnapshot.load(p) for p in found]


def _h(value: Optional[int]) -> Optional[str]:
    """Format a 64-bit value for the browser.

    Addresses cross into JavaScript as strings on purpose. A JS number is a
    double, so anything above 2**53 is silently rounded, and a tcache head
    holding stale chunk data is exactly the kind of value that exceeds it.
    """
    return None if value is None else "%#x" % value


def _display_snapshot(snap: HeapSnapshot) -> Dict[str, Any]:
    """The snapshot as the page wants it: hex strings, states already decided.

    Chunk states are computed here rather than read out of the file. They are a
    function of the chunk and the tcache chains, so recomputing keeps the rule
    in one place and means a snapshot written before a fix to the rule still
    draws correctly.
    """
    members = snap.tcache_members()
    return {
        "label": snap.label,
        "pid": snap.pid,
        "glibc": snap.glibc,
        "base": _h(snap.base),
        "truncated": snap.truncated,
        "libc_base": _h(snap.libc_base),
        "offsets": {k: _h(v) for k, v in snap.offsets.items()},
        "chunks": [{
            "header": _h(c["header"]),
            "addr": _h(c["addr"]),
            "size": _h(c["size"]),
            "digest": c["digest"],
            "is_top": c["is_top"],
            "state": _classify(c, members, snap.libc_base, snap.libc_end),
            "fd": _h(c["fd"]),
            "bk": _h(c["bk"]),
        } for c in snap.chunks],
        "tcache": {str(k): {
            "count": b["count"],
            # Derived from the index rather than read back out of the file. The
            # size of a bin is a property of its slot, so taking it from the
            # slot means an older snapshot, or a hand-written one, still
            # labels its bins correctly instead of rendering "n/a".
            "size": _h(tcache_size_for_index(k)),
            "head": _h(b["head"]),
            "entries": [_h(e) for e in b["entries"]],
            "truncated": b["truncated"],
        } for k, b in snap.tcache.items()},
    }


def _diff_dict(diff: Optional[HeapDiff]) -> Optional[Dict[str, Any]]:
    if diff is None:
        return None
    return {
        "added": [_h(a) for a in diff.added],
        "removed": [_h(a) for a in diff.removed],
        "changed": [[_h(c[0]), c[1], c[2]] for c in diff.changed],
        "tcache_changed": diff.tcache_changed,
        "tcache_before": {str(k): [v[0], _h(v[1])]
                          for k, v in diff.tcache_before.items()},
        "tcache_after": {str(k): [v[0], _h(v[1])]
                         for k, v in diff.tcache_after.items()},
    }


def payload(snapshots: Sequence[HeapSnapshot]) -> Dict[str, Any]:
    """Everything the page needs, in one response.

    Diffs are computed here rather than in JavaScript so the browser does no
    heap reasoning of its own, and so the diff you look at is the same code
    path as :meth:`HeapSnapshot.diff`.
    """
    # Index-aligned with snapshots: diffs[i] is the change from i-1 to i, and
    # diffs[0] is None because there is nothing before the first one. Built at
    # full length up front so the two lists cannot drift apart, including when
    # there are no snapshots at all.
    diffs: List[Optional[Dict[str, Any]]] = [None] * len(snapshots)
    for i in range(1, len(snapshots)):
        diffs[i] = _diff_dict(snapshots[i - 1].diff(snapshots[i]))
    return {
        "format": FORMAT,
        "snapshots": [_display_snapshot(s) for s in snapshots],
        "diffs": diffs,
    }


def _page_bytes() -> bytes:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "view.html")
    with open(path, "rb") as fh:
        return fh.read()


def make_server(snapshots: Sequence[HeapSnapshot], host: str = "127.0.0.1",
                port: int = 0):
    """Build the viewer's HTTP server without starting it.

    Returns ``(httpd, url)``. Split out from :func:`serve` so the routes can be
    exercised in a test, and so a caller can embed the viewer in something else
    and shut it down deliberately.

    The payload is serialised once here. A snapshot set does not change while
    the server is up, so there is no reason to rebuild it per request.
    """
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    page = _page_bytes()
    body = json.dumps(payload(snapshots)).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        server_version = "heapscope"

        def do_GET(self):  # noqa: N802 - required name
            route = self.path.split("?", 1)[0]
            if route == "/":
                self._send(200, "text/html; charset=utf-8", page)
            elif route == "/api/snapshots":
                self._send(200, "application/json", body)
            else:
                self._send(404, "text/plain; charset=utf-8", b"not found\n")

        def _send(self, code: int, ctype: str, data: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *args):  # noqa: N802 - required name
            # Per-request logging is off either way. A viewer is refreshed a
            # lot, and a line per fetch buries the snapshot list printed at
            # startup. ``quiet`` controls that list, not this.
            return

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    return httpd, "http://%s:%d/" % (host, httpd.server_address[1])


def serve(snapshots: Sequence[HeapSnapshot], host: str = "127.0.0.1",
          port: int = 0, open_browser: bool = True, quiet: bool = False) -> None:
    """Serve *snapshots* on localhost until interrupted.

    Binds to 127.0.0.1 only, and implements GET on two routes. There is no
    write path and no way to reach a process from here.
    """
    httpd, url = make_server(snapshots, host, port)

    if not quiet:
        print("heapscope view: %d snapshot(s)" % len(snapshots))
        for i, snap in enumerate(snapshots, 1):
            print("  %2d. %s" % (i, snap))
        print("\nserving on %s  (ctrl-c to stop)" % url)

    if open_browser:
        import webbrowser
        webbrowser.open(url)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        if not quiet:
            print("\nstopped")
    finally:
        httpd.server_close()
