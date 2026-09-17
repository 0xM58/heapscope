"""Command line interface.

Things you can do from a shell without writing a script: read the offset table
out of a libc, see what a target actually mapped, look at its heap at startup,
and browse a set of saved heap snapshots in a browser.

    heapscope offsets ./libc.so.6
    heapscope bases  -- ./chall
    heapscope heap   -- ./chall
    heapscope view   ./stages
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .glibc import GlibcLayout
from .probe import Probe


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--libc", help="path to the target's libc")
    parser.add_argument("--wait", type=float, default=0.4,
                        help="quiet period to allow before reading (default: 0.4s)")
    parser.add_argument("--no-aslr", action="store_true",
                        help="attempt to disable ASLR for the child (often a no-op)")
    parser.add_argument("target", nargs=argparse.REMAINDER,
                        help="-- command to run")


def _target_argv(ns) -> List[str]:
    argv = list(ns.target)
    if argv and argv[0] == "--":
        argv = argv[1:]
    return argv


def _cmd_offsets(args) -> int:
    try:
        layout = GlibcLayout.from_libc(args.libc)
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    print(layout)
    return 0


def _cmd_bases(args) -> int:
    argv = _target_argv(args)
    if not argv:
        print("error: no target given (use: heapscope bases -- ./chall)", file=sys.stderr)
        return 2

    p = Probe(argv, libc=args.libc, no_aslr=args.no_aslr)
    try:
        p.recv(quiet=args.wait)
        print("pid          %d" % p.pid)
        print("pie base     %s" % _hex(p.pie_base()))
        print("libc base    %s" % _hex(p.libc_base()))
        print("heap base    %s" % _hex(p.heap_base()))
        layout = p.glibc
        if layout is not None:
            print()
            print(layout)
        else:
            print("\n(no libc layout resolved - pass --libc to get offsets)")
    finally:
        p.close()
    return 0


def _cmd_maps(args) -> int:
    argv = _target_argv(args)
    if not argv:
        print("error: no target given", file=sys.stderr)
        return 2
    p = Probe(argv, libc=args.libc, no_aslr=args.no_aslr)
    try:
        p.recv(quiet=args.wait)
        print(p.maps())
    finally:
        p.close()
    return 0


def _cmd_heap(args) -> int:
    argv = _target_argv(args)
    if not argv:
        print("error: no target given", file=sys.stderr)
        return 2
    p = Probe(argv, libc=args.libc, no_aslr=args.no_aslr)
    try:
        p.recv(quiet=args.wait)
        base = p.heap_base()
        if base is None:
            print("error: could not locate the heap", file=sys.stderr)
            return 1
        print(p.heap())
    finally:
        p.close()
    return 0


def _cmd_view(args) -> int:
    from .view import load_snapshots, serve

    try:
        snapshots = load_snapshots(args.paths)
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    if not snapshots:
        print("error: no snapshots found in %s" % ", ".join(args.paths),
              file=sys.stderr)
        return 1

    serve(snapshots, port=args.port, open_browser=not args.no_browser)
    return 0


def _hex(value: Optional[int]) -> str:
    return "n/a" if value is None else "%#x" % value


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="heapscope",
        description="Headless glibc heap introspection.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_off = sub.add_parser("offsets", help="print symbol offsets read from a libc")
    p_off.add_argument("libc")
    p_off.set_defaults(func=_cmd_offsets)

    for name, help_text, func in (
        ("bases", "resolve pie/libc/heap bases for a target", _cmd_bases),
        ("maps", "dump /proc/<pid>/maps for a target", _cmd_maps),
        ("heap", "dump the heap of a freshly started target", _cmd_heap),
    ):
        sp = sub.add_parser(name, help=help_text)
        _add_target_args(sp)
        sp.set_defaults(func=func)

    p_view = sub.add_parser("view", help="browse saved heap snapshots in a browser")
    p_view.add_argument("paths", nargs="+", help="snapshot files or directories")
    p_view.add_argument("--port", type=int, default=0,
                        help="port to listen on (default: any free port)")
    p_view.add_argument("--no-browser", action="store_true",
                        help="do not try to open a browser")
    p_view.set_defaults(func=_cmd_view)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
