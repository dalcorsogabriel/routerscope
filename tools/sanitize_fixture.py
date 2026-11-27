#!/usr/bin/env python3
"""Sanitize device output before committing it as a fixture, or check files for leftovers.

    uv run python tools/sanitize_fixture.py IN [-o OUT | --in-place] [--salt S]
        [--remap-private] [--keep-descriptions] [--vendor V] [--map-out FILE]
    uv run python tools/sanitize_fixture.py --check PATH...

Thin wrapper around ``routerscope.sanitize``; see tools/README.md.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from routerscope.sanitize import ALLOW_FILE, Sanitizer, load_allowlist, scan_paths
from routerscope.sanitize.encoding import UndecodableError, decode_bytes, encode_text

REPO_ROOT = Path(__file__).resolve().parent.parent


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("input", nargs="?", help="file to sanitize")
    p.add_argument("-o", "--output", help="write here instead of stdout")
    p.add_argument("--in-place", action="store_true", help="overwrite the input file")
    p.add_argument("--salt", default="", help="salt for the deterministic mapping")
    p.add_argument("--remap-private", action="store_true", help="also remap RFC1918/CGNAT")
    p.add_argument(
        "--keep-descriptions",
        action="store_true",
        help="do not replace descriptions, banners, comments and user names",
    )
    p.add_argument("--vendor", help="vendor hint (e.g. cisco_ios)")
    p.add_argument("--map-out", help="write the original->sanitized mapping (never commit it)")
    p.add_argument("--check", nargs="+", metavar="PATH", help="scan files/dirs; exit 1 on findings")
    p.add_argument("--allow-file", default=str(REPO_ROOT / ALLOW_FILE), help="allowlist file")
    return p


def _inside_git_repo(path: Path) -> bool:
    """True when ``path`` lives in a git work tree (a mapping file there could be committed)."""
    return any((p / ".git").exists() for p in (path.resolve().parent, *path.resolve().parents))


def _check(paths: list[str], allow_file: str) -> int:
    try:
        findings = scan_paths(paths, allow=load_allowlist(allow_file))
    except FileNotFoundError as exc:
        print(f"error: no such path: {exc}", file=sys.stderr)
        return 2
    for ff in findings:
        f = ff.finding
        detail = f" ({f.detail})" if f.detail else ""
        shown = "" if f.sensitive else f": {f.text}"
        print(f"{ff.path}:{f.line}: {f.kind}{detail}{shown}")
    if findings:
        print(
            f"{len(findings)} finding(s); sanitize the files or add an entry to {ALLOW_FILE}",
            file=sys.stderr,
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.check:
        if args.input:
            parser.error("--check takes paths only; do not combine it with an input file")
        return _check(args.check, args.allow_file)
    if not args.input:
        parser.error("an input file is required (or use --check)")
    if args.in_place and args.output:
        parser.error("--in-place and -o are mutually exclusive")
    if args.map_out and _inside_git_repo(Path(args.map_out)):
        print(
            f"error: refusing to write {args.map_out} inside a git repository: the mapping maps "
            "sanitized values back to the originals; choose a path outside the repo",
            file=sys.stderr,
        )
        return 2
    src = Path(args.input)
    try:
        data = src.read_bytes()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        decoded = decode_bytes(data)
    except UndecodableError as exc:
        print(
            f"error: {src}: {exc}; convert the capture to UTF-8 (or UTF-16/32) and retry",
            file=sys.stderr,
        )
        return 2
    text = decoded.text
    san = Sanitizer(
        args.salt, remap_private=args.remap_private, descriptions=not args.keep_descriptions
    )
    result = encode_text(san.sanitize(text, args.vendor), decoded)
    if args.in_place:
        src.write_bytes(result)
    elif args.output:
        Path(args.output).write_bytes(result)
    else:
        sys.stdout.buffer.write(result)
    if args.map_out:
        Path(args.map_out).write_text(
            json.dumps(san.mapping, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(
            f"warning: {args.map_out} maps sanitized values back to the originals; "
            "keep it local and never commit it",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
