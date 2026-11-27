"""Check mode: report values that should not be committed."""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from routerscope.sanitize._addr import iter_addr_spans
from routerscope.sanitize._asn import is_public_asn, iter_asn_spans
from routerscope.sanitize._lines import split_lines
from routerscope.sanitize.encoding import UndecodableError, decode_bytes
from routerscope.sanitize.redaction import iter_block_spans, iter_secret_spans
from routerscope.sanitize.sanitizer import EMAIL_RE, SAFE_EMAIL_DOMAIN

ALLOW_FILE = ".sanitize-allow"
_SKIP_DIRS = frozenset({".git"})
# Files with these suffixes cannot be inspected as text: they are findings, never skipped.
_OPAQUE_SUFFIXES = frozenset(
    {".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".7z", ".rar", ".zst", ".png", ".jpg", ".jpeg"}
    | {".gif", ".bmp", ".webp", ".ico", ".pdf", ".pyc", ".db", ".sqlite", ".sqlite3", ".bin"}
)


@dataclass(frozen=True, slots=True)
class Finding:
    """One problem: ``kind`` is secret, pem, certificate, ipv4, ipv6, asn or email."""

    kind: str
    line: int
    column: int
    text: str
    detail: str = ""

    @property
    def sensitive(self) -> bool:
        """True when ``text`` is a secret and must not be echoed in logs."""
        return self.kind in {"secret", "pem", "certificate"}


@dataclass(frozen=True, slots=True)
class FileFinding:
    path: Path
    finding: Finding


def load_allowlist(path: str | Path) -> list[str]:
    """Read an allowlist: one literal or regex per line, ``#`` starts a comment."""
    p = Path(path)
    if not p.is_file():
        return []
    entries = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        entry = raw.strip()
        if entry and not entry.startswith("#"):
            entries.append(entry)
    return entries


def _allowed(text: str, allow: Sequence[re.Pattern[str] | str]) -> bool:
    for entry in allow:
        if isinstance(entry, str):
            if entry == text:
                return True
            try:
                if re.fullmatch(entry, text):
                    return True
            except re.error:
                continue
        elif entry.fullmatch(text):
            return True
    return False


def scan(
    text: str, *, allow: Iterable[re.Pattern[str] | str] = (), vendor: str | None = None
) -> list[Finding]:
    """Report unredacted secrets, PEM blocks, public IPs, public ASNs and e-mail addresses.

    A finding whose text equals (or fully matches, as a regex) an ``allow`` entry is skipped.
    """
    allowed = list(allow)
    starts = [ln.start for ln in split_lines(text)]

    def where(offset: int) -> tuple[int, int]:
        i = max(bisect_right(starts, offset) - 1, 0)
        return i + 1, offset - (starts[i] if starts else 0) + 1

    raw: list[Finding] = []
    for sp in iter_block_spans(text):
        ln, col = where(sp.start)
        raw.append(Finding(sp.rule, ln, col, sp.value, sp.rule))
    for line in split_lines(text):
        for sp in iter_secret_spans(line, vendor):
            raw.append(Finding("secret", line.number, sp.start - line.start + 1, sp.value, sp.rule))
    for a in iter_addr_spans(text):
        if a.classify() == "public":
            ln, col = where(a.start)
            kind = "ipv4" if a.v4 is not None else "ipv6"
            raw.append(Finding(kind, ln, col, text[a.start : a.end]))
    for s in iter_asn_spans(text):
        if is_public_asn(s.value):
            ln, col = where(s.start)
            raw.append(Finding("asn", ln, col, text[s.start : s.end]))
    for m in EMAIL_RE.finditer(text):
        if not SAFE_EMAIL_DOMAIN.search(m.group().split("@", 1)[1]):
            ln, col = where(m.start())
            raw.append(Finding("email", ln, col, m.group()))
    raw.sort(key=lambda f: (f.line, f.column, f.kind))
    return [f for f in raw if not _allowed(f.text, allowed)]


def iter_files(paths: Iterable[str | Path]) -> Iterator[Path]:
    """Yield files under ``paths`` (directories recursively, wildcards expanded)."""
    for item in paths:
        p = Path(item)
        if any(ch in str(item) for ch in "*?[") and not p.exists():
            matches = (
                sorted(Path().glob(str(item)))
                if not p.is_absolute()
                else sorted(Path(p.anchor).glob(str(p.relative_to(p.anchor))))
            )
            yield from iter_files(matches)
        elif p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and not (set(f.parts) & _SKIP_DIRS):
                    yield f
        elif p.is_file():
            yield p
        else:
            raise FileNotFoundError(str(item))


def scan_file(path: Path, *, allow: Iterable[re.Pattern[str] | str] = ()) -> list[Finding]:
    """Scan one file. Fails closed: undecodable or archive/image files are findings."""
    if path.suffix.lower() in _OPAQUE_SUFFIXES:
        return [Finding("binary", 0, 0, path.name, "archive or image suffix: cannot be inspected")]
    data = path.read_bytes()
    try:
        decoded = decode_bytes(data)
    except UndecodableError as exc:
        return [Finding("binary", 0, 0, path.name, str(exc))]
    return scan(decoded.text, allow=allow)


def scan_paths(
    paths: Iterable[str | Path], *, allow: Iterable[re.Pattern[str] | str] = ()
) -> list[FileFinding]:
    """Scan files and directories recursively. No file is ever skipped."""
    allowed = list(allow)
    out: list[FileFinding] = []
    for f in iter_files(paths):
        out.extend(FileFinding(f, x) for x in scan_file(f, allow=allowed))
    return out
