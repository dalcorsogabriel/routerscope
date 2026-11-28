"""Walk the history of a git repository of device backups (read-only).

Oxidized and RANCID can keep every device configuration as a file in a git repository, one
commit per change. :func:`walk_history` yields one :class:`FileVersion` per (file, commit)
where the file was added or modified, oldest first. It never touches a device and never
writes to the repository.

How git is used (only read-only plumbing, through the ``git`` CLI):

* ``git rev-parse --git-dir`` and ``git rev-parse --verify ref^{commit}`` to validate the
  repository and the ref;
* ``git log -z --first-parent -m --root --reverse --no-renames --diff-filter=AMT --raw
  --no-abbrev --relative --format=%x01%H%x01%cI <ref> --`` streamed once for the history;
* ``git cat-file --batch`` (one long-lived process) to read each blob by object id.

Behaviour worth knowing:

* Only the **first-parent** history is followed; a merge commit is compared with its first
  parent, so changes brought in by a merged branch appear once, at the merge.
* Renames are not detected (``--no-renames``): a renamed file is a new file at the new name.
* Deleted files, symlinks, submodules, binary files (a NUL byte in the first 8 KiB) and
  blobs larger than ``max_blob_bytes`` are skipped.
* ``captured_at`` is the **committer** date with its original UTC offset.
* ``since``/``until`` filter on that committer time, inclusive. Naive datetimes are taken as
  UTC. ``paths`` are glob patterns (``fnmatch``, ``*`` also matches ``/``) matched against
  the path relative to the repository (or to the directory passed, if it is a subdirectory).
* Content is returned exactly as committed: ``str`` when it is valid UTF-8, else ``bytes``.
"""

from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO

from routerscope.capture.importers.base import ImportError_

__all__ = ["FileVersion", "is_git_repository", "safe_hostname", "walk_history"]

DEFAULT_MAX_BLOB_BYTES = 32 * 1024 * 1024
_SAFE_REF = re.compile(r"^(?!-)[A-Za-z0-9_./@{}^~+-]+$")
_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_SKIPPED_MODES = frozenset({"120000", "160000"})  # symlink, submodule
_NUL = b"\0"
_CHUNK = 1 << 16


@dataclass(frozen=True, slots=True)
class FileVersion:
    """One version of one file: the file as it was in ``commit``."""

    commit: str
    committed_at: datetime
    path: str
    """POSIX-style path relative to the repository (or the directory walked)."""
    content: str | bytes


def safe_hostname(name: str) -> str | None:
    """Return ``name`` when it is a plain hostname (letters, digits, ``.``, ``_``, ``-``)."""
    return name if _HOSTNAME.match(name) else None


def _git_binary() -> str:
    found = shutil.which("git")
    if found is None:
        raise ImportError_(
            "the git executable was not found on PATH; install git to import history"
        )
    return found


def _safe_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_TERMINAL_PROMPT="0",
        GIT_PAGER="cat",
        GIT_OPTIONAL_LOCKS="0",
        LC_ALL="C",
    )
    return env


def _base_cmd(repo: Path) -> list[str]:
    return [
        _git_binary(),
        "-c",
        "core.quotepath=off",
        "-c",
        "core.pager=cat",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "log.showSignature=false",
        "-C",
        str(repo),
    ]


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            [*_base_cmd(repo), *args],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=_safe_env(),
            check=False,
        )
    except OSError as exc:
        raise ImportError_(f"cannot run git: {exc}") from exc


def _message(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace").strip() or "unknown git error"


def is_git_repository(path: Path) -> bool:
    """Whether ``path`` is inside a git work tree or is a bare repository."""
    if not path.is_dir():
        return False
    return _run(path.resolve(), "rev-parse", "--git-dir").returncode == 0


def _tokens(stream: IO[bytes]) -> Iterator[bytes]:
    """Split a NUL-separated byte stream lazily."""
    pending = b""
    while chunk := stream.read(_CHUNK):
        pending += chunk
        *done, pending = pending.split(_NUL)
        yield from done
    if pending:
        yield pending


def _entries(stream: IO[bytes]) -> Iterator[tuple[str, datetime, str, str, str]]:
    """Yield ``(commit, time, blob, mode, path)`` from the ``git log -z --raw`` stream."""
    commit = ""
    when = datetime.min.replace(tzinfo=UTC)
    meta: list[str] | None = None
    for raw in _tokens(stream):
        if meta is not None:
            yield commit, when, meta[3], meta[1], raw.decode("utf-8", errors="replace")
            meta = None
            continue
        token = raw.lstrip(b"\n")
        if token.startswith(b"\x01"):
            _, sha, date = token.decode("ascii", errors="replace").split("\x01")
            commit, when = sha, datetime.fromisoformat(date)
        elif token.startswith(b":"):
            meta = token[1:].decode("ascii", errors="replace").split()


def _read_blob(proc: subprocess.Popen[bytes], blob: str, limit: int) -> bytes | None:
    """Read one object through ``git cat-file --batch``; ``None`` when too big or missing."""
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(blob.encode("ascii") + b"\n")
    proc.stdin.flush()
    header = proc.stdout.readline().split()
    if len(header) != 3 or header[1] != b"blob":
        return None
    size = int(header[2])
    if size > limit:
        remaining = size + 1
        while remaining > 0:
            got = proc.stdout.read(min(remaining, _CHUNK))
            if not got:
                break
            remaining -= len(got)
        return None
    return proc.stdout.read(size + 1)[:size]


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def _has_commits(repo: Path, ref: str) -> bool:
    """True when ``ref`` names a commit; False for an empty repository."""
    if _run(repo, "rev-parse", "--git-dir").returncode != 0:
        raise ImportError_(f"not a git repository: {repo}")
    if _run(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").returncode == 0:
        return True
    if ref == "HEAD":
        refs = _run(repo, "for-each-ref", "--count=1", "--format=%(refname)")
        if not refs.stdout.strip():
            return False
        raise ImportError_(f"HEAD of {repo} does not point to a commit; pass an explicit ref")
    raise ImportError_(f"unknown git ref {ref!r} in {repo}")


def walk_history(
    repo: Path | str,
    *,
    ref: str = "HEAD",
    since: datetime | None = None,
    until: datetime | None = None,
    paths: Sequence[str] | None = None,
    max_blob_bytes: int = DEFAULT_MAX_BLOB_BYTES,
) -> Iterator[FileVersion]:
    """Yield every added/modified text file version, oldest commit first.

    Raises :class:`ImportError_` when git is missing, ``repo`` is not a repository, or
    ``ref`` does not exist. An empty repository yields nothing.
    """
    root = Path(repo).resolve()
    if not root.is_dir():
        raise ImportError_(f"not a directory: {root}")
    if not _SAFE_REF.match(ref) or ".." in ref:
        raise ImportError_(f"invalid git ref: {ref!r}")
    if not _has_commits(root, ref):
        return
    lo, hi = _aware(since), _aware(until)
    patterns = list(paths) if paths else None
    base = _base_cmd(root)
    log_cmd = [
        *base,
        "log",
        "-z",
        "--first-parent",
        "-m",
        "--root",
        "--reverse",
        "--no-renames",
        "--no-ext-diff",
        "--diff-filter=AMT",
        "--raw",
        "--no-abbrev",
        "--relative",
        "--format=%x01%H%x01%cI",
        ref,
        "--",
    ]
    env = _safe_env()
    with tempfile.TemporaryFile() as errfile:
        log = subprocess.Popen(
            log_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=errfile, env=env
        )
        cat = subprocess.Popen(
            [*base, "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        try:
            assert log.stdout is not None
            for commit, when, blob, mode, path in _entries(log.stdout):
                if mode in _SKIPPED_MODES:
                    continue
                if (lo and when < lo) or (hi and when > hi):
                    continue
                if patterns and not any(fnmatch.fnmatchcase(path, p) for p in patterns):
                    continue
                data = _read_blob(cat, blob, max_blob_bytes)
                if data is None or _NUL in data[:8000]:
                    continue
                try:
                    content: str | bytes = data.decode("utf-8")
                except UnicodeDecodeError:
                    content = data
                yield FileVersion(commit, when, path, content)
            if log.wait() != 0:
                errfile.seek(0)
                raise ImportError_(f"git log failed: {_message(errfile.read())}")
        finally:
            for proc in (log, cat):
                if proc.poll() is None:
                    proc.kill()
                for pipe in (proc.stdin, proc.stdout):
                    if pipe is not None:
                        pipe.close()
                proc.wait()
