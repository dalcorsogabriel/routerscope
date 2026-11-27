"""Watched drop folder: save a terminal log or a config into a folder and it gets imported.

``DropFolder(path)`` looks at the regular files directly inside the folder (not
subfolders; hidden files, the state file and ``*.tmp``/``*.part`` files are ignored). Each
file is read as a terminal log (format auto-detected, see
:mod:`~routerscope.capture.importers.session_log`; ``Source.importer`` is the format id) when
it contains prompts, else as a configuration when it looks like one
(:func:`~routerscope.capture.importers._common.looks_like_config`; ``importer`` is
``"drop_folder"``, ``captured_at`` is the file modification time). Anything else is recorded as
skipped with the reason and not retried until the file changes. The source kind is
``drop_folder`` and the uri is the file path.

Processed files are tracked by name, size, modification time and SHA-256 in
``.routerscope-drop.json`` inside the folder (written atomically). A file is imported again
only when its *content* changed; touching it is not enough. A file is marked processed only
after its items were consumed (``items()``) or the callback returned (``watch()``), so a
failing consumer gets the file again at the next scan.

``watch()`` polls with the standard library only. ``min_age`` (seconds, default 0) skips files
modified more recently than that, which avoids reading a log a terminal is still writing.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, tzinfo
from pathlib import Path
from typing import Any

import netprompt

from routerscope.capture.importers._common import (
    config_hostname,
    decode_bytes,
    looks_like_config,
)
from routerscope.capture.importers.base import ImportError_, ImportItem
from routerscope.capture.importers.session_log import parse_session_log, session_items
from routerscope.model import Source
from routerscope.vendors.registry import VendorRegistry, default_registry

__all__ = ["STATE_FILE", "DropFolder"]

logger = logging.getLogger(__name__)

STATE_FILE = ".routerscope-drop.json"
_IGNORED_SUFFIXES = (".tmp", ".part", ".crdownload")


@dataclass(frozen=True, slots=True)
class _Candidate:
    name: str
    size: int
    mtime_ns: int
    sha256: str
    data: bytes


class DropFolder:
    """Import new or changed files from a folder (see the module docstring)."""

    name = "drop_folder"

    def __init__(
        self,
        path: str | Path,
        *,
        tz: tzinfo | None = None,
        min_age: float = 0.0,
        registry: VendorRegistry | None = None,
    ) -> None:
        self.path = Path(path)
        self.tz = tz
        self.min_age = min_age
        self.registry = registry if registry is not None else default_registry()
        self.state_path = self.path / STATE_FILE
        self._files: dict[str, dict[str, Any]] = self._load_state()

    # -- state -----------------------------------------------------------------------------

    def _load_state(self) -> dict[str, dict[str, Any]]:
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            files = raw["files"]
            if isinstance(files, dict):
                return {str(k): dict(v) for k, v in files.items()}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            logger.warning("ignoring unreadable drop-folder state %s", self.state_path)
        return {}

    def _save_state(self) -> None:
        tmp = self.state_path.with_name(STATE_FILE + ".tmp")
        payload = json.dumps({"version": 1, "files": self._files}, indent=2, sort_keys=True)
        tmp.write_text(payload + "\n", encoding="utf-8", newline="\n")
        os.replace(tmp, self.state_path)

    def _mark(self, cand: _Candidate, skipped: str | None = None) -> None:
        entry: dict[str, Any] = {
            "size": cand.size,
            "mtime_ns": cand.mtime_ns,
            "sha256": cand.sha256,
        }
        if skipped:
            entry["skipped"] = skipped
        self._files[cand.name] = entry
        self._save_state()

    # -- scanning --------------------------------------------------------------------------

    def _candidates(self) -> Iterator[_Candidate]:
        try:
            entries = sorted(
                (p for p in self.path.iterdir() if p.is_file()),
                key=lambda p: (p.stat().st_mtime_ns, p.name),
            )
        except OSError as exc:
            raise ImportError_(f"cannot list {self.path}: {exc.strerror or exc}") from exc
        for path in entries:
            if path.name.startswith(".") or path.name.endswith(_IGNORED_SUFFIXES):
                continue
            try:
                stat = path.stat()
                known = self._files.get(path.name)
                if (
                    known
                    and known.get("size") == stat.st_size
                    and known.get("mtime_ns") == stat.st_mtime_ns
                ):
                    continue
                if time.time() - stat.st_mtime < self.min_age:
                    continue
                data = path.read_bytes()
            except OSError as exc:  # locked or vanished: try again at the next scan
                logger.debug("cannot read %s yet: %s", path, exc)
                continue
            cand = _Candidate(
                path.name, stat.st_size, stat.st_mtime_ns, hashlib.sha256(data).hexdigest(), data
            )
            if known and known.get("sha256") == cand.sha256:
                self._mark(cand, known.get("skipped"))  # only touched: refresh the mtime
                continue
            yield cand

    def _import(self, cand: _Candidate) -> list[ImportItem]:
        path = self.path / cand.name
        text = decode_bytes(cand.data)
        if not text.strip():
            raise ImportError_("empty file")
        mtime = datetime.fromtimestamp(cand.mtime_ns / 1e9, self.tz)
        if self.tz is None:
            mtime = mtime.astimezone()
        parsed = parse_session_log(text, tz=self.tz, fallback=mtime)
        if parsed.segments:
            source = Source(kind="drop_folder", uri=str(path), importer=parsed.format)
            return list(session_items(parsed, source))
        content = netprompt.normalize(text)
        if not looks_like_config(content, self.registry):
            raise ImportError_("neither a terminal log (no prompts) nor a configuration")
        source = Source(kind="drop_folder", uri=str(path), importer="drop_folder")
        return [
            ImportItem(
                content=content,
                kind="config",
                captured_at=mtime,
                source=source,
                hostname=config_hostname(content),
                vendor=self.registry.detect_vendor(content),
            )
        ]

    def _walk(self) -> Iterator[tuple[_Candidate, list[ImportItem]]]:
        for cand in self._candidates():
            try:
                items = self._import(cand)
            except ImportError_ as exc:
                logger.warning("skipping %s: %s", cand.name, exc)
                self._mark(cand, skipped=str(exc))
                continue
            yield cand, items

    # -- public API ------------------------------------------------------------------------

    def items(self) -> Iterator[ImportItem]:
        """Yield the items of every new or changed file; each file is marked once consumed."""
        for cand, items in self._walk():
            yield from items
            self._mark(cand)

    def scan(self) -> list[ImportItem]:
        """Import new or changed files once and return their items (oldest file first)."""
        return list(self.items())

    def poll(self, callback: Callable[[list[ImportItem]], None]) -> int:
        """One scan that hands each file's items to ``callback``; returns the items handled.

        A file whose callback raised is left unmarked (and logged), so it is offered again.
        """
        handled = 0
        for cand, items in self._walk():
            try:
                callback(items)
            except Exception:
                logger.exception("callback failed for %s; it will be retried", cand.name)
                continue
            self._mark(cand)
            handled += len(items)
        return handled

    def watch(
        self,
        callback: Callable[[list[ImportItem]], None],
        interval: float = 2.0,
        stop_event: threading.Event | None = None,
    ) -> None:
        """Poll every ``interval`` seconds until ``stop_event`` is set (or Ctrl+C).

        ``callback`` receives the items of one file at a time. Runs one scan immediately.
        """
        stop = stop_event if stop_event is not None else threading.Event()
        try:
            while not stop.is_set():
                self.poll(callback)
                stop.wait(interval)
        except KeyboardInterrupt:  # pragma: no cover - interactive use
            logger.info("drop-folder watch stopped")
