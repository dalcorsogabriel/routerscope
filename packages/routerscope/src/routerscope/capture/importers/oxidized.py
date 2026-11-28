"""Import the git history written by Oxidized (``output: git``).

Oxidized stores one file per device, named after the device, and commits every change. With
``single_repo: true`` all devices live in one repository, optionally inside a directory per
group (``<group>/<device>``). With the default (one repository per group) each group has its
own repository; point the importer at the directory that holds them with ``layout="group"``.

* ``layout="single"`` (default): ``repo_path`` is one repository (any of the above shapes).
* ``layout="group"``: ``repo_path`` is a directory whose immediate subdirectories are
  repositories (normal clones or bare ``*.git``); each is walked in name order.

Content is kept exactly as committed (Oxidized's own header comments are not stripped).
The hostname is the file name when it is a safe hostname, else ``None``. Oxidized does not
store the device model in the repository, so the vendor is ``None`` (ingestion detects it)
unless you give a mapping:

* ``model_map``: ``{device name: model}``; the model is an Oxidized model name (``ios``,
  ``iosxr``, ``vrp``, ``routeros``, ``junos``, ``sros``, ``ocnos``...) or already a
  routerscope vendor id;
* ``model_file``: a ``router.db``-style file, one device per line, ``name:model`` (extra
  fields such as ``name:ip:model:group`` are accepted: the first field that is a known model
  is used). ``;``, ``,`` and ``:`` separate fields; ``#`` starts a comment.
* ``default_model``: used for devices not listed.

``captured_at`` is the commit's committer time.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Literal

from routerscope.capture.importers.base import ImportError_, ImportItem
from routerscope.capture.importers.git_history import (
    safe_hostname,
    walk_history,
)
from routerscope.model import Source

__all__ = ["OXIDIZED_MODELS", "OxidizedImporter", "parse_model_file"]

OXIDIZED_MODELS: Mapping[str, str] = {
    "ios": "cisco_ios",
    "iosxe": "cisco_ios",
    "iosxr": "cisco_xr",
    "xr": "cisco_xr",
    "junos": "juniper_junos",
    "vrp": "huawei_vrp",
    "vrpv8": "huawei_vrp",
    "routeros": "mikrotik_ros7",
    "sros": "nokia_sros",
    "timos": "nokia_sros",
    "ocnos": "ipinfusion_ocnos",
}
"""Oxidized model name -> routerscope vendor id (only vendors with a plugin)."""

_VENDOR_IDS = frozenset(OXIDIZED_MODELS.values())
_SPLIT = re.compile(r"[;:,\s]+")


def _vendor_for(model: str | None) -> str | None:
    if not model:
        return None
    key = model.strip().lower()
    if key in _VENDOR_IDS:
        return key
    return OXIDIZED_MODELS.get(key)


def parse_model_file(path: Path) -> dict[str, str]:
    """Read a ``name:model`` mapping file (see the module docs)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ImportError_(f"cannot read model file {path}: {exc}") from exc
    result: dict[str, str] = {}
    for line in text.splitlines():
        fields = [f for f in _SPLIT.split(line.split("#", 1)[0].strip()) if f]
        if len(fields) < 2:
            continue
        model = next((f for f in fields[1:] if _vendor_for(f)), fields[1])
        result[fields[0]] = model
    return result


def _is_repo_dir(path: Path) -> bool:
    """A directory that is itself a repository (checkout or bare), not merely inside one."""
    if (path / ".git").exists():
        return True
    return (path / "HEAD").is_file() and (path / "objects").is_dir()


class OxidizedImporter:
    """Yield one ``config`` item per (device file, commit) of an Oxidized git output."""

    name = "oxidized"

    def __init__(
        self,
        repo_path: Path | str,
        *,
        layout: Literal["single", "group"] = "single",
        model_map: Mapping[str, str] | None = None,
        model_file: Path | str | None = None,
        default_model: str | None = None,
        ref: str = "HEAD",
        since: datetime | None = None,
        until: datetime | None = None,
        paths: list[str] | None = None,
    ) -> None:
        if layout not in ("single", "group"):
            raise ValueError("layout must be 'single' or 'group'")
        self.repo_path = Path(repo_path)
        self.layout = layout
        self.ref = ref
        self.since = since
        self.until = until
        self.paths = paths
        models: dict[str, str] = {}
        if model_file is not None:
            models.update(parse_model_file(Path(model_file)))
        if model_map:
            models.update(model_map)
        self._models = models
        self._lower = {k.lower(): v for k, v in models.items()}
        self._default = default_model

    def _vendor(self, hostname: str | None) -> str | None:
        model = None
        if hostname is not None:
            model = self._models.get(hostname) or self._lower.get(hostname.lower())
        return _vendor_for(model or self._default)

    def _repos(self) -> list[Path]:
        if self.layout == "single":
            return [self.repo_path]
        if not self.repo_path.is_dir():
            raise ImportError_(f"not a directory: {self.repo_path}")
        repos = sorted(p for p in self.repo_path.iterdir() if p.is_dir() and _is_repo_dir(p))
        if not repos:
            raise ImportError_(f"no group repositories found in {self.repo_path}")
        return repos

    def items(self) -> Iterator[ImportItem]:
        for repo in self._repos():
            uri = str(repo.resolve())
            for version in walk_history(
                repo, ref=self.ref, since=self.since, until=self.until, paths=self.paths
            ):
                file_name = PurePosixPath(version.path).name
                if file_name.startswith("."):
                    continue
                hostname = safe_hostname(file_name)
                yield ImportItem(
                    content=version.content,
                    kind="config",
                    captured_at=version.committed_at,
                    source=Source(
                        kind="oxidized", uri=uri, importer=self.name, git_commit=version.commit
                    ),
                    hostname=hostname,
                    vendor=self._vendor(hostname),
                )
