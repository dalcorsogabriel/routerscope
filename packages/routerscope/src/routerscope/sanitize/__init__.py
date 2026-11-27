"""Sanitize router output and configs: redact secrets, anonymize addresses, scan before commit."""

from routerscope.sanitize.sanitizer import Sanitizer
from routerscope.sanitize.scan import (
    ALLOW_FILE,
    FileFinding,
    Finding,
    load_allowlist,
    scan,
    scan_paths,
)
from routerscope.sanitize.redaction import PLACEHOLDER, redact_secrets

__all__ = [
    "ALLOW_FILE",
    "PLACEHOLDER",
    "FileFinding",
    "Finding",
    "Sanitizer",
    "load_allowlist",
    "redact_secrets",
    "scan",
    "scan_paths",
]
