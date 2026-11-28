"""Diffs over time: semantic (by natural key), hierarchical (config blocks) and plain lines.

See ``docs/diff.md``.
"""

from routerscope.services.diff.config import (
    ORDERED_SECTIONS,
    VOLATILE_LINES,
    ConfigChange,
    ConfigDiff,
    ConfigDiffOptions,
    DiffNode,
    OrderedRule,
    diff_config,
)
from routerscope.services.diff.history import SnapshotDiff, changes, diff_device, diff_snapshots
from routerscope.services.diff.semantic import (
    FieldChange,
    ItemChange,
    ItemSpec,
    KindSpec,
    ObjectChange,
    SemanticDiff,
    diff_objects,
    register_kind,
)
from routerscope.services.diff.text import LineChange, LineDiff, diff_lines

__all__ = [
    "ORDERED_SECTIONS",
    "VOLATILE_LINES",
    "ConfigChange",
    "ConfigDiff",
    "ConfigDiffOptions",
    "DiffNode",
    "FieldChange",
    "ItemChange",
    "ItemSpec",
    "KindSpec",
    "LineChange",
    "LineDiff",
    "ObjectChange",
    "OrderedRule",
    "SemanticDiff",
    "SnapshotDiff",
    "changes",
    "diff_config",
    "diff_device",
    "diff_lines",
    "diff_objects",
    "diff_snapshots",
    "register_kind",
]
