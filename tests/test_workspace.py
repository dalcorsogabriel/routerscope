"""Workspace-level checks (cross-package)."""

import netaddr_search
import netcmd_safety
import netprompt
import routerscope


def test_all_packages_import() -> None:
    for mod in (netcmd_safety, netprompt, netaddr_search, routerscope):
        assert mod.__version__
