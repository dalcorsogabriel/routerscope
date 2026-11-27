import netcmd_safety


def test_version_is_exposed() -> None:
    assert isinstance(netcmd_safety.__version__, str)
