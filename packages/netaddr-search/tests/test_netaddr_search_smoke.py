import netaddr_search


def test_version_is_exposed() -> None:
    assert isinstance(netaddr_search.__version__, str)
