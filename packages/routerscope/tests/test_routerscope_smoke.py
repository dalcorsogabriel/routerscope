import routerscope


def test_version_is_exposed() -> None:
    assert isinstance(routerscope.__version__, str)
