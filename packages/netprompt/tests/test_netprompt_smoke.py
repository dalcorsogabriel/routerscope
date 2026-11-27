import netprompt


def test_version_is_exposed() -> None:
    assert isinstance(netprompt.__version__, str)
