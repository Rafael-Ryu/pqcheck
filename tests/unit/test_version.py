from pqcheck import __version__


def test_version_is_pep440_string() -> None:
    assert isinstance(__version__, str)
    assert __version__.count(".") >= 2
