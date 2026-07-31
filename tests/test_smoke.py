"""Smoke tests for peta package."""


def test_smoke() -> None:
    """Test that the package can be imported."""
    import peta  # noqa: PLC0415

    assert peta is not None
