from email_analyzer import _prepare_raw_eml
from schemas import EmailAnalysisRequest


def test_raw_eml_string_is_safely_converted_to_bytes():
    payload = EmailAnalysisRequest(from_email="a@b.com", message_text="hi", raw_eml="d=example.com;\r\n\r\nbody")
    encoded = _prepare_raw_eml(payload.raw_eml)
    assert isinstance(encoded, bytes)
    assert b"d=example.com;" in encoded


def test_raw_eml_with_invalid_bytes_does_not_crash():
    bad = "d=example.com\udcff"  # unpaired surrogate
    prepared = _prepare_raw_eml(bad)
    assert prepared is not None
    assert isinstance(prepared, bytes)


def test_raw_eml_none_returns_none():
    assert _prepare_raw_eml(None) is None
