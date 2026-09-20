import pytest
from pydantic import ValidationError
from schemas import EmailAnalysisRequest


def test_email_analysis_request_rejects_oversized_headers():
    with pytest.raises(ValidationError):
        EmailAnalysisRequest(
            from_email="a@b.com",
            message_text="hi",
            raw_headers="x" * 70_000,
        )


def test_email_analysis_request_rejects_oversized_raw_eml():
    with pytest.raises(ValidationError):
        EmailAnalysisRequest(
            from_email="a@b.com",
            message_text="hi",
            raw_eml="x" * 2_500_000,
        )


def test_email_analysis_request_accepts_valid_payload():
    req = EmailAnalysisRequest(
        from_email="a@b.com",
        message_text="hi",
        raw_headers="From: a@b.com",
        raw_eml="Subject: test",
    )
    assert req.raw_headers == "From: a@b.com"
    assert req.raw_eml == "Subject: test"
