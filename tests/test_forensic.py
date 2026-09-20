from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from fastapi.testclient import TestClient

import storage
from forensic.evidence import create_evidence_metadata
from forensic.forensic_report import render_report
from forensic.report_models import ForensicReportContext
from config import config
from main import app

import os
os.environ["FORENSIC_READ_API_KEY"] = config.api.api_key

client = TestClient(app, headers={"x-api-key": config.api.api_key})


def test_evidence_metadata_hash_is_deterministic():
    evidence = create_evidence_metadata("mail-1", b"raw email")
    assert evidence.sha256 == hashlib.sha256(b"raw email").hexdigest()
    assert evidence.content_length == 9


def test_report_template_escapes_dynamic_content():
    context = ForensicReportContext(
        report_id="report-1",
        email_id="mail-1",
        generated_at=datetime.now(timezone.utc),
        generator_version="1.0.0",
        risk_score=80,
        risk_level="high",
        verdict="SCAM",
        evidence=create_evidence_metadata("mail-1", b"raw"),
        sender={"from_address": "<script>alert(1)</script>"},
        authentication={},
        headers={},
        origin_trace={},
        indicators=[],
        limitations=["<img src=x onerror=alert(1)>"]
    )
    html = render_report(context)
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img" in html


def test_forensic_metadata_requires_authentication():
    assert client.get("/emails/mail-1/report/metadata").status_code == 404
    assert TestClient(app).get("/emails/mail-1/report/metadata").status_code == 401


def test_forensic_metadata_returns_evidence():
    email_id = "forensic-test"
    storage.save_email_analysis(email_id, {"is_scam": True, "risk": {"score": 91}})
    storage.save_evidence_metadata(email_id, create_evidence_metadata(email_id, b"captured"))
    response = client.get(f"/emails/{email_id}/report/metadata")
    assert response.status_code == 200
    assert response.json()["evidence"]["integrity_status"] == "verified"
    storage.reset_runtime_state()


def test_extract_auth_status_dict_and_pydantic():
    from forensic.forensic_report import _extract_auth_status

    assert _extract_auth_status({"status": "pass"}) == "pass"
    assert _extract_auth_status({"result": "fail"}) == "fail"

    class DummyAuth:
        status = "temperror"

    assert _extract_auth_status(DummyAuth()) == "temperror"
    assert _extract_auth_status("pass") == "pass"
    assert _extract_auth_status(None) == "NOT_CHECKED"

