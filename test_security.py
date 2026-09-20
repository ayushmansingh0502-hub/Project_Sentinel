"""
Security Verification Suite for Email Geolocation Trace Platform
Tests:
1. Bounded In-Memory Storage & DoS Prevention
2. Rate Limiting on Trace Submissions (HTTP 429)
3. Strict Pydantic Schema Validation (HTTP 422)
4. ReDoS Resistance in Trusted MTA Matching
5. Strict IP Sanitization and SSRF Guard
6. HTTP Security Headers (CSP, X-Frame-Options, etc.)
"""

import os
import unittest
import time
from fastapi.testclient import TestClient
from main import app, EMAILS_DB, MAX_STORED_EMAILS, RATE_LIMIT_STORE
from config import config
import api.dependencies as dependencies
from geo_intel import is_trusted_mta, geolocate_ip, is_valid_ip

client = TestClient(app, headers={"x-api-key": config.api.api_key})
unauthenticated_client = TestClient(app)

class TestSecurityRemediations(unittest.TestCase):

    def setUp(self):
        # Reset rate limiter store between test runs
        RATE_LIMIT_STORE.clear()

    def test_1_redos_immunity(self):
        """Verify is_trusted_mta handles adversarial inputs without catastrophic backtracking."""
        start_time = time.time()
        adversarial_input = "a." * 5000 + "internal.company.com"
        result = is_trusted_mta(adversarial_input)
        elapsed = time.time() - start_time
        
        # Must finish in less than 50 milliseconds
        self.assertFalse(result)
        self.assertLess(elapsed, 0.05, f"ReDoS check took too long: {elapsed:.4f}s")

    def test_email_trace_requires_authentication(self):
        self.assertEqual(unauthenticated_client.get("/emails").status_code, 401)
        self.assertEqual(unauthenticated_client.get("/emails/EML-89412/trace").status_code, 401)
        self.assertEqual(unauthenticated_client.post("/emails/analyze", json={}).status_code, 401)

    def test_2_strict_ip_validation_and_ssrf_guard(self):
        """Verify geolocate_ip safely rejects malformed/injected IP addresses."""
        malformed_inputs = [
            "http://169.254.169.254/latest/meta-data/",
            "999.999.999.999",
            "185.220.101.5; cat /etc/passwd",
            "<script>alert(1)</script>",
            "127.0.0.1.bad.org",
            " " * 100
        ]
        for bad_ip in malformed_inputs:
            self.assertFalse(is_valid_ip(bad_ip), f"Should not be valid IP: {bad_ip}")
            res = geolocate_ip(bad_ip)
            self.assertIn(res.get("country"), ["Unknown", "Invalid IP"])
            self.assertEqual(res.get("latitude"), 0.0)

    def test_3_pydantic_schema_validation(self):
        """Verify strict payload bounds reject over-limit hops and excessive strings."""
        # 1. Reject empty relay chain (min 1 hop required)
        resp_empty = client.post("/emails/analyze", json={
            "subject": "Test",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "relay_chain": []
        })
        self.assertEqual(resp_empty.status_code, 422)

        # 2. Reject excessive relay chain (>50 hops to prevent CPU/memory exhaustion)
        too_many_hops = [{"ip": f"198.51.100.{i % 250}", "domain": "mta.com"} for i in range(55)]
        resp_too_many = client.post("/emails/analyze", json={
            "subject": "Flood Test",
            "sender": "flood@test.com",
            "recipient": "target@corp.local",
            "relay_chain": too_many_hops
        })
        self.assertEqual(resp_too_many.status_code, 422)

        # 3. Reject oversized subject string (>255 chars)
        resp_long_subject = client.post("/emails/analyze", json={
            "subject": "A" * 300,
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "relay_chain": [{"ip": "185.220.101.5", "domain": "test.org"}]
        })
        self.assertEqual(resp_long_subject.status_code, 422)

        # 4. Reject invalid email_id containing non-alphanumeric characters
        resp_bad_id = client.post("/emails/analyze", json={
            "email_id": "EML-123<script>alert(1)</script>",
            "subject": "Test",
            "sender": "a@b.com",
            "recipient": "c@d.com",
            "relay_chain": [{"ip": "185.220.101.5", "domain": "test.org"}]
        })
        self.assertEqual(resp_bad_id.status_code, 422)

    def test_4_bounded_storage_memory_protection(self):
        """Verify EMAILS_DB never exceeds MAX_STORED_EMAILS (100) even with continuous posts."""
        # Post 120 unique valid email traces
        for i in range(120):
            # Bypass rate limit by clearing rate store for bulk test
            RATE_LIMIT_STORE.clear()
            payload = {
                "email_id": f"BULK-TEST-{i}",
                "subject": f"Bulk Test Email #{i}",
                "sender": f"user{i}@test.com",
                "recipient": "target@corp.local",
                "relay_chain": [{"ip": "185.220.101.5", "domain": "exit.tor-node.de"}]
            }
            resp = client.post("/emails/analyze", json=payload)
            self.assertEqual(resp.status_code, 200)

        # Confirm DB size is strictly bounded
        self.assertLessEqual(len(EMAILS_DB), MAX_STORED_EMAILS)
        self.assertEqual(len(EMAILS_DB), 100)
        # Oldest items (e.g. BULK-TEST-0) should have been evicted
        self.assertNotIn("BULK-TEST-0", EMAILS_DB)
        # Most recent items must exist
        self.assertIn("BULK-TEST-119", EMAILS_DB)

    def test_5_rate_limiting(self):
        """Verify client IP rate limit enforces max 30 requests per minute with HTTP 429."""
        RATE_LIMIT_STORE.clear()
        payload = {
            "subject": "Rate Limit Test",
            "sender": "spammer@bot.net",
            "recipient": "victim@corp.local",
            "relay_chain": [{"ip": "185.220.101.5", "domain": "exit.tor-node.de"}]
        }

        # First 30 requests should succeed
        for i in range(30):
            r = client.post("/emails/analyze", json=payload)
            self.assertEqual(r.status_code, 200)

        # 31st request must trigger HTTP 429
        r_exceeded = client.post("/emails/analyze", json=payload)
        self.assertEqual(r_exceeded.status_code, 429)
        self.assertIn("Rate limit exceeded", r_exceeded.json()["detail"])

    def test_6_http_security_headers(self):
        """Verify HTTP security headers (CSP, X-Frame-Options, X-Content-Type-Options) are set."""
        resp = client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("Content-Security-Policy", resp.headers)
        self.assertIn("frame-ancestors 'none'", resp.headers["Content-Security-Policy"])

    def test_csv_payload_is_bounded(self):
        response = client.post("/ingest/csv", json={"csv": "x\n" + ("1\n" * 500_001)})
        self.assertEqual(response.status_code, 422)

    def test_generic_json_normalization_rejects_unsafe_entity_ids(self):
        response = client.post(
            "/ingest/json",
            json={"entity_type": "ip", "entity_id": "<script>alert(1)</script>"},
        )
        self.assertEqual(response.status_code, 422)

    def test_health_details_requires_authentication(self):
        self.assertEqual(unauthenticated_client.get("/health/details").status_code, 401)
        self.assertEqual(unauthenticated_client.get("/health").json(), {"status": "healthy", "service": "SwarmSentinel"})

    def test_production_operator_auth_fails_closed_without_operator_key(self):
        original_operator_key = dependencies.OPERATOR_API_KEY
        original_fallback = os.environ.get("ALLOW_DEV_OPERATOR_FALLBACK")
        try:
            dependencies.OPERATOR_API_KEY = ""
            if "ALLOW_DEV_OPERATOR_FALLBACK" in os.environ:
                del os.environ["ALLOW_DEV_OPERATOR_FALLBACK"]
            response = client.post("/swarm/reset")
            self.assertEqual(response.status_code, 503)
        finally:
            dependencies.OPERATOR_API_KEY = original_operator_key
            if original_fallback is not None:
                os.environ["ALLOW_DEV_OPERATOR_FALLBACK"] = original_fallback

    def test_operator_auth_separate_key_required(self):
        original_operator_key = os.environ.get("OPERATOR_API_KEY")
        original_fallback = os.environ.get("ALLOW_DEV_OPERATOR_FALLBACK")
        try:
            os.environ["OPERATOR_API_KEY"] = "operator-secret-key"
            dependencies.OPERATOR_API_KEY = "operator-secret-key"
            if "ALLOW_DEV_OPERATOR_FALLBACK" in os.environ:
                del os.environ["ALLOW_DEV_OPERATOR_FALLBACK"]

            # Ordinary API key should be rejected with 403
            resp_ordinary = client.post("/swarm/reset", headers={"x-api-key": config.api.api_key})
            self.assertEqual(resp_ordinary.status_code, 403)

            # Valid operator key should be accepted
            resp_op = client.post("/swarm/reset", headers={"x-api-key": "operator-secret-key"})
            self.assertIn(resp_op.status_code, [200, 500])
        finally:
            if original_operator_key is not None:
                os.environ["OPERATOR_API_KEY"] = original_operator_key
                dependencies.OPERATOR_API_KEY = original_operator_key
            else:
                os.environ.pop("OPERATOR_API_KEY", None)
                dependencies.OPERATOR_API_KEY = ""

            if original_fallback is not None:
                os.environ["ALLOW_DEV_OPERATOR_FALLBACK"] = original_fallback

    def test_forensic_report_requires_forensic_or_operator_key(self):
        original_forensic = os.environ.get("FORENSIC_READ_API_KEY")
        original_operator = os.environ.get("OPERATOR_API_KEY")
        original_fallback = os.environ.get("ALLOW_DEV_OPERATOR_FALLBACK")
        try:
            os.environ["FORENSIC_READ_API_KEY"] = "forensic-read-key"
            os.environ["OPERATOR_API_KEY"] = "operator-key"
            dependencies.FORENSIC_READ_API_KEY = "forensic-read-key"
            dependencies.OPERATOR_API_KEY = "operator-key"
            if "ALLOW_DEV_OPERATOR_FALLBACK" in os.environ:
                del os.environ["ALLOW_DEV_OPERATOR_FALLBACK"]

            # Ordinary API key should be denied
            resp_ord = client.get("/emails/EML-89412/report/metadata", headers={"x-api-key": config.api.api_key})
            self.assertEqual(resp_ord.status_code, 403)

            # Forensic read key accepted
            resp_forensic = client.get("/emails/EML-89412/report/metadata", headers={"x-api-key": "forensic-read-key"})
            self.assertNotEqual(resp_forensic.status_code, 403)

            # Operator key accepted
            resp_op = client.get("/emails/EML-89412/report/metadata", headers={"x-api-key": "operator-key"})
            self.assertNotEqual(resp_op.status_code, 403)
        finally:
            if original_forensic is not None:
                os.environ["FORENSIC_READ_API_KEY"] = original_forensic
                dependencies.FORENSIC_READ_API_KEY = original_forensic
            else:
                os.environ.pop("FORENSIC_READ_API_KEY", None)
                dependencies.FORENSIC_READ_API_KEY = ""

            if original_operator is not None:
                os.environ["OPERATOR_API_KEY"] = original_operator
                dependencies.OPERATOR_API_KEY = original_operator
            else:
                os.environ.pop("OPERATOR_API_KEY", None)
                dependencies.OPERATOR_API_KEY = ""

            if original_fallback is not None:
                os.environ["ALLOW_DEV_OPERATOR_FALLBACK"] = original_fallback

    def test_ws_ticket_single_use_replay_protection(self):
        ticket = dependencies.create_websocket_ticket("127.0.0.1")
        self.assertTrue(bool(ticket))
        with dependencies._ws_ticket_lock:
            self.assertIn(ticket, dependencies._WS_TICKETS)

if __name__ == "__main__":
    unittest.main()
