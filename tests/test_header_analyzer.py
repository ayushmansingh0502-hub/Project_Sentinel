from header_analyzer import analyze_headers


BASE_HEADERS = """From: Analyst <analyst@example.com>\nReturn-Path: <analyst@example.com>\nMessage-ID: <message@example.com>\nReceived: from relay.example.net (8.8.8.8) by mx.example.com with ESMTP; Tue, 01 Jan 2030 12:00:00 +0000\nReceived: from sender.example.net (1.1.1.1) by relay.example.net with ESMTP; Tue, 01 Jan 2030 11:59:00 +0000\n\n"""


def test_received_chain_is_reconstructed_earliest_first():
    result = analyze_headers(BASE_HEADERS)

    assert [hop.hop_index for hop in result.relay_chain] == [0, 1]
    assert result.relay_chain[0].from_host == "sender.example.net (1.1.1.1)"
    assert result.relay_chain[1].by_host == "mx.example.com"
    assert result.relay_chain[1].delay_seconds == 60.0
    assert result.origin_ip == "1.1.1.1"


def test_negative_transit_time_is_reported():
    headers = BASE_HEADERS.replace(
        "Tue, 01 Jan 2030 12:00:00 +0000", "Tue, 01 Jan 2030 11:58:00 +0000"
    )
    result = analyze_headers(headers)

    assert "Relay timestamps are out of order." in result.anomalies
    assert 0.0 <= result.spoofing_risk_score <= 1.0


def test_missing_required_headers_are_anomalies():
    result = analyze_headers("From: analyst@example.com\n\nBody")

    assert "Return-Path header is missing." in result.anomalies
    assert "Message-ID is missing or not RFC-compliant." in result.anomalies
    assert result.spoofing_risk_score > 0.0


def test_empty_headers_return_bounded_result():
    result = analyze_headers("   ")

    assert result.is_spoofed is True
    assert result.spoofing_risk_score == 1.0
    assert result.relay_chain == []


def test_domain_mismatch_and_disjoint_hops_anomalies():
    headers = (
        "From: Alice <alice@spoofed.com>\n"
        "Return-Path: <legit@legitdomain.com>\n"
        "Message-ID: <12345@legitdomain.com>\n"
        "Received: from public.relay (8.8.8.8) by mx.example.com; Tue, 01 Jan 2030 12:00:00 +0000\n"
        "Received: from 192.168.1.50 by public.relay; Tue, 01 Jan 2030 11:59:00 +0000\n\n"
    )
    result = analyze_headers(headers)

    assert "From domain and Return-Path domain do not match." in result.anomalies
    assert "Private or non-global IP address exposed in a public MTA transition." in result.anomalies
    assert result.is_spoofed is True
    assert 0.0 <= result.spoofing_risk_score <= 1.0


def test_dkim_verification_with_eml_payload():
    headers = BASE_HEADERS
    eml_data = (headers + "Subject: Test\n\nHello world").encode("utf-8")

    result = analyze_headers(headers, raw_eml=eml_data)
    assert result.dkim.status in ("pass", "fail", "none", "temperror", "permerror")
    assert isinstance(result.spoofing_risk_score, float)


def test_received_header_pathological_input_completes_quickly():
    import time

    evil = "Received: from " + "a " * 50_000 + "x"
    start = time.perf_counter()
    result = analyze_headers(evil)
    assert time.perf_counter() - start < 1.0


def test_spf_lookup_timeout_returns_temperror(monkeypatch):
    import time
    from header_analyzer import _spf_result

    def slow_check2(*a, **kw):
        time.sleep(3.5)

    monkeypatch.setattr("spf.check2", slow_check2, raising=False)
    start = time.perf_counter()
    result = _spf_result("1.2.3.4", "example.com")
    assert time.perf_counter() - start < 4.5
    assert result.status == "temperror"


def test_headers_exceeding_max_size_return_error():
    evil_headers = "X-Header: " + "a" * 70_000
    result = analyze_headers(evil_headers)
    assert "Headers exceed maximum allowed size." in result.anomalies
    assert result.is_spoofed is True
    assert result.spoofing_risk_score == 1.0


