"""Email header and authentication analysis for forensic workflows."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import re
from datetime import datetime, timezone
from email.message import Message
from email.parser import Parser
from email.policy import default
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Optional

from schemas import AuthProtocolResult, HeaderAnalysisResult, RelayHop

logger = logging.getLogger(__name__)


def extract_message_body(raw_eml: Optional[bytes]) -> str:
    """Extract plain text body from a raw EML bytes object."""
    if not raw_eml:
        return ""
    try:
        from email import message_from_bytes
        msg = message_from_bytes(raw_eml)
        if msg.is_multipart():
            parts = []
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        parts.append(payload.decode("utf-8", errors="replace"))
            return "\n".join(parts)
        payload = msg.get_payload(decode=True)
        return payload.decode("utf-8", errors="replace") if payload else ""
    except Exception:
        return ""


MAX_HEADER_LENGTH = 32_768
_SPF_TIMEOUT_SECONDS = 3.0
_DMARC_TIMEOUT_SECONDS = 3.0

_RECEIVED_PART_PATTERN = re.compile(
    r"\b(?P<label>from|by|with)\s+(?P<value>[^;]*?)(?=\s+(?:from|by|with)\b|;|$)",
    re.IGNORECASE,
)
_IP_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_:])(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]{2,45})(?![A-Za-z0-9_:])"
)
_MESSAGE_ID_PATTERN = re.compile(r"^<[^<>@\s]+@[^<>@\s]+>$")
_DOMAIN_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")
_AUTH_STATUSES = {"pass", "fail", "softfail", "none", "temperror", "permerror"}


def _result(status: str, domain: Optional[str] = None, details: Optional[str] = None) -> AuthProtocolResult:
    normalized = status if status in _AUTH_STATUSES else "temperror"
    return AuthProtocolResult(status=normalized, domain=domain, details=details)


def _header_domain(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    addresses = getaddresses([value])
    address = next((address for _, address in addresses if "@" in address), "")
    domain = address.rsplit("@", 1)[-1].strip().lower().rstrip(".")
    return domain if _DOMAIN_PATTERN.fullmatch(domain) else None


def _extract_ips(value: str) -> list[str]:
    result: list[str] = []
    for candidate in _IP_PATTERN.findall(value):
        try:
            parsed = ipaddress.ip_address(candidate.strip("[]()"))
        except ValueError:
            continue
        normalized = str(parsed)
        if normalized not in result:
            result.append(normalized)
    return result


def _parse_received(value: str, index: int) -> RelayHop:
    if len(value) > MAX_HEADER_LENGTH:
        value = value[:MAX_HEADER_LENGTH]

    fields: dict[str, str] = {}
    for match in _RECEIVED_PART_PATTERN.finditer(value):
        fields[match.group("label").lower()] = " ".join(match.group("value").split())

    timestamp: Optional[datetime] = None
    if ";" in value:
        raw_timestamp = value.rsplit(";", 1)[1].strip()
        try:
            timestamp = parsedate_to_datetime(raw_timestamp)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError, OverflowError):
            timestamp = None

    return RelayHop(
        hop_index=index,
        from_host=fields.get("from"),
        by_host=fields.get("by"),
        with_protocol=fields.get("with"),
        timestamp=timestamp,
    )


def _dkim_result(raw_eml: Optional[bytes]) -> AuthProtocolResult:
    if not raw_eml:
        return _result("none", details="Raw EML was not supplied.")
    try:
        import dkim  # type: ignore

        signature_values = re.findall(rb"^d=([^;\r\n]+)", raw_eml, re.MULTILINE | re.IGNORECASE)
        domain = signature_values[0].decode("ascii", errors="replace").strip() if signature_values else None
        verifier = getattr(dkim, "dkim_verify", None) or getattr(dkim, "verify", None)
        if verifier is None:
            return _result("temperror", domain, "Installed dkimpy does not expose a verification function.")
        verified = bool(verifier(raw_eml))
        return _result("pass" if verified else "fail", domain, None if verified else "DKIM signature verification failed.")
    except (ImportError, OSError) as exc:
        return _result("temperror", details=f"DKIM verifier unavailable: {exc}")
    except Exception as exc:
        logger.warning("DKIM verification failed: %s", exc)
        return _result("temperror", details=f"DKIM verification error: {exc}")


def _spf_result(origin_ip: Optional[str], envelope_domain: Optional[str]) -> AuthProtocolResult:
    if not origin_ip or not envelope_domain:
        return _result("none", envelope_domain, "Origin IP or Return-Path domain was not available.")
    try:
        import spf  # type: ignore

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(spf.check2, origin_ip, f"postmaster@{envelope_domain}", envelope_domain)
            try:
                status, explanation = future.result(timeout=_SPF_TIMEOUT_SECONDS)
            except concurrent.futures.TimeoutError:
                return _result("temperror", envelope_domain, "SPF lookup timed out.")
        return _result(str(status).lower(), envelope_domain, str(explanation) if explanation else None)
    except ImportError:
        return _result("temperror", envelope_domain, "pyspf is not installed.")
    except Exception as exc:
        logger.warning("SPF validation failed: %s", exc)
        return _result("temperror", envelope_domain, f"SPF validation error: {exc}")


def _dmarc_record(domain: Optional[str]) -> tuple[Optional[bool], Optional[str]]:
    if not domain:
        return None, "From domain was not available."
    try:
        import checkdmarc  # type: ignore

        checker = getattr(checkdmarc, "check_dmarc", None)
        if checker is None:
            return None, "checkdmarc does not expose check_dmarc."
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(checker, domain, timeout=2)
            try:
                response: Any = future.result(timeout=_DMARC_TIMEOUT_SECONDS)
            except concurrent.futures.TimeoutError:
                return None, "DMARC lookup timed out."
        if isinstance(response, dict):
            if response.get("error"):
                return False, str(response["error"])
            return bool(response.get("valid", True)), str(response.get("record", "DMARC record checked."))
        return bool(response), "DMARC record checked."
    except ImportError:
        return None, "checkdmarc is not installed."
    except Exception as exc:
        logger.warning("DMARC lookup failed: %s", exc)
        return None, f"DMARC lookup error: {exc}"


def _dmarc_result(
    from_domain: Optional[str], spf_result: AuthProtocolResult, dkim_result: AuthProtocolResult
) -> AuthProtocolResult:
    if not from_domain:
        return _result("none", details="From domain was not available.")

    checked, details = _dmarc_record(from_domain)
    aligned_spf = bool(spf_result.domain and spf_result.domain == from_domain and spf_result.status == "pass")
    aligned_dkim = bool(dkim_result.domain and dkim_result.domain == from_domain and dkim_result.status == "pass")
    if aligned_spf or aligned_dkim:
        return _result("pass", from_domain, details)
    if checked is False:
        return _result("permerror", from_domain, details)
    if checked is None:
        return _result("temperror", from_domain, details)
    return _result("fail", from_domain, "No aligned SPF or DKIM authentication passed.")


def _add_anomaly(anomalies: list[str], message: str) -> None:
    if message not in anomalies:
        anomalies.append(message)


def analyze_headers(raw_headers: str, raw_eml: Optional[bytes] = None) -> HeaderAnalysisResult:
    """Parse headers and return authentication, relay, and spoofing signals."""
    anomalies: list[str] = []
    empty_auth = _result("none", details="Header analysis did not complete.")
    if not isinstance(raw_headers, str) or not raw_headers.strip():
        return HeaderAnalysisResult(
            relay_chain=[], origin_ip=None, spf=empty_auth, dkim=empty_auth, dmarc=empty_auth,
            anomalies=["Headers are empty or not a string."], is_spoofed=True, spoofing_risk_score=1.0,
        )

    if len(raw_headers) > 65_536:
        return HeaderAnalysisResult(
            relay_chain=[], origin_ip=None, spf=empty_auth, dkim=empty_auth, dmarc=empty_auth,
            anomalies=["Headers exceed maximum allowed size."], is_spoofed=True, spoofing_risk_score=1.0,
        )

    try:
        message: Message = Parser(policy=default).parsestr(raw_headers)
    except (TypeError, ValueError) as exc:
        return HeaderAnalysisResult(
            relay_chain=[], origin_ip=None, spf=empty_auth, dkim=empty_auth, dmarc=empty_auth,
            anomalies=[f"Headers could not be parsed: {exc}"], is_spoofed=True, spoofing_risk_score=1.0,
        )

    relay_chain = [_parse_received(value, index) for index, value in enumerate(message.get_all("Received", []))]
    relay_chain.reverse()
    for index, hop in enumerate(relay_chain):
        hop.hop_index = index
        if index and hop.timestamp and relay_chain[index - 1].timestamp:
            delay = (hop.timestamp - relay_chain[index - 1].timestamp).total_seconds()
            hop.delay_seconds = delay
            if delay < 0:
                _add_anomaly(anomalies, "Relay timestamps are out of order.")

    all_hop_text = " ".join(value for raw in reversed(message.get_all("Received", [])) for value in [str(raw)])
    hop_ips = _extract_ips(all_hop_text)
    public_ips = [ip for ip in hop_ips if ipaddress.ip_address(ip).is_global]
    origin_ip = public_ips[0] if public_ips else None
    if any(not ipaddress.ip_address(ip).is_global for ip in hop_ips) and public_ips:
        _add_anomaly(anomalies, "Private or non-global IP address exposed in a public MTA transition.")
    if len(relay_chain) > 1 and any(not hop.from_host or not hop.by_host for hop in relay_chain):
        _add_anomaly(anomalies, "Relay chain contains a disjoint hop without both endpoints.")
    if not relay_chain:
        _add_anomaly(anomalies, "No Received headers were present.")

    from_domain = _header_domain(message.get("From"))
    return_domain = _header_domain(message.get("Return-Path"))
    if not message.get("Return-Path"):
        _add_anomaly(anomalies, "Return-Path header is missing.")
    elif not return_domain:
        _add_anomaly(anomalies, "Return-Path header is malformed.")
    elif not from_domain:
        _add_anomaly(anomalies, "From header does not contain a valid domain.")

    message_id = str(message.get("Message-ID", "")).strip()
    if not message_id or not _MESSAGE_ID_PATTERN.fullmatch(message_id):
        _add_anomaly(anomalies, "Message-ID is missing or not RFC-compliant.")
    if from_domain and return_domain and from_domain != return_domain:
        _add_anomaly(anomalies, "From domain and Return-Path domain do not match.")

    spf_result = _spf_result(origin_ip, return_domain)
    dkim_result = _dkim_result(raw_eml)
    dmarc_result = _dmarc_result(from_domain, spf_result, dkim_result)
    authenticated_domains = {domain for domain in (spf_result.domain, dkim_result.domain) if domain}
    if from_domain and authenticated_domains and not any(domain == from_domain for domain in authenticated_domains):
        _add_anomaly(anomalies, "From domain does not match an authenticated SPF or DKIM domain.")

    risk = min(1.0, len(anomalies) * 0.12)
    risk += sum(0.16 for result in (spf_result, dkim_result, dmarc_result) if result.status in {"fail", "permerror"})
    risk += sum(0.07 for result in (spf_result, dkim_result, dmarc_result) if result.status == "temperror")
    risk = min(1.0, round(risk, 4))
    is_spoofed = risk >= 0.5 or any(result.status in {"fail", "permerror"} for result in (spf_result, dkim_result, dmarc_result))

    return HeaderAnalysisResult(
        relay_chain=relay_chain,
        origin_ip=origin_ip,
        spf=spf_result,
        dkim=dkim_result,
        dmarc=dmarc_result,
        anomalies=anomalies,
        is_spoofed=is_spoofed,
        spoofing_risk_score=risk,
    )

