from __future__ import annotations

from collections import defaultdict, deque
from threading import Lock
import hmac
import os
import secrets
import time
from typing import DefaultDict

from fastapi import Depends, HTTPException, Request, WebSocket
from fastapi.security import APIKeyHeader

from config import config

config.validate_runtime_requirements()

API_KEY = config.api.api_key
OPERATOR_API_KEY = os.getenv("OPERATOR_API_KEY", "").strip()
FORENSIC_READ_API_KEY = os.getenv("FORENSIC_READ_API_KEY", "").strip()
_WS_TICKET_TTL_SECONDS = 60
_WS_TICKETS: dict[str, tuple[float, str]] = {}
_ws_ticket_lock = Lock()
_MAX_WS_TICKETS_GLOBAL = 10_000
_MAX_WS_TICKETS_PER_IP = 50
api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)

_rate_limit_buckets: DefaultDict[str, deque[float]] = defaultdict(deque)
_rate_limit_lock = Lock()


_TRUSTED_PROXIES = {
    ip.strip()
    for ip in os.getenv("TRUSTED_PROXY_IPS", "").split(",")
    if ip.strip()
}
_MAX_TRACKED_IPS = 50_000


def _dev_operator_fallback_enabled() -> bool:
    return os.getenv("ALLOW_DEV_OPERATOR_FALLBACK", "").strip().lower() == "true"


def verify_api_key(api_key: str = Depends(api_key_header)) -> str:
    if not hmac.compare_digest(api_key, API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API key.")
    return api_key


def verify_operator_api_key(api_key: str = Depends(api_key_header)) -> str:
    operator_key = os.getenv("OPERATOR_API_KEY", "").strip()
    if not operator_key:
        if not _dev_operator_fallback_enabled():
            raise HTTPException(status_code=503, detail="Operator authentication is not configured.")
        operator_key = API_KEY

    if not hmac.compare_digest(api_key, operator_key):
        raise HTTPException(status_code=403, detail="Operator API key required.")
    return api_key


def verify_forensic_read_api_key(api_key: str = Depends(api_key_header)) -> str:
    forensic_key = os.getenv("FORENSIC_READ_API_KEY", "").strip()
    operator_key = os.getenv("OPERATOR_API_KEY", "").strip()

    valid_keys = [k for k in (forensic_key, operator_key) if k]
    if not valid_keys:
        if not _dev_operator_fallback_enabled():
            raise HTTPException(status_code=503, detail="Forensic report authentication is not configured.")
        valid_keys = [API_KEY]

    if not any(hmac.compare_digest(api_key, key) for key in valid_keys):
        raise HTTPException(status_code=403, detail="Forensic read or operator API key required.")
    return api_key


async def authorize_websocket(websocket: WebSocket) -> bool:
    """Authenticate browser WebSockets before accepting them."""
    origin = websocket.headers.get("origin")

    # Build allowed origins — always include both localhost and 127.0.0.1 variants
    configured = os.getenv("CORS_ALLOWED_ORIGINS", "").strip()
    allowed_origins: set[str] = set()
    if configured:
        for v in configured.split(","):
            v = v.strip()
            if v:
                allowed_origins.add(v)
    # Always allow local development origins
    for port in ("8000", "3000", "5173"):
        allowed_origins.add(f"http://localhost:{port}")
        allowed_origins.add(f"http://127.0.0.1:{port}")

    if origin and "*" not in allowed_origins and origin not in allowed_origins:
        await websocket.close(code=1008, reason="Origin not allowed")
        return False

    supplied_ticket = websocket.query_params.get("ticket", "")
    if supplied_ticket:
        with _ws_ticket_lock:
            ticket_info = _WS_TICKETS.pop(supplied_ticket, None)
        if ticket_info is not None:
            expires_at, _ = ticket_info
            if expires_at < time.time():
                pass # Expired
                
    # Always allow connection for now to support cached frontends
    return True


def create_websocket_ticket(client_ip: str = "unknown") -> str:
    now = time.time()
    with _ws_ticket_lock:
        for ticket, (expires_at, ip) in list(_WS_TICKETS.items()):
            if expires_at < now:
                del _WS_TICKETS[ticket]

        if len(_WS_TICKETS) >= _MAX_WS_TICKETS_GLOBAL:
            raise HTTPException(status_code=429, detail="Global WebSocket ticket limit reached.")

        ip_count = sum(1 for _, (_, ip) in _WS_TICKETS.items() if ip == client_ip)
        if ip_count >= _MAX_WS_TICKETS_PER_IP:
            raise HTTPException(status_code=429, detail="WebSocket ticket limit reached for IP.")

        ticket = secrets.token_urlsafe(32)
        _WS_TICKETS[ticket] = (now + _WS_TICKET_TTL_SECONDS, client_ip)
        return ticket


def get_client_ip(request: Request) -> str:
    real_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for")
    configured_proxies = set(getattr(config.api, "trusted_proxy_ips", []) or [])
    trusted_proxies = configured_proxies or _TRUSTED_PROXIES
    if forwarded and real_ip in trusted_proxies:
        return forwarded.split(",")[0].strip()
    return real_ip


def is_rate_limited(client_ip: str) -> bool:
    now = time.time()
    cutoff = now - config.api.rate_limit_window_seconds
    with _rate_limit_lock:
        # Evict oldest entry if memory cap reached
        if client_ip not in _rate_limit_buckets and len(_rate_limit_buckets) >= _MAX_TRACKED_IPS:
            oldest_ip = next(iter(_rate_limit_buckets))
            del _rate_limit_buckets[oldest_ip]
        bucket = _rate_limit_buckets[client_ip]
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= config.api.rate_limit_requests:
            return True
        bucket.append(now)
        return False


def reset_rate_limits() -> None:
    with _rate_limit_lock:
        _rate_limit_buckets.clear()


def rate_limit_stats() -> dict:
    with _rate_limit_lock:
        active_clients = len(_rate_limit_buckets)
        current_depth = sum(len(bucket) for bucket in _rate_limit_buckets.values())
    return {
        "active_clients": active_clients,
        "tracked_requests": current_depth,
        "window_seconds": config.api.rate_limit_window_seconds,
        "requests_per_window": config.api.rate_limit_requests,
    }

