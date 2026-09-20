import pytest
from config import AppConfig, ConfigError


def test_config_rejects_unauthenticated_redis_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")
    monkeypatch.setenv("API_KEY", "real-secret-value")
    cfg = AppConfig.from_env()
    with pytest.raises(ConfigError) as exc_info:
        cfg.validate_runtime_requirements()
    assert "REDIS_URL has no credentials and ENVIRONMENT=production" in str(exc_info.value)


def test_config_allows_unauthenticated_redis_in_production_if_overridden(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379")
    monkeypatch.setenv("API_KEY", "real-secret-value")
    monkeypatch.setenv("REDIS_ALLOW_NO_AUTH", "true")
    cfg = AppConfig.from_env()
    validated = cfg.validate_runtime_requirements()
    assert validated.redis_url == "redis://localhost:6379"


def test_config_allows_authenticated_redis_in_production(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("REDIS_URL", "redis://user:pass@localhost:6379")
    monkeypatch.setenv("API_KEY", "real-secret-value")
    cfg = AppConfig.from_env()
    validated = cfg.validate_runtime_requirements()
    assert validated.redis_url == "redis://user:pass@localhost:6379"


def test_config_requires_redis_in_production_when_specified(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("REDIS_URL", "redis://user:pass@localhost:6379")
    monkeypatch.setenv("API_KEY", "real-secret-value")
    monkeypatch.setenv("REQUIRE_REDIS_IN_PRODUCTION", "true")
    cfg = AppConfig.from_env()
    with pytest.raises(ConfigError) as exc_info:
        cfg.validate_runtime_requirements()
    assert "Production environment requires a connected Redis instance" in str(exc_info.value)


def test_config_uses_safe_defaults_for_invalid_numeric_values(monkeypatch):
    monkeypatch.setenv("API_KEY", "real-secret-value")
    monkeypatch.setenv("RATE_LIMIT_REQUESTS", "not-a-number")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "-10")
    monkeypatch.setenv("GRAPH_DECAY_RATE", "invalid")
    monkeypatch.setenv("CORRELATION_WINDOW", "1")
    monkeypatch.setenv("CORRELATION_THRESHOLD", "101")

    cfg = AppConfig.from_env()

    assert cfg.api.rate_limit_requests == 30
    assert cfg.api.rate_limit_window_seconds == 1
    assert cfg.graph.decay_rate == 0.95
    assert cfg.correlation.window_seconds == 10.0
    assert cfg.correlation.create_threshold == 100.0
