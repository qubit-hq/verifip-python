"""VerifIP SDK response models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class CheckResponse:
    """Response from a single IP check."""

    request_id: str = ""
    ip: str = ""
    fraud_score: int = 0
    is_proxy: bool = False
    is_vpn: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    country_code: str = ""
    country_name: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    asn: int = 0
    connection_type: str = ""
    hostname: str = ""
    signal_breakdown: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CheckResponse:
        if not isinstance(data, dict):
            return cls()
        return cls(
            request_id=data.get("request_id", ""),
            ip=data.get("ip", ""),
            fraud_score=data.get("fraud_score", 0),
            is_proxy=data.get("is_proxy", False),
            is_vpn=data.get("is_vpn", False),
            is_tor=data.get("is_tor", False),
            is_datacenter=data.get("is_datacenter", False),
            country_code=data.get("country_code", ""),
            country_name=data.get("country_name", ""),
            region=data.get("region", ""),
            city=data.get("city", ""),
            isp=data.get("isp", ""),
            asn=data.get("asn", 0),
            connection_type=data.get("connection_type", ""),
            hostname=data.get("hostname", ""),
            signal_breakdown=data.get("signal_breakdown", {}),
            error=data.get("error"),
        )


@dataclass
class BatchResponse:
    """Response from a batch IP check."""

    results: list[CheckResponse] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BatchResponse:
        if not isinstance(data, dict):
            return cls()
        raw = data.get("results", [])
        if not isinstance(raw, list):
            return cls()
        results = [CheckResponse.from_dict(r) for r in raw]
        return cls(results=results)


@dataclass
class HealthResponse:
    """Response from the health check endpoint."""

    status: str = ""
    version: str = ""
    data_loaded_at: str = ""
    redis: str = ""
    postgres: str = ""
    uptime_seconds: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HealthResponse:
        if not isinstance(data, dict):
            return cls()
        return cls(
            status=data.get("status", ""),
            version=data.get("version", ""),
            data_loaded_at=data.get("data_loaded_at", ""),
            redis=data.get("redis", ""),
            postgres=data.get("postgres", ""),
            uptime_seconds=data.get("uptime_seconds", 0),
        )


def _get_header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    lower = name.lower()
    for k, v in headers.items():
        if k.lower() == lower:
            return v
    return None


@dataclass
class RateLimitInfo:
    """Rate limit information parsed from response headers."""

    limit: int = 0
    remaining: int = 0
    reset: datetime | None = None

    @classmethod
    def from_headers(cls, headers: dict[str, str]) -> RateLimitInfo | None:
        limit_str = _get_header(headers, "X-RateLimit-Limit")
        if limit_str is None:
            return None
        remaining_str = _get_header(headers, "X-RateLimit-Remaining") or "0"
        reset_str = _get_header(headers, "X-RateLimit-Reset")

        try:
            limit = int(limit_str)
        except (ValueError, TypeError):
            return None

        try:
            remaining = int(remaining_str)
        except (ValueError, TypeError):
            remaining = 0

        reset_dt = None
        if reset_str:
            try:
                reset_dt = datetime.fromtimestamp(int(reset_str), tz=timezone.utc)
            except (ValueError, OSError, TypeError):
                pass

        return cls(limit=limit, remaining=remaining, reset=reset_dt)
