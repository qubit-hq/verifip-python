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


@dataclass
class EmailResponse:
    """Response from an email validation check."""

    request_id: str = ""
    email: str = ""
    risk_score: int = 0
    valid_syntax: bool = False
    mx_found: bool = False
    is_disposable: bool = False
    is_free_provider: bool = False
    is_role_based: bool = False
    domain_age_days: int = 0
    domain: str = ""
    signal_breakdown: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EmailResponse:
        if not isinstance(data, dict):
            return cls()
        return cls(
            request_id=data.get("request_id", ""),
            email=data.get("email", ""),
            risk_score=data.get("risk_score", 0),
            valid_syntax=data.get("valid_syntax", False),
            mx_found=data.get("mx_found", False),
            is_disposable=data.get("is_disposable", False),
            is_free_provider=data.get("is_free_provider", False),
            is_role_based=data.get("is_role_based", False),
            domain_age_days=data.get("domain_age_days", 0),
            domain=data.get("domain", ""),
            signal_breakdown=data.get("signal_breakdown", {}),
            error=data.get("error"),
        )


@dataclass
class PhoneResponse:
    """Response from a phone validation check."""

    request_id: str = ""
    phone: str = ""
    risk_score: int = 0
    valid: bool = False
    country_code: str = ""
    carrier: str = ""
    line_type: str = ""
    is_voip: bool = False
    signal_breakdown: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PhoneResponse:
        if not isinstance(data, dict):
            return cls()
        return cls(
            request_id=data.get("request_id", ""),
            phone=data.get("phone", ""),
            risk_score=data.get("risk_score", 0),
            valid=data.get("valid", False),
            country_code=data.get("country_code", ""),
            carrier=data.get("carrier", ""),
            line_type=data.get("line_type", ""),
            is_voip=data.get("is_voip", False),
            signal_breakdown=data.get("signal_breakdown", {}),
            error=data.get("error"),
        )


@dataclass
class URLResponse:
    """Response from a URL reputation check."""

    request_id: str = ""
    url: str = ""
    risk_score: int = 0
    is_phishing: bool = False
    is_malware: bool = False
    safe_browsing_threat: str = ""
    in_phishtank: bool = False
    spamhaus_dbl: bool = False
    domain_age_days: int = 0
    ssl_valid: bool = False
    ssl_issuer: str = ""
    signal_breakdown: dict[str, int] = field(default_factory=dict)
    error: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> URLResponse:
        if not isinstance(data, dict):
            return cls()
        return cls(
            request_id=data.get("request_id", ""),
            url=data.get("url", ""),
            risk_score=data.get("risk_score", 0),
            is_phishing=data.get("is_phishing", False),
            is_malware=data.get("is_malware", False),
            safe_browsing_threat=data.get("safe_browsing_threat", ""),
            in_phishtank=data.get("in_phishtank", False),
            spamhaus_dbl=data.get("spamhaus_dbl", False),
            domain_age_days=data.get("domain_age_days", 0),
            ssl_valid=data.get("ssl_valid", False),
            ssl_issuer=data.get("ssl_issuer", ""),
            signal_breakdown=data.get("signal_breakdown", {}),
            error=data.get("error"),
        )


@dataclass
class WHOISResponse:
    """Response from a WHOIS/RDAP lookup."""

    request_id: str = ""
    ip: str = ""
    network_cidr: str = ""
    network_name: str = ""
    org_name: str = ""
    abuse_contact: str = ""
    rir: str = ""
    allocation_date: str = ""
    country_code: str = ""
    asn: int = 0
    asn_org: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WHOISResponse:
        if not isinstance(data, dict):
            return cls()
        return cls(
            request_id=data.get("request_id", ""),
            ip=data.get("ip", ""),
            network_cidr=data.get("network_cidr", ""),
            network_name=data.get("network_name", ""),
            org_name=data.get("org_name", ""),
            abuse_contact=data.get("abuse_contact", ""),
            rir=data.get("rir", ""),
            allocation_date=data.get("allocation_date", ""),
            country_code=data.get("country_code", ""),
            asn=data.get("asn", 0),
            asn_org=data.get("asn_org", ""),
        )


@dataclass
class ReportResponse:
    """Response from a fraud report submission."""

    request_id: str = ""
    status: str = ""
    message: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReportResponse:
        if not isinstance(data, dict):
            return cls()
        return cls(
            request_id=data.get("request_id", ""),
            status=data.get("status", ""),
            message=data.get("message", ""),
        )


@dataclass
class AssessResponse:
    """Response from a unified multi-entity assessment."""

    request_id: str = ""
    overall_risk: int = 0
    ip: CheckResponse | None = None
    email: EmailResponse | None = None
    phone: PhoneResponse | None = None
    url: URLResponse | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssessResponse:
        if not isinstance(data, dict):
            return cls()
        ip_data = data.get("ip")
        email_data = data.get("email")
        phone_data = data.get("phone")
        url_data = data.get("url")
        return cls(
            request_id=data.get("request_id", ""),
            overall_risk=data.get("overall_risk", 0),
            ip=CheckResponse.from_dict(ip_data) if ip_data else None,
            email=EmailResponse.from_dict(email_data) if email_data else None,
            phone=PhoneResponse.from_dict(phone_data) if phone_data else None,
            url=URLResponse.from_dict(url_data) if url_data else None,
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
