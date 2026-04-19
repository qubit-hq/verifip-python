"""VerifIP API client."""

from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ._version import __version__
from .exceptions import (
    AuthenticationError,
    InvalidRequestError,
    RateLimitError,
    ServerError,
    VerifIPError,
)
from .models import BatchResponse, CheckResponse, HealthResponse, RateLimitInfo

_DEFAULT_BASE_URL = "https://api.verifip.com"
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_MAX_RETRIES = 3
_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class VerifIPClient:
    """Client for the VerifIP IP fraud scoring API.

    Args:
        api_key: Your VerifIP API key (starts with ``vip_``).
        base_url: API base URL. Defaults to ``https://api.verifip.com``.
        timeout: Request timeout in seconds. Defaults to 30.
        max_retries: Maximum retry attempts on 429/5xx. Defaults to 3.

    Example::

        client = VerifIPClient("vip_your_key")
        result = client.check("185.220.101.1")
        print(result.fraud_score)  # 70
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = _DEFAULT_TIMEOUT,
        max_retries: int = _DEFAULT_MAX_RETRIES,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries
        self._rate_limit: RateLimitInfo | None = None

    @property
    def rate_limit(self) -> RateLimitInfo | None:
        """Last observed rate limit info from the most recent API response."""
        return self._rate_limit

    def check(self, ip: str) -> CheckResponse:
        """Check a single IP address for fraud risk.

        Args:
            ip: IPv4 or IPv6 address to check.

        Returns:
            CheckResponse with fraud score, threat flags, geo data, and signal breakdown.

        Raises:
            InvalidRequestError: If the IP is malformed or reserved.
            AuthenticationError: If the API key is invalid or disabled.
            RateLimitError: If the daily limit is exceeded.
        """
        if not ip:
            raise ValueError("ip is required")
        data = self._request("GET", f"/v1/check?ip={urllib.parse.quote(ip, safe='')}")
        return CheckResponse.from_dict(data)

    def check_batch(self, ips: list[str]) -> BatchResponse:
        """Check multiple IP addresses in a single request.

        Requires Starter plan or higher. Maximum 100 IPs per request.

        Args:
            ips: List of IPv4/IPv6 addresses (1-100).

        Returns:
            BatchResponse containing a list of CheckResponse objects.
        """
        if not ips:
            raise ValueError("ips list is required and cannot be empty")
        if len(ips) > 100:
            raise ValueError("Maximum 100 IPs per batch request")
        body = json.dumps({"ips": ips}).encode()
        data = self._request("POST", "/v1/check/batch", body=body)
        return BatchResponse.from_dict(data)

    def health(self) -> HealthResponse:
        """Check API server health status. Does not require authentication."""
        data = self._request("GET", "/health", auth=False)
        return HealthResponse.from_dict(data)

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        auth: bool = True,
    ) -> dict[str, Any]:
        url = self._base_url + path
        last_error: Exception | None = None

        for attempt in range(self._max_retries + 1):
            req = urllib.request.Request(url, method=method, data=body)
            req.add_header("User-Agent", f"verifip-python/{__version__}")
            req.add_header("Accept", "application/json")
            if body is not None:
                req.add_header("Content-Type", "application/json")
            if auth:
                req.add_header("Authorization", f"Bearer {self._api_key}")

            try:
                resp = urllib.request.urlopen(req, timeout=self._timeout)
                resp_body = resp.read().decode()
                headers = {k: v for k, v in resp.getheaders()}
                self._update_rate_limit(headers)
                return json.loads(resp_body) if resp_body else {}

            except urllib.error.HTTPError as e:
                status = e.code
                resp_body = e.read().decode()
                headers = {k: v for k, v in e.headers.items()}
                self._update_rate_limit(headers)

                error_data = {}
                try:
                    error_data = json.loads(resp_body)
                except (json.JSONDecodeError, ValueError):
                    pass

                error_code = error_data.get("error", "")
                message = error_data.get("message", resp_body)
                retry_after = error_data.get("retry_after")

                err = _make_error(status, error_code, message, retry_after)

                if status in _RETRYABLE_STATUS_CODES and attempt < self._max_retries:
                    last_error = err
                    try:
                        delay = float(retry_after) if retry_after else 0.5 * (2 ** attempt)
                    except (TypeError, ValueError):
                        delay = 0.5 * (2 ** attempt)
                    delay = min(delay, 30)
                    delay += random.uniform(0, 0.25 * delay)
                    time.sleep(delay)
                    continue

                raise err

            except urllib.error.URLError as e:
                last_error = VerifIPError(
                    f"Connection error: {e.reason}",
                    status_code=0,
                    error_code="connection_error",
                )
                if attempt < self._max_retries:
                    time.sleep(0.5 * (2 ** attempt))
                    continue
                raise last_error from e

        raise last_error or VerifIPError("Request failed after retries")

    def _update_rate_limit(self, headers: dict[str, str]) -> None:
        info = RateLimitInfo.from_headers(headers)
        if info is not None:
            self._rate_limit = info

    def __enter__(self) -> VerifIPClient:
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def __repr__(self) -> str:
        return f"VerifIPClient(base_url={self._base_url!r})"


def _make_error(
    status: int, code: str, message: str, retry_after: int | None
) -> VerifIPError:
    kwargs = dict(status_code=status, error_code=code, retry_after=retry_after)
    if status == 400:
        return InvalidRequestError(message, **kwargs)
    if status in (401, 403):
        return AuthenticationError(message, **kwargs)
    if status == 429:
        return RateLimitError(message, **kwargs)
    if status >= 500:
        return ServerError(message, **kwargs)
    return VerifIPError(message, **kwargs)
