"""Tests for VerifIPClient."""

import json
import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from verifip import (
    AuthenticationError,
    InvalidRequestError,
    RateLimitError,
    ServerError,
    VerifIPClient,
)

SAMPLE_CHECK_RESPONSE = {
    "request_id": "test-uuid",
    "ip": "185.220.101.1",
    "fraud_score": 70,
    "is_proxy": True,
    "is_vpn": True,
    "is_tor": True,
    "is_datacenter": True,
    "country_code": "DE",
    "country_name": "Germany",
    "region": "Brandenburg",
    "city": "Brandenburg",
    "isp": "Stiftung Erneuerbare Freiheit",
    "asn": 60729,
    "connection_type": "Data Center",
    "hostname": "tor-exit.example.org",
    "signal_breakdown": {"tor_exit": 25, "vpn_detected": 20, "proxy_detected": 15, "datacenter_ip": 10},
}

SAMPLE_HEALTH_RESPONSE = {
    "status": "ok",
    "version": "1.0.0",
    "data_loaded_at": "2026-04-19T12:00:00Z",
    "redis": "ok",
    "postgres": "ok",
    "uptime_seconds": 3600,
}


def _mock_response(data: dict, status: int = 200, headers: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = json.dumps(data).encode()
    resp.status = status
    h = {"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "999", "X-RateLimit-Reset": "1713052800"}
    if headers:
        h.update(headers)
    resp.getheaders.return_value = list(h.items())
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _mock_http_error(data: dict, status: int, headers: dict | None = None) -> urllib.error.HTTPError:
    h = {"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1713052800"}
    if headers:
        h.update(headers)
    err = urllib.error.HTTPError(
        url="http://test",
        code=status,
        msg="Error",
        hdrs=h,
        fp=BytesIO(json.dumps(data).encode()),
    )
    return err


class TestCheck:
    @patch("verifip.client.urllib.request.urlopen")
    def test_check_success(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _mock_response(SAMPLE_CHECK_RESPONSE)
        client = VerifIPClient("vip_testkey", base_url="http://localhost:8080")
        result = client.check("185.220.101.1")

        assert result.fraud_score == 70
        assert result.is_tor is True
        assert result.is_vpn is True
        assert result.country_code == "DE"
        assert result.asn == 60729
        assert result.signal_breakdown["tor_exit"] == 25

    @patch("verifip.client.urllib.request.urlopen")
    def test_check_parses_rate_limit(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _mock_response(SAMPLE_CHECK_RESPONSE)
        client = VerifIPClient("vip_testkey", base_url="http://localhost:8080")
        client.check("8.8.8.8")

        assert client.rate_limit is not None
        assert client.rate_limit.limit == 1000
        assert client.rate_limit.remaining == 999

    def test_check_empty_ip_raises(self) -> None:
        client = VerifIPClient("vip_testkey")
        with pytest.raises(ValueError, match="ip is required"):
            client.check("")

    @patch("verifip.client.urllib.request.urlopen")
    def test_check_invalid_ip_raises(self, mock_urlopen: MagicMock) -> None:
        error_data = {"error": "invalid_ip", "message": "Invalid IP address"}
        mock_urlopen.side_effect = _mock_http_error(error_data, 400)
        client = VerifIPClient("vip_testkey", base_url="http://localhost:8080", max_retries=0)
        with pytest.raises(InvalidRequestError) as exc_info:
            client.check("not-an-ip")
        assert exc_info.value.status_code == 400

    @patch("verifip.client.urllib.request.urlopen")
    def test_check_auth_error(self, mock_urlopen: MagicMock) -> None:
        error_data = {"error": "invalid_api_key", "message": "Invalid API key"}
        mock_urlopen.side_effect = _mock_http_error(error_data, 401)
        client = VerifIPClient("vip_badkey", base_url="http://localhost:8080", max_retries=0)
        with pytest.raises(AuthenticationError):
            client.check("8.8.8.8")

    @patch("verifip.client.urllib.request.urlopen")
    def test_check_rate_limit_error(self, mock_urlopen: MagicMock) -> None:
        error_data = {"error": "rate_limit_exceeded", "message": "Limit exceeded", "retry_after": 3600}
        mock_urlopen.side_effect = _mock_http_error(error_data, 429)
        client = VerifIPClient("vip_testkey", base_url="http://localhost:8080", max_retries=0)
        with pytest.raises(RateLimitError) as exc_info:
            client.check("8.8.8.8")
        assert exc_info.value.retry_after == 3600

    @patch("verifip.client.urllib.request.urlopen")
    def test_check_server_error(self, mock_urlopen: MagicMock) -> None:
        error_data = {"error": "internal_error", "message": "Server error"}
        mock_urlopen.side_effect = _mock_http_error(error_data, 500)
        client = VerifIPClient("vip_testkey", base_url="http://localhost:8080", max_retries=0)
        with pytest.raises(ServerError):
            client.check("8.8.8.8")


class TestBatch:
    @patch("verifip.client.urllib.request.urlopen")
    def test_batch_success(self, mock_urlopen: MagicMock) -> None:
        batch_data = {"results": [SAMPLE_CHECK_RESPONSE, {**SAMPLE_CHECK_RESPONSE, "ip": "8.8.8.8", "fraud_score": 0}]}
        mock_urlopen.return_value = _mock_response(batch_data)
        client = VerifIPClient("vip_testkey", base_url="http://localhost:8080")
        result = client.check_batch(["185.220.101.1", "8.8.8.8"])

        assert len(result.results) == 2
        assert result.results[0].fraud_score == 70
        assert result.results[1].fraud_score == 0

    def test_batch_empty_raises(self) -> None:
        client = VerifIPClient("vip_testkey")
        with pytest.raises(ValueError, match="cannot be empty"):
            client.check_batch([])

    def test_batch_over_100_raises(self) -> None:
        client = VerifIPClient("vip_testkey")
        with pytest.raises(ValueError, match="Maximum 100"):
            client.check_batch([f"1.2.3.{i}" for i in range(101)])


class TestHealth:
    @patch("verifip.client.urllib.request.urlopen")
    def test_health_success(self, mock_urlopen: MagicMock) -> None:
        mock_urlopen.return_value = _mock_response(SAMPLE_HEALTH_RESPONSE)
        client = VerifIPClient("vip_testkey", base_url="http://localhost:8080")
        result = client.health()

        assert result.status == "ok"
        assert result.version == "1.0.0"
        assert result.uptime_seconds == 3600


class TestClientInit:
    def test_empty_api_key_raises(self) -> None:
        with pytest.raises(ValueError, match="api_key is required"):
            VerifIPClient("")

    def test_context_manager(self) -> None:
        with VerifIPClient("vip_testkey") as client:
            assert isinstance(client, VerifIPClient)

    def test_repr(self) -> None:
        client = VerifIPClient("vip_testkey", base_url="http://localhost:8080")
        assert "localhost:8080" in repr(client)
