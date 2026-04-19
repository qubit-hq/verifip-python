# VerifIP Python SDK

Official Python SDK for the [VerifIP](https://verifip.com) IP fraud risk scoring API.

## Installation

```bash
pip install verifip
```

## Quick Start

```python
from verifip import VerifIPClient

client = VerifIPClient("vip_your_api_key")
result = client.check("185.220.101.1")

print(result.fraud_score)       # 70
print(result.is_tor)            # True
print(result.signal_breakdown)  # {"tor_exit": 25, "vpn_detected": 20, ...}
```

## Methods

### `check(ip: str) -> CheckResponse`

Check a single IPv4 or IPv6 address.

```python
result = client.check("185.220.101.1")

result.request_id       # UUID
result.ip               # "185.220.101.1"
result.fraud_score      # 0-100
result.is_proxy         # bool
result.is_vpn           # bool
result.is_tor           # bool
result.is_datacenter    # bool
result.country_code     # "DE"
result.country_name     # "Germany"
result.region           # "Brandenburg"
result.city             # "Brandenburg"
result.isp              # "Stiftung Erneuerbare Freiheit"
result.asn              # 60729
result.connection_type  # "Data Center"
result.hostname         # "tor-exit.example.org"
result.signal_breakdown # {"tor_exit": 25, ...}
```

### `check_batch(ips: list[str]) -> BatchResponse`

Check up to 100 IPs in a single request. Requires Starter plan or higher.

```python
batch = client.check_batch(["185.220.101.1", "8.8.8.8", "49.36.128.1"])
for result in batch.results:
    print(f"{result.ip}: score={result.fraud_score}")
```

Results with invalid IPs include an `error` field instead of raising.

### `health() -> HealthResponse`

Check API server health (no authentication required).

```python
health = client.health()
print(health.status)          # "ok" or "degraded"
print(health.uptime_seconds)  # 3600
```

## Error Handling

```python
from verifip import (
    VerifIPClient,
    VerifIPError,
    AuthenticationError,
    RateLimitError,
    InvalidRequestError,
)

try:
    result = client.check("1.2.3.4")
except AuthenticationError:
    # 401/403: invalid or disabled API key
    pass
except RateLimitError as e:
    # 429: daily limit exceeded
    print(f"Retry after {e.retry_after} seconds")
except InvalidRequestError:
    # 400: malformed or private IP
    pass
except VerifIPError as e:
    # Catch-all for any API error
    print(f"Error {e.status_code}: {e.error_code} - {e}")
```

## Rate Limits

Rate limit info is available after any authenticated request:

```python
result = client.check("8.8.8.8")
if client.rate_limit:
    print(f"{client.rate_limit.remaining}/{client.rate_limit.limit} requests left")
    print(f"Resets at {client.rate_limit.reset}")
```

## Configuration

```python
client = VerifIPClient(
    api_key="vip_your_key",
    base_url="https://api.verifip.com",  # default
    timeout=30.0,                         # seconds, default 30
    max_retries=3,                        # retries on 429/5xx, default 3
)
```

| Option | Default | Description |
|--------|---------|-------------|
| `api_key` | required | Your VerifIP API key |
| `base_url` | `https://api.verifip.com` | API base URL |
| `timeout` | `30.0` | Request timeout in seconds |
| `max_retries` | `3` | Max retries on 429/5xx with exponential backoff |

## Retry Behavior

The SDK automatically retries on HTTP 429 and 5xx errors with exponential backoff:
- Delay: `min(retry_after or 0.5 * 2^attempt, 30) + jitter`
- Respects `retry_after` from rate limit responses
- Connection errors are also retried

## Requirements

- Python 3.10+
- Zero runtime dependencies (uses `urllib` stdlib)
