"""Error handling example."""

from verifip import AuthenticationError, InvalidRequestError, RateLimitError, VerifIPClient, VerifIPError

client = VerifIPClient("vip_your_api_key_here", base_url="http://localhost:8080")

try:
    result = client.check("185.220.101.1")
    print(f"Score: {result.fraud_score}")

    # Check rate limit status
    if client.rate_limit:
        print(f"Requests remaining: {client.rate_limit.remaining}/{client.rate_limit.limit}")

except AuthenticationError:
    print("Invalid API key. Check your credentials.")

except RateLimitError as e:
    print(f"Rate limited. Retry after {e.retry_after} seconds.")

except InvalidRequestError as e:
    print(f"Bad request: {e}")

except VerifIPError as e:
    print(f"API error ({e.status_code}): {e}")
