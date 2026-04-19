"""Batch IP check example."""

from verifip import VerifIPClient

client = VerifIPClient("vip_your_api_key_here", base_url="http://localhost:8080")

batch = client.check_batch(["185.220.101.1", "8.8.8.8", "49.36.128.1"])

for result in batch.results:
    if result.error:
        print(f"{result.ip}: ERROR - {result.error}")
    else:
        risk = "LOW" if result.fraud_score <= 25 else "MODERATE" if result.fraud_score <= 50 else "HIGH" if result.fraud_score <= 75 else "CRITICAL"
        print(f"{result.ip}: score={result.fraud_score} ({risk}) country={result.country_code}")
