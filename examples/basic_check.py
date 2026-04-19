"""Basic IP check example."""

from verifip import VerifIPClient

client = VerifIPClient("vip_your_api_key_here", base_url="http://localhost:8080")

result = client.check("185.220.101.1")

print(f"IP:          {result.ip}")
print(f"Fraud Score: {result.fraud_score}/100")
print(f"Tor:         {result.is_tor}")
print(f"VPN:         {result.is_vpn}")
print(f"Proxy:       {result.is_proxy}")
print(f"Datacenter:  {result.is_datacenter}")
print(f"Country:     {result.country_name} ({result.country_code})")
print(f"ISP:         {result.isp} (AS{result.asn})")
print(f"Type:        {result.connection_type}")
print(f"Signals:     {result.signal_breakdown}")
