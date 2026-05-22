import requests
import httpx
import urllib.request

# ruleid: python.lang.security.cwe-918.ssrf-user-url
response = requests.get(user_url, timeout=10)

# ruleid: python.lang.security.cwe-918.ssrf-user-url
response = requests.post(user_url, json=data)

# ruleid: python.lang.security.cwe-918.ssrf-user-url
response = httpx.get(user_url)

# ruleid: python.lang.security.cwe-918.ssrf-user-url
data = urllib.request.urlopen(user_url)

# ruleid: python.lang.security.cwe-918.ssrf-user-url
client.get(user_url, headers=headers)

# ok: python.lang.security.cwe-918.ssrf-user-url
response = requests.get("https://api.example.com/data", timeout=10)

# ok: python.lang.security.cwe-918.ssrf-user-url
response = httpx.get("https://api.internal.com/health")
