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

# ruleid: python.lang.security.cwe-918.ssrf-user-url
self.session.post(user_url, json=data)

# ruleid: python.lang.security.cwe-918.ssrf-user-url
response = requests.get(f"https://{user_host}/data", timeout=10)

# ruleid: python.lang.security.cwe-918.ssrf-user-url
response = requests.get("https://" + user_host, timeout=10)

# ok: python.lang.security.cwe-918.ssrf-user-url
response = requests.get("https://api.example.com/data", timeout=10)

# ok: python.lang.security.cwe-918.ssrf-user-url
response = httpx.get("https://api.internal.com/health")

# Dict lookups are not HTTP calls. The unconstrained $CLIENT receiver used to
# match all of these, which accounted for 477 of 538 findings in a self-scan.
# ok: python.lang.security.cwe-918.ssrf-user-url
detection = entry.get("detection", "sast")

# ok: python.lang.security.cwe-918.ssrf-user-url
pricing = self._pricing.get(resolved)

# ok: python.lang.security.cwe-918.ssrf-user-url
walk = entry.get("walk_direction")

# ok: python.lang.security.cwe-918.ssrf-user-url
value = os.environ.get(name, default)
