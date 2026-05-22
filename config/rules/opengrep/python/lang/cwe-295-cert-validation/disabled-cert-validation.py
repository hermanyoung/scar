import requests
import httpx
import ssl
import urllib3

# ruleid: python.lang.security.cwe-295.disabled-cert-validation
response = requests.get("https://api.example.com", verify=False)

# ruleid: python.lang.security.cwe-295.disabled-cert-validation
response = requests.post("https://api.example.com/data", json=data, verify=False)

# ruleid: python.lang.security.cwe-295.disabled-cert-validation
client = httpx.Client(verify=False)

# ruleid: python.lang.security.cwe-295.disabled-cert-validation
client = httpx.AsyncClient(verify=False)

# ruleid: python.lang.security.cwe-295.disabled-cert-validation
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ruleid: python.lang.security.cwe-295.disabled-cert-validation
ctx = ssl._create_unverified_context()

# ok: python.lang.security.cwe-295.disabled-cert-validation
response = requests.get("https://api.example.com")

# ok: python.lang.security.cwe-295.disabled-cert-validation
response = requests.get("https://api.example.com", verify=True)

# ok: python.lang.security.cwe-295.disabled-cert-validation
response = requests.get("https://api.example.com", verify="/etc/ssl/certs/ca-bundle.crt")

# ok: python.lang.security.cwe-295.disabled-cert-validation
client = httpx.AsyncClient(verify=True)
