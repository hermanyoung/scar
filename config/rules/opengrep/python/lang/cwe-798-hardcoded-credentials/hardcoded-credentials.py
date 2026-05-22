import os

# ruleid: python.lang.security.cwe-798.hardcoded-credentials
password = "SuperSecret123!"

# ruleid: python.lang.security.cwe-798.hardcoded-credentials
API_KEY = "sk-proj-abc123def456ghi789"

# ruleid: python.lang.security.cwe-798.hardcoded-credentials
SECRET_KEY = "my-secret-key-do-not-share"

# ok: python.lang.security.cwe-798.hardcoded-credentials
password = os.environ.get("DB_PASSWORD")

# ok: python.lang.security.cwe-798.hardcoded-credentials
api_key = os.environ["API_KEY"]

# ok: python.lang.security.cwe-798.hardcoded-credentials
password = ""  # empty string is a valid default
