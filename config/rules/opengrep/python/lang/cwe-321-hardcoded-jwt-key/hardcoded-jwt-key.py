import os

import jwt

# ruleid: python.lang.security.cwe-321.hardcoded-jwt-key
token = jwt.encode(payload, "my-hardcoded-secret-key", algorithm="HS256")

# ok: python.lang.security.cwe-321.hardcoded-jwt-key
token = jwt.encode(payload, os.environ["JWT_SECRET"], algorithm="HS256")
