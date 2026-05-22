from flask import Flask
from flask_cors import CORS
from fastapi.middleware.cors import CORSMiddleware

app = Flask(__name__)

# ruleid: python.lang.security.cwe-942.permissive-cors
CORS(app, origins="*")

# ruleid: python.lang.security.cwe-942.permissive-cors
CORS_ORIGIN_ALLOW_ALL = True

# ruleid: python.lang.security.cwe-942.permissive-cors
CORS_ALLOW_ALL_ORIGINS = True

# ruleid: python.lang.security.cwe-942.permissive-cors
CORS_ALLOWED_ORIGINS = ["*"]

# ruleid: python.lang.security.cwe-942.permissive-cors
response.headers["Access-Control-Allow-Origin"] = "*"

# ok: python.lang.security.cwe-942.permissive-cors
CORS(app, origins="https://myapp.example.com")

# ok: python.lang.security.cwe-942.permissive-cors
CORS_ALLOWED_ORIGINS = ["https://myapp.example.com", "https://admin.example.com"]

# ok: python.lang.security.cwe-942.permissive-cors
CORS_ORIGIN_ALLOW_ALL = False

# ok: python.lang.security.cwe-942.permissive-cors
response.headers["Access-Control-Allow-Origin"] = "https://myapp.example.com"
