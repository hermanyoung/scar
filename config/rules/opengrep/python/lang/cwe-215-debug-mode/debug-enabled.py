from flask import Flask
import uvicorn

app = Flask(__name__)

# ruleid: python.lang.security.cwe-215.debug-enabled
DEBUG = True

# ruleid: python.lang.security.cwe-215.debug-enabled
app.run(host="0.0.0.0", port=5000, debug=True)

# ruleid: python.lang.security.cwe-215.debug-enabled
app.debug = True

# ruleid: python.lang.security.cwe-215.debug-enabled
FLASK_DEBUG = True

# ruleid: python.lang.security.cwe-215.debug-enabled
uvicorn.run("main:app", host="0.0.0.0", reload=True)

# ok: python.lang.security.cwe-215.debug-enabled
DEBUG = False

# ok: python.lang.security.cwe-215.debug-enabled
app.run(host="0.0.0.0", port=5000)

# ok: python.lang.security.cwe-215.debug-enabled
app.debug = False

# ok: python.lang.security.cwe-215.debug-enabled
uvicorn.run("main:app", host="0.0.0.0", reload=False)
