from flask import make_response

response = make_response("OK")

# ruleid: python.flask.security.cwe-614.insecure-cookie
response.set_cookie("session_id", value=token, secure=False)

# ruleid: python.flask.security.cwe-614.insecure-cookie
response.set_cookie("session_id", value=token, httponly=False)

# ruleid: python.flask.security.cwe-614.insecure-cookie
SESSION_COOKIE_SECURE = False

# ok: python.flask.security.cwe-614.insecure-cookie
response.set_cookie("session_id", value=token, secure=True, httponly=True)

# ok: python.flask.security.cwe-614.insecure-cookie
SESSION_COOKIE_SECURE = True
