from django.http import HttpResponse

response = HttpResponse("OK")

# ruleid: python.django.security.cwe-614.insecure-cookie
response.set_cookie("session_id", value=token, secure=False)

# ruleid: python.django.security.cwe-614.insecure-cookie
response.set_cookie("session_id", value=token, httponly=False)

# ruleid: python.django.security.cwe-614.insecure-cookie
SESSION_COOKIE_SECURE = False

# ruleid: python.django.security.cwe-614.insecure-cookie
CSRF_COOKIE_SECURE = False

# ok: python.django.security.cwe-614.insecure-cookie
response.set_cookie("session_id", value=token, secure=True, httponly=True)

# ok: python.django.security.cwe-614.insecure-cookie
SESSION_COOKIE_SECURE = True

# ok: python.django.security.cwe-614.insecure-cookie
SESSION_COOKIE_HTTPONLY = True
