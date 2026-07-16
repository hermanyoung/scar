import jwt

# ruleid: python.lang.security.cwe-757.jwt-no-algorithm
data = jwt.decode(token, secret)

# ok: python.lang.security.cwe-757.jwt-no-algorithm
data = jwt.decode(token, secret, algorithms=["HS256"])
