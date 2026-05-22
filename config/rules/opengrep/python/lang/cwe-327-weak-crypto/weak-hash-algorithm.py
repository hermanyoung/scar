import hashlib
import hmac

# ruleid: python.lang.security.cwe-327.weak-hash-algorithm
digest = hashlib.md5(password.encode()).hexdigest()

# ruleid: python.lang.security.cwe-327.weak-hash-algorithm
digest = hashlib.sha1(data).hexdigest()

# ruleid: python.lang.security.cwe-327.weak-hash-algorithm
digest = hashlib.new("md5", data).hexdigest()

# ruleid: python.lang.security.cwe-327.weak-hash-algorithm
mac = hmac.new(key, msg, digestmod=hashlib.md5)

# ok: python.lang.security.cwe-327.weak-hash-algorithm
digest = hashlib.sha256(data).hexdigest()

# ok: python.lang.security.cwe-327.weak-hash-algorithm
mac = hmac.new(key, msg, digestmod=hashlib.sha256)
