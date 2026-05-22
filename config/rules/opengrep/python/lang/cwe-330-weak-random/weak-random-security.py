import random
import secrets
import os

# ruleid: python.lang.security.cwe-330.weak-random-security
token = random.random()

# ruleid: python.lang.security.cwe-330.weak-random-security
otp = random.randint(100000, 999999)

# ruleid: python.lang.security.cwe-330.weak-random-security
password_char = random.choice("abcdefghijklmnopqrstuvwxyz0123456789")

# ruleid: python.lang.security.cwe-330.weak-random-security
code = random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=6)

# ruleid: python.lang.security.cwe-330.weak-random-security
bits = random.getrandbits(128)

# ok: python.lang.security.cwe-330.weak-random-security
token = secrets.token_hex(32)

# ok: python.lang.security.cwe-330.weak-random-security
token = secrets.token_urlsafe(32)

# ok: python.lang.security.cwe-330.weak-random-security
password_char = secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789")

# ok: python.lang.security.cwe-330.weak-random-security
nonce = os.urandom(16)
