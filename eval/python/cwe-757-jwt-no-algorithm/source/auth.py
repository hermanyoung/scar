import jwt


def decode_token(token: str, secret: str) -> dict:
    return jwt.decode(token, secret)
