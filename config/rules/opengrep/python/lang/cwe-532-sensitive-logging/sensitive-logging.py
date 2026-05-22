import logging

logger = logging.getLogger(__name__)

# ruleid: python.lang.security.cwe-532.sensitive-logging
logger.info("Login attempt", password=user_password)

# ruleid: python.lang.security.cwe-532.sensitive-logging
logger.debug("API call", token=bearer_token)

# ruleid: python.lang.security.cwe-532.sensitive-logging
logger.info("Config loaded", api_key=settings.api_key)

# ruleid: python.lang.security.cwe-532.sensitive-logging
logger.error(f"Auth failed for password={password}")

# ruleid: python.lang.security.cwe-532.sensitive-logging
print(f"Debug: token={auth_token}")

# ok: python.lang.security.cwe-532.sensitive-logging
logger.info("Login attempt", user_id=user.id)

# ok: python.lang.security.cwe-532.sensitive-logging
logger.info("Request completed", request_id=req_id, duration_ms=150)

# ok: python.lang.security.cwe-532.sensitive-logging
logger.error("Auth failed", user_id=user.id, error=str(e))
