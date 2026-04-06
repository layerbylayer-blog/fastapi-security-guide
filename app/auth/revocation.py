# In-memory token blacklist — single process only.
# For multi-worker or multi-instance deployments, replace with a Redis-backed
# implementation using the same interface:
#
#   import redis
#   r = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
#
#   def revoke(jti: str, ttl_seconds: int) -> None:
#       r.setex(f"revoked:{jti}", ttl_seconds, "1")
#
#   def is_revoked(jti: str) -> bool:
#       return r.exists(f"revoked:{jti}") == 1

_revoked: set[str] = set()


def revoke(jti: str) -> None:
    """Add a token JTI to the revocation list."""
    _revoked.add(jti)


def is_revoked(jti: str) -> bool:
    """Return True if the token has been revoked."""
    return jti in _revoked


def clear() -> None:
    """Clear all revoked tokens — for testing only."""
    _revoked.clear()
