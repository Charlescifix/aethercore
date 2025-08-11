import time

# Simple per-IP rate limiter state
RATE_LIMIT = {}

def is_rate_limited(ip: str, endpoint: str, limit: int = 5, window: int = 60) -> bool:
    """
    Basic rate limiter that allows `limit` requests per `window` seconds.
    """
    now = time.time()
    key = f"{ip}:{endpoint}"
    calls = RATE_LIMIT.get(key, [])

    # Remove expired timestamps
    calls = [ts for ts in calls if now - ts < window]
    calls.append(now)
    RATE_LIMIT[key] = calls

    return len(calls) > limit
