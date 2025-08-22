"""
Persistent rate limiter using SQLite for state management
Replaces in-memory rate limiting to persist across restarts
"""
import sqlite3
import time
import os
from typing import Optional
import threading
from contextlib import contextmanager

class PersistentRateLimiter:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(os.getcwd(), "rate_limits.db")
        self._lock = threading.Lock()
        self._init_db()
    
    def _init_db(self):
        """Initialize the rate limiting database"""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rate_limits (
                    key TEXT PRIMARY KEY,
                    attempts INTEGER DEFAULT 0,
                    window_start REAL,
                    last_attempt REAL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_window_start 
                ON rate_limits(window_start)
            """)
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with proper cleanup"""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def is_rate_limited(self, identifier: str, endpoint: str, limit: int = 5, window: int = 60) -> bool:
        """
        Check if request should be rate limited
        Returns True if rate limited, False if allowed
        """
        key = f"{identifier}:{endpoint}"
        now = time.time()
        
        with self._lock:
            with self._get_connection() as conn:
                # Clean expired entries periodically
                self._cleanup_expired(conn, now)
                
                # Get current state
                cursor = conn.execute(
                    "SELECT attempts, window_start FROM rate_limits WHERE key = ?",
                    (key,)
                )
                row = cursor.fetchone()
                
                if row is None:
                    # First request
                    conn.execute(
                        "INSERT INTO rate_limits (key, attempts, window_start, last_attempt) VALUES (?, 1, ?, ?)",
                        (key, now, now)
                    )
                    return False
                
                attempts, window_start = row
                
                # Check if window has expired
                if now - window_start >= window:
                    # Start new window
                    conn.execute(
                        "UPDATE rate_limits SET attempts = 1, window_start = ?, last_attempt = ? WHERE key = ?",
                        (now, now, key)
                    )
                    return False
                
                # Window is active, check limit
                if attempts >= limit:
                    # Update last attempt time for logging
                    conn.execute(
                        "UPDATE rate_limits SET last_attempt = ? WHERE key = ?",
                        (now, key)
                    )
                    return True
                
                # Increment attempts
                conn.execute(
                    "UPDATE rate_limits SET attempts = attempts + 1, last_attempt = ? WHERE key = ?",
                    (now, key)
                )
                return False
    
    def _cleanup_expired(self, conn, now: float):
        """Remove expired rate limit entries"""
        # Clean entries older than 1 hour
        cleanup_threshold = now - 3600
        conn.execute(
            "DELETE FROM rate_limits WHERE window_start < ?",
            (cleanup_threshold,)
        )
    
    def reset_limits(self, identifier: str = None, endpoint: str = None):
        """Reset rate limits for specific identifier/endpoint or all"""
        with self._lock:
            with self._get_connection() as conn:
                if identifier and endpoint:
                    key = f"{identifier}:{endpoint}"
                    conn.execute("DELETE FROM rate_limits WHERE key = ?", (key,))
                elif identifier:
                    conn.execute("DELETE FROM rate_limits WHERE key LIKE ?", (f"{identifier}:%",))
                else:
                    conn.execute("DELETE FROM rate_limits")
    
    def get_status(self, identifier: str, endpoint: str) -> dict:
        """Get current rate limit status for debugging"""
        key = f"{identifier}:{endpoint}"
        
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT attempts, window_start, last_attempt FROM rate_limits WHERE key = ?",
                (key,)
            )
            row = cursor.fetchone()
            
            if row is None:
                return {"attempts": 0, "window_start": None, "last_attempt": None}
            
            attempts, window_start, last_attempt = row
            return {
                "attempts": attempts,
                "window_start": window_start,
                "last_attempt": last_attempt,
                "window_remaining": max(0, 60 - (time.time() - window_start))
            }

# Global instance
persistent_limiter = PersistentRateLimiter()

def is_rate_limited(ip: str, endpoint: str, limit: int = 5, window: int = 60) -> bool:
    """
    Persistent rate limiter that survives server restarts
    """
    return persistent_limiter.is_rate_limited(ip, endpoint, limit, window)

# Maintain backwards compatibility
def reset_rate_limits():
    """Reset all rate limits - for testing/admin use"""
    persistent_limiter.reset_limits()