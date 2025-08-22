"""
CSRF Protection Middleware for FastAPI
Implements CSRF token validation for state-changing operations
"""
from fastapi import Request, HTTPException, Form
from fastapi.responses import JSONResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import os
from typing import Optional
import secrets

class CSRFProtection:
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or os.getenv("SESSION_SECRET", "unsafe-dev-key")
        self.serializer = URLSafeTimedSerializer(self.secret_key)
        self.token_name = "csrf_token"
        self.header_name = "X-CSRF-Token"
        
    def generate_csrf_token(self) -> str:
        """Generate a new CSRF token"""
        random_value = secrets.token_urlsafe(32)
        return self.serializer.dumps(random_value)
    
    def validate_csrf_token(self, token: str, max_age: int = 3600) -> bool:
        """Validate a CSRF token"""
        try:
            self.serializer.loads(token, max_age=max_age)
            return True
        except (BadSignature, SignatureExpired):
            return False
    
    def get_csrf_token_from_request(self, request: Request) -> Optional[str]:
        """Extract CSRF token from request (form data or header)"""
        # Try form data first
        if hasattr(request, '_form_data'):
            form_data = getattr(request, '_form_data', {})
            if self.token_name in form_data:
                return form_data[self.token_name]
        
        # Try headers
        return request.headers.get(self.header_name)
    
    async def validate_request(self, request: Request) -> bool:
        """Validate CSRF token for the request"""
        # Skip validation for safe HTTP methods
        if request.method in ["GET", "HEAD", "OPTIONS", "TRACE"]:
            return True
            
        # Skip validation for certain endpoints (like login forms that don't have session yet)
        safe_paths = ["/pulse-init", "/pulse-sync", "/admin/login"]  # Initial registration, login, and admin login
        if request.url.path in safe_paths:
            return True
            
        # Get CSRF token from request
        csrf_token = self.get_csrf_token_from_request(request)
        
        if not csrf_token:
            return False
            
        return self.validate_csrf_token(csrf_token)

# Global CSRF protection instance
csrf_protection = CSRFProtection()

async def csrf_middleware(request: Request, call_next):
    """CSRF middleware for FastAPI"""
    # Validate CSRF token for state-changing operations
    if not await csrf_protection.validate_request(request):
        # For AJAX requests, return JSON error
        if request.headers.get("content-type") == "application/json":
            return JSONResponse(
                status_code=403,
                content={"error": "CSRF token validation failed"}
            )
        # For form submissions, raise HTTP exception
        raise HTTPException(status_code=403, detail="CSRF token validation failed")
    
    response = await call_next(request)
    return response

def get_csrf_token() -> str:
    """Helper function to generate CSRF token for templates"""
    return csrf_protection.generate_csrf_token()

def csrf_token_dependency() -> str:
    """FastAPI dependency to inject CSRF token"""
    return csrf_protection.generate_csrf_token()