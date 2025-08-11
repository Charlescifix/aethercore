from fastapi import Request, HTTPException, status
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from typing import Final, Tuple
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# 🔐 Use a secure secret key from environment
SIGNING_SECRET: Final[str] = os.getenv("SESSION_SECRET", "unsafe-dev-key")
signer = TimestampSigner(SIGNING_SECRET)

# ⏱️ Token lifespan (1 day)
SESSION_TTL = 86400


def verify_session(request: Request) -> str:
    """
    Validates the session token and extracts user email.
    Only ensures that a valid session exists.
    """
    token = request.session.get("user")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please log in again."
        )

    try:
        email = signer.unsign(token, max_age=SESSION_TTL).decode()
        return email
    except SignatureExpired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please log in again."
        )
    except BadSignature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session token. Please log in again."
        )


def verify_admin_session(request: Request) -> str:
    """
    Validates session token and ensures the user has admin role.
    Assumes admin tokens are signed as "admin:<email>".
    """
    token = request.session.get("admin")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin session expired. Please log in again."
        )

    try:
        payload = signer.unsign(token, max_age=SESSION_TTL).decode()

        if not payload.startswith("admin:"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized as admin."
            )

        email = payload.split("admin:")[1]
        return email

    except SignatureExpired:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin session expired. Please log in again."
        )

    except BadSignature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin session token."
        )
