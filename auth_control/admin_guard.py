from fastapi import Request, HTTPException, status
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
from data_layer.init_db import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from data_layer.gateway_model import SecureUser
import os
from dotenv import load_dotenv

load_dotenv()

SIGNING_SECRET = os.getenv("SESSION_SECRET", "unsafe-dev-key")
signer = TimestampSigner(SIGNING_SECRET)
SESSION_TTL = 86400

async def verify_admin(request: Request, db: AsyncSession) -> str:
    """
    Validates admin session token and ensures the user has admin role.
    Uses the same approach as session_utils.py for consistency.
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
