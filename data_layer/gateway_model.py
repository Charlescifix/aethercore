from sqlalchemy import Column, Integer, String, DateTime, Boolean, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from enum import Enum as PyEnum
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from fastapi import HTTPException

Base = declarative_base()


# Enum for roles
class UserRole(PyEnum):
    USER = "user"
    ADMIN = "admin"


# Enum for tracking onboarding steps
class OnboardingStep(PyEnum):
    NONE = "none"
    OVERVIEW = "overview"
    EXPECTATIONS = "expectations"
    AGREEMENTS = "agreements"
    PLAN_SELECTED = "plan_selected"
    DEPOSIT_REQUESTED = "deposit_requested"
    DEPOSIT_CONFIRMED = "deposit_confirmed"

# Enum for verification status
class VerificationStatus(PyEnum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    SUSPENDED = "SUSPENDED"



# Secure user table
class SecureUser(Base):
    __tablename__ = "secure_users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    hashed_pw = Column(String, nullable=False)
    phone = Column(String, nullable=False)
    dob = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    otp_secret = Column(String, nullable=True)


# Tracks the user's onboarding state and deposit-related details
class UserFlag(Base):
    __tablename__ = "user_flags"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, nullable=False, unique=True, index=True)
    current_step = Column(Enum(OnboardingStep), default=OnboardingStep.NONE)
    selected_plan = Column(String, nullable=True)  # JSON string for plan details
    tx_hash = Column(String, nullable=True)
    withdrawal_address = Column(String, nullable=True)
    payout_status = Column(String, default="Pending Review")
    contract_accepted = Column(Boolean, default=False)
    terms_accepted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    verification_status = Column(Enum(VerificationStatus), default=VerificationStatus.PENDING)
    deposit_amount = Column(String, nullable=True)  # Amount user claims to have sent
    verified_amount = Column(String, nullable=True)  # Amount admin confirms
    verified_at = Column(DateTime(timezone=True), nullable=True)
    verified_by = Column(String, nullable=True)  # Admin who verified
    rejection_reason = Column(String, nullable=True)  # If rejected


# ─────────────────────────────────────────
# Async Helper Functions
# ─────────────────────────────────────────

async def get_user_by_email(db: AsyncSession, email: str) -> SecureUser:
    """Get user by email asynchronously"""
    result = await db.execute(select(SecureUser).where(SecureUser.email == email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


async def get_or_create_user_flag(db: AsyncSession, email: str) -> UserFlag:
    """Get or create user flag entry"""
    result = await db.execute(select(UserFlag).where(UserFlag.email == email))
    user_flag = result.scalar_one_or_none()

    if not user_flag:
        # Verify user exists first
        user = await get_user_by_email(db, email)

        # Create new user flag
        user_flag = UserFlag(email=email)
        db.add(user_flag)
        await db.commit()
        await db.refresh(user_flag)

    return user_flag


async def update_user_flag(db: AsyncSession, email: str, **kwargs):
    """
    Update user flag fields

    Args:
        db: Database session
        email: User email
        **kwargs: Fields to update (current_step, selected_plan, tx_hash, etc.)
    """
    user_flag = await get_or_create_user_flag(db, email)

    # Update allowed fields only
    allowed_fields = {
        'current_step', 'selected_plan', 'tx_hash',
        'withdrawal_address', 'payout_status',
        'contract_accepted', 'terms_accepted',
        'verification_status', 'deposit_amount',  # Add these
        'verified_amount', 'verified_at', 'verified_by',
        'rejection_reason'
    }

    for key, value in kwargs.items():
        if key in allowed_fields:
            setattr(user_flag, key, value)

    # Update timestamp
    user_flag.updated_at = datetime.now()

    await db.commit()
    await db.refresh(user_flag)
    return user_flag


async def get_users_by_step(db: AsyncSession, step: OnboardingStep) -> list[UserFlag]:
    """Get all users at a specific onboarding step"""
    result = await db.execute(
        select(UserFlag).where(UserFlag.current_step == step)
    )
    return result.scalars().all()


async def check_user_progress(db: AsyncSession, email: str) -> dict:
    """Check user's onboarding progress"""
    user_flag = await get_or_create_user_flag(db, email)

    return {
        "email": email,
        "current_step": user_flag.current_step.value,
        "has_selected_plan": user_flag.selected_plan is not None,
        "has_submitted_deposit": user_flag.tx_hash is not None,
        "agreements_accepted": user_flag.contract_accepted and user_flag.terms_accepted,
        "payout_status": user_flag.payout_status
    }