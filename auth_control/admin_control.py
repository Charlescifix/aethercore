from fastapi import APIRouter, Request, Form, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc
from passlib.context import CryptContext
from datetime import datetime
import os

from data_layer.init_db import get_db
from data_layer.gateway_model import SecureUser, UserFlag, VerificationStatus, OnboardingStep
from monitor_unit.audit_log import log_event

templates = Jinja2Templates(directory="templates")
router = APIRouter(tags=["admin"], prefix="/admin")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

print("[ADMIN] Admin control module loaded")

# Secure admin authentication check
async def verify_admin_session(request: Request):
    """Verify admin is logged in with signature validation"""
    from itsdangerous import TimestampSigner, BadSignature, SignatureExpired
    import os
    
    admin_token = request.session.get("admin_user")
    if not admin_token:
        raise HTTPException(status_code=401, detail="Admin not authenticated")
    
    # Verify signed session token
    signer = TimestampSigner(os.getenv("SESSION_SECRET"))
    try:
        verified_admin = signer.unsign(admin_token, max_age=3600).decode()
        return verified_admin
    except (BadSignature, SignatureExpired):
        request.session.clear()
        raise HTTPException(status_code=401, detail="Invalid admin session")

# ─────────────────────────────────────────
# ADMIN LOGIN
# ─────────────────────────────────────────
@router.get("/login", response_class=HTMLResponse)
async def admin_login_form(request: Request):
    """Show admin login form"""
    print(f"\n[ADMIN] Login form requested")
    return templates.TemplateResponse("admin_login.html", {"request": request})

@router.post("/login")
async def admin_login_process(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    """Process admin login"""
    print(f"\n[ADMIN] Login attempt by: {username}")
    
    # Get admin credentials from environment
    admin_username = os.getenv("ADMIN_USERNAME", "admin")
    admin_password_hash = os.getenv("ADMIN_PASSWORD_HASH")
    
    if not admin_password_hash:
        raise HTTPException(status_code=500, detail="Admin not configured")
    
    # Verify credentials
    if username != admin_username:
        print(f"[ADMIN] ❌ Wrong username: {username}")
        return RedirectResponse("/admin/login?error=invalid_credentials", status_code=303)
    
    if not pwd_context.verify(password, admin_password_hash):
        print(f"[ADMIN] ❌ Wrong password")
        log_event("admin", "Failed admin login attempt")
        return RedirectResponse("/admin/login?error=invalid_credentials", status_code=303)
    
    # Set signed admin session
    from itsdangerous import TimestampSigner
    signer = TimestampSigner(os.getenv("SESSION_SECRET"))
    signed_token = signer.sign(admin_username).decode()
    request.session["admin_user"] = signed_token
    print(f"[ADMIN] ✅ Login successful")
    log_event("admin", "Admin logged in")
    
    return RedirectResponse("/admin/dashboard", status_code=303)

# ─────────────────────────────────────────
# ADMIN DASHBOARD
# ─────────────────────────────────────────
@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    admin: str = Depends(verify_admin_session),
    db: AsyncSession = Depends(get_db)
):
    """Admin dashboard with pending deposits"""
    print(f"\n[ADMIN] Dashboard requested")
    
    # Get pending deposits
    pending_query = await db.execute(
        select(UserFlag)
        .join(SecureUser, UserFlag.email == SecureUser.email)
        .where(UserFlag.verification_status == VerificationStatus.PENDING)
        .where(UserFlag.tx_hash.isnot(None))
        .order_by(desc(UserFlag.updated_at))
    )
    pending_deposits = pending_query.scalars().all()
    
    # Get user details for each deposit
    deposit_data = []
    for flag in pending_deposits:
        user_query = await db.execute(
            select(SecureUser).where(SecureUser.email == flag.email)
        )
        user = user_query.scalar_one_or_none()
        
        if user:
            deposit_data.append({
                "user_id": user.id,
                "email": user.email,
                "amount": flag.deposit_amount,
                "tx_hash": flag.tx_hash,
                "withdrawal_address": flag.withdrawal_address,
                "submitted_at": flag.updated_at,
                "plan": flag.selected_plan
            })
    
    # Get statistics
    from sqlalchemy import func
    stats_query = await db.execute(
        select(UserFlag.verification_status, func.count(UserFlag.id))
        .group_by(UserFlag.verification_status)
    )
    stats = dict(stats_query.all())
    
    return templates.TemplateResponse("admin_dashboard.html", {
        "request": request,
        "admin": admin,
        "pending_deposits": deposit_data,
        "stats": {
            "pending": stats.get(VerificationStatus.PENDING, 0),
            "verified": stats.get(VerificationStatus.VERIFIED, 0),
            "rejected": stats.get(VerificationStatus.REJECTED, 0)
        }
    })

# ─────────────────────────────────────────
# APPROVE/REJECT DEPOSITS
# ─────────────────────────────────────────
@router.post("/approve-deposit")
async def approve_deposit(
    request: Request,
    user_id: int = Form(...),
    verified_amount: float = Form(...),
    admin: str = Depends(verify_admin_session),
    db: AsyncSession = Depends(get_db)
):
    """Approve a deposit"""
    print(f"\n[ADMIN] Approving deposit for user_id: {user_id}")
    
    # Get user and flag
    user_query = await db.execute(select(SecureUser).where(SecureUser.id == user_id))
    user = user_query.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    flag_query = await db.execute(select(UserFlag).where(UserFlag.email == user.email))
    user_flag = flag_query.scalar_one_or_none()
    
    if not user_flag:
        raise HTTPException(status_code=404, detail="User flag not found")
    
    # Update verification status
    user_flag.verification_status = VerificationStatus.VERIFIED
    user_flag.current_step = OnboardingStep.DEPOSIT_CONFIRMED
    user_flag.verified_amount = str(verified_amount)
    user_flag.verified_at = datetime.now()
    user_flag.payout_status = "Active"
    
    await db.commit()
    
    log_event(user.email, f"Deposit approved by admin - Amount: ${verified_amount}")
    print(f"[ADMIN] ✅ Deposit approved for {user.email}")
    
    return RedirectResponse("/admin/dashboard?success=approved", status_code=303)

@router.post("/reject-deposit")
async def reject_deposit(
    request: Request,
    user_id: int = Form(...),
    rejection_reason: str = Form(...),
    admin: str = Depends(verify_admin_session),
    db: AsyncSession = Depends(get_db)
):
    """Reject a deposit"""
    print(f"\n[ADMIN] Rejecting deposit for user_id: {user_id}")
    
    # Get user and flag
    user_query = await db.execute(select(SecureUser).where(SecureUser.id == user_id))
    user = user_query.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    flag_query = await db.execute(select(UserFlag).where(UserFlag.email == user.email))
    user_flag = flag_query.scalar_one_or_none()
    
    if not user_flag:
        raise HTTPException(status_code=404, detail="User flag not found")
    
    # Update verification status
    user_flag.verification_status = VerificationStatus.REJECTED
    user_flag.rejection_reason = rejection_reason
    user_flag.payout_status = "Rejected"
    
    await db.commit()
    
    log_event(user.email, f"Deposit rejected by admin - Reason: {rejection_reason}")
    print(f"[ADMIN] ❌ Deposit rejected for {user.email}")
    
    return RedirectResponse("/admin/dashboard?success=rejected", status_code=303)

# ─────────────────────────────────────────
# ADMIN LOGOUT
# ─────────────────────────────────────────
@router.get("/logout")
async def admin_logout(request: Request):
    """Admin logout"""
    print(f"\n[ADMIN] Logout requested")
    request.session.clear()
    log_event("admin", "Admin logged out")
    return RedirectResponse("/admin/login?message=logged_out", status_code=303)

print("[ADMIN] All admin routes loaded")