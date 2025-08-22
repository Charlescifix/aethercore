from fastapi import (
    APIRouter, HTTPException, Request, Form, status, Depends, Query
)
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from pydantic import EmailStr, ValidationError
from itsdangerous import TimestampSigner, URLSafeTimedSerializer, BadSignature, SignatureExpired
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from datetime import datetime
import os

from data_layer.init_db import get_db
from data_layer.gateway_model import SecureUser, get_or_create_user_flag
from monitor_unit.audit_log import log_event
from monitor_unit.persistent_rate_limiter import is_rate_limited
from auth_control.otp_module import verify_otp, generate_otp_secret, get_otp_uri
import pyotp
import qrcode
import io
import base64

from auth_control.session_utils import verify_session

templates = Jinja2Templates(directory="templates")
router = APIRouter(tags=["auth"])

# ─────────────────────────────────────────
# Security Contexts
# ─────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
signer = TimestampSigner(os.getenv("SESSION_SECRET"))
serializer = URLSafeTimedSerializer(os.getenv("RESET_SECRET"))

print("[GATEWAY INIT] Authentication module loaded")
print("[GATEWAY INIT] Session secret configured")


# ─────────────────────────────────────────
# 🔐 REGISTER
# ─────────────────────────────────────────
@router.post("/pulse-init")
async def register_process(
        request: Request,
        email: EmailStr = Form(...),
        password: str = Form(...),
        confirm_password: str = Form(...),
        phone: str = Form(...),
        dob: str = Form(...),
        db: AsyncSession = Depends(get_db)
):
    print(f"\n[REGISTER] New registration attempt")
    print(f"[REGISTER] Email: {email}")
    print(f"[REGISTER] Phone: {phone}")
    print(f"[REGISTER] DOB: {dob}")
    print(f"[REGISTER] IP: {request.client.host}")

    # Check rate limiting
    ip = request.client.host
    if is_rate_limited(ip, endpoint="register", limit=3, window=3600):
        print(f"[REGISTER] ERROR: Rate limited")
        raise HTTPException(status_code=429, detail="Too many registration attempts")

    # Validate passwords
    if password != confirm_password:
        print(f"[REGISTER] ERROR: Passwords don't match")
        raise HTTPException(status_code=400, detail="Passwords do not match")

    if len(password) < 8 or not any(c.isdigit() for c in password):
        print(f"[REGISTER] ERROR: Weak password - length: {len(password)}, has digit: {any(c.isdigit() for c in password)}")
        raise HTTPException(status_code=400, detail="Weak password")

    # Check existing user
    print(f"[REGISTER] Checking if user exists...")
    existing = await db.execute(select(SecureUser).where(SecureUser.email == email))
    if existing.scalar_one_or_none():
        print(f"[REGISTER] User already exists: {email}")
        raise HTTPException(status_code=409, detail="Account already exists")

    # Validate DOB
    try:
        dob_date = datetime.strptime(dob, "%Y-%m-%d")
        age = (datetime.now() - dob_date).days / 365.25
        print(f"[REGISTER] User age: {age:.1f} years")
        if age < 18:
            print(f"[REGISTER] ERROR: User under 18")
            raise HTTPException(status_code=400, detail="Must be 18 or older")
    except ValueError:
        print(f"[REGISTER] ERROR: Invalid DOB format: {dob}")
        raise HTTPException(status_code=400, detail="DOB format must be YYYY-MM-DD")

    # Generate OTP secret
    otp_secret = generate_otp_secret()
    print(f"[REGISTER] Generated OTP secret successfully")

    # Hash password
    hashed_pw = pwd_context.hash(password)
    print(f"[REGISTER] Password hashed successfully")

    # Create user
    new_user = SecureUser(
        email=email,
        hashed_pw=hashed_pw,
        phone=phone,
        dob=dob,
        otp_secret=otp_secret
    )

    try:
        db.add(new_user)
        await db.commit()
        print(f"[REGISTER] User created in database successfully")
    except Exception as e:
        print(f"[REGISTER] Database error: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Registration failed")

    # Create temporary session for OTP setup
    temp_token = signer.sign(f"otp_setup:{email}").decode()
    request.session["otp_setup"] = temp_token
    print(f"[REGISTER] Created OTP setup session")

    log_event(email, "Account registered - pending OTP setup")

    print(f"[REGISTER] SUCCESS: Registration successful, redirecting to OTP setup")
    return RedirectResponse("/otp-setup", status_code=303)


# ─────────────────────────────────────────
# 🔐 OTP SETUP PAGE
# ─────────────────────────────────────────
@router.get("/otp-setup", response_class=HTMLResponse)
async def otp_setup_page(
        request: Request,
        error: str = Query(None),
        db: AsyncSession = Depends(get_db)
):
    """Show QR code for OTP setup after registration"""
    print(f"\n[OTP SETUP] Page requested")
    print(f"[OTP SETUP] Error param: {error}")

    # Check for OTP setup session
    otp_token = request.session.get("otp_setup")
    print(f"[OTP SETUP] Has session token: {bool(otp_token)}")

    if not otp_token:
        print(f"[OTP SETUP] ERROR: No setup session, redirecting to register")
        return RedirectResponse("/seed-link", status_code=303)

    try:
        payload = signer.unsign(otp_token, max_age=600).decode()  # 10 min expiry
        print(f"[OTP SETUP] Token payload: {payload[:20]}...")

        if not payload.startswith("otp_setup:"):
            print(f"[OTP SETUP] ERROR: Invalid token format")
            raise HTTPException(status_code=403, detail="Invalid setup token")

        email = payload.split("otp_setup:")[1]
        print(f"[OTP SETUP] Email from token: {email}")
    except SignatureExpired:
        print(f"[OTP SETUP] ERROR: Token expired")
        return RedirectResponse("/seed-link?error=session_expired", status_code=303)
    except Exception as e:
        print(f"[OTP SETUP] ERROR: Token error: {str(e)}")
        return RedirectResponse("/seed-link", status_code=303)

    # Get user
    print(f"[OTP SETUP] Fetching user from database...")
    result = await db.execute(select(SecureUser).where(SecureUser.email == email))
    user = result.scalar_one_or_none()

    if not user:
        print(f"[OTP SETUP] ERROR: User not found: {email}")
        return RedirectResponse("/seed-link", status_code=303)

    print(f"[OTP SETUP] SUCCESS: User found")

    # Generate provisioning URI and QR
    totp = pyotp.TOTP(user.otp_secret)
    otp_uri = totp.provisioning_uri(name=email, issuer_name="AEGOCAP Secure DeFi")
    print(f"[OTP SETUP] Generated OTP URI")

    # Generate QR code
    try:
        qr = qrcode.make(otp_uri)
        buf = io.BytesIO()
        qr.save(buf, format="PNG")
        qr_data = base64.b64encode(buf.getvalue()).decode("utf-8")
        qr_img = f"data:image/png;base64,{qr_data}"
        print(f"[OTP SETUP] SUCCESS: QR code generated successfully")
    except Exception as e:
        print(f"[OTP SETUP] ERROR: QR generation error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to generate QR code")

    return templates.TemplateResponse("otp_qr.html", {
        "request": request,
        "email": email,
        "qr_img": qr_img,
        "otp_secret": user.otp_secret,
        "error": error
    })


# ─────────────────────────────────────────
# 🔐 VERIFY OTP SETUP
# ─────────────────────────────────────────
@router.post("/verify-otp-setup")
async def verify_otp_setup(
        request: Request,
        otp_code: str = Form(...),
        db: AsyncSession = Depends(get_db)
):
    """Verify the OTP setup is working before allowing login"""
    print(f"\n[OTP VERIFY] Verification attempt")
    print(f"[OTP VERIFY] OTP code received: '{otp_code}'")

    # Check for OTP setup session
    otp_token = request.session.get("otp_setup")
    if not otp_token:
        print(f"[OTP VERIFY] ERROR: No setup session")
        raise HTTPException(status_code=403, detail="Setup session expired")

    try:
        payload = signer.unsign(otp_token, max_age=600).decode()
        email = payload.split("otp_setup:")[1]
        print(f"[OTP VERIFY] Email from session: {email}")
    except Exception as e:
        print(f"[OTP VERIFY] ERROR: Session token error: {str(e)}")
        raise HTTPException(status_code=403, detail="Invalid setup token")

    # Get user and verify OTP
    print(f"[OTP VERIFY] Fetching user...")
    result = await db.execute(select(SecureUser).where(SecureUser.email == email))
    user = result.scalar_one_or_none()

    if not user:
        print(f"[OTP VERIFY] ERROR: User not found")
        raise HTTPException(status_code=404, detail="User not found")

    # Validate OTP format
    import re
    if not re.match(r'^\d{6}$', otp_code.strip()):
        print(f"[OTP VERIFY] ERROR: Invalid OTP format")
        return RedirectResponse("/otp-setup?error=invalid_format", status_code=303)
    clean_otp = otp_code.strip()
    print(f"[OTP VERIFY] Cleaned OTP: '{clean_otp}'")

    # Verify OTP
    print(f"[OTP VERIFY] Verifying OTP...")
    if not verify_otp(user.otp_secret, clean_otp):
        print(f"[OTP VERIFY] ERROR: Invalid OTP code")
        # Get expected OTP for debug
        totp = pyotp.TOTP(user.otp_secret)
        print(f"[OTP VERIFY] OTP verification failed - timing mismatch")
        return RedirectResponse("/otp-setup?error=invalid_code", status_code=303)

    print(f"[OTP VERIFY] SUCCESS: OTP verified successfully")

    # Clear setup session
    request.session.pop("otp_setup", None)
    print(f"[OTP VERIFY] Cleared setup session")

    log_event(email, "OTP setup completed successfully")

    print(f"[OTP VERIFY] Redirecting to success page")
    return RedirectResponse("/otp-success", status_code=303)


# ─────────────────────────────────────────
# 🎉 OTP SUCCESS PAGE
# ─────────────────────────────────────────
@router.get("/otp-success", response_class=HTMLResponse)
async def otp_success_page(request: Request):
    """Display OTP setup success page"""
    print(f"\n[OTP SUCCESS] Success page requested")
    return templates.TemplateResponse("otp_success.html", {"request": request})


# ─────────────────────────────────────────
# 🔐 LOGIN
# ─────────────────────────────────────────
@router.post("/pulse-sync")
async def login_process(
        request: Request,
        email: EmailStr = Form(...),
        password: str = Form(...),
        otp: str = Form(...),
        db: AsyncSession = Depends(get_db)
):
    print(f"\n[LOGIN] Starting login for: {email}")
    print(f"[LOGIN] Password length: {len(password)}")
    print(f"[LOGIN] OTP received: '{otp}'")
    print(f"[LOGIN] IP: {request.client.host}")

    try:
        # Check rate limiting
        ip = request.client.host
        if is_rate_limited(ip, endpoint="login"):
            print(f"[LOGIN] ERROR: Rate limited")
            return RedirectResponse("/sync-form?error=rate_limited", status_code=303)

        # Find user
        print(f"[LOGIN] Looking up user in database...")
        query = await db.execute(select(SecureUser).where(SecureUser.email == email))
        user = query.scalar_one_or_none()

        if not user:
            print(f"[LOGIN] ERROR: User not found: {email}")
            log_event(email, "Login failed - user not found")
            return RedirectResponse("/sync-form?error=auth_failed", status_code=303)

        print(f"[LOGIN] SUCCESS: User found")

        # Verify password
        print(f"[LOGIN] Verifying password...")
        password_valid = pwd_context.verify(password, user.hashed_pw)
        print(f"[LOGIN] Password valid: {password_valid}")

        if not password_valid:
            print(f"[LOGIN] ERROR: Password verification failed")
            log_event(email, "Login failed - wrong password")
            return RedirectResponse("/sync-form?error=auth_failed", status_code=303)

        print(f"[LOGIN] SUCCESS: Password correct")

        # Validate OTP format
        import re
        if not re.match(r'^\d{6}$', otp.strip()):
            print(f"[LOGIN] ERROR: Invalid OTP format")
            return RedirectResponse("/sync-form?error=invalid_otp", status_code=303)
        clean_otp = otp.strip()
        print(f"[LOGIN] Cleaned OTP: '{clean_otp}'")

        # Get current expected OTP for debug
        totp = pyotp.TOTP(user.otp_secret)
        expected_otp = totp.now()
        print(f"[LOGIN] Verifying OTP timing")

        # Verify OTP
        print(f"[LOGIN] Verifying OTP...")
        otp_valid = verify_otp(user.otp_secret, clean_otp)
        print(f"[LOGIN] OTP valid: {otp_valid}")

        if not otp_valid:
            print(f"[LOGIN] ERROR: OTP verification failed")
            print(f"[LOGIN] OTP verification failed - timing mismatch")

            # Check time windows for debugging
            print(f"[LOGIN] Checking time windows:")
            for i in range(-2, 3):
                window_otp = totp.at(datetime.now().timestamp() + (i * 30))
                match = "MATCH" if window_otp == clean_otp else "NO_MATCH"
                print(f"[LOGIN]   Checking window {i:+d}")

            log_event(email, "Login failed - invalid OTP")
            return RedirectResponse("/sync-form?error=invalid_otp", status_code=303)

        # Login successful
        print(f"[LOGIN] SUCCESS: All checks passed - creating session")
        token = signer.sign(email).decode()
        request.session["user"] = token
        print(f"[LOGIN] Session created successfully")

        # Check onboarding status
        print(f"[LOGIN] Checking onboarding status...")
        user_flag = await get_or_create_user_flag(db, email)
        print(f"[LOGIN] Current onboarding step: {user_flag.current_step.value}")
        print(f"[LOGIN] Verification status: {user_flag.verification_status.value if hasattr(user_flag, 'verification_status') else 'N/A'}")

        log_event(email, "Login successful")

        # Import verification status here
        from data_layer.gateway_model import VerificationStatus, OnboardingStep
        
        # Redirect logic for different user states
        if (user_flag.current_step == OnboardingStep.DEPOSIT_CONFIRMED and 
            user_flag.verification_status == VerificationStatus.VERIFIED):
            # User is fully verified - go directly to dashboard
            print(f"[LOGIN] SUCCESS: Verified user - redirecting to dashboard")
            return RedirectResponse("/vision-frame", status_code=303)
        elif user_flag.current_step == OnboardingStep.NONE:
            # New user - start onboarding
            print(f"[LOGIN] SUCCESS: New user - redirecting to onboarding")
            return RedirectResponse("/structure-glimpse", status_code=303)
        else:
            # User in middle of onboarding or pending verification
            print(f"[LOGIN] SUCCESS: User in onboarding process - redirecting to dashboard for status check")
            return RedirectResponse("/vision-frame", status_code=303)

    except Exception as e:
        print(f"[LOGIN] ERROR: Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        log_event(email, f"Login error: {str(e)}")
        return RedirectResponse("/sync-form?error=server_error", status_code=303)


# ─────────────────────────────────────────
# 🔓 LOGOUT
# ─────────────────────────────────────────
@router.get("/pulse-clear")
async def logout_handler(request: Request):
    print(f"\n[LOGOUT] Logout requested")
    print(f"[LOGOUT] Had session: {bool(request.session.get('user'))}")

    request.session.clear()
    print(f"[LOGOUT] SUCCESS: Session cleared")

    return RedirectResponse("/", status_code=302)


# ─────────────────────────────────────────
# 🔁 PASSWORD RESET REQUEST
# ─────────────────────────────────────────
@router.get("/retrieve-access", response_class=HTMLResponse)
async def forgot_password_form(request: Request):
    print(f"\n[RESET] Password reset form requested")
    return templates.TemplateResponse("forgot_password.html", {"request": request})


@router.post("/retrieve-access")
async def send_reset_link(
        email: EmailStr = Form(...),
        db: AsyncSession = Depends(get_db)
):
    print(f"\n[RESET] Password reset requested for: {email}")

    result = await db.execute(select(SecureUser).where(SecureUser.email == email))
    user = result.scalar_one_or_none()

    if not user:
        print(f"[RESET] User not found: {email}")
    else:
        print(f"[RESET] SUCCESS: User found, generating token")
        token = serializer.dumps(email)
        reset_url = f"/reset-link?token={token}"
        print(f"[RESET] Reset URL: {reset_url}")
        log_event(email, "Password reset requested")

    # Always return same message for security
    return JSONResponse(content={"message": "If your account exists, a reset link has been sent."})


# ─────────────────────────────────────────
# 🔁 PASSWORD RESET FORM
# ─────────────────────────────────────────
@router.get("/reset-link", response_class=HTMLResponse)
async def show_reset_form(request: Request, token: str = Query(...)):
    print(f"\n[RESET] Reset form requested with token")

    try:
        email = serializer.loads(token, max_age=3600)
        print(f"[RESET] SUCCESS: Valid token for: {email}")
    except SignatureExpired:
        print(f"[RESET] ERROR: Token expired")
        return RedirectResponse("/sync-form?error=token_expired", status_code=303)
    except Exception as e:
        print(f"[RESET] ERROR: Invalid token: {str(e)}")
        return RedirectResponse("/sync-form", status_code=303)

    return templates.TemplateResponse("reset_password.html", {
        "request": request,
        "token": token
    })


# ─────────────────────────────────────────
# 🔁 PROCESS PASSWORD RESET
# ─────────────────────────────────────────
@router.post("/process-reset")
async def handle_reset_form(
        token: str = Form(...),
        new_password: str = Form(...),
        confirm_password: str = Form(...),
        db: AsyncSession = Depends(get_db)
):
    print(f"\n[RESET] Processing password reset")

    try:
        email = serializer.loads(token, max_age=3600)
        print(f"[RESET] Token valid for: {email}")
    except Exception as e:
        print(f"[RESET] ERROR: Token error: {str(e)}")
        raise HTTPException(status_code=403, detail="Invalid or expired reset token")

    # Validate passwords
    if new_password != confirm_password:
        print(f"[RESET] ERROR: Passwords don't match")
        raise HTTPException(status_code=400, detail="Passwords do not match")

    if len(new_password) < 8:
        print(f"[RESET] ERROR: Password too short: {len(new_password)}")
        raise HTTPException(status_code=400, detail="Password validation failed")

    # Find user
    print(f"[RESET] Looking up user...")
    result = await db.execute(select(SecureUser).where(SecureUser.email == email))
    user = result.scalar_one_or_none()

    if not user:
        print(f"[RESET] ERROR: User not found")
        raise HTTPException(status_code=404, detail="User not found")

    # Update password
    print(f"[RESET] Updating password...")
    user.hashed_pw = pwd_context.hash(new_password)
    await db.commit()

    print(f"[RESET] SUCCESS: Password updated successfully")
    log_event(email, "Password reset completed")

    return RedirectResponse("/pulse-confirm", status_code=303)


# ─────────────────────────────────────────
# 🧾 FORMS (Display Routes)
# ─────────────────────────────────────────
@router.get("/sync-form", response_class=HTMLResponse)
async def show_login_form(request: Request, error: str = Query(None)):
    print(f"\n[FORM] Login form requested")
    print(f"[FORM] Error param: {error}")
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error
    })


@router.get("/seed-link", response_class=HTMLResponse)
async def show_register_form(request: Request, error: str = Query(None)):
    print(f"\n[FORM] Register form requested")
    print(f"[FORM] Error param: {error}")
    return templates.TemplateResponse("register.html", {
        "request": request,
        "error": error
    })


@router.get("/pulse-confirm", response_class=HTMLResponse)
async def show_pulse_confirm(request: Request):
    print(f"\n[FORM] Pulse confirm page requested")
    return templates.TemplateResponse("pulse_confirm.html", {"request": request})


print("[GATEWAY INIT] All routes loaded successfully")