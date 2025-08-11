from fastapi import APIRouter, Request, Form, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from auth_control.session_utils import verify_session
from monitor_unit.audit_log import log_event
from data_layer.gateway_model import (
    SecureUser, UserFlag, OnboardingStep, VerificationStatus,
    get_or_create_user_flag, update_user_flag
)
from data_layer.init_db import get_db
import os, qrcode, io, base64
import json
import re
from datetime import datetime

templates = Jinja2Templates(directory="templates")
router = APIRouter(tags=["onboarding"])

print("[PREVIEW] Onboarding module loaded")


# ─────────────────────────────────────────────────────────────
# STEP 1: Overview of Business Model
# ─────────────────────────────────────────────────────────────
@router.get("/structure-glimpse", response_class=HTMLResponse)
async def overview_step(request: Request, email: str = Depends(verify_session), db: AsyncSession = Depends(get_db)):
    print(f"\n[ONBOARDING] Step 1 - Overview requested by: {email}")

    await update_user_flag(db, email, current_step=OnboardingStep.OVERVIEW)
    log_event(email, "Started onboarding - overview step")

    print(f"[ONBOARDING] ✅ Updated to OVERVIEW step")
    return templates.TemplateResponse("overview.html", {"request": request, "email": email})


# ─────────────────────────────────────────────────────────────
# STEP 2: Expectations & Disclaimers
# ─────────────────────────────────────────────────────────────
@router.get("/expectation-frame", response_class=HTMLResponse)
async def expectation_step(request: Request, email: str = Depends(verify_session), db: AsyncSession = Depends(get_db)):
    print(f"\n[ONBOARDING] Step 2 - Expectations requested by: {email}")

    user_flag = await get_or_create_user_flag(db, email)
    print(f"[ONBOARDING] Current step: {user_flag.current_step}")

    if user_flag.current_step != OnboardingStep.OVERVIEW:
        print(f"[ONBOARDING] ❌ Wrong step order, redirecting to overview")
        return RedirectResponse("/structure-glimpse", status_code=303)

    await update_user_flag(db, email, current_step=OnboardingStep.EXPECTATIONS)
    log_event(email, "Viewing expectations")

    print(f"[ONBOARDING] ✅ Updated to EXPECTATIONS step")
    return templates.TemplateResponse("expectations.html", {"request": request, "email": email})


# ─────────────────────────────────────────────────────────────
# STEP 3: Agreement Form
# ─────────────────────────────────────────────────────────────
@router.post("/accept-frame")
async def agreement_step(
        request: Request,
        agree_1: str = Form(None),
        agree_2: str = Form(None),
        email: str = Depends(verify_session),
        db: AsyncSession = Depends(get_db)
):
    print(f"\n[ONBOARDING] Step 3 - Agreement submission by: {email}")
    print(f"[ONBOARDING] Agreement 1: {agree_1}, Agreement 2: {agree_2}")

    user_flag = await get_or_create_user_flag(db, email)

    if user_flag.current_step != OnboardingStep.EXPECTATIONS:
        print(f"[ONBOARDING] ❌ Wrong step order")
        return RedirectResponse("/expectation-frame", status_code=303)

    if agree_1 != "on" or agree_2 != "on":
        print(f"[ONBOARDING] ❌ Agreements not accepted")
        return RedirectResponse("/expectation-frame?error=must_agree", status_code=303)

    await update_user_flag(
        db,
        email,
        current_step=OnboardingStep.AGREEMENTS,
        contract_accepted=True,
        terms_accepted=True
    )
    log_event(email, "Agreements accepted")

    print(f"[ONBOARDING] ✅ Agreements accepted, redirecting to plan selection")
    return RedirectResponse("/submit-plan", status_code=303)


# ─────────────────────────────────────────────────────────────
# STEP 4: Plan Selection
# ─────────────────────────────────────────────────────────────
@router.get("/submit-plan", response_class=HTMLResponse)
async def plan_selection_form(
        request: Request,
        email: str = Depends(verify_session),
        db: AsyncSession = Depends(get_db)
):
    print(f"\n[ONBOARDING] Step 4 - Plan selection form requested by: {email}")

    user_flag = await get_or_create_user_flag(db, email)

    if user_flag.current_step != OnboardingStep.AGREEMENTS:
        print(f"[ONBOARDING] ❌ Wrong step order")
        return RedirectResponse("/expectation-frame", status_code=303)

    return templates.TemplateResponse("plan_selection.html", {"request": request, "email": email})




@router.post("/submit-plan")
async def submit_plan(
        request: Request,
        amount_range: str = Form(...),
        return_rate: str = Form(...),
        duration: str = Form(...),
        email: str = Depends(verify_session),
        db: AsyncSession = Depends(get_db)
):
    print(f"\n[ONBOARDING] Plan submission by: {email}")
    print(f"[ONBOARDING] Plan details - Range: {amount_range}, Rate: {return_rate}, Duration: {duration}")

    user_flag = await get_or_create_user_flag(db, email)

    if user_flag.current_step != OnboardingStep.AGREEMENTS:
        print(f"[ONBOARDING] ❌ Wrong step order")
        return RedirectResponse("/expectation-frame", status_code=303)

    # Validate plan matrix
    plan_matrix = {
        "1000-4500": "5%",
        "4501-9000": "6%"
    }

    if amount_range not in plan_matrix or return_rate != plan_matrix[amount_range]:
        print(f"[ONBOARDING] ❌ Invalid plan combination")
        return RedirectResponse("/plan-choice?error=invalid_plan", status_code=303)

    if duration.lower() != "quarterly":
        print(f"[ONBOARDING] ❌ Invalid duration")
        return RedirectResponse("/plan-choice?error=invalid_duration", status_code=303)

    # Store plan as JSON string
    plan_data = json.dumps({
        "range": amount_range,
        "return": return_rate,
        "duration": duration
    })

    await update_user_flag(
        db,
        email,
        current_step=OnboardingStep.PLAN_SELECTED,
        selected_plan=plan_data
    )

    log_event(email, f"Plan selected: {amount_range}")

    print(f"[ONBOARDING] ✅ Plan selected, redirecting to deposit instructions")
    return RedirectResponse("/deposit-instructions", status_code=303)


# ─────────────────────────────────────────────────────────────
# STEP 5: Deposit Instructions + QR
# ─────────────────────────────────────────────────────────────
@router.get("/deposit-instructions", response_class=HTMLResponse)
async def deposit_page(
        request: Request,
        email: str = Depends(verify_session),
        db: AsyncSession = Depends(get_db)
):
    print(f"\n[ONBOARDING] Step 5 - Deposit instructions requested by: {email}")

    user_flag = await get_or_create_user_flag(db, email)

    if user_flag.current_step != OnboardingStep.PLAN_SELECTED:
        print(f"[ONBOARDING] ❌ Wrong step order")
        return RedirectResponse("/submit-plan", status_code=303)

    # Parse plan to show minimum amount
    min_amount = "1000"
    if user_flag.selected_plan:
        plan_data = json.loads(user_flag.selected_plan)
        if plan_data['range'] == "4501-9000":
            min_amount = "4501"

    wallet_address = os.getenv("USDT_WALLET_ADDRESS")
    print(f"[ONBOARDING] Using wallet address: {wallet_address}")

    # Generate QR code
    qr = qrcode.make(wallet_address)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_data = base64.b64encode(buf.getvalue()).decode("utf-8")
    qr_img = f"data:image/png;base64,{qr_data}"

    return templates.TemplateResponse("deposit_instructions.html", {
        "request": request,
        "email": email,
        "wallet_address": wallet_address,
        "qr_img": qr_img,
        "min_amount": min_amount
    })


# ─────────────────────────────────────────────────────────────
# STEP 6: Deposit Confirmation
# ─────────────────────────────────────────────────────────────
@router.get("/confirm-deposit", response_class=HTMLResponse)
async def confirm_deposit_form(
        request: Request,
        error: str = Query(None),
        email: str = Depends(verify_session),
        db: AsyncSession = Depends(get_db)
):
    print(f"\n[ONBOARDING] Step 6 - Deposit confirmation form requested by: {email}")
    print(f"[ONBOARDING] Error param: {error}")

    user_flag = await get_or_create_user_flag(db, email)

    if user_flag.current_step not in [OnboardingStep.PLAN_SELECTED, OnboardingStep.DEPOSIT_REQUESTED]:
        print(f"[ONBOARDING] ❌ Wrong step order")
        return RedirectResponse("/deposit-instructions", status_code=303)

    # Get minimum amount for their plan
    min_amount = "1000"
    if user_flag.selected_plan:
        plan_data = json.loads(user_flag.selected_plan)
        if plan_data['range'] == "4501-9000":
            min_amount = "4501"

    return templates.TemplateResponse("confirm_deposit.html", {
        "request": request,
        "email": email,
        "error": error,
        "min_amount": min_amount
    })


@router.post("/confirm-deposit")
async def handle_deposit_submission(
        request: Request,
        email: str = Depends(verify_session),
        db: AsyncSession = Depends(get_db)
):
    print(f"\n[DEPOSIT] Submission by: {email}")
    
    try:
        # Manually parse form data to avoid FastAPI validation errors
        form_data = await request.form()
        
        # Debug: Print all form keys and values
        print(f"[DEPOSIT] All form data keys: {list(form_data.keys())}")
        for key in form_data.keys():
            value = form_data.get(key, "")
            print(f"[DEPOSIT] Form field '{key}': '{value}' (length: {len(str(value))})")
        
        tx_hash = form_data.get("tx_hash", "").strip()
        withdrawal_address = form_data.get("withdrawal_address", "").strip()
        deposit_amount = form_data.get("deposit_amount", "").strip()
        
        print(f"[DEPOSIT] Processed data:")
        print(f"[DEPOSIT] - TX Hash: '{tx_hash}' (len: {len(tx_hash)})")
        print(f"[DEPOSIT] - Address: '{withdrawal_address}' (len: {len(withdrawal_address)})")
        print(f"[DEPOSIT] - Amount: '{deposit_amount}' (len: {len(deposit_amount)})")
        
        # Check for missing required fields
        if not tx_hash or not withdrawal_address or not deposit_amount:
            print(f"[DEPOSIT] ❌ Missing required fields")
            log_event(email, f"Deposit submission failed - missing fields: tx_hash={bool(tx_hash)}, address={bool(withdrawal_address)}, amount={bool(deposit_amount)}")
            return RedirectResponse("/confirm-deposit?error=missing_fields", status_code=303)
            
    except Exception as e:
        print(f"[DEPOSIT] ❌ Form parsing error: {e}")
        import traceback
        traceback.print_exc()
        log_event(email, "Deposit submission failed - form parsing error")
        return RedirectResponse("/confirm-deposit?error=system_error", status_code=303)
    
    print(f"[DEPOSIT] TX Hash: {tx_hash[:10]}...{tx_hash[-10:]}")
    print(f"[DEPOSIT] Withdrawal Address: {withdrawal_address[:10]}...{withdrawal_address[-10:]}")
    print(f"[DEPOSIT] Claimed Amount: ${deposit_amount}")

    # Security: Clean and validate inputs
    tx_hash = tx_hash.strip().upper()
    withdrawal_address = withdrawal_address.strip()

    # Validate amount
    try:
        amount_float = float(deposit_amount)
        if amount_float <= 0:
            print(f"[DEPOSIT] ❌ Invalid amount: {deposit_amount}")
            return RedirectResponse("/confirm-deposit?error=invalid_amount", status_code=303)
    except ValueError:
        print(f"[DEPOSIT] ❌ Non-numeric amount: {deposit_amount}")
        return RedirectResponse("/confirm-deposit?error=invalid_amount", status_code=303)

    # STRICT VALIDATION - TRON ONLY
    # Transaction hash: exactly 64 hexadecimal characters
    tx_pattern = re.compile(r'^[A-F0-9]{64}$')
    if not tx_pattern.match(tx_hash):
        print(f"[DEPOSIT] ❌ Invalid TX format - Length: {len(tx_hash)}")
        log_event(email, f"Invalid deposit attempt - bad TX format")
        return RedirectResponse("/confirm-deposit?error=invalid_tx", status_code=303)

    # TRON address: T followed by exactly 33 base58 characters (excludes 0OIl)
    address_pattern = re.compile(r'^T[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{33}$')
    if not address_pattern.match(withdrawal_address):
        print(f"[DEPOSIT] ❌ Invalid address format")
        log_event(email, f"Invalid deposit attempt - bad address format")
        return RedirectResponse("/confirm-deposit?error=invalid_address", status_code=303)

    # Additional security checks
    # 1. Check if TX hash already exists (prevent reuse)
    existing_tx = await db.execute(
        select(UserFlag).where(UserFlag.tx_hash == tx_hash)
    )
    if existing_tx.scalar_one_or_none():
        print(f"[DEPOSIT] ❌ TX hash already used")
        log_event(email, f"Duplicate TX hash attempt: {tx_hash[:10]}...")
        return RedirectResponse("/confirm-deposit?error=duplicate_tx", status_code=303)

    # 2. Rate limiting check
    from monitor_unit.anomaly_guard import is_rate_limited
    if is_rate_limited(request.client.host, endpoint="deposit", limit=3, window=3600):
        print(f"[DEPOSIT] ❌ Rate limited")
        log_event(email, "Rate limited on deposit submission")
        raise HTTPException(status_code=429, detail="Too many deposit attempts")

    # 3. Get user flag and check status
    user_flag = await get_or_create_user_flag(db, email)

    # Check if already has verified deposit
    if (user_flag.verification_status == VerificationStatus.VERIFIED and
            user_flag.tx_hash):
        print(f"[DEPOSIT] ❌ User already has verified deposit")
        log_event(email, "Attempted duplicate deposit after verification")
        return RedirectResponse("/vision-frame", status_code=303)

    # 4. Validate amount meets minimum for selected plan
    if user_flag.selected_plan:
        plan_data = json.loads(user_flag.selected_plan)
        amount_range = plan_data.get('range', '')

        if amount_range == "1000-4500" and amount_float < 1000:
            print(f"[DEPOSIT] ❌ Amount below minimum for plan: ${amount_float} < $1000")
            log_event(email, f"Deposit below minimum: ${amount_float}")
            return RedirectResponse("/confirm-deposit?error=below_minimum", status_code=303)
        elif amount_range == "4501-9000" and amount_float < 4501:
            print(f"[DEPOSIT] ❌ Amount below minimum for plan: ${amount_float} < $4501")
            log_event(email, f"Deposit below minimum: ${amount_float}")
            return RedirectResponse("/confirm-deposit?error=below_minimum", status_code=303)

    # All validations passed - save deposit for PENDING verification
    try:
        # CRITICAL: Set DEPOSIT_REQUESTED not DEPOSIT_CONFIRMED
        await update_user_flag(
            db,
            email,
            current_step=OnboardingStep.DEPOSIT_REQUESTED,  # NOT CONFIRMED!
            tx_hash=tx_hash,
            withdrawal_address=withdrawal_address,
            deposit_amount=str(amount_float),  # Store claimed amount
            verification_status=VerificationStatus.PENDING,  # Requires admin approval
            payout_status="Pending Verification"
        )

        # Log successful submission
        log_event(email,
                  f"Deposit submitted for verification - TX: {tx_hash[:10]}...{tx_hash[-10:]}, Amount: ${amount_float}")

        # TODO: Send admin notification
        # await notify_admin_new_deposit(email, tx_hash, amount_float)

        print(f"[DEPOSIT] ✅ Deposit submitted, pending admin verification")
        return RedirectResponse("/vision-frame", status_code=303)

    except Exception as e:
        print(f"[DEPOSIT] ❌ Database error: {str(e)}")
        await db.rollback()
        log_event(email, f"Deposit submission failed - DB error")
        return RedirectResponse("/confirm-deposit?error=system_error", status_code=303)