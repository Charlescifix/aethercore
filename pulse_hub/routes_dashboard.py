from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from auth_control.session_utils import verify_session
from data_layer.gateway_model import UserFlag, OnboardingStep, VerificationStatus, get_or_create_user_flag
from data_layer.init_db import get_db
import json
from datetime import datetime

templates = Jinja2Templates(directory="templates")
router = APIRouter(tags=["dashboard"])

print("[DASHBOARD] Dashboard module loaded")


@router.get("/vision-frame", response_class=HTMLResponse)
async def dashboard_page(
        request: Request,
        email: str = Depends(verify_session),
        db: AsyncSession = Depends(get_db)
):
    """
    Show dashboard based on verification status
    """
    print(f"\n[DASHBOARD] Access attempt by: {email}")

    try:
        # Get or create user flag
        user_flag = await get_or_create_user_flag(db, email)
        print(f"[DASHBOARD] Current step: {user_flag.current_step}")
        print(
            f"[DASHBOARD] Verification status: {user_flag.verification_status if hasattr(user_flag, 'verification_status') else 'N/A'}")

        # PRIORITY CHECK: If user is VERIFIED, fix inconsistent step and show dashboard
        if user_flag.verification_status == VerificationStatus.VERIFIED:
            print(f"[DASHBOARD] ✅ User is VERIFIED - checking step consistency")
            
            # Auto-fix inconsistent database state
            if user_flag.current_step != OnboardingStep.DEPOSIT_CONFIRMED:
                print(f"[DASHBOARD] 🔧 Fixing inconsistent step: {user_flag.current_step.value} -> DEPOSIT_CONFIRMED")
                user_flag.current_step = OnboardingStep.DEPOSIT_CONFIRMED
                await db.commit()
            
            # Jump directly to verified user dashboard logic
            print(f"[DASHBOARD] ✅ Verified user accessing dashboard - user is fully approved")

            # Parse plan data - will be overridden by correct plan based on amount

            # Calculate investment metrics based on actual plan tiers
            verified_amount = float(user_flag.verified_amount or 5000)
            
            # Determine correct return rate based on deposit amount
            if verified_amount <= 4500:
                return_rate = 0.05  # 5% monthly for Starter Plan ($1,000 - $4,500)
                plan_name = "Starter Plan"
            else:
                return_rate = 0.06  # 6% monthly for Premium Plan ($4,501 - $9,000)
                plan_name = "Premium Plan"
                
            monthly_return = verified_amount * return_rate

            # Calculate next payout date (quarterly) - using timezone-naive approach for simplicity
            from datetime import datetime, timedelta
            
            # Use timezone-naive datetime throughout for consistency
            current_time = datetime.now()
            
            if user_flag.verified_at:
                # Convert verified_at to timezone-naive if it's timezone-aware
                if hasattr(user_flag.verified_at, 'tzinfo') and user_flag.verified_at.tzinfo is not None:
                    verified_at = user_flag.verified_at.replace(tzinfo=None)
                else:
                    verified_at = user_flag.verified_at
                next_payout_date = verified_at + timedelta(days=90)  # 3 months
            else:
                # Default to 90 days from now if no verification date
                next_payout_date = current_time + timedelta(days=90)
            
            # Calculate days remaining safely
            try:
                if next_payout_date > current_time:
                    days_remaining = (next_payout_date - current_time).days
                else:
                    days_remaining = 0
            except Exception as e:
                print(f"[DASHBOARD] Warning: Date calculation error: {e}")
                days_remaining = 75  # Default fallback
            
            return templates.TemplateResponse("dashboard.html", {
                "request": request,
                "email": email,
                "plan": plan_name,
                "tx_hash": user_flag.tx_hash if user_flag.tx_hash else "N/A",
                "withdrawal": user_flag.withdrawal_address or "N/A",
                "payout_status": user_flag.payout_status or "Scheduled",
                "verified_amount": f"${verified_amount:,.2f}",
                "monthly_return": f"${monthly_return:,.2f}",
                "return_rate": f"{return_rate*100:.0f}%",
                "verified_date": user_flag.verified_at.strftime("%b %d, %Y") if user_flag.verified_at else "Jan 21, 2025",
                "next_payout": next_payout_date.strftime("%b %d, %Y"),
                "days_remaining": days_remaining
            })

        # Case 1: User hasn't started onboarding
        if user_flag.current_step == OnboardingStep.NONE:
            print(f"[DASHBOARD] ❌ No onboarding started, redirecting")
            return RedirectResponse("/structure-glimpse", status_code=303)

        # Case 2: User is in middle of onboarding (before deposit)
        if user_flag.current_step in [OnboardingStep.OVERVIEW, OnboardingStep.EXPECTATIONS,
                                      OnboardingStep.AGREEMENTS, OnboardingStep.PLAN_SELECTED]:
            print(f"[DASHBOARD] ❌ Onboarding incomplete, redirecting")
            # Redirect to appropriate step
            redirect_map = {
                OnboardingStep.OVERVIEW: "/expectation-frame",
                OnboardingStep.EXPECTATIONS: "/expectation-frame",
                OnboardingStep.AGREEMENTS: "/submit-plan",
                OnboardingStep.PLAN_SELECTED: "/deposit-instructions"
            }
            return RedirectResponse(redirect_map.get(user_flag.current_step, "/structure-glimpse"), status_code=303)

        # Case 3: Deposit submitted but NOT verified (CRITICAL CHECK)
        if (user_flag.current_step == OnboardingStep.DEPOSIT_REQUESTED and
                user_flag.verification_status == VerificationStatus.PENDING):
            print(f"[DASHBOARD] ⏳ Deposit pending verification")

            # Calculate time since submission
            deposit_time = user_flag.updated_at or datetime.now()

            return templates.TemplateResponse("dashboard_incomplete.html", {
                "request": request,
                "email": email,
                "deposit_id": f"DEP{user_flag.id:06d}",
                "amount": f"${user_flag.deposit_amount}" if user_flag.deposit_amount else "Pending",
                "submitted_time": deposit_time.strftime("%Y-%m-%d %H:%M"),
                "est_completion": "1-6 hours",
                "tx_hash": user_flag.tx_hash[:10] + "..." + user_flag.tx_hash[-10:] if user_flag.tx_hash else "N/A"
            })

        # Case 4: Deposit was rejected
        if user_flag.verification_status == VerificationStatus.REJECTED:
            print(f"[DASHBOARD] ❌ Deposit rejected")

            # Create deposit_rejected.html or show error
            return templates.TemplateResponse("deposit_rejected.html", {
                "request": request,
                "email": email,
                "reason": user_flag.rejection_reason or "Please contact support for details",
                "support_email": "support@aegocap.com"
            })

        # Case 5: This case is now handled by the priority VERIFIED check above
        # Keeping this comment for reference - verified users are handled at the top

        # Case 6: User somehow has DEPOSIT_CONFIRMED but not verified (data inconsistency)
        if user_flag.current_step == OnboardingStep.DEPOSIT_CONFIRMED:
            print(f"[DASHBOARD] ⚠️ Data inconsistency - DEPOSIT_CONFIRMED but not verified")
            # Fix the inconsistency
            user_flag.current_step = OnboardingStep.DEPOSIT_REQUESTED
            user_flag.verification_status = VerificationStatus.PENDING
            await db.commit()

            return RedirectResponse("/vision-frame", status_code=303)

        # Default: redirect to start
        print(f"[DASHBOARD] ❓ Unexpected state, redirecting to start")
        return RedirectResponse("/structure-glimpse", status_code=303)

    except HTTPException as e:
        # If session is invalid, redirect to login
        if e.status_code == 401:
            print(f"[DASHBOARD] ❌ Session invalid")
            return RedirectResponse("/sync-form?session=expired", status_code=303)
        raise e
    except Exception as e:
        print(f"[DASHBOARD] ❌ Error: {str(e)}")
        # Log the error and redirect to login
        from monitor_unit.audit_log import log_event
        log_event(email, f"Dashboard error: {str(e)}")
        return RedirectResponse("/sync-form?error=1", status_code=303)