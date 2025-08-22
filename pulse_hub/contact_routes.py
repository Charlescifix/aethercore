"""
Contact page routes for AEGOCAP
Handles contact form submissions with validation and CSRF protection
"""
from fastapi import APIRouter, Request, Form, Depends, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import EmailStr, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
import re

from data_layer.init_db import get_db
from monitor_unit.audit_log import log_event
from monitor_unit.anomaly_guard import is_rate_limited
from middleware_layer.csrf_protection import get_csrf_token

templates = Jinja2Templates(directory="templates")
router = APIRouter(tags=["contact"])

print("[CONTACT] Contact routes module loaded")

@router.get("/contact", response_class=HTMLResponse)
async def contact_page(
    request: Request,
    success: str = Query(None),
    error: str = Query(None)
):
    """Display the contact form page"""
    print(f"\n[CONTACT] Contact page requested")
    
    return templates.TemplateResponse("contact.html", {
        "request": request,
        "success": success,
        "error": error,
        "csrf_token": get_csrf_token
    })

@router.post("/contact")
async def handle_contact_form(
    request: Request,
    name: str = Form(...),
    email: EmailStr = Form(...),
    phone: str = Form(...),
    note: str = Form(...),
    csrf_token: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    """Handle contact form submission"""
    print(f"\n[CONTACT] Form submission received")
    print(f"[CONTACT] Name: {name}")
    print(f"[CONTACT] Email: {email}")
    print(f"[CONTACT] Phone: {phone}")
    print(f"[CONTACT] Note length: {len(note)} chars")
    
    try:
        # Rate limiting check
        ip = request.client.host
        if is_rate_limited(ip, endpoint="contact", limit=5, window=3600):
            print(f"[CONTACT] ❌ Rate limited for IP: {ip}")
            return RedirectResponse("/contact?error=Too many submissions. Please wait before trying again.", status_code=303)
        
        # Validate inputs
        if len(name.strip()) < 2:
            print(f"[CONTACT] ❌ Invalid name length")
            return RedirectResponse("/contact?error=Please enter a valid name.", status_code=303)
        
        if len(note.strip()) < 10:
            print(f"[CONTACT] ❌ Note too short")
            return RedirectResponse("/contact?error=Please provide a more detailed message.", status_code=303)
        
        if len(note.strip()) > 1000:
            print(f"[CONTACT] ❌ Note too long")
            return RedirectResponse("/contact?error=Message is too long. Please keep it under 1000 characters.", status_code=303)
        
        # Validate phone number format
        clean_phone = re.sub(r'[^\d+\-\(\)\s]', '', phone)
        if len(re.sub(r'[^\d]', '', clean_phone)) < 10:
            print(f"[CONTACT] ❌ Invalid phone format")
            return RedirectResponse("/contact?error=Please enter a valid phone number.", status_code=303)
        
        # Clean inputs
        clean_name = name.strip()[:100]  # Limit name length
        clean_note = note.strip()[:1000]  # Limit note length
        
        # Security: Check for spam patterns
        spam_keywords = ['crypto', 'bitcoin', 'loan', 'investment opportunity', 'guaranteed returns']
        note_lower = clean_note.lower()
        if any(keyword in note_lower for keyword in spam_keywords):
            print(f"[CONTACT] ⚠️ Potential spam detected")
            # Don't block but flag for review
        
        # Log the contact attempt
        log_event(str(email), f"Contact form submission - Name: {clean_name}, Phone: {clean_phone}")
        
        # Here you would typically:
        # 1. Save to database
        # 2. Send email notification to admin
        # 3. Send auto-reply to user
        
        # For now, just log success
        print(f"[CONTACT] ✅ Contact form processed successfully")
        print(f"[CONTACT] Cleaned data - Name: {clean_name}, Email: {email}, Phone: {clean_phone}")
        
        # TODO: Implement email sending functionality
        # await send_contact_notification(clean_name, email, clean_phone, clean_note)
        # await send_auto_reply(email, clean_name)
        
        return RedirectResponse("/contact?success=true", status_code=303)
        
    except ValidationError as e:
        print(f"[CONTACT] ❌ Validation error: {e}")
        return RedirectResponse("/contact?error=Please check your email format.", status_code=303)
    
    except Exception as e:
        print(f"[CONTACT] ❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        return RedirectResponse("/contact?error=Something went wrong. Please try again later.", status_code=303)

print("[CONTACT] All contact routes loaded successfully")