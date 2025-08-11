from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import RedirectResponse

import os

# Centralized template engine
templates = Jinja2Templates(directory="templates")

# Secure router prefix (avoid exposing functionality)
router = APIRouter(tags=["root"])

@router.get("/", response_class=HTMLResponse)
async def secured_entry(request: Request):
    """
    Serves the secure landing page with buttons for:
    - Deposits
    - Dividends
    - Token Info
    - Login
    - Admin (hidden unless authorized)
    """
    # Placeholder for user session/role checks later
    return templates.TemplateResponse("home.html", {"request": request})

@router.get("/tokens", response_class=HTMLResponse)
async def token_page(request: Request):
    """
    Serves the AEGOCAP token information page with:
    - Token launch details
    - Waiting list signup
    - Benefits table
    - Investment opportunities
    """
    return templates.TemplateResponse("token.html", {"request": request})

@router.get("/who-we-are", response_class=HTMLResponse)
async def who_we_are_page(request: Request):
    """
    Serves the exclusive 'Who We Are' page with:
    - Elite group introduction
    - AI business portfolio
    - Global services overview
    - Invitation-only exclusivity
    """
    return templates.TemplateResponse("who_we_are.html", {"request": request})
