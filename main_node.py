# main_node.py

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.exceptions import RequestValidationError
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv
import os

# Secure .env variables
load_dotenv()

# Routers
from pulse_hub.routes_landing import router as landing_router
from pulse_hub.preview_stage import router as preview_router
from pulse_hub.routes_dashboard import router as dashboard_router
from pulse_hub.contact_routes import router as contact_router
from auth_control.gateway import router as auth_router
from auth_control.admin_control import router as admin_router

# Middleware
import middleware_layer
from middleware_layer.csrf_protection import csrf_middleware

# DB init
from data_layer.init_db import init_models

# ───────────────────────────────────────────────
# ✅ ASYNC LIFESPAN FOR DB INIT
# ───────────────────────────────────────────────
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_models()  # create tables on startup
    yield
    # You can add graceful shutdown logic here if needed

# ──────────────── FastAPI App ────────────────
app = FastAPI(
    title="AegoCap DeFi System",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan
)

# Global exception handler for form validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Check if this is a form submission to confirm-deposit
    if request.url.path == "/confirm-deposit" and request.method == "POST":
        print(f"[SECURITY] Form validation error on {request.url.path}: {exc.errors()}")
        return RedirectResponse("/confirm-deposit?error=missing_fields", status_code=303)
    
    # For other endpoints, let FastAPI handle it normally
    from fastapi.exception_handlers import request_validation_exception_handler
    return await request_validation_exception_handler(request, exc)

# ──────────────── Middleware Setup ────────────────
frontend_origin = os.getenv("FRONTEND_URL", "http://localhost:3000")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.middleware("http")(middleware_layer.security_headers)
app.middleware("http")(csrf_middleware)

app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "unsafe-dev-key"),
    same_site="strict",
    https_only=os.getenv("ENVIRONMENT") == "production",  # HTTPS in production
    max_age=3600 * 12
)

# ──────────────── Static Files & Templates ────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ──────────────── Register Routes ────────────────
app.include_router(landing_router)
app.include_router(preview_router)
app.include_router(dashboard_router)
app.include_router(contact_router)
app.include_router(auth_router)
app.include_router(admin_router)

@app.get("/")
def root():
    return {"status": "AegoCap Secure DeFi Platform is Online"}
