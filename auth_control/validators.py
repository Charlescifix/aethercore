"""
FastAPI Pydantic validators for comprehensive input validation
Provides secure validation models for all user inputs
"""
from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional
import re
from datetime import datetime, date

class UserRegistrationModel(BaseModel):
    """Validation model for user registration"""
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=8, max_length=128, description="Password (8-128 chars)")
    confirm_password: str = Field(..., min_length=8, max_length=128, description="Password confirmation")
    phone: str = Field(..., min_length=10, max_length=20, description="Phone number")
    dob: str = Field(..., description="Date of birth (YYYY-MM-DD)")
    
    @validator('password')
    def validate_password_strength(cls, v):
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        return v
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        """Validate password confirmation matches"""
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v
    
    @validator('phone')
    def validate_phone(cls, v):
        """Validate phone number format"""
        # Remove all non-digit characters
        clean_phone = re.sub(r'[^\d]', '', v)
        if len(clean_phone) < 10 or len(clean_phone) > 15:
            raise ValueError('Invalid phone number format')
        return clean_phone
    
    @validator('dob')
    def validate_dob(cls, v):
        """Validate date of birth and age"""
        try:
            dob_date = datetime.strptime(v, "%Y-%m-%d").date()
        except ValueError:
            raise ValueError('Date must be in YYYY-MM-DD format')
        
        today = date.today()
        age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))
        
        if age < 18:
            raise ValueError('Must be 18 or older')
        if age > 120:
            raise ValueError('Invalid birth date')
        
        return v

class UserLoginModel(BaseModel):
    """Validation model for user login"""
    email: EmailStr = Field(..., description="Valid email address")
    password: str = Field(..., min_length=1, max_length=128, description="Password")
    otp: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")
    
    @validator('otp')
    def validate_otp(cls, v):
        """Validate OTP format"""
        clean_otp = ''.join(filter(str.isdigit, v.strip()))
        if len(clean_otp) != 6:
            raise ValueError('OTP must be exactly 6 digits')
        return clean_otp

class OTPVerificationModel(BaseModel):
    """Validation model for OTP verification"""
    otp_code: str = Field(..., min_length=6, max_length=6, description="6-digit OTP code")
    
    @validator('otp_code')
    def validate_otp_code(cls, v):
        """Validate OTP code format"""
        clean_otp = ''.join(filter(str.isdigit, v.strip()))
        if len(clean_otp) != 6:
            raise ValueError('OTP must be exactly 6 digits')
        return clean_otp

class PasswordResetModel(BaseModel):
    """Validation model for password reset"""
    token: str = Field(..., min_length=1, max_length=500, description="Reset token")
    new_password: str = Field(..., min_length=8, max_length=128, description="New password")
    confirm_password: str = Field(..., min_length=8, max_length=128, description="Password confirmation")
    
    @validator('new_password')
    def validate_password_strength(cls, v):
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        return v
    
    @validator('confirm_password')
    def passwords_match(cls, v, values):
        """Validate password confirmation matches"""
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class PlanSelectionModel(BaseModel):
    """Validation model for investment plan selection"""
    amount_range: str = Field(..., description="Investment amount range")
    return_rate: str = Field(..., description="Expected return rate")
    duration: str = Field(..., description="Investment duration")
    csrf_token: str = Field(..., description="CSRF protection token")
    
    @validator('amount_range')
    def validate_amount_range(cls, v):
        """Validate amount range selection"""
        valid_ranges = ["1000-4500", "4501-9000"]
        if v not in valid_ranges:
            raise ValueError('Invalid amount range selected')
        return v
    
    @validator('return_rate')
    def validate_return_rate(cls, v):
        """Validate return rate selection"""
        valid_rates = ["5%", "6%"]
        if v not in valid_rates:
            raise ValueError('Invalid return rate selected')
        return v
    
    @validator('duration')
    def validate_duration(cls, v):
        """Validate duration selection"""
        if v.lower() != "quarterly":
            raise ValueError('Only quarterly duration is supported')
        return v

class DepositConfirmationModel(BaseModel):
    """Validation model for deposit confirmation"""
    tx_hash: str = Field(..., min_length=64, max_length=64, description="Transaction hash")
    withdrawal_address: str = Field(..., min_length=34, max_length=34, description="TRON withdrawal address")
    deposit_amount: str = Field(..., description="Deposit amount")
    csrf_token: str = Field(..., description="CSRF protection token")
    
    @validator('tx_hash')
    def validate_tx_hash(cls, v):
        """Validate TRON transaction hash format"""
        clean_hash = v.strip().upper()
        if not re.match(r'^[A-F0-9]{64}$', clean_hash):
            raise ValueError('Invalid transaction hash format')
        return clean_hash
    
    @validator('withdrawal_address')
    def validate_withdrawal_address(cls, v):
        """Validate TRON address format"""
        clean_address = v.strip()
        if not re.match(r'^T[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{33}$', clean_address):
            raise ValueError('Invalid TRON address format')
        return clean_address
    
    @validator('deposit_amount')
    def validate_deposit_amount(cls, v):
        """Validate deposit amount"""
        try:
            amount = float(v)
            if amount <= 0:
                raise ValueError('Deposit amount must be positive')
            if amount < 1000:
                raise ValueError('Minimum deposit is $1000')
            if amount > 10000:
                raise ValueError('Maximum deposit is $10000')
            return str(amount)
        except ValueError as e:
            if "could not convert" in str(e):
                raise ValueError('Invalid amount format')
            raise e

class AgreementModel(BaseModel):
    """Validation model for agreement acceptance"""
    agree_1: Optional[str] = Field(None, description="First agreement checkbox")
    agree_2: Optional[str] = Field(None, description="Second agreement checkbox")
    csrf_token: str = Field(..., description="CSRF protection token")
    
    @validator('agree_1')
    def validate_agreement_1(cls, v):
        """Validate first agreement is accepted"""
        if v != "on":
            raise ValueError('First agreement must be accepted')
        return v
    
    @validator('agree_2')
    def validate_agreement_2(cls, v):
        """Validate second agreement is accepted"""
        if v != "on":
            raise ValueError('Second agreement must be accepted')
        return v

class AdminLoginModel(BaseModel):
    """Validation model for admin login"""
    username: str = Field(..., min_length=1, max_length=50, description="Admin username")
    password: str = Field(..., min_length=1, max_length=128, description="Admin password")
    
    @validator('username')
    def validate_username(cls, v):
        """Validate username format"""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Invalid username format')
        return v

class DepositApprovalModel(BaseModel):
    """Validation model for admin deposit approval"""
    user_email: EmailStr = Field(..., description="User email address")
    action: str = Field(..., description="Approval action")
    
    @validator('action')
    def validate_action(cls, v):
        """Validate approval action"""
        valid_actions = ["approve", "reject"]
        if v not in valid_actions:
            raise ValueError('Invalid action specified')
        return v