#!/usr/bin/env python3
"""
Test script to verify OTP functionality
Run this to check if your OTP is working correctly
"""

import asyncio
import pyotp
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from data_layer.init_db import get_db
from data_layer.gateway_model import SecureUser
from auth_control.otp_module import verify_otp


async def test_user_otp(email: str):
    """Test OTP for a specific user"""
    print(f"\n🔍 Testing OTP for user: {email}")
    print("=" * 50)

    # Get user from database
    async for db in get_db():
        result = await db.execute(select(SecureUser).where(SecureUser.email == email))
        user = result.scalar_one_or_none()

        if not user:
            print(f"❌ User not found: {email}")
            return

        print(f"✅ User found")
        print(f"📧 Email: {user.email}")
        print(f"🔐 Has OTP secret: {bool(user.otp_secret)}")

        if not user.otp_secret:
            print("❌ No OTP secret stored for this user!")
            return

        # Create TOTP instance
        totp = pyotp.TOTP(user.otp_secret)

        # Show current time info
        current_time = datetime.now()
        print(f"\n⏰ Server time: {current_time}")
        print(f"📱 Current OTP: {totp.now()}")

        # Generate provisioning URI
        otp_uri = totp.provisioning_uri(name=email, issuer_name="AEGOCAP")
        print(f"\n🔗 OTP URI for manual entry:")
        print(f"   {otp_uri}")

        # Test OTP verification
        print(f"\n🧪 Testing OTP verification:")
        test_otp = input("Enter the 6-digit code from your authenticator app: ").strip()

        # Clean input
        clean_otp = ''.join(filter(str.isdigit, test_otp))

        # Test with multiple time windows
        print(f"\n🔍 Checking OTP '{clean_otp}'...")

        # Method 1: Direct verification
        if verify_otp(user.otp_secret, clean_otp):
            print("✅ OTP verified successfully using verify_otp()")
        else:
            print("❌ OTP failed with verify_otp()")

        # Method 2: Manual verification with time windows
        matched = False
        for window in [-2, -1, 0, 1, 2]:
            test_time = current_time.timestamp() + (window * 30)
            expected_otp = totp.at(test_time)
            if expected_otp == clean_otp:
                print(f"✅ OTP matched in time window {window:+d} (±{window * 30} seconds)")
                matched = True
                break

        if not matched:
            print("❌ OTP did not match any time window")
            print("\n🤔 Possible issues:")
            print("1. Time sync problem between server and your device")
            print("2. Wrong OTP secret in authenticator app")
            print("3. Typo in the entered code")

        # Show next few OTPs
        print(f"\n📱 Next few valid OTPs:")
        for i in range(5):
            future_time = current_time.timestamp() + (i * 30)
            future_otp = totp.at(future_time)
            print(f"   In {i * 30} seconds: {future_otp}")

        break


async def main():
    print("🔐 AEGOCAP OTP Test Tool")
    print("=" * 50)

    email = input("Enter user email to test: ").strip()
    if email:
        await test_user_otp(email)
    else:
        print("❌ No email provided")


if __name__ == "__main__":
    asyncio.run(main())