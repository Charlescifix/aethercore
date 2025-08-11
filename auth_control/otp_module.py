# aether_core/auth_control/otp_module.py

import pyotp
import base64
import os


def generate_otp_secret() -> str:
    """
    Generates a new base32 secret for TOTP.
    """
    return base64.b32encode(os.urandom(10)).decode("utf-8")


def get_otp_uri(email: str, secret: str, issuer: str = "AEGOCAP") -> str:
    """
    Returns a URI that can be converted to a QR code for OTP apps like Google Authenticator.
    """
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_otp(secret: str, otp: str, window: int = 2) -> bool:
    """
    Verifies the OTP against the shared secret with time window tolerance.

    Args:
        secret: The user's OTP secret
        otp: The OTP code to verify
        window: Number of 30-second intervals to check (default 2 = ±60 seconds)

    Returns:
        bool: True if OTP is valid within the time window
    """
    try:
        # Clean the OTP input - remove any spaces or non-digits
        clean_otp = ''.join(filter(str.isdigit, str(otp).strip()))

        # Ensure it's exactly 6 digits
        if len(clean_otp) != 6:
            return False

        # Create TOTP instance
        totp = pyotp.TOTP(secret)

        # Verify with time window tolerance
        # This allows for clock drift between server and client
        return totp.verify(clean_otp, valid_window=window)

    except Exception as e:
        print(f"[OTP_ERROR] Error verifying OTP: {e}")
        return False


def get_current_otp(secret: str) -> str:
    """
    Get the current valid OTP for testing/debugging purposes.
    """
    totp = pyotp.TOTP(secret)
    return totp.now()