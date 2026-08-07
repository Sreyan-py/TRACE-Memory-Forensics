import os
import logging
import random
import string
from datetime import datetime, timedelta, timezone

import jwt
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash

from database import SessionLocal
from models.models import User, ActivityLog

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__)

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 5
OTP_EXPIRY_MINUTES = 10
TOKEN_EXPIRY_HOURS = 24
REMEMBER_EXPIRY_DAYS = 30


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _is_locked(user: User) -> bool:
    """Return True if the account is still within its lockout window."""
    if not user.locked_until:
        return False
    try:
        locked_until = datetime.fromisoformat(user.locked_until)
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        return _now_utc() < locked_until
    except ValueError:
        return False


def _lock_account(user: User) -> None:
    """Lock the account for LOCKOUT_MINUTES after too many failed attempts."""
    user.locked_until = (_now_utc() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    user.failed_attempts = 0


def _generate_jwt(user: User, remember: bool = False) -> str:
    secret = current_app.config["SECRET_KEY"]
    expiry = (
        _now_utc() + timedelta(days=REMEMBER_EXPIRY_DAYS)
        if remember
        else _now_utc() + timedelta(hours=TOKEN_EXPIRY_HOURS)
    )
    payload = {
        "sub": user.username,
        "ver": user.token_version,
        "exp": expiry,
        "iat": _now_utc(),
        "remember": remember,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def _verify_jwt(token: str):
    """
    Decode and validate a JWT.
    Returns the payload dict on success, or raises jwt.PyJWTError on failure.
    """
    secret = current_app.config["SECRET_KEY"]
    return jwt.decode(token, secret, algorithms=["HS256"])


def _generate_otp() -> str:
    return "".join(random.choices(string.digits, k=6))


def require_auth(f):
    """
    Decorator that validates the Bearer JWT on protected endpoints.
    Attaches `g.current_user` for downstream use.
    """
    from functools import wraps
    from flask import g

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"success": False, "error": "Authorization required"}), 401
        token = auth_header.split(" ", 1)[1]
        try:
            payload = _verify_jwt(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "error": "Session expired. Please login again."}), 401
        except jwt.PyJWTError:
            return jsonify({"success": False, "error": "Invalid session token"}), 401

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.username == payload["sub"]).first()
            if not user:
                return jsonify({"success": False, "error": "Analyst not found"}), 401
            # Invalidate tokens issued before a password reset
            if user.token_version != payload.get("ver", 0):
                return jsonify({"success": False, "error": "Session invalidated. Please login again."}), 401
            g.current_user = user
        finally:
            db.close()
        return f(*args, **kwargs)

    return decorated


# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/signup", methods=["POST"])
def signup():
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        email = (data.get("email") or "").strip() or None

        if not username or not password:
            return jsonify({"success": False, "error": "Analyst ID and Access Key are required"}), 400

        # Password strength validation
        if len(password) < 8:
            return jsonify({"success": False, "error": "Access Key must be at least 8 characters"}), 400
        if not any(c.isupper() for c in password):
            return jsonify({"success": False, "error": "Access Key must contain an uppercase letter"}), 400
        if not any(c.isdigit() for c in password):
            return jsonify({"success": False, "error": "Access Key must contain a number"}), 400
        if not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
            return jsonify({"success": False, "error": "Access Key must contain a special character"}), 400

        if db.query(User).filter(User.username == username).first():
            return jsonify({"success": False, "error": "Analyst ID already registered"}), 400

        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
        )
        db.add(new_user)
        db.commit()
        return jsonify({"success": True, "message": "Neural link established. You may now login."}), 201
    except Exception as e:
        logger.error(f"SIGNUP_ERROR: {str(e)}")
        return jsonify({"success": False, "error": "Internal infrastructure failure"}), 500
    finally:
        db.close()


@auth_bp.route("/login", methods=["POST"])
def login():
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        remember = bool(data.get("remember", False))

        # Generic error — never reveal whether ID or password is wrong
        GENERIC_ERROR = "Invalid Analyst ID or Access Key."
        LOCKOUT_ERROR = "Maximum authentication attempts exceeded. Please try again in 5 minutes."

        user = db.query(User).filter(User.username == username).first()

        # Always run through lockout / password check even for unknown users
        # to prevent timing-based username enumeration
        if user and _is_locked(user):
            return jsonify({"success": False, "error": LOCKOUT_ERROR, "locked": True}), 429

        if not user or not check_password_hash(user.password, password):
            if user:
                user.failed_attempts = (user.failed_attempts or 0) + 1
                if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    _lock_account(user)
                    db.commit()
                    return jsonify({"success": False, "error": LOCKOUT_ERROR, "locked": True}), 429
                db.commit()
            return jsonify({"success": False, "error": GENERIC_ERROR}), 401

        # Successful login — reset lockout state
        user.failed_attempts = 0
        user.locked_until = None
        user.last_active = _now_utc().strftime("%Y-%m-%d %H:%M")
        db.commit()

        token = _generate_jwt(user, remember=remember)

        db.add(ActivityLog(user_id=user.id, event_type="auth", message="Analyst authenticated successfully"))
        db.commit()

        return jsonify({
            "success": True,
            "message": "Neural link established",
            "username": user.username,
            "token": token,
        })
    except Exception as e:
        logger.error(f"LOGIN_ERROR: {str(e)}")
        return jsonify({"success": False, "error": "Authentication server timeout"}), 500
    finally:
        db.close()


# ──────────────────────────────────────────────────────────────────────────────
# Forgot Access Key — Step 1: Request OTP
# ──────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/forgot-password", methods=["POST"])
def forgot_password():
    """
    Step 1: Analyst submits their Analyst ID or registered email.
    We generate a 6-digit OTP, store a bcrypt hash of it with a 10-minute TTL,
    and (in dev mode) return it in the response.
    In production, wire in SendGrid / AWS SES here to email it.
    """
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        identifier = (data.get("identifier") or "").strip()

        if not identifier:
            return jsonify({"success": False, "error": "Analyst ID or email is required"}), 400

        # Look up by username or email — always return generic success to prevent enumeration
        user = (
            db.query(User).filter(User.username == identifier).first()
            or db.query(User).filter(User.email == identifier).first()
        )

        otp = _generate_otp()
        otp_hash = generate_password_hash(otp)
        expires_at = (_now_utc() + timedelta(minutes=OTP_EXPIRY_MINUTES)).isoformat()

        if user:
            user.otp_hash = otp_hash
            user.otp_expires_at = expires_at
            db.commit()
            logger.info(f"OTP generated for user {user.username}: {otp}")

        # DEV MODE: return OTP in response so analysts can test without email
        # PRODUCTION: send otp to user.email via email service and remove from response
        return jsonify({
            "success": True,
            "message": "If your Analyst ID or email is registered, a 6-digit synchronization code has been dispatched.",
            # Remove `otp` field in production (send via email instead)
            "dev_otp": otp if user else None,
            "expires_in_minutes": OTP_EXPIRY_MINUTES,
        })
    except Exception as e:
        logger.error(f"FORGOT_PASSWORD_ERROR: {str(e)}")
        return jsonify({"success": False, "error": "System failure. Try again."}), 500
    finally:
        db.close()


# ──────────────────────────────────────────────────────────────────────────────
# Forgot Access Key — Step 2: Verify OTP
# ──────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/verify-otp", methods=["POST"])
def verify_otp():
    """
    Step 2: Analyst submits their OTP.
    On success, return a one-time reset token (valid for 15 minutes).
    """
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        identifier = (data.get("identifier") or "").strip()
        otp = (data.get("otp") or "").strip()

        if not identifier or not otp:
            return jsonify({"success": False, "error": "Analyst ID and OTP are required"}), 400

        user = (
            db.query(User).filter(User.username == identifier).first()
            or db.query(User).filter(User.email == identifier).first()
        )

        INVALID = "Invalid or expired synchronization code."

        if not user or not user.otp_hash or not user.otp_expires_at:
            return jsonify({"success": False, "error": INVALID}), 401

        # Check expiry
        try:
            expires_at = datetime.fromisoformat(user.otp_expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if _now_utc() > expires_at:
                return jsonify({"success": False, "error": INVALID}), 401
        except ValueError:
            return jsonify({"success": False, "error": INVALID}), 401

        if not check_password_hash(user.otp_hash, otp):
            return jsonify({"success": False, "error": INVALID}), 401

        # OTP verified — generate a short-lived reset token
        reset_raw = "".join(random.choices(string.ascii_letters + string.digits, k=64))
        reset_hash = generate_password_hash(reset_raw)
        reset_expires = (_now_utc() + timedelta(minutes=15)).isoformat()

        user.otp_hash = None
        user.otp_expires_at = None
        user.reset_token = reset_hash
        user.reset_token_expires_at = reset_expires
        db.commit()

        return jsonify({
            "success": True,
            "message": "OTP verified. Proceed to set a new Access Key.",
            "reset_token": reset_raw,
            "username": user.username,
        })
    except Exception as e:
        logger.error(f"VERIFY_OTP_ERROR: {str(e)}")
        return jsonify({"success": False, "error": "System failure. Try again."}), 500
    finally:
        db.close()


# ──────────────────────────────────────────────────────────────────────────────
# Forgot Access Key — Step 3: Reset Password
# ──────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    """
    Step 3: Analyst sets a new Access Key using the reset token.
    All existing JWT sessions are invalidated via token_version bump.
    """
    db = SessionLocal()
    try:
        data = request.get_json() or {}
        username = (data.get("username") or "").strip()
        reset_token = (data.get("reset_token") or "").strip()
        new_password = data.get("new_password") or ""

        if not username or not reset_token or not new_password:
            return jsonify({"success": False, "error": "All fields are required"}), 400

        # Strength validation
        if len(new_password) < 8:
            return jsonify({"success": False, "error": "Access Key must be at least 8 characters"}), 400
        if not any(c.isupper() for c in new_password):
            return jsonify({"success": False, "error": "Access Key must contain an uppercase letter"}), 400
        if not any(c.isdigit() for c in new_password):
            return jsonify({"success": False, "error": "Access Key must contain a number"}), 400
        if not any(c in '!@#$%^&*(),.?":{}|<>' for c in new_password):
            return jsonify({"success": False, "error": "Access Key must contain a special character"}), 400

        INVALID_TOKEN = "Reset session invalid or expired. Please restart the recovery process."

        user = db.query(User).filter(User.username == username).first()
        if not user or not user.reset_token or not user.reset_token_expires_at:
            return jsonify({"success": False, "error": INVALID_TOKEN}), 401

        # Check expiry
        try:
            expires_at = datetime.fromisoformat(user.reset_token_expires_at)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if _now_utc() > expires_at:
                return jsonify({"success": False, "error": INVALID_TOKEN}), 401
        except ValueError:
            return jsonify({"success": False, "error": INVALID_TOKEN}), 401

        if not check_password_hash(user.reset_token, reset_token):
            return jsonify({"success": False, "error": INVALID_TOKEN}), 401

        # Update password and invalidate all existing JWT sessions
        user.password = generate_password_hash(new_password)
        user.token_version = (user.token_version or 0) + 1
        user.reset_token = None
        user.reset_token_expires_at = None
        user.failed_attempts = 0
        user.locked_until = None
        db.commit()

        db.add(ActivityLog(user_id=user.id, event_type="auth", message="Access Key reset. All sessions invalidated."))
        db.commit()

        return jsonify({
            "success": True,
            "message": "Access Key updated. All previous sessions have been terminated. Please login with your new key.",
        })
    except Exception as e:
        logger.error(f"RESET_PASSWORD_ERROR: {str(e)}")
        return jsonify({"success": False, "error": "System failure. Try again."}), 500
    finally:
        db.close()


# ──────────────────────────────────────────────────────────────────────────────
# Token Validation (frontend session restore)
# ──────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/validate-token", methods=["POST"])
def validate_token():
    """Called by the frontend on startup to check if a stored JWT is still valid."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"success": False, "error": "No token provided"}), 401
    token = auth_header.split(" ", 1)[1]
    try:
        payload = _verify_jwt(token)
    except jwt.ExpiredSignatureError:
        return jsonify({"success": False, "error": "Token expired"}), 401
    except jwt.PyJWTError:
        return jsonify({"success": False, "error": "Invalid token"}), 401

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == payload["sub"]).first()
        if not user or user.token_version != payload.get("ver", 0):
            return jsonify({"success": False, "error": "Session invalidated"}), 401
        return jsonify({"success": True, "username": user.username})
    finally:
        db.close()


# ──────────────────────────────────────────────────────────────────────────────
# Debug (remove in production)
# ──────────────────────────────────────────────────────────────────────────────

@auth_bp.route("/debug/users", methods=["GET"])
def debug_users():
    db = SessionLocal()
    try:
        users = db.query(User).all()
        return jsonify({
            "success": True,
            "users": [{"id": u.id, "username": u.username, "email": u.email} for u in users],
        })
    except Exception as e:
        logger.error(f"DEBUG_USERS_ERROR: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        db.close()
