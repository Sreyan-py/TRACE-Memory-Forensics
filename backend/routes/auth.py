from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models.models import User
from database import SessionLocal
import logging

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

def validate_password(password):
    if len(password) < 8: return False, "Minimum 8 characters required"
    if not any(c.isupper() for c in password): return False, "At least one uppercase letter required"
    if not any(c.islower() for c in password): return False, "At least one lowercase letter required"
    if not any(c.isdigit() for c in password): return False, "At least one number required"
    if not any(c in "!@#$%^&*(),.?\":{}|<>" for c in password): return False, "At least one special character required"
    return True, None

@auth_bp.route("/signup", methods=["POST"])
def signup():
    db = SessionLocal()
    try:
        data = request.json or {}
        username = data.get("username")
        password = (data.get("password") or "").strip()
        
        if not username or not password:
            return jsonify({"success": False, "error": "Username and password required"}), 400
            
        is_valid, val_error = validate_password(password)
        if not is_valid:
            return jsonify({"success": False, "error": val_error}), 400
            
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            return jsonify({"success": False, "error": "Analyst ID already registered"}), 400
            
        new_user = User(username=username, password=generate_password_hash(password))
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
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        
        user = db.query(User).filter(User.username == username).first()
        if user and check_password_hash(user.password, password):
            return jsonify({
                "success": True, 
                "message": "Neural link established", 
                "username": user.username
            })
        
        return jsonify({"success": False, "error": "Invalid Analyst ID or Access Key"}), 401
    except Exception as e:
        logger.error(f"LOGIN_ERROR: {str(e)}")
        return jsonify({"success": False, "error": "Authentication server timeout"}), 500
    finally:
        db.close()
