from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from models.models import User
from database import SessionLocal
import logging

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)

def validate_password(password):
    if len(password) < 8: return False, "Password too short"
    if not any(c.isupper() for c in password): return False, "Missing uppercase"
    if not any(c.islower() for c in password): return False, "Missing lowercase"
    if not any(c.isdigit() for c in password): return False, "Missing number"
    if not any(c in "!@#$%^&*(),.?\":{}|<>" for c in password): return False, "Missing special character"
    return True, None

@auth_bp.route("/signup", methods=["POST"])
def signup():
    db = SessionLocal()
    try:
        data = request.json or {}
        username = data.get("username")
        password = (data.get("password") or "").strip()
        
        if not username or not password:
            return jsonify({"error": "Username and password required"}), 400
            
        is_valid, val_error = validate_password(password)
        if not is_valid:
            return jsonify({"success": False, "error": f"Security check failed: {val_error}"}), 400
            
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            return jsonify({"error": "Username already exists"}), 400
            
        new_user = User(username=username, password=generate_password_hash(password))
        db.add(new_user)
        db.commit()
        return jsonify({"message": "User created successfully"}), 201
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
            return jsonify({"message": "Login successful", "username": user.username})
        
        return jsonify({"error": "Invalid username or password"}), 401
    finally:
        db.close()
