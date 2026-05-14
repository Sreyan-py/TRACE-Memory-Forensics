from flask import Blueprint, request, jsonify
from models.models import User, Scan, ActivityLog
from database import SessionLocal
from datetime import datetime

profile_bp = Blueprint('profile', __name__)

@profile_bp.route("/profile/<username>", methods=["GET"])
def get_profile(username):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user: return jsonify({"error": "User not found"}), 404
        
        total_scans = db.query(Scan).filter(Scan.user_id == user.id).count()
        critical_threats = db.query(Scan).filter(Scan.user_id == user.id, Scan.severity.in_(["CRITICAL", "HIGH"])).count()
        
        return jsonify({
            "username": user.username,
            "display_name": user.display_name or user.username,
            "codename": user.codename or f"AGENT-{user.id:04d}",
            "bio": user.bio or "Operational field agent specializing in memory forensics and malware neutralization.",
            "role": user.role,
            "specialization": user.specialization,
            "location": user.location,
            "avatar_preset": user.avatar_preset,
            "rank": user.rank,
            "joined_at": user.joined_at,
            "last_active": user.last_active,
            "stats": {
                "total_scans": total_scans,
                "critical_threats": critical_threats,
                "ioc_count": total_scans * 12,
                "data_analyzed": round(total_scans * 1.2, 1)
            }
        })
    finally:
        db.close()

@profile_bp.route("/profile/update", methods=["POST"])
def update_profile():
    db = SessionLocal()
    try:
        data = request.json
        username = data.get("username")
        user = db.query(User).filter(User.username == username).first()
        if not user: return jsonify({"error": "User not found"}), 404
        
        user.display_name = data.get("display_name", user.display_name)
        user.codename = data.get("codename", user.codename)
        user.bio = data.get("bio", user.bio)
        user.role = data.get("role", user.role)
        user.specialization = data.get("specialization", user.specialization)
        user.location = data.get("location", user.location)
        user.avatar_preset = data.get("avatar_preset", user.avatar_preset)
        
        db.commit()
        return jsonify({"message": "Profile updated successfully"})
    finally:
        db.close()
