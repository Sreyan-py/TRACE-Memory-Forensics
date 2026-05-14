from flask import Blueprint, jsonify
from models.models import User, Scan
from database import SessionLocal

lab_bp = Blueprint('lab', __name__)

@lab_bp.route("/lab/samples/<username>", methods=["GET"])
def get_lab_samples(username):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user: return jsonify({"error": "User not found"}), 404
        
        scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).all()
        return jsonify([{
            "name": s.filename,
            "type": "Memory Dump" if ".raw" in s.filename.lower() else "Artifact",
            "date": s.scan_timestamp,
            "risk": s.severity
        } for s in scans])
    finally:
        db.close()
