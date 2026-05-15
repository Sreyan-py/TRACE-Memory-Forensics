from flask import Blueprint, jsonify
from models.models import User, Scan
from database import SessionLocal

lab_bp = Blueprint('lab', __name__)

@lab_bp.route("/lab/samples/<username>", methods=["GET"])
def get_lab_samples(username):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user: return jsonify({"success": False, "error": "User not found"}), 404
        
        scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).all()
        samples = [{
            "name": s.filename,
            "type": "Memory Dump" if ".raw" in s.filename.lower() else "Artifact",
            "date": s.scan_timestamp,
            "risk": s.severity
        } for s in scans]
        
        return jsonify({"success": True, "data": samples})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        db.close()
