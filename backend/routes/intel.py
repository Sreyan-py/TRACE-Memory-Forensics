from flask import Blueprint, jsonify
from models.models import User
from database import SessionLocal

intel_bp = Blueprint('intel', __name__)

@intel_bp.route("/intel/aggregate/<username>", methods=["GET"])
def get_intel_aggregate(username):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user: return jsonify({"success": False, "error": "User not found"}), 404
        
        intel_data = {
            "trending_cves": [
                {"id": "CVE-2024-38063", "title": "Windows TCP/IP RCE", "severity": "CRITICAL", "score": "9.8"},
                {"id": "CVE-2024-38077", "title": "Windows RDP RCE", "severity": "CRITICAL", "score": "9.8"}
            ],
            "mitre_techs": [
                {"id": "T1059", "name": "Command & Scripting"},
                {"id": "T1055", "name": "Process Injection"},
                {"id": "T1003", "name": "OS Credential Dumping"}
            ],
            "critical_iocs": [
                "8.8.8.8 (C2 Beacon)",
                "powershell.exe -enc ...",
                f"sample_{user.id}_hash.exe"
            ]
        }
        return jsonify({"success": True, "data": intel_data})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        db.close()
