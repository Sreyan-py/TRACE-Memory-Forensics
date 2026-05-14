from flask import Blueprint, jsonify
from models.models import User, Scan, ActivityLog
from database import SessionLocal

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route("/dashboard/stats/<username>", methods=["GET"])
def dashboard_stats(username):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user: return jsonify({"error": "User not found"}), 404
            
        scans = db.query(Scan).filter(Scan.user_id == user.id).all()
        total_dumps = len(scans)
        critical_threats = sum(1 for s in scans if s.severity in ("CRITICAL", "HIGH"))
        avg_threat = sum(s.threat_score for s in scans) / total_dumps if total_dumps > 0 else 0
        health_score = max(0, int(100 - avg_threat))
        
        distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for s in scans:
            if s.severity in distribution: distribution[s.severity] += 1
                
        activity_data = []
        for i, s in enumerate(scans[-10:]):
            activity_data.append({
                "time": s.scan_timestamp,
                "value": s.threat_score
            })

        return jsonify({
            "total_dumps": total_dumps,
            "critical_threats": critical_threats,
            "health_score": health_score,
            "distribution_data": [{"name": k, "value": v} for k, v in distribution.items() if v > 0],
            "activity_data": activity_data
        })
    finally:
        db.close()

@dashboard_bp.route("/activities/<username>", methods=["GET"])
def get_activities(username):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user: return jsonify({"error": "User not found"}), 404
        
        logs = db.query(ActivityLog).filter(ActivityLog.user_id == user.id).order_by(ActivityLog.id.desc()).limit(10).all()
        return jsonify([{
            "time": l.timestamp,
            "msg": l.message,
            "type": l.event_type
        } for l in logs])
    finally:
        db.close()
