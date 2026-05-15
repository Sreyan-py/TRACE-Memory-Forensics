import os
import json
import hashlib
from flask import Blueprint, request, jsonify, current_app
from models.models import User, Scan, ActivityLog, CachedAnalysis
from database import SessionLocal
from analysis.volatility_runner import analyze_memory
from analysis.report_generator import generate_pdf_report
from datetime import datetime

forensics_bp = Blueprint('forensics', __name__)

def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def update_user_rank(user, db):
    total_scans = db.query(Scan).filter(Scan.user_id == user.id).count()
    if total_scans >= 50: user.rank = "Elite Forensics Operator"
    elif total_scans >= 25: user.rank = "Malware Specialist"
    elif total_scans >= 15: user.rank = "Incident Responder"
    elif total_scans >= 10: user.rank = "Threat Hunter"
    elif total_scans >= 5: user.rank = "SOC Analyst"
    else: user.rank = "Rookie Analyst"
    db.commit()

@forensics_bp.route("/upload", methods=["POST"])
def upload_file():
    db = SessionLocal()
    try:
        username = request.form.get("username")
        file = request.files.get("file")
        
        if not username or not file:
            return jsonify({"success": False, "error": "Username and file required"}), 400

        user = db.query(User).filter(User.username == username).first()
        if not user: return jsonify({"success": False, "error": "User not found"}), 404

        upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
        file.save(upload_path)
        
        file_hash = get_file_hash(upload_path)
        cached = db.query(CachedAnalysis).filter(CachedAnalysis.file_hash == file_hash).first()
        
        if cached:
            indicators = json.loads(cached.indicators)
            analysis_result = {
                "threat_score": cached.threat_score,
                "severity": cached.severity,
                "timestamps": {"scan_end": cached.timestamp, "scan_start": cached.timestamp},
                "suspicious_processes": indicators.get("suspicious_processes", []),
                "forensic_summary": "CACHED: " + indicators.get("forensic_summary", ""),
                "plugin_results": json.loads(cached.plugin_results),
                "analysis_mode": "cached"
            }
        else:
            analysis_result = analyze_memory(upload_path, file_hash)
            if "error" in analysis_result:
                return jsonify({"success": False, "error": analysis_result["error"]}), 400
                
            new_cache = CachedAnalysis(
                file_hash=file_hash,
                filename=file.filename,
                threat_score=analysis_result["threat_score"],
                severity=analysis_result["severity"],
                indicators=json.dumps({
                    "suspicious_processes": analysis_result.get("suspicious_processes", []),
                    "forensic_summary": analysis_result.get("forensic_summary", "")
                }),
                plugin_results=json.dumps(analysis_result.get("plugin_results", {})),
                timestamp=analysis_result["timestamps"]["scan_end"]
            )
            db.add(new_cache)
            db.commit()
            analysis_result["analysis_mode"] = "live"

        report_filename = generate_pdf_report(analysis_result, file.filename)
        
        scan = Scan(
            user_id=user.id,
            filename=file.filename,
            file_hash=file_hash,
            threat_score=analysis_result["threat_score"],
            severity=analysis_result["severity"],
            scan_timestamp=analysis_result["timestamps"]["scan_end"],
            report_path=report_filename,
            dump_size=os.path.getsize(upload_path),
            suspicious_process_count=len(analysis_result.get("suspicious_processes", []))
        )
        db.add(scan)
        db.add(ActivityLog(user_id=user.id, event_type="system", message=f"Analyzed: {file.filename}"))
        
        update_user_rank(user, db)
        user.last_active = datetime.now().strftime("%Y-%m-%d %H:%M")
        db.commit()

        return jsonify({
            "success": True,
            "message": "Analysis Complete",
            "analysis": analysis_result,
            "report_url": f"{request.host_url.rstrip('/')}/reports/{report_filename}"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        db.close()

@forensics_bp.route("/history/<username>", methods=["GET"])
def get_history(username):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user: return jsonify({"success": False, "error": "User not found"}), 404
        
        scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).all()
        history = [{
            "id": f"TRC-{s.id:03d}",
            "name": s.filename,
            "date": s.scan_timestamp,
            "score": s.threat_score,
            "severity": s.severity,
            "report_url": f"{request.host_url.rstrip('/')}/reports/{s.report_path}"
        } for s in scans]
        
        return jsonify({"success": True, "data": history})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        db.close()
