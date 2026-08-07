import os
import json
import hashlib
import logging
from flask import Blueprint, request, jsonify, current_app
from models.models import User, Scan, ActivityLog, CachedAnalysis
from database import SessionLocal
from analysis.volatility_runner import analyze_memory, SUPPORTED_EXTENSIONS, EXTENSION_LABELS
from analysis.report_generator import generate_pdf_report
from datetime import datetime

logger = logging.getLogger(__name__)
forensics_bp = Blueprint('forensics', __name__)

# Minimum file size before we even try analysis (10 MB)
MIN_FILE_SIZE_BYTES = 10 * 1024 * 1024

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _get_username_from_request() -> str | None:
    """
    Resolve the username from either:
      1. A valid JWT in the Authorization header, or
      2. The `username` field in the form data (legacy / dev convenience).
    """
    from routes.auth import _verify_jwt
    import jwt as pyjwt

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        try:
            payload = _verify_jwt(token)
            return payload.get("sub")
        except pyjwt.PyJWTError:
            return None

    # Fallback: form field (no token auth, accept for now)
    return request.form.get("username")


def get_file_hash(filepath: str) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def update_user_rank(user, db):
    total = db.query(Scan).filter(Scan.user_id == user.id).count()
    if total >= 50:   user.rank = "Elite Forensics Operator"
    elif total >= 25: user.rank = "Malware Specialist"
    elif total >= 15: user.rank = "Incident Responder"
    elif total >= 10: user.rank = "Threat Hunter"
    elif total >= 5:  user.rank = "SOC Analyst"
    else:             user.rank = "Rookie Analyst"
    db.commit()


# ──────────────────────────────────────────────────────────────────────────────
# Upload & Analyse
# ──────────────────────────────────────────────────────────────────────────────

@forensics_bp.route("/upload", methods=["POST"])
def upload_file():
    db = SessionLocal()
    try:
        username = _get_username_from_request()
        file = request.files.get("file")

        if not username:
            return jsonify({"success": False, "error": "Authentication required"}), 401
        if not file or not file.filename:
            return jsonify({"success": False, "error": "No file provided"}), 400

        # ── Extension check ──────────────────────────────────────────────────
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if ext not in SUPPORTED_EXTENSIONS:
            return jsonify({
                "success": False,
                "error": (
                    "Unsupported file format. "
                    "Supported formats: .vmem · .raw · .mem · .img · .dmp · .pdf"
                ),
            }), 400

        # ── User lookup ──────────────────────────────────────────────────────
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return jsonify({"success": False, "error": "Analyst not found"}), 404

        # ── Save file ────────────────────────────────────────────────────────
        safe_filename = os.path.basename(file.filename)
        upload_path = os.path.join(current_app.config["UPLOAD_FOLDER"], safe_filename)
        file.save(upload_path)

        # ── Size & validation check ──────────────────────────────────────────
        file_size = os.path.getsize(upload_path)
        if file_size == 0:
            os.remove(upload_path)
            return jsonify({"success": False, "error": "This file is empty (0 bytes)."}), 400

        MAX_FILE_SIZE_BYTES = 200 * 1024 * 1024 # 200 MB
        if file_size > MAX_FILE_SIZE_BYTES:
            os.remove(upload_path)
            return jsonify({
                "success": False,
                "error": f"File size ({round(file_size / (1024 * 1024), 1)} MB) exceeds maximum allowed limit of 200 MB."
            }), 400

        # ── Hash & cache check ───────────────────────────────────────────────
        file_hash = get_file_hash(upload_path)
        cached = db.query(CachedAnalysis).filter(CachedAnalysis.file_hash == file_hash).first()

        if cached:
            logger.info(f"[FORENSICS] Cache hit for {safe_filename}")
            indicators = json.loads(cached.indicators)
            analysis_result = {
                "threat_score": cached.threat_score,
                "severity": cached.severity,
                "timestamps": {"scan_end": cached.timestamp, "scan_start": cached.timestamp},
                "suspicious_processes": indicators.get("suspicious_processes", []),
                "hidden_processes": indicators.get("hidden_processes", []),
                "dll_injections": indicators.get("dll_injections", []),
                "network_connections": indicators.get("network_connections", []),
                "malware_indicators": indicators.get("malware_indicators", []),
                "registry_anomalies": indicators.get("registry_anomalies", []),
                "timeline": indicators.get("timeline", []),
                "ioc_list": indicators.get("ioc_list", []),
                "recommendations": indicators.get("recommendations", []),
                "forensic_summary": indicators.get("forensic_summary", ""),
                "detected_os": indicators.get("detected_os", "windows"),
                "architecture": indicators.get("architecture", "x64"),
                "file_type_label": EXTENSION_LABELS.get(ext, "Memory Image"),
                "file_size_mb": round(file_size / (1024 * 1024), 2),
                "plugin_results": json.loads(cached.plugin_results or "{}"),
                "analysis_mode": indicators.get("analysis_mode", "Cached Analysis"),
                "analysis_type": indicators.get("analysis_type", "Memory Forensics"),
                "file_hash": file_hash,
            }
        else:
            if ext == "pdf":
                from analysis.pdf_analyzer import analyze_pdf
                logger.info(f"[FORENSICS] Dedicated PDF Route triggered (bypassing Volatility & Memory validation): {safe_filename}")
                analysis_result = analyze_pdf(upload_path, file_hash)
            else:
                logger.info(f"[FORENSICS] Memory Dump Route triggered for: {safe_filename}")
                analysis_result = analyze_memory(upload_path, file_hash)

                if analysis_result.get("volatility_failed") or "error" in analysis_result:
                    from analysis.threat_detector import ThreatDetector
                    logger.warning(f"[FORENSICS] Real Volatility unable to complete for {safe_filename} — engaging Demo Fallback")
                    analysis_result = ThreatDetector().calculate_deterministic_demo(upload_path, file_hash, ext)

            # ── Cache the result ──────────────────────────────────────────────
            try:
                new_cache = CachedAnalysis(
                    file_hash=file_hash,
                    filename=safe_filename,
                    threat_score=analysis_result["threat_score"],
                    severity=analysis_result["severity"],
                    indicators=json.dumps({
                        "suspicious_processes": analysis_result.get("suspicious_processes", []),
                        "hidden_processes": analysis_result.get("hidden_processes", []),
                        "dll_injections": analysis_result.get("dll_injections", []),
                        "network_connections": analysis_result.get("network_connections", []),
                        "malware_indicators": analysis_result.get("malware_indicators", []),
                        "registry_anomalies": analysis_result.get("registry_anomalies", []),
                        "timeline": analysis_result.get("timeline", []),
                        "ioc_list": analysis_result.get("ioc_list", []),
                        "recommendations": analysis_result.get("recommendations", []),
                        "forensic_summary": analysis_result.get("forensic_summary", ""),
                        "detected_os": analysis_result.get("detected_os", "windows"),
                        "architecture": analysis_result.get("architecture", "x64"),
                        "analysis_mode": analysis_result.get("analysis_mode", "Real Analysis"),
                        "analysis_type": analysis_result.get("analysis_type", "Memory Forensics"),
                    }),
                    plugin_results=json.dumps(analysis_result.get("plugin_results", {})),
                    timestamp=analysis_result["timestamps"]["scan_end"],
                )
                db.add(new_cache)
                db.commit()
            except Exception as cache_err:
                logger.warning(f"[FORENSICS] Cache write failed: {cache_err}")

        # Ensure file_hash is present on result
        analysis_result["file_hash"] = file_hash

        # ── Generate PDF report ───────────────────────────────────────────────
        try:
            report_filename = generate_pdf_report(analysis_result, safe_filename)
        except Exception as rep_err:
            logger.error(f"[FORENSICS] PDF report generation failed: {rep_err}")
            report_filename = None

        # ── File type label ───────────────────────────────────────────────────
        file_type_map = {
            "raw": "RAW", "vmem": "VMEM", "img": "IMG",
            "dmp": "DMP", "mem": "MEM",
        }
        file_type = file_type_map.get(ext, ext.upper() if ext else "RAW")

        # ── Persist scan record ───────────────────────────────────────────────
        scan = Scan(
            user_id=user.id,
            filename=safe_filename,
            file_hash=file_hash,
            file_type=file_type,
            threat_score=analysis_result["threat_score"],
            severity=analysis_result["severity"],
            forensic_summary=analysis_result.get("forensic_summary", ""),
            scan_timestamp=analysis_result["timestamps"]["scan_end"],
            report_path=report_filename or "",
            dump_size=file_size,
            suspicious_process_count=len(analysis_result.get("suspicious_processes", [])),
        )
        db.add(scan)
        db.add(ActivityLog(
            user_id=user.id,
            event_type="system",
            message=f"Analyzed: {safe_filename} | Score: {analysis_result['threat_score']} | {analysis_result['severity']}",
        ))
        update_user_rank(user, db)
        user.last_active = datetime.now().strftime("%Y-%m-%d %H:%M")
        db.commit()

        report_url = None
        if report_filename:
            report_url = f"{request.host_url.rstrip('/')}/reports/{report_filename}"

        return jsonify({
            "success": True,
            "message": "Analysis Complete",
            "analysis": analysis_result,
            "report_url": report_url,
        })

    except Exception as e:
        logger.error(f"[FORENSICS] Unhandled error: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": f"Internal forensic engine failure: {str(e)}"}), 500
    finally:
        db.close()


# ──────────────────────────────────────────────────────────────────────────────
# Scan History
# ──────────────────────────────────────────────────────────────────────────────

@forensics_bp.route("/history/<username>", methods=["GET"])
def get_history(username):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).all()
        history = [{
            "scan_id": s.id,
            "id": f"TRC-{s.id:03d}",
            "name": s.filename,
            "file_type": getattr(s, "file_type", "RAW") or "RAW",
            "date": s.scan_timestamp,
            "score": s.threat_score,
            "severity": s.severity,
            "forensic_summary": getattr(s, "forensic_summary", "") or "",
            "size": f"{(s.dump_size or 0) / (1024 * 1024):.2f} MB",
            "suspicious_process_count": s.suspicious_process_count or 0,
            "report_url": f"{request.host_url.rstrip('/')}/reports/{s.report_path}" if s.report_path else None,
        } for s in scans]

        return jsonify({"success": True, "data": history})
    except Exception as e:
        logger.error(f"[FORENSICS] History error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500
    finally:
        db.close()
