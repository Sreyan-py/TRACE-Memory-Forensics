import os
import hashlib
import json

import logging
# pyrefly: ignore [missing-import]
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
# pyrefly: ignore [missing-import]
from werkzeug.security import generate_password_hash, check_password_hash
# pyrefly: ignore [missing-import]
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

from analysis.volatility_runner import analyze_memory
from analysis.report_generator import generate_pdf_report

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORTS_FOLDER = os.path.join(BASE_DIR, "reports")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-dev-key')
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 # 1GB limit

ALLOWED_EXTENSIONS = {'raw', 'mem', 'dmp', 'img'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Centralized DB setup
# Use PostgreSQL if provided, otherwise fallback to local SQLite
fallback_db_path = os.path.join(BASE_DIR, "users.db")
DB_URL = os.environ.get("DATABASE_URL", f"sqlite:///{fallback_db_path}")
if DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if "sqlite" in DB_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)
    scans = relationship("Scan", back_populates="user")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    file_hash = Column(String(64), nullable=False, index=True)
    threat_score = Column(Integer, nullable=False)
    severity = Column(String(20), nullable=False)
    scan_timestamp = Column(String(50), nullable=False)
    report_path = Column(String(255), nullable=False)
    dump_size = Column(Integer)
    suspicious_process_count = Column(Integer)
    user = relationship("User", back_populates="scans")

class CachedAnalysis(Base):
    __tablename__ = "cached_analysis"
    file_hash = Column(String(64), primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    threat_score = Column(Integer, nullable=False)
    severity = Column(String(20), nullable=False)
    indicators = Column(Text, nullable=False) # JSON encoded string
    plugin_results = Column(Text, nullable=False) # JSON encoded string
    timestamp = Column(String(50), nullable=False)

Base.metadata.create_all(bind=engine)

def get_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

@app.route("/")
def home():
    return {"message": "TRACE Backend Running (Deterministic & Cached)"}

@app.route("/upload", methods=["POST"])
def upload_file():
    db = SessionLocal()
    try:
        username = request.form.get("username")
        if not username:
            return jsonify({"error": "Username is required"}), 400

        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "Empty filename"}), 400
            
        if not allowed_file(file.filename):
            return jsonify({"error": "Invalid file type. Allowed extensions: .raw, .mem, .dmp, .img"}), 400

        user = db.query(User).filter(User.username == username).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return jsonify({"error": "Uploaded file is empty or corrupted."}), 400

        file_hash = get_file_hash(filepath)
        dump_size = os.path.getsize(filepath)

        # 1. Check cache
        cached = db.query(CachedAnalysis).filter(CachedAnalysis.file_hash == file_hash).first()
        
        if cached:
            # Reconstruct analysis result
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
                "forensic_summary": "CACHED ANALYSIS (SHA256 Match): " + indicators.get("forensic_summary", "Analysis loaded from cache."),
                "plugin_results": json.loads(cached.plugin_results)
            }
        else:
            # 2. Run analysis deterministically
            analysis_result = analyze_memory(filepath)
            if "error" in analysis_result:
                return jsonify({"error": f"Analysis failed: {analysis_result['error']}"}), 400
                
            # 3. Save to cache
            indicators = {
                "suspicious_processes": analysis_result.get("suspicious_processes", []),
                "hidden_processes": analysis_result.get("hidden_processes", []),
                "dll_injections": analysis_result.get("dll_injections", []),
                "network_connections": analysis_result.get("network_connections", []),
                "malware_indicators": analysis_result.get("malware_indicators", []),
                "forensic_summary": analysis_result.get("forensic_summary", "")
            }
            
            new_cache = CachedAnalysis(
                file_hash=file_hash,
                filename=file.filename,
                threat_score=analysis_result["threat_score"],
                severity=analysis_result["severity"],
                indicators=json.dumps(indicators),
                plugin_results=json.dumps(analysis_result.get("plugin_results", {})),
                timestamp=analysis_result["timestamps"]["scan_end"]
            )
            db.add(new_cache)
            db.commit()

        # 4. Generate report
        report_filename = generate_pdf_report(analysis_result, file.filename)
        base_url = request.host_url.rstrip('/')
        report_url = f"{base_url}/reports/{report_filename}"

        # 5. Record scan for user
        scan = Scan(
            user_id=user.id,
            filename=file.filename,
            file_hash=file_hash,
            threat_score=analysis_result["threat_score"],
            severity=analysis_result["severity"],
            scan_timestamp=analysis_result["timestamps"]["scan_end"],
            report_path=report_filename,
            dump_size=dump_size,
            suspicious_process_count=len(analysis_result.get("suspicious_processes", []))
        )
        db.add(scan)
        db.commit()

        return jsonify({
            "message": "Analysis Complete",
            "filename": file.filename,
            "analysis": analysis_result,
            "report_url": report_url
        })
    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500
    finally:
        db.close()

@app.route("/dashboard/stats/<username>", methods=["GET"])
def dashboard_stats(username):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.asc()).all()
        
        total_dumps = len(scans)
        critical_threats = sum(1 for s in scans if s.severity in ("CRITICAL", "HIGH"))
        avg_threat = sum(s.threat_score for s in scans) / total_dumps if total_dumps > 0 else 0
        health_score = max(0, int(100 - avg_threat))
        
        distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for s in scans:
            if s.severity in distribution:
                distribution[s.severity] += 1
                
        distribution_data = [{"name": k, "value": v} for k, v in distribution.items() if v > 0]
        if not distribution_data:
            distribution_data = [{"name": "No Threats", "value": 1}]
            
        activity_data = []
        for i, s in enumerate(scans[-10:]):
            activity_data.append({
                "name": f"Scan {i+1}",
                "threats": s.suspicious_process_count or 0,
                "score": s.threat_score
            })

        return jsonify({
            "total_dumps": total_dumps,
            "critical_threats": critical_threats,
            "health_score": f"{health_score}%",
            "distribution_data": distribution_data,
            "activity_data": activity_data
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/signup", methods=["POST"])
def signup():
    db = SessionLocal()
    try:
        data = request.json or {}
        username = data.get("username")
        password = data.get("password")
        
        logger.info(f"SIGNUP ATTEMPT - Username: {username}")
        
        if not username or not password:
            logger.warning("SIGNUP FAILED - Missing credentials")
            return jsonify({"error": "Username and password required"}), 400
            
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            logger.warning(f"SIGNUP FAILED - Username already exists: {username}")
            return jsonify({"error": "Username already exists"}), 400
            
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.add(new_user)
        db.commit()
        logger.info(f"SIGNUP SUCCESS - User created: {username}")
        return jsonify({"message": "User created successfully"}), 201
    except Exception as e:
        db.rollback()
        logger.error(f"SIGNUP ERROR: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route("/login", methods=["POST"])
def login():
    db = SessionLocal()
    try:
        data = request.json or {}
        username = data.get("username")
        password = data.get("password")
        
        logger.info(f"LOGIN ATTEMPT - Username: {username}")
        
        user = db.query(User).filter(User.username == username).first()
        if user and check_password_hash(user.password, password):
            logger.info(f"LOGIN SUCCESS - Username: {username}")
            return jsonify({"message": "Login successful", "username": username}), 200
        else:
            logger.warning(f"LOGIN FAILED - Invalid credentials for {username}")
            return jsonify({"error": "Invalid username or password"}), 401
    except Exception as e:
        logger.error(f"LOGIN ERROR: {str(e)}")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()

@app.route('/reports/<path:filename>')
def download_report(filename):
    return send_from_directory(REPORTS_FOLDER, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5001)))