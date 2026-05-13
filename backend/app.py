from analysis.volatility_runner import analyze_memory
from analysis.report_generator import generate_pdf_report
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
REPORTS_FOLDER = "reports"

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
if not os.path.exists(REPORTS_FOLDER):
    os.makedirs(REPORTS_FOLDER)

DB_FILE = "users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    threat_score INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    scan_timestamp TEXT NOT NULL,
                    report_path TEXT NOT NULL,
                    dump_size INTEGER,
                    suspicious_process_count INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                 )''')
    conn.commit()
    conn.close()

init_db()

@app.route("/")
def home():
    return {
        "message": "TRACE Backend Running"
    }

@app.route("/upload", methods=["POST"])
def upload_file():
    try:
        username = request.form.get("username")
        if not username:
            return jsonify({"error": "Username is required"}), 400

        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]

        if file.filename == "":
            return jsonify({"error": "Empty filename"}), 400

        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return jsonify({"error": "Uploaded file is empty or corrupted."}), 400

        # Get user ID
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_row = c.fetchone()
        if not user_row:
            conn.close()
            return jsonify({"error": "User not found"}), 404
        user_id = user_row[0]

        analysis_result = analyze_memory(filepath)

        if "error" in analysis_result:
            conn.close()
            return jsonify({
                "error": f"Analysis failed: {analysis_result['error']}. Are you sure this is a valid memory dump?"
            }), 400
        
        report_filename = generate_pdf_report(analysis_result, file.filename)
        report_url = f"http://127.0.0.1:5001/reports/{report_filename}"

        # Insert scan record
        threat_score = analysis_result.get("threat_score", 0)
        severity = analysis_result.get("severity", "LOW")
        scan_timestamp = analysis_result.get("timestamps", {}).get("scan_end", "")
        suspicious_process_count = len(analysis_result.get("suspicious_processes", []))
        dump_size = os.path.getsize(filepath)

        c.execute('''INSERT INTO scans 
                     (user_id, filename, threat_score, severity, scan_timestamp, report_path, dump_size, suspicious_process_count)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', 
                  (user_id, file.filename, threat_score, severity, scan_timestamp, report_filename, dump_size, suspicious_process_count))
        conn.commit()
        conn.close()

        return jsonify({
            "message": "Analysis Complete",
            "filename": file.filename,
            "analysis": analysis_result,
            "report_url": report_url
        })
    except Exception as e:
        return jsonify({
            "error": f"Internal server error during upload processing: {str(e)}"
        }), 500

@app.route("/dashboard/stats/<username>", methods=["GET"])
def dashboard_stats(username):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        user_row = c.fetchone()
        if not user_row:
            conn.close()
            return jsonify({"error": "User not found"}), 404
        user_id = user_row[0]
        
        c.execute("SELECT threat_score, severity, scan_timestamp, suspicious_process_count FROM scans WHERE user_id = ? ORDER BY id ASC", (user_id,))
        scans = c.fetchall()
        conn.close()
        
        total_dumps = len(scans)
        critical_threats = sum(1 for s in scans if s[1] in ("CRITICAL", "HIGH"))
        avg_threat = sum(s[0] for s in scans) / total_dumps if total_dumps > 0 else 0
        health_score = max(0, int(100 - avg_threat))
        
        distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for s in scans:
            if s[1] in distribution:
                distribution[s[1]] += 1
                
        distribution_data = [{"name": k, "value": v} for k, v in distribution.items() if v > 0]
        if not distribution_data:
            distribution_data = [{"name": "No Threats", "value": 1}]
            
        activity_data = []
        for i, s in enumerate(scans[-10:]): # Last 10 scans
            activity_data.append({
                "name": f"Scan {i+1}",
                "threats": s[3],
                "score": s[0]
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

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    hashed_password = generate_password_hash(password)
    
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 400
    finally:
        conn.close()
        
    return jsonify({"message": "User created successfully"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    
    if row and check_password_hash(row[0], password):
        return jsonify({"message": "Login successful", "username": username}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401

@app.route('/reports/<path:filename>')
def download_report(filename):
    return send_from_directory(REPORTS_FOLDER, filename, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, port=5001)