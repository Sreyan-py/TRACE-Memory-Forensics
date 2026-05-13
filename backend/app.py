from analysis.volatility_runner import analyze_memory
from analysis.report_generator import generate_pdf_report
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
# pyrefly: ignore [missing-import]
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

    if "file" not in request.files:
        return jsonify({
            "error": "No file uploaded"
        }), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({
            "error": "Empty filename"
        }), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)

    file.save(filepath)

    analysis_result = analyze_memory(filepath)

    if "error" in analysis_result:
        return jsonify({
            "error": f"Analysis failed: {analysis_result['error']}. Are you sure this is a valid memory dump?"
        }), 400
    
    report_filename = generate_pdf_report(analysis_result, file.filename)
    report_url = f"https://trace-memory-forensics.onrender.com/reports/{report_filename}"

    return jsonify({
        "message": "Analysis Complete",
        "filename": file.filename,
        "analysis": analysis_result,
        "report_url": report_url
    })

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