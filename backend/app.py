import os
from flask import Flask, send_from_directory, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from migrate_db import migrate

# Load environment variables from .env
load_dotenv()
from database import engine, Base
import models.models  # noqa: F401 — ensures all ORM models are registered before table creation
from routes.auth import auth_bp
from routes.profile import profile_bp
from routes.forensics import forensics_bp
from routes.dashboard import dashboard_bp
from routes.intel import intel_bp
from routes.lab import lab_bp

app = Flask(__name__)

# Strict CORS for production security
CORS(app, resources={
    r"/*": {
        "origins": [
            "https://trace-memory-forensics.vercel.app",
            "http://localhost:5173",
            "http://localhost:5174"
        ],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# Configurations
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORTS_FOLDER = os.path.join(BASE_DIR, "reports")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORTS_FOLDER'] = REPORTS_FOLDER
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'trace-core-secure-key')
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 # 1GB

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(profile_bp)
app.register_blueprint(forensics_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(intel_bp)
app.register_blueprint(lab_bp)

# Static Routes
@app.route('/reports/<path:filename>')
def download_report(filename):
    return send_from_directory(app.config['REPORTS_FOLDER'], filename, as_attachment=True)

@app.route("/")
@app.route("/health")
def health_check():
    return jsonify({
        "success": True,
        "status": "operational", 
        "engine": "TRACE-Volatility-V3",
        "environment": os.environ.get("FLASK_ENV", "production")
    })

# Initialize DB
migrate()
Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)
