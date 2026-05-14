# TRACE: Elite Memory Forensics & Threat Intel Platform

![TRACE Dashboard](https://raw.githubusercontent.com/Sreyan-py/TRACE-Memory-Forensics/main/screenshots/dashboard_v2.png)

## 🛡️ Project Overview
TRACE is a next-generation Digital Forensics and Incident Response (DFIR) platform designed for modern Security Operations Centers (SOC). It provides analysts with a high-fidelity interface to analyze memory dumps, track global threat intelligence, and manage malware samples within a unified, cyberpunk-themed workstation.

The core of TRACE is its **Deterministic Forensic Engine**, which ensures consistent, auditable results even when processing complex memory artifacts under resource-constrained environments.

## 🚀 Key Features
- **Deterministic Forensic Engine**: Consistent SHA256-based analysis for auditable results.
- **Elite SOC Dashboard**: Real-time telemetry, threat radar, and global pulse visualization.
- **Deep Analysis Pipeline**: Support for `.raw`, `.mem`, `.dmp`, and `.img` forensic images.
- **Threat Intelligence**: Integrated MITRE ATT&CK technique mapping and live CVE tracking.
- **Malware Laboratory**: Static analysis lab with entropy visualization and PE import risk assessment.
- **Analyst Progression System**: Dynamic rank calculation based on forensic performance.
- **Automated Reporting**: Generation of professional PDF forensic reports for every scan.

## 🛠️ Tech Stack
### Frontend
- **React 19 (Vite)**: High-performance component-based architecture.
- **Tailwind CSS v4**: Utility-first styling with custom cyber-design tokens.
- **Lucide React**: Enterprise-grade iconography.
- **Recharts**: Advanced data visualization for threat telemetry.

### Backend
- **Flask**: Lightweight and modular WSGI application framework.
- **SQLAlchemy**: Robust ORM for user and forensic data management.
- **Volatility Integration**: Automated memory forensics (Simulated/Hybrid mode).
- **ReportLab**: Dynamic PDF generation for forensic documentation.

## 📂 Repository Structure
```text
TRACE-Memory-Forensics/
├── frontend/             # React application
│   ├── src/
│   │   ├── components/   # UI widgets & layouts
│   │   ├── pages/        # Main SOC modules
│   │   └── services/     # API integration
├── backend/              # Flask API
│   ├── analysis/         # Forensic engine logic
│   ├── models/           # DB schemas
│   ├── routes/           # API blueprints
│   ├── uploads/          # Artifact quarantine
│   └── reports/          # Generated documentation
└── scripts/              # Setup & seeding utilities
```

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.10+
- Node.js 18+
- npm or yarn

### 1. Backend Setup
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python scripts/seed_db.py # Initialize analyst database
python app.py
```

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

## 🧠 Deterministic Engine Explained
TRACE uses a hybrid forensic approach. When a memory dump is uploaded, the system calculates a unique SHA256 signature. This signature is used to:
1. **Cache Lookups**: Instant retrieval of previous analysis for identical artifacts.
2. **Stable Fallback**: If full Volatility plugin execution fails due to memory limits, the engine generates a high-fidelity deterministic result based on entropy and signature matching, ensuring the analyst always receives actionable data.

## 📜 License
Professional use only. Designed for educational and cybersecurity portfolio demonstration.

---
**Developed by [Sreyan-py](https://github.com/Sreyan-py)**
