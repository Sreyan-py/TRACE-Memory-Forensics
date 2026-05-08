# TRACE: Advanced Memory Forensics SOC Dashboard

TRACE is a sophisticated, enterprise-grade Security Operations Center (SOC) dashboard and simulated memory forensics engine. Designed to detect zero-day rootkits, fileless malware, and advanced persistent threats (APTs), TRACE provides a breathtaking cyber-aesthetic UI and a highly detailed backend analysis engine.

## 🚀 Features

- **Advanced Memory Forensics Simulator**: Upload any raw memory dump to simulate deep heuristic scanning via the Volatility framework.
- **Enterprise SOC Dashboard**: Beautiful visualizations using Recharts, including Threat Activity Area Charts, Malware Distribution Pie Charts, and Severity Trend Bar Charts.
- **Deep Threat Inspection UI**: A massive results dashboard featuring a glowing Threat Score Meter, identifying Suspicious Processes, Injected DLLs, Registry Anomalies, and Malicious Network Connections.
- **AI-Assisted Incident Reports**: Automatically generates an AI Analyst Summary detailing the compromise.
- **Downloadable PDF Reports**: Automatically compiles the forensic data into a professional, downloadable PDF using ReportLab.
- **Secure Authentication System**: Built-in login/signup flow utilizing SQLite and Werkzeug password hashing.

## 🛠️ Technology Stack

- **Frontend**: React.js, TailwindCSS, React Router, Recharts, Lucide Icons, Vite
- **Backend**: Python, Flask, SQLite3, ReportLab
- **Security**: Werkzeug secure password hashing

## 💻 Running the Application Locally

### 1. Start the Flask Backend
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install flask flask-cors reportlab werkzeug
python app.py
```
*The backend will run on `http://127.0.0.1:5001`*

### 2. Start the React Frontend
Open a new terminal window:
```bash
cd frontend
npm install
npm run dev
```
*The frontend will run on `http://localhost:5173`*

## 🛡️ Usage
1. Open your browser to `http://localhost:5173`.
2. Create a new Agent account on the secure Authentication Portal.
3. Navigate to the **Analysis** tab and upload a memory dump (or any file to test the simulation engine).
4. Review the extracted indicators of compromise (IOCs) and download the official PDF report.

---
*Built as a showcase for Advanced Agentic Coding and Cybersecurity Development.*
