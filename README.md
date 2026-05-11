# TRACE: Advanced Memory Forensics SOC Dashboard

TRACE is a sophisticated, enterprise-grade Security Operations Center (SOC) dashboard and simulated memory forensics engine. Designed to detect zero-day rootkits, fileless malware, and advanced persistent threats (APTs), TRACE provides a breathtaking cyber-aesthetic UI and a highly detailed backend analysis engine.

---

## 🚀 Live Deployment Links

### 🌐 Frontend
https://trace-memory-forensics.vercel.app

### ⚙️ Backend API
https://trace-memory-forensics.onrender.com

---

## 🚀 Features

- **Advanced Memory Forensics Simulator** — Upload raw memory dumps and simulate deep heuristic scanning using Volatility-inspired workflows.

- **Enterprise SOC Dashboard** — Interactive cyber visualizations powered by Recharts including Threat Activity Area Charts, Malware Distribution Pie Charts, and Severity Trend Analytics.

- **Deep Threat Inspection UI** — Analyze Suspicious Processes, Injected DLLs, Registry Anomalies, and Malicious Network Connections using a cinematic SOC interface.

- **AI-Assisted Incident Reports** — Automatically generates AI Analyst summaries and forensic insights.

- **Downloadable PDF Reports** — Export detailed investigation reports using ReportLab.

- **Secure Authentication System** — Built-in login/signup system with SQLite and Werkzeug password hashing.

---

## 🛠️ Technology Stack

### Frontend
- React.js
- TailwindCSS
- React Router
- Recharts
- Lucide Icons
- Vite

### Backend
- Python
- Flask
- SQLite3
- ReportLab

### Security
- Werkzeug secure password hashing

---

## ☁️ Deployment

- Frontend hosted on Vercel
- Backend hosted on Render
- Source Control managed via GitHub

---

## 💻 Running the Application Locally

### 1. Start the Flask Backend

```bash
cd backend

python3 -m venv venv
source venv/bin/activate

pip install flask flask-cors reportlab werkzeug

python app.py
```

The backend will run on:

```bash
http://127.0.0.1:5001
```

---

### 2. Start the React Frontend

Open a new terminal window:

```bash
cd frontend

npm install
npm run dev
```

The frontend will run on:

```bash
http://localhost:5173
```

---

## 🛡️ Usage

1. Open the deployed application:
   https://trace-memory-forensics.vercel.app

2. Create a new Agent account using the secure Authentication Portal

3. Navigate to the Analysis tab

4. Upload a memory dump (or any file to test the simulation engine)

5. Review Indicators of Compromise (IOCs)

6. Analyze Suspicious Processes, DLL Injections, Registry Anomalies, and Network Threats

7. Download the official PDF forensic investigation report

---

## 📸 Screenshots

### Authentication Portal
<img width="1464" height="820" alt="Screenshot 2026-05-08 at 11 54 39" src="https://github.com/user-attachments/assets/85cdfa93-e535-4cd9-9dba-8d024167573f" />

### SOC Dashboard
<img width="1467" height="763" alt="Screenshot 2026-05-08 at 11 56 04" src="https://github.com/user-attachments/assets/02826423-18eb-452a-b7c4-482daa6a734b" />


### Threat Analysis Results
<img width="1211" height="775" alt="Screenshot 2026-05-08 at 11 56 36" src="https://github.com/user-attachments/assets/e6754f5f-e794-472e-b00d-81acc9ff65a0" />


---

## 👨‍💻 Developed By

### Sreyan Swarna

Cybersecurity Enthusiast | SOC & Memory Forensics Project Developer

---

## 🎯 Future Improvements

- Real Volatility framework integration
- Live threat intelligence feeds
- Multi-user SOC analyst system
- AI-powered malware classification
- SIEM integration support

---

## 📜 License

This project is built for educational, cybersecurity research, and showcase purposes.

---

Built as a showcase for Advanced Agentic Coding and Cybersecurity Development.
