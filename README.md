# TRACE - Advanced Memory Forensics & Threat Detection Platform

**TRACE** is a professional-grade, AI-assisted memory forensics and incident response platform. It provides deterministic, highly accurate analysis of raw memory dumps to identify zero-day threats, rootkits, fileless malware, and advanced persistent threats (APTs) using **Volatility3**.

### Deployed URLs
- **Frontend (Vercel):** [https://trace-memory-forensics.vercel.app](https://trace-memory-forensics.vercel.app) *(Update with your actual Vercel URL)*
- **Backend (Render):** [https://trace-memory-forensics.onrender.com](https://trace-memory-forensics.onrender.com)

---

## 🚀 Key Features

### 1. Deterministic Forensic Engine
TRACE utilizes a strict, mathematically weighted threat scoring algorithm. By directly parsing the JSON outputs from Volatility3, TRACE evaluates suspicious processes, injected DLLs, and anomalous network connections.
- **Identical Memory Dumps = Identical Results.** 
- 100% stable, repeatable, and robust scoring mechanism (clamped at 100).
- Eradicates "random" or mock threat scoring, making it completely viable for real SOC environments.

### 2. SHA256 Cryptographic Caching
Memory analysis is extremely computationally expensive. TRACE calculates a `SHA256` hash for every uploaded memory dump. 
- If an exact memory dump has been previously analyzed, TRACE instantly bypasses the Volatility engine and retrieves the results from the `cached_analysis` database, dropping response times from minutes to milliseconds.

### 3. Supported File Formats
TRACE's robust upload pipeline handles large file constraints (up to 1GB) and officially supports:
- `.raw`
- `.mem`
- `.dmp`
- `.img`

### 4. Real-Time SOC Dashboard
A sleek, isolated React dashboard built for incident responders.
- Visualizes threat distributions (CRITICAL, HIGH, MEDIUM, LOW).
- Tracks individual SOC analyst scan history in real-time.
- Strict data isolation: Your dashboard explicitly tracks and displays only the forensic scans authorized under your user account.

### 5. Multi-User Authentication & Persistence
Powered by `SQLAlchemy`, TRACE features a centralized SQLite (dev) / PostgreSQL (production) database.
- Secures passwords using robust `werkzeug` cryptographic hashing.
- Safely maintains cross-device user sessions and isolates forensic reports per analyst.

---

## 🛠 Tech Stack

- **Frontend:** React, Vite, TailwindCSS, Recharts, Lucide Icons
- **Backend:** Python, Flask, Gunicorn, SQLAlchemy
- **Forensic Engine:** Volatility3 (`vol`)
- **Reporting:** ReportLab (Automated PDF generation)
- **Database:** PostgreSQL (Production) / SQLite (Local Fallback)
- **Infrastructure:** Vercel (Frontend), Render (Backend WSGI)

---
## 💻 Setup Instructions

### Local Development

**1. Clone the repository:**
```bash
git clone https://github.com/Sreyan-py/TRACE-Memory-Forensics.git
cd TRACE-Memory-Forensics
```

**2. Backend Setup:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # (Windows: venv\Scripts\activate)
pip install -r requirements.txt
```

**3. Volatility3 Installation Requirement:**
Ensure the `vol` command is globally available in your PATH to allow the backend subprocess calls to execute correctly. 
- *Note: TRACE gracefully handles plugin crashes and timeouts (300s limit) to prevent total analysis failure.*

**4. Run Local Backend:**
```bash
gunicorn app:app --bind 0.0.0.0:5001
```

**5. Frontend Setup:**
```bash
cd ../frontend
npm install
npm run dev
```

### Production Deployment

**Render (Backend):**
- Create a new Web Service on Render.
- Set Root Directory to `backend`.
- Build Command: `pip install -r requirements.txt`
- Start Command: `gunicorn app:app`
- Environment Variables:
  - `PYTHON_VERSION`: `3.10.x`
  - `DATABASE_URL`: `postgres://...` (Render Postgres instance)
  - `SECRET_KEY`: `<your-secure-random-key>`

**Vercel (Frontend):**
- Import the repository into Vercel.
- Framework Preset: `Vite`.
- Root Directory: `frontend`.
- No additional environment variables required natively.

---

## 👥 Team Credits

- **Sunanda**: CLI integration, Volatility3 architecture, and Plugin configuration.
- **Sreyan**: Full-stack integration, Deterministic Threat Detection Engine, PostgreSQL/Auth Architecture, and Real-Time Dashboard UI.

---
*Built for Advanced Threat Detection and Memory Forensics.*
