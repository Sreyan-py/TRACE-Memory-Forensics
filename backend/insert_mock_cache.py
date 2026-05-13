import hashlib
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys

# We need to import CachedAnalysis from app.py
sys.path.append('.')
from app import CachedAnalysis, Base

engine = create_engine("sqlite:///users.db")
Session = sessionmaker(bind=engine)
session = Session()

# Calculate hash of test_dump.raw
sha256 = hashlib.sha256()
with open("test_dump.raw", "rb") as f:
    sha256.update(f.read())
file_hash = sha256.hexdigest()

indicators = {
    "suspicious_processes": ["cmd.exe", "mimikatz.exe"],
    "hidden_processes": ["hidden1.exe"],
    "dll_injections": ["inject.dll"],
    "network_connections": ["1.2.3.4:80"],
    "malware_indicators": ["Malware signature found"]
}

cache = CachedAnalysis(
    file_hash=file_hash,
    filename="test_dump.raw",
    threat_score=85,
    severity="CRITICAL",
    indicators=json.dumps(indicators),
    plugin_results=json.dumps({"pslist": [], "malfind": [], "netscan": []}),
    timestamp=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
)

session.merge(cache)
session.commit()
print(f"Inserted mock cache for hash {file_hash}")
