import hashlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app import User, Scan, ActivityLog, Base
from datetime import datetime
from werkzeug.security import generate_password_hash

engine = create_engine("sqlite:///users.db")
Session = sessionmaker(bind=engine)
session = Session()

# Create tables if not exist
Base.metadata.create_all(engine)

# Create default investigator user
username = "investigator"
user = session.query(User).filter(User.username == username).first()

if not user:
    user = User(
        username=username,
        password=generate_password_hash("Trace@2026"),
        display_name="Senior Lead Investigator",
        codename="STRIKER-01",
        role="Threat Hunter",
        specialization="Memory Forensics",
        location="SOC Alpha - Zone 4",
        rank="Elite Forensics Operator"
    )
    session.add(user)
    session.commit()
    print(f"User {username} created.")
else:
    print(f"User {username} already exists.")

# Add some mock scans if empty
scan_count = session.query(Scan).filter(Scan.user_id == user.id).count()
if scan_count == 0:
    scans = [
        Scan(
            user_id=user.id,
            filename="win10_mem_dump.raw",
            file_hash="mock_hash_1",
            threat_score=85,
            severity="CRITICAL",
            scan_timestamp="2026-05-13T14:20:00Z",
            dump_size=2147483648,
            report_path="report_1.pdf",
            suspicious_process_count=4
        ),
        Scan(
            user_id=user.id,
            filename="suspicious_artifact.exe",
            file_hash="mock_hash_2",
            threat_score=45,
            severity="MEDIUM",
            scan_timestamp="2026-05-14T09:15:00Z",
            dump_size=1048576,
            report_path="report_2.pdf",
            suspicious_process_count=1
        )
    ]
    session.add_all(scans)
    
    # Add activity logs
    logs = [
        ActivityLog(user_id=user.id, message="Neural link established with SOC Alpha.", event_type="auth"),
        ActivityLog(user_id=user.id, message="Critical threat neutralized in win10_mem_dump.raw.", event_type="threat"),
        ActivityLog(user_id=user.id, message="Deep scan initiated for suspicious_artifact.exe.", event_type="lab"),
        ActivityLog(user_id=user.id, message="IOC database synchronized with global feed.", event_type="intel")
    ]
    session.add_all(logs)
    
    session.commit()
    print("Mock data seeded.")
else:
    print("Data already exists.")

session.close()
