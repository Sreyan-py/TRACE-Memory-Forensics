from sqlalchemy import Column, Integer, String, Text, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password = Column(String(255), nullable=False)
    display_name = Column(String(100))
    codename = Column(String(50))
    bio = Column(Text)
    role = Column(String(50), default="SOC Analyst")
    specialization = Column(String(50), default="Generalist")
    location = Column(String(100), default="Remote Hub")
    avatar_path = Column(String(255))
    avatar_preset = Column(String(50), default="agent_1")
    rank = Column(String(50), default="Rookie Analyst")
    joined_at = Column(String(50), default=lambda: datetime.now().strftime("%Y-%m-%d"))
    last_active = Column(String(50), default=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"))
    
    scans = relationship("Scan", back_populates="user")
    activities = relationship("ActivityLog", back_populates="user")

class ActivityLog(Base):
    __tablename__ = "activity_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    event_type = Column(String(50)) # threat, system, intel, lab, auth
    message = Column(Text, nullable=False)
    timestamp = Column(String(50), default=lambda: datetime.now().strftime("%H:%M:%S"))
    
    user = relationship("User", back_populates="activities")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    file_hash = Column(String(64), nullable=False, index=True)
    file_type = Column(String(20), default="raw")
    threat_score = Column(Integer, nullable=False)
    severity = Column(String(20), nullable=False)
    forensic_summary = Column(Text)
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

# Database Engine
engine = create_engine("sqlite:///users.db")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
