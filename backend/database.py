# import os
# from sqlalchemy import create_engine
# from sqlalchemy.orm import sessionmaker, declarative_base

# BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# fallback_db_path = os.path.join(BASE_DIR, "users.db")

# # Use DATABASE_URL for PostgreSQL (Render/Heroku), fallback to local SQLite
# DB_URL = os.environ.get("DATABASE_URL")
# if not DB_URL:
#     DB_URL = f"sqlite:///{fallback_db_path}"
# elif DB_URL.startswith("postgres://"):
#     # Fix for SQLAlchemy/Render compatibility
#     DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

# # SQLite-specific optimization (check_same_thread)
# connect_args = {"check_same_thread": False} if "sqlite" in DB_URL else {}

# engine = create_engine(DB_URL, connect_args=connect_args)
# SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# Base = declarative_base()


import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
fallback_db_path = os.path.join(BASE_DIR, "users.db")

# Use DATABASE_URL for PostgreSQL (Render/Heroku), fallback to local SQLite
DB_URL = os.environ.get("DATABASE_URL")

if not DB_URL:
    DB_URL = f"sqlite:///{fallback_db_path}"
elif DB_URL.startswith("postgres://"):
    # Fix for SQLAlchemy/Render compatibility
    DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)

# ADD THESE LINES
print("=" * 60)
print("DATABASE URL :", DB_URL)
print("DATABASE PATH:", fallback_db_path)
print("=" * 60)

# SQLite-specific optimization (check_same_thread)
connect_args = {"check_same_thread": False} if "sqlite" in DB_URL else {}

engine = create_engine(DB_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()