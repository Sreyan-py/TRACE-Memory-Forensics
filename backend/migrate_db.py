"""
migrate_db.py — Add new security columns to the existing users table.
Run once: python migrate_db.py
Safe to run multiple times (uses IF NOT EXISTS / try-except).
"""
import sqlite3
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

COLUMNS_TO_ADD = [
    ("email",                  "TEXT"),
    ("failed_attempts",        "INTEGER DEFAULT 0"),
    ("locked_until",           "TEXT"),
    ("token_version",          "INTEGER DEFAULT 0"),
    ("otp_hash",               "TEXT"),
    ("otp_expires_at",         "TEXT"),
    ("reset_token",            "TEXT"),
    ("reset_token_expires_at", "TEXT"),
]

def migrate():
    if not os.path.exists(DB_PATH):
        print(f"[MIGRATE] Database not found at {DB_PATH}. Will be created by SQLAlchemy on first run.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get existing columns
    cursor.execute("PRAGMA table_info(users)")
    existing = {row[1] for row in cursor.fetchall()}
    print(f"[MIGRATE] Existing columns: {existing}")

    for col_name, col_def in COLUMNS_TO_ADD:
        if col_name not in existing:
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
                print(f"[MIGRATE] Added column: {col_name}")
            except sqlite3.OperationalError as e:
                print(f"[MIGRATE] Skipped {col_name}: {e}")
        else:
            print(f"[MIGRATE] Column already exists: {col_name}")

    conn.commit()
    conn.close()
    print("[MIGRATE] Migration complete.")

if __name__ == "__main__":
    migrate()
