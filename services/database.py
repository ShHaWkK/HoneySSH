import sqlite3
import json

DB_PATH = "logs/honeypot.db"
USER_FILE = "config/fake_users.json"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ssh_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            command TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def log_ssh_attempt(ip, command):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO ssh_attempts (ip, command) VALUES (?, ?)", (ip, command))
    conn.commit()
    conn.close()

def get_fake_users():
    with open(USER_FILE, "r") as f:
        return json.load(f)

init_db()
