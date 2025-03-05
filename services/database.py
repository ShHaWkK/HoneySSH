import sqlite3
from datetime import datetime

DB_PATH = "logs/ssh_logs.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssh_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            command TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_ssh_attempt(ip, command):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO ssh_logs (ip, command)
        VALUES (?, ?)
    ''', (ip, command))
    conn.commit()
    conn.close()

init_db()
