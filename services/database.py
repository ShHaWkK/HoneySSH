import sqlite3
import os

DB_DIR = "logs"
DB_PATH = os.path.join(DB_DIR, "ssh_logs.db")

def init_db():
    # Vérifier si le dossier logs existe, sinon le créer
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)

    # Connexion à la base de données (elle est créée si elle n'existe pas)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssh_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            command TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

def log_ssh_attempt(ip, command):
    # Vérifie si la base de données existe, sinon l'initialiser
    if not os.path.exists(DB_PATH):
        init_db()

    # Insére
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO ssh_logs (ip, command)
        VALUES (?, ?)
    ''', (ip, command))

    conn.commit()
    conn.close()

init_db()
