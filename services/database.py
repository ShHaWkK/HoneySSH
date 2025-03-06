import sqlite3
import os

# Chemin de la base de données
DB_DIR = "logs"
DB_PATH = os.path.join(DB_DIR, "honeypot.db")

# Fonction pour initialiser la base de données
def init_db():
    # Vérifier et créer le dossier logs si nécessaire
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)

    # Connexion à la base SQLite
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Création des tables si elles n'existent pas
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ssh_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip TEXT,
        username TEXT,
        password TEXT,
        command TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

# Fonction pour enregistrer une tentative SSH
def log_ssh_attempt(ip, username, password, command):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO ssh_attempts (ip, username, password, command)
    VALUES (?, ?, ?, ?)
    """, (ip, username, password, command))

    conn.commit()
    conn.close()

# Fonction pour bloquer une IP après trop de tentatives
def block_ip(ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT OR IGNORE INTO blocked_ips (ip) VALUES (?)
    """, (ip,))

    conn.commit()
    conn.close()

# Fonction pour vérifier si une IP est bloquée
def is_ip_blocked(ip):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT COUNT(*) FROM blocked_ips WHERE ip = ?
    """, (ip,))
    result = cursor.fetchone()

    conn.close()
    return result[0] > 0  # True si l'IP est bloquée, False sinon

# Initialiser la base de données au démarrage
init_db()
