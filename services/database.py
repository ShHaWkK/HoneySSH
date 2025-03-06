import sqlite3
import os
import json

# Chemins des fichiers
DB_DIR = "logs"
DB_PATH = os.path.join(DB_DIR, "honeypot.db")
USER_FILE = "config/fake_users.json"

# Fonction pour initialiser la base de données
def init_db():
    """Initialise la base de données et crée les tables si elles n'existent pas"""
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Table des tentatives SSH
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

    # Table des IP bloquées
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
    """Log une tentative de connexion SSH en base de données"""
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
    """Ajoute une IP à la liste des IP bloquées"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT OR IGNORE INTO blocked_ips (ip) VALUES (?)
    """, (ip,))

    conn.commit()
    conn.close()

# Fonction pour vérifier si une IP est bloquée
def is_ip_blocked(ip):
    """Vérifie si une IP est bloquée"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT COUNT(*) FROM blocked_ips WHERE ip = ?
    """, (ip,))
    result = cursor.fetchone()

    conn.close()
    return result[0] > 0  # Retourne True si l'IP est bloquée, False sinon

# Fonction pour charger les faux utilisateurs
def get_fake_users():
    """Charge les faux utilisateurs depuis fake_users.json"""
    if not os.path.exists(USER_FILE):
        return {}

    with open(USER_FILE, "r") as f:
        return json.load(f)

# Initialiser la base de données au démarrage
init_db()
