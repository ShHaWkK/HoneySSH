#!/usr/bin/env python3
import socket
import threading
import paramiko
import sqlite3
import time
import random
import re
import os
import smtplib
from email.mime.text import MIMEText
from fpdf import FPDF
import uuid
import select
import signal
import sys
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import logging
import json
import hashlib
import string
import csv
import subprocess
import psutil
import shutil
import asyncio
from telegram import Bot
from telegram.error import TelegramError


# Configuration des logs
logging.basicConfig(filename='honeypot.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
HOST = ""  # Listen on all interfaces
PORT = 2224
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
ENABLE_REDIRECTION = True
REAL_SSH_HOST = "192.168.1.100"
REAL_SSH_PORT = 22
TELEGRAM_TOKEN = '7925032655:AAFbTyetwfQEw0qdCEgMgJceyzJRRvwlO-c'
CHAT_ID = '6802198160'
bot = Bot(token=TELEGRAM_TOKEN)

DB_NAME = "server_data.db"
FS_DB = "filesystem.db"
BRUTE_FORCE_THRESHOLD = 5
CMD_LIMIT_PER_SESSION = 50
_brute_force_alerted = set()
_brute_force_lock = threading.Lock()
current_language = "fr"

SESSION_LOG_DIR = "session_logs"
if not os.path.exists(SESSION_LOG_DIR):
    os.makedirs(SESSION_LOG_DIR, exist_ok=True)

FAKE_SERVICES = {
    "ftp": 21,
    "http": 80,
    "mysql": 3306
}

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "honeycute896@gmail.com"  # Replace with your email
SMTP_PASS = "jawm fmcm dmaf qkyl"  # Replace with your app-specific password
ALERT_FROM = SMTP_USER
ALERT_TO = "admin@example.com"  # Replace with a valid email


PREDEFINED_USERS = {
    "admin": {"home": "/home/admin", "password": hashlib.sha256("admin123".encode()).hexdigest(), "files": {
        "admin_credentials.txt": "admin:supersecret\nImportant credentials for admin account",
        "admin_sshkey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...admin_key",
        "projectA_config": "projectA: configuration data..."
    }, "theme": "green", "motto": "Securing the future"},
    "devops": {"home": "/home/devops", "password": hashlib.sha256("devops456".encode()).hexdigest(), "files": {
        "deploy_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD...devops_key",
        "jenkins_config.yml": "jenkins: {url: http://localhost:8080, user: admin, pass: admin123}"
    }, "theme": "blue", "motto": "Building with code"},
    "dbadmin": {"home": "/home/dbadmin", "password": hashlib.sha256("dbadmin789".encode()).hexdigest(), "files": {
        "db_backup.sql": "-- Fake SQL dump\nDROP TABLE IF EXISTS test;",
        "db_scripts.sh": "#!/bin/bash\necho 'Running DB maintenance...'"
    }, "theme": "red", "motto": "Master of data"}
}

def generate_dynamic_user():
    username = f"temp_{''.join(random.choices(string.ascii_lowercase, k=6))}"
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    PREDEFINED_USERS[username] = {
        "home": f"/home/{username}",
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "files": {f"{username}_notes.txt": f"Temp user {username} notes"},
        "theme": random.choice(["green", "blue", "red"]),
        "motto": f"Temp user {random.choice(['explorer', 'guardian', 'coder'])}"
    }
    return username, password

KEYSTROKES_LOG = "keystrokes.log"
FILE_TRANSFER_LOG = "file_transfers.log"
HONEY_TOKEN_FILES = [
    "/home/admin/financial_report.pdf",
    "/home/admin/compromised_email.eml",
    "/home/admin/secret_plans.txt",
    "/secret/critical_data.txt"
]

def get_dynamic_df():
    result = subprocess.run(['df', '-h'], capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else "Error retrieving disk usage"

def get_dynamic_uptime():
    result = subprocess.run(['uptime'], capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else "Error retrieving uptime"

def get_dynamic_ps():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        try:
            pinfo = proc.info
            processes.append(f"{pinfo['username']:<10} {pinfo['pid']:<6} {pinfo['cpu_percent']:.1f} {pinfo['memory_percent']:.1f} ... {pinfo['name']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return "\n".join(processes)

def get_dynamic_netstat():
    result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else "Error retrieving network stats"

def get_dynamic_messages():
    result = subprocess.run(['cat', '/var/log/syslog'], capture_output=True, text=True)
    return result.stdout[:1000] if result.returncode == 0 else "Error retrieving messages"

def get_dynamic_dmesg():
    result = subprocess.run(['dmesg'], capture_output=True, text=True)
    return result.stdout[:1000] if result.returncode == 0 else "Error retrieving dmesg"

def get_dev_null(): return ""
def get_dev_zero(): return "\0" * 1024

def init_filesystem_db():
    try:
        with sqlite3.connect(FS_DB) as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS filesystem (
                    path TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    content TEXT,
                    owner TEXT,
                    permissions TEXT,
                    mtime TEXT
                )
            """)
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"[!] Erreur FS DB init: {e}")

def load_filesystem():
    fs = {}
    try:
        with sqlite3.connect(FS_DB) as conn:
            cur = conn.cursor()
            cur.execute("SELECT path, type, content, owner, permissions, mtime FROM filesystem")
            for path, type_, content, owner, perms, mtime in cur.fetchall():
                fs[path] = {"type": type_, "content": content, "owner": owner, "permissions": perms, "mtime": mtime}
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if parent_dir not in fs:
                    fs[parent_dir] = {"type": "dir", "contents": [], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                if path.split("/")[-1] not in fs[parent_dir]["contents"]:
                    fs[parent_dir]["contents"].append(path.split("/")[-1])
    except sqlite3.Error as e:
        logging.error(f"[!] Erreur FS load: {e}")
    return fs

def save_filesystem(fs, base_path="honeypot_fs"):
    """
    Enregistre en base ET reproduit le FS dans un dossier local ./honeypot_fs
    (plutôt que sous /honeypot_fs qui demande des droits root).
    """
    # 1) Créer le dossier racine local s’il n’existe pas
    os.makedirs(base_path, exist_ok=True)

    # 2) Parcourir chaque entrée et écrire dans ./honeypot_fs
    for path, data in fs.items():
        local_path = os.path.join(base_path, path.lstrip("/"))
        if data["type"] == "dir":
            os.makedirs(local_path, exist_ok=True)
        else:
            parent = os.path.dirname(local_path)
            os.makedirs(parent, exist_ok=True)
            with open(local_path, "w", encoding="utf-8") as f:
                f.write(data.get("content", ""))

    # 3) Enregistrer en base SQLite
    try:
        with sqlite3.connect(FS_DB) as conn:
            cur = conn.cursor()
            for path, data in fs.items():
                cur.execute(
                    "INSERT OR REPLACE INTO filesystem (path, type, content, owner, permissions, mtime) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        path,
                        data["type"],
                        data.get("content", ""),
                        data.get("owner", "root"),
                        data.get("permissions", "rw-r--r--"),
                        data.get("mtime", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    )
                )
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"[!] Erreur FS save: {e}")

BASE_FILE_SYSTEM = {
    "/": {"type": "dir", "contents": ["bin", "sbin", "usr", "var", "opt", "root", "home", "etc", "tmp", "secret", "proc", "dev", "sys", "lib"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/bin": {"type": "dir", "contents": ["bash", "ls", "cat", "grep", "chmod", "chown", "mv", "cp", "top", "ifconfig", "ip"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/sbin": {"type": "dir", "contents": ["init", "sshd", "iptables", "reboot"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
}

def populate_predefined_users(fs):
    if "/home" not in fs:
        fs["/home"] = {"type": "dir", "contents": [], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    for user, info in PREDEFINED_USERS.items():
        home_dir = info["home"]
        fs[home_dir] = {"type": "dir", "contents": list(info["files"].keys()), "owner": user, "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        if user not in fs["/home"]["contents"] and home_dir.startswith("/home"):
            fs["/home"]["contents"].append(user)
        for filename, content in info["files"].items():
            fs[f"{home_dir}/{filename}"] = {"type": "file", "content": content, "owner": user, "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    return fs

init_filesystem_db()
FS = load_filesystem()
if not FS:
    FS = populate_predefined_users(BASE_FILE_SYSTEM.copy())
    save_filesystem(FS)

LANGUAGES = {
    "fr": {
        "welcome": "Bienvenue sur le serveur SSH simulé",
        "error": "Erreur: ",
        "exit": "Déconnexion...",
        "cmd_not_found": "commande non trouvée",
        "session_limit": "Limite de session atteinte. Veuillez vous reconnecter."
    },
    "en": {
        "welcome": "Welcome to the simulated SSH server",
        "error": "Error: ",
        "exit": "Disconnecting...",
        "cmd_not_found": "command not found",
        "session_limit": "Session limit reached. Please reconnect."
    }
}
current_language = "fr"

def send_telegram_alert(message):
    try:
        # exécute la coroutine
        asyncio.run(bot.send_message(chat_id=CHAT_ID, text=message))
        logging.info(f"[TELEGRAM] Alerte envoyée: {message}")
    except TelegramError as e:
        logging.error(f"[!] Erreur Telegram: {e}")

def send_alert(session_id, event_type, details, client_ip, username):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    message = f"[ALERT] {timestamp} - {client_ip} ({username}): {event_type} - {details}"
    logging.info(message)
    send_telegram_alert(message)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            msg = MIMEText(f"Time: {timestamp}\nIP: {client_ip}\nUser: {username}\nEvent: {event_type}\nDetails: {details}")
            msg["From"] = ALERT_FROM
            msg["To"] = ALERT_TO
            msg["Subject"] = f"Honeypot Alert - {event_type}"
            smtp.send_message(msg)
    except smtplib.SMTPException as e:
        logging.error(f"[!] SMTP error for {client_ip}: {str(e)}")

    try:
        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO events (timestamp, ip, username, event_type, details) VALUES (?, ?, ?, ?, ?)",
                        (timestamp, client_ip, username, event_type, details))
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"[!] Erreur DB: {e}")

def log_keystroke(session_id, client_ip, username, key, timestamp):
    try:
        with open(KEYSTROKES_LOG, "a", encoding="utf-8") as f:
            f.write(f"{timestamp},{session_id},{client_ip},{username},{key}\n")
    except Exception as e:
        logging.error(f"[!] Erreur keylog: {e}")

def log_session_video(session_id, client_ip, username, command, output):
    try:
        with open(f"{SESSION_LOG_DIR}/session_{session_id}.log", "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}|{client_ip}|{username}|{command}|{output}\n")
    except Exception as e:
        logging.error(f"[!] Erreur session video log: {e}")

def log_action(session_id, client_ip, username, action_type, details):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
        "session_id": session_id,
        "ip": client_ip,
        "username": username,
        "action_type": action_type,
        "details": details
    }
    with open(f"{SESSION_LOG_DIR}/actions_{session_id}.json", "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry) + "\n")

def check_brute_force(ip):
    with _brute_force_lock:
        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND timestamp > ?",
                        (ip, (datetime.now() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")))
            count = cur.fetchone()[0]
            if count >= BRUTE_FORCE_THRESHOLD and ip not in _brute_force_alerted:
                _brute_force_alerted.add(ip)
                send_alert(-1, "Brute Force Detected", f"{count} attempts from {ip} in 15m", ip, "unknown")
            return count

def detect_port_scan(ip, port):
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM events WHERE ip = ? AND event_type LIKE '%Connection' AND timestamp > ?",
                        (ip, (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")))
            count = cur.fetchone()[0]
            if count >= 3:
                send_alert(-1, "Port Scan Detected", f"Potential scan from {ip} on port {port}", ip, "unknown")
    except sqlite3.Error as e:
        logging.error(f"[!] Erreur port scan detection: {e}")

def get_completions(current_input, current_dir, username, fs, history, lang):
    base_cmds = {
        "ls": ["-l", "-a", "-la", "--help"], "cat": ["-n", "--help"], "rm": ["-f", "-r", "-rf", "--force"], "cp": ["-r", "--verbose"],
        "mv": ["-f", "--no-clobber"], "mkdir": ["-p", "--verbose"], "rmdir": ["--ignore-fail-on-non-empty"], "chmod": ["+x", "-r", "755", "644", "u+x"],
        "chown": ["--recursive"], "kill": ["-9", "-15", "--signal"], "ping": ["-c 4", "-t"], "traceroute": ["-n", "-m 10"],
        "vim": ["-o", "--readonly"], "nano": ["-w", "--backup"], "backup_data": ["--full", "--incremental"], "cd": [],
        "pwd": ["-P"], "whoami": [], "id": ["-u", "-g"], "uname": ["-a"], "ps": ["-aux", "-ef"], "netstat": ["-tuln", "-an"],
        "top": ["-n 1"], "ifconfig": [], "ip": ["addr", "route"], "uptime": [], "df": ["-h", "-i"], "exit": [],
        "iptables": ["-L", "-A"], "service": ["--status-all"], "systemctl": ["start", "stop", "restart", "nginx"],
        "crontab": ["-l"], "dmesg": ["-T"], "grep": ["-i", "-r"], "find": ["/", "-name"], "head": ["-n 10"], "tail": ["-f", "-n 20"],
        "history": ["-c"], "sudo": [], "su": [], "curl": ["-O", "-s"], "wget": ["--quiet"], "telnet": [], "apt-get": ["install", "update"],
        "dpkg": ["-l"], "make": ["-j4"], "scp": ["-r"], "sftp": [], "ftp": [], "db": [], "smb": [], "who": [], "w": [], "last": [],
        "ss": ["-t"], "vuln_app": [], "status_report": [], "install_malware": [], "export_logs": ["--session", "--system"],
        "set_language": ["fr", "en"]
    }
    if not current_input.strip():
        return sorted(base_cmds.keys())
    
    parts = current_input.split()
    cmd = parts[0].lower() if parts else ""
    partial = parts[-1] if len(parts) > 1 else current_input
    
    if cmd in base_cmds:
        if len(parts) == 1:
            return [c for c in base_cmds.keys() if c.startswith(cmd)] + [f"{cmd} {opt}" for opt in base_cmds[cmd] if opt]
        elif len(parts) > 1 and not partial.startswith("-"):
            resolved_path = partial if partial.startswith("/") else f"{current_dir}/{partial}" if current_dir != "/" else f"/{partial}"
            resolved_path = os.path.normpath(resolved_path)
            parent_dir = os.path.dirname(resolved_path) or "/"
            base_name = os.path.basename(resolved_path) or ""
            
            completions = []
            if parent_dir in fs and fs[parent_dir]["type"] == "dir":
                for item in fs[parent_dir]["contents"]:
                    full_path = f"{parent_dir}/{item}" if parent_dir != "/" else f"/{item}"
                    if full_path in fs and item.startswith(base_name):
                        display_item = item if cmd in ["ls", "cd"] else f"{parent_dir}/{item}"
                        completions.append(display_item)
                for hist_cmd in history[-5:]:
                    if hist_cmd.startswith(cmd) and hist_cmd.split()[1:] and hist_cmd.split()[1].startswith(partial):
                        completions.append(hist_cmd)
            return sorted(completions)
        elif partial.startswith("-"):
            return [f"{cmd} {opt}" for opt in base_cmds[cmd] if opt and opt.startswith(partial)]
    return [h for h in history if h.startswith(current_input)] + [c for c in base_cmds.keys() if c.startswith(cmd)]

def autocomplete(current_input, current_dir, username, fs, chan, history, lang):
    completions = get_completions(current_input, current_dir, username, fs, history, lang)
    if len(completions) == 1 and current_input.strip():
        cmd_parts = current_input.rsplit(" ", 1)
        if len(cmd_parts) > 1:
            cmd, partial = cmd_parts
            new_input = f"{cmd} {completions[0]}"
        else:
            new_input = completions[0]
        return new_input
    elif completions and current_input.strip():
        chan.send(b"\r\n" + "\r\n".join(c.encode() for c in completions) + b"\r\n" + f"[{len(completions)} options disponibles]".encode())
        return current_input
    return current_input

def load_history(username):
    filename = f"history_{username.replace('/', '_')}.txt"
    try:
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logging.error(f"[!] Erreur history load: {e}")
    return []

def save_history(username, history):
    filename = f"history_{username.replace('/', '_')}.txt"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            for cmd in history[-1000:]:
                f.write(cmd + "\n")
    except Exception as e:
        logging.error(f"[!] Erreur history save: {e}")

def init_database():
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    ip TEXT NOT NULL,
                    username TEXT,
                    password TEXT,
                    success INTEGER,
                    redirected INTEGER
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    username TEXT NOT NULL,
                    command TEXT NOT NULL,
                    session_id INTEGER NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    username TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS behavioral_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    username TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    score INTEGER,
                    details TEXT
                )
            """)
            conn.commit()
    except sqlite3.Error as e:
        logging.error(f"[!] Erreur DB init: {e}")

def generate_report(period):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"Rapport {period} - Serveur SSH", 0, 1, "C")
    pdf.set_font("Arial", size=12)
    start_time = (datetime.now() - timedelta(minutes=15 if period == "15min" else 60 if period == "hourly" else 10080)).strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 10, f"Période: {start_time} à {datetime.now()}", 0, 1)
    
    try:
        with sqlite3.connect(DB_NAME) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM login_attempts WHERE timestamp > ?", (start_time,))
            login_count = cur.fetchone()[0]
            pdf.cell(0, 10, f"Total des tentatives de connexion: {login_count}", 0, 1)
            cur.execute("SELECT ip, COUNT(*) as count FROM login_attempts WHERE timestamp > ? GROUP BY ip ORDER BY count DESC LIMIT 5", (start_time,))
            for ip, count in cur.fetchall():
                pdf.cell(0, 10, f"IP: {ip} - {count} tentatives", 0, 1)
            cur.execute("SELECT command, COUNT(*) as count FROM commands WHERE timestamp > ? GROUP BY command ORDER BY count DESC LIMIT 5", (start_time,))
            for cmd, count in cur.fetchall():
                pdf.cell(0, 10, f"Commande: {cmd} - {count} exécutions", 0, 1)
            cur.execute("SELECT timestamp, ip, username, event_type, details FROM events WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 10", (start_time,))
            for timestamp, ip, username, event_type, details in cur.fetchall():
                pdf.cell(0, 10, f"{timestamp} - {ip} ({username}): {event_type} - {details}", 0, 1)
    except sqlite3.Error as e:
        logging.error(f"[!] Erreur report: {e}")
    
    report_filename = f"{period}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(report_filename)
    return report_filename

def send_weekly_report():
    while True:
        now = datetime.now()
        if now.weekday() == 0 and now.hour == 8:
            report_filename = generate_report("weekly")
            subject = f"Rapport Hebdomadaire Serveur SSH - {datetime.now().strftime('%Y-%m-%d')}"
            body = "Veuillez trouver ci-joint le rapport hebdomadaire."
            msg = MIMEText(body)
            msg["From"] = ALERT_FROM
            msg["To"] = ALERT_TO
            msg["Subject"] = subject
            try:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
                    smtp.starttls()
                    smtp.login(SMTP_USER, SMTP_PASS)
                    smtp.send_message(msg)
                logging.info(f"[*] Rapport hebdomadaire envoyé: {report_filename}")
            except Exception as e:
                logging.error(f"[!] Erreur email hebdo: {e}")
            os.remove(report_filename)
        time.sleep(3600)

def send_periodic_report():
    while True:
        time.sleep(900)
        report_filename = generate_report("15min")
        body = f"Rapport 15min - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        send_alert(-1, "15min Activity Report", body, "honeypot", "system")
        os.remove(report_filename)

class SFTPServer(paramiko.SFTPServer):
    def __init__(self, channel, name, server, sftp_si, *args, **kwargs):
        super().__init__(channel, name, server, sftp_si, *args, **kwargs)
        self.fs = FS.copy()
        self.session_id = server.session_id
        self.client_ip = server.client_ip
        self.username = server.transport.get_username() or "unknown"

    def open(self, path, flags, attr):
        send_alert(self.session_id, "SFTP File Open", f"Opened file: {path}", self.client_ip, self.username)
        log_action(self.session_id, self.client_ip, self.username, "file_open", f"Opened file: {path}")
        if path not in self.fs or self.fs[path]["type"] != "file":
            raise OSError("No such file")
        return paramiko.SFTPHandle()

    def list_folder(self, path):
        send_alert(self.session_id, "SFTP List Directory", f"Listed directory: {path}", self.client_ip, self.username)
        log_action(self.session_id, self.client_ip, self.username, "dir_list", f"Listed directory: {path}")
        if path not in self.fs or self.fs[path]["type"] != "dir":
            raise OSError("No such directory")
        contents = []
        for item in self.fs[path]["contents"]:
            full_path = f"{path}/{item}" if path != "/" else f"/{item}"
            if full_path in fs:
                sftp_attr = paramiko.SFTPAttributes()
                sftp_attr.filename = item
                sftp_attr.st_mode = 0o755 if self.fs[full_path]["type"] == "dir" else 0o644
                sftp_attr.st_size = len(self.fs[full_path].get("content", "")) if self.fs[full_path]["type"] == "file" else 0
                contents.append(sftp_attr)
        return contents

    def stat(self, path):
        send_alert(self.session_id, "SFTP Stat", f"Queried stats for: {path}", self.client_ip, self.username)
        log_action(self.session_id, self.client_ip, self.username, "file_stat", f"Queried stats for: {path}")
        if path not in self.fs:
            raise OSError("No such file or directory")
        sftp_attr = paramiko.SFTPAttributes()
        sftp_attr.filename = path.split("/")[-1]
        sftp_attr.st_mode = 0o755 if self.fs[path]["type"] == "dir" else 0o644
        sftp_attr.st_size = len(self.fs[path].get("content", "")) if self.fs[path]["type"] == "file" else 0
        return sftp_attr

    def remove(self, path):
        if path in self.fs and self.fs[path]["type"] == "file":
            parent_dir = "/".join(path.split("/")[:-1]) or "/"
            self.fs[parent_dir]["contents"].remove(path.split("/")[-1])
            del self.fs[path]
            save_filesystem(self.fs)
            send_alert(self.session_id, "SFTP File Removed", f"Removed file: {path}", self.client_ip, self.username)
            log_action(self.session_id, self.client_ip, self.username, "file_remove", f"Removed file: {path}")
            return
        raise OSError("Operation not permitted or file not found")

    def rename(self, oldpath, newpath): raise OSError("Operation not permitted")
    def mkdir(self, path, attr): raise OSError("Operation not permitted")
    def rmdir(self, path): raise OSError("Operation not permitted")

def read_line_advanced(chan, prompt, history, current_dir, username, fs, session_log, session_id, client_ip, jobs=None, cmd_count=0, last_cmd_time=None):
    chan.send(prompt.encode())
    command = ""
    cursor_pos = 0
    history_index = len(history)
    jobs = jobs or {}
    last_cmd_time = last_cmd_time or time.time()
    
    def redraw_line():
        chan.send(b"\r" + b" " * 80 + b"\r" + prompt.encode() + command.encode())
        if cursor_pos < len(command):
            chan.send(b"\x1b[" + str(len(command) - cursor_pos).encode() + b"D")
    
    while True:
        start_time = time.time()
        try:
            char = chan.recv(1).decode('utf-8', errors='ignore')
            if not char:
                break
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            log_keystroke(session_id, client_ip, username, char.encode().hex(), timestamp)
            session_log.write(f"{timestamp}: {char.encode().hex()}\n")
            
            if char == "\r":
                chan.send(b"\r\n")
                session_log.write(f"Command: {command}\n")
                current_time = time.time()
                delay = current_time - last_cmd_time
                if delay < 0.1:
                    send_alert(session_id, "Bot Detected", f"Rapid command execution (delay: {delay:.2f}s) by {username}", client_ip, username)
                    log_action(session_id, client_ip, username, "behavioral", {"type": "rapid_execution", "delay": delay})
                return command.strip(), jobs, cmd_count + 1, current_time
            elif char in ["\x7f", "\x08"] and cursor_pos > 0:
                command = command[:cursor_pos-1] + command[cursor_pos:]
                cursor_pos -= 1
                redraw_line()
            elif char == "\t":
                command = autocomplete(command, current_dir, username, fs, chan, history, current_language)
                cursor_pos = len(command)
                redraw_line()
            elif char == "\x03":
                chan.send(b"^C\r\n")
                command = ""
                cursor_pos = 0
                redraw_line()
            elif char == "\x1a":
                if command.strip():
                    job_id = len(jobs) + 1
                    jobs[job_id] = {"cmd": command, "status": "stopped"}
                    chan.send(f"\n[{job_id}] {command} stopped\n".encode())
                    command = ""
                    cursor_pos = 0
                    redraw_line()
            elif char == "\x1b":
                seq = chan.recv(2).decode('utf-8', errors='ignore')
                if seq == "[A" and history_index > 0:
                    history_index -= 1
                    command = history[history_index]
                    cursor_pos = len(command)
                    redraw_line()
                elif seq == "[B" and history_index < len(history):
                    history_index += 1
                    command = history[history_index] if history_index < len(history) else ""
                    cursor_pos = len(command)
                    redraw_line()
                elif seq == "[C" and cursor_pos < len(command):
                    cursor_pos += 1
                    chan.send(b"\x1b[C")
                elif seq == "[D" and cursor_pos > 0:
                    cursor_pos -= 1
                    chan.send(b"\x1b[D")
            elif char.isprintable():
                command = command[:cursor_pos] + char + command[cursor_pos:]
                cursor_pos += 1
                redraw_line()
        except Exception as e:
            logging.error(f"[!] Erreur read_line: {e}")
            send_alert(session_id, "Session Error", f"Error in input handling: {str(e)}", client_ip, username)
            break
        end_time = time.time()
        if end_time - start_time > 0.5:
            send_alert(session_id, "Slow Input Detected", f"Slow input by {username} (delay: {end_time - start_time:.2f}s)", client_ip, username)
    return "", jobs, cmd_count, last_cmd_time

def detect_exploit(command):
    exploit_signatures = {
        "buffer_overflow": r"[^a-zA-Z0-9]{100,}",  # Longue chaîne non alphanumérique
        "sql_injection": r"(?i)\b(union|select|insert|update|delete|drop)\b.*(--|;|#)",
        "shell_injection": r";.*(rm|reboot|format)"
    }
    for exploit_type, pattern in exploit_signatures.items():
        if re.search(pattern, command):
            return exploit_type, pattern
    return None, None

def analyze_behavior(history, cmd_count, client_ip, username, session_id):
    if len(history) < 5:
        return 0
    score = 0
    patterns = []
    if any("rm -rf" in cmd.lower() for cmd in history[-5:]):
        score += 5
        patterns.append("recursive_delete")
    if any("wget" in cmd.lower() or "curl" in cmd.lower() for cmd in history[-5:]):
        score += 3
        patterns.append("download_attempt")
    if cmd_count > 20 and len(set(history[-20:])) / len(history[-20:]) < 0.3:
        score += 4
        patterns.append("repetitive_commands")
    if score > 5:
        for pattern in patterns:
            log_action(session_id, client_ip, username, "behavioral", {"type": pattern, "score": score})
            send_alert(session_id, f"Behavioral Anomaly - {pattern}", f"Score: {score} for {username}", client_ip, username)
    return score

def process_command(cmd, current_dir, username, fs, client_ip, session_id, session_log, command_history, jobs=None, cmd_count=0, last_cmd_time=None):
    global current_language
    if not cmd.strip():
        return "", current_dir, jobs or {}, cmd_count, last_cmd_time
    
    new_dir = current_dir
    output = ""
    cmd_parts = cmd.split()
    cmd_name = cmd_parts[0].lower()
    arg_str = " ".join(cmd_parts[1:]) if len(cmd_parts) > 1 else ""
    jobs = jobs or {}
    last_cmd_time = last_cmd_time or time.time()
    
    session_log.write(f"[{datetime.now()}] {username}@{client_ip}: {cmd}\n")
    log_session_video(session_id, client_ip, username, cmd, output)
    log_action(session_id, client_ip, username, "command", {"command": cmd, "dir": current_dir})
    
    exploit_type, _ = detect_exploit(cmd)
    if exploit_type:
        send_alert(session_id, f"Exploit Detected - {exploit_type}", f"Command: {cmd}", client_ip, username)
        if exploit_type == "buffer_overflow":
            return "Segmentation fault (core dumped) - Exploit trapped!", new_dir, jobs, cmd_count, last_cmd_time
        elif random.random() < 0.5:  # 50% chance de quarantaine
            send_alert(session_id, "Quarantine Triggered", f"User {username} quarantined due to {exploit_type}", client_ip, username)
            return "Account locked for security reasons.", new_dir, jobs, cmd_count, last_cmd_time
    
    suspicious_patterns = ["rm -rf", "chmod 777", "wget http", "curl -O", "reboot", "format"]
    for pattern in suspicious_patterns:
        if pattern in cmd.lower():
            send_alert(session_id, "Suspicious Command", f"Detected: {pattern} by {username}", client_ip, username)
            break
    
    malicious_patterns = {
        "rm -rf /": 10, "rm -rf": 5, "wget": 3, "curl": 3, "format": 7, "reboot": 4, "nc -l": 8, "chmod 777": 6
    }
    risk_score = sum(malicious_patterns.get(pattern, 0) for pattern in malicious_patterns if pattern in cmd.lower())
    if risk_score > 5:
        send_alert(session_id, "High Risk Command", f"Command '{cmd}' scored {risk_score} risk points", client_ip, username)
    
    if risk_score > 10 and random.random() < 0.3:
        output = LANGUAGES[current_language]["error"] + "System crash detected. Disconnecting..."
        send_alert(session_id, "System Crash", f"Crash triggered by {username} with command {cmd}", client_ip, username)
        return output, new_dir, jobs, cmd_count, last_cmd_time
    
    if cmd_name == "ls" or cmd_name == "dir":
        path = arg_str if arg_str else current_dir
        path = os.path.normpath(path if path.startswith("/") else f"{current_dir}/{path}")
        if path in fs and fs[path]["type"] == "dir":
            if "-l" in cmd_parts:
                lines = []
                for item in fs[path]["contents"]:
                    full_path = f"{path}/{item}" if path != "/" else f"/{item}"
                    if full_path in fs:
                        item_type = "d" if fs[full_path]["type"] == "dir" else "-"
                        perms = fs[full_path].get("permissions", "rw-r--r--")
                        size = len(fs[full_path].get("content", "")) if fs[full_path]["type"] == "file" else 0
                        mod_time = fs[full_path].get("mtime", datetime.now().strftime("%b %d %H:%M"))
                        lines.append(f"{item_type}{perms} 1 {fs[full_path].get('owner', username)} {username} {size:>8} {mod_time} {item}")
                output = "\n".join(lines)
            else:
                if random.random() < 0.3:
                    trap_file = f".trap_{random.randint(1, 1000)}.txt"
                    if trap_file not in fs[path]["contents"]:
                        fs[path]["contents"].append(trap_file)
                        fs[f"{path}/{trap_file}"] = {"type": "file", "content": f"Trap data {random.randint(1, 1000)}", "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "expires": time.time() + 3600}
                        send_alert(session_id, "Honeypot Trap Triggered", f"User {username} accessed {path} with trap {trap_file}", client_ip, username)
                output = " ".join(f for f in fs[path]["contents"] if not f.startswith(".trap_") or fs.get(f"{path}/{f}", {}).get("expires", 0) > time.time())
        else:
            output = LANGUAGES[current_language]["error"] + f"ls: cannot access '{arg_str}': No such file or directory"
    elif cmd_name == "cd":
        path = arg_str if arg_str else f"/home/{username}"
        path = os.path.normpath(path if path.startswith("/") else f"{current_dir}/{path}")
        if path in fs and fs[path]["type"] == "dir":
            new_dir = path
        else:
            output = LANGUAGES[current_language]["error"] + f"cd: {arg_str}: No such file or directory"
    elif cmd_name == "cat":
        if arg_str:
            path = os.path.normpath(arg_str if arg_str.startswith("/") else f"{current_dir}/{arg_str}")
            if path in HONEY_TOKEN_FILES:
                send_alert(session_id, "Honeytoken Access", f"Accessed {path}", client_ip, username)
            if path in fs and fs[path]["type"] == "file":
                output = fs[path]["content"]() if callable(fs[path]["content"]) else fs[path]["content"]
            else:
                output = LANGUAGES[current_language]["error"] + f"cat: {arg_str}: No such file or directory"
        else:
            output = LANGUAGES[current_language]["error"] + "cat: missing file operand"
    elif cmd_name == "rm":
        if arg_str:
            path = os.path.normpath(arg_str if arg_str.startswith("/") else f"{current_dir}/{arg_str}")
            if path in fs and fs[path]["type"] == "file":
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                fs[parent_dir]["contents"].remove(path.split("/")[-1])
                del fs[path]
                save_filesystem(fs)
                output = f"rm: removed '{arg_str}'"
                if "-r" in cmd_parts and path in fs and fs[path]["type"] == "dir":
                    send_alert(session_id, "Recursive Delete Attempt", f"Attempted rm -r on {path}", client_ip, username)
            else:
                output = LANGUAGES[current_language]["error"] + f"rm: cannot remove '{arg_str}': No such file or directory"
        else:
            output = LANGUAGES[current_language]["error"] + "rm: missing operand"
    elif cmd_name == "mkdir":
        if arg_str:
            path = os.path.normpath(arg_str if arg_str.startswith("/") else f"{current_dir}/{arg_str}")
            if path not in fs:
                fs[path] = {"type": "dir", "contents": [], "owner": username, "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if parent_dir in fs:
                    fs[parent_dir]["contents"].append(path.split("/")[-1])
                save_filesystem(fs)
                output = f"mkdir: created directory '{arg_str}'"
            else:
                output = LANGUAGES[current_language]["error"] + f"mkdir: cannot create directory '{arg_str}': File exists"
        else:
            output = LANGUAGES[current_language]["error"] + "mkdir: missing operand"
    elif cmd_name == "rmdir":
        if arg_str:
            path = os.path.normpath(arg_str if arg_str.startswith("/") else f"{current_dir}/{arg_str}")
            if path in fs and fs[path]["type"] == "dir" and not fs[path]["contents"]:
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if parent_dir in fs:
                    fs[parent_dir]["contents"].remove(path.split("/")[-1])
                del fs[path]
                save_filesystem(fs)
                output = f"rmdir: removed directory '{arg_str}'"
            else:
                output = LANGUAGES[current_language]["error"] + f"rmdir: failed to remove '{arg_str}': Directory not empty or does not exist"
        else:
            output = LANGUAGES[current_language]["error"] + "rmdir: missing operand"
    elif cmd_name == "cp" or cmd_name == "mv":
        if len(cmd_parts) >= 3:
            src = os.path.normpath(cmd_parts[1] if cmd_parts[1].startswith("/") else f"{current_dir}/{cmd_parts[1]}")
            dst = os.path.normpath(cmd_parts[2] if cmd_parts[2].startswith("/") else f"{current_dir}/{cmd_parts[2]}")
            if src in fs and fs[src]["type"] == "file":
                fs[dst] = fs[src].copy()
                fs[dst]["owner"] = username
                fs[dst]["mtime"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                parent_dir = "/".join(dst.split("/")[:-1]) or "/"
                if parent_dir in fs and dst.split("/")[-1] not in fs[parent_dir]["contents"]:
                    fs[parent_dir]["contents"].append(dst.split("/")[-1])
                if cmd_name == "mv" and src in fs:
                    parent_src_dir = "/".join(src.split("/")[:-1]) or "/"
                    if parent_src_dir in fs:
                        fs[parent_src_dir]["contents"].remove(src.split("/")[-1])
                    del fs[src]
                save_filesystem(fs)
                output = f"{cmd_name}: '{src}' {'copied' if cmd_name == 'cp' else 'moved'} to '{dst}'"
            else:
                output = LANGUAGES[current_language]["error"] + f"{cmd_name}: cannot stat '{cmd_parts[1]}': No such file or directory"
        else:
            output = LANGUAGES[current_language]["error"] + f"{cmd_name}: missing file operand"
    elif cmd_name == "chmod" or cmd_name == "chown":
        if len(cmd_parts) >= 3:
            path = os.path.normpath(cmd_parts[2] if cmd_parts[2].startswith("/") else f"{current_dir}/{cmd_parts[2]}")
            if path in fs:
                if cmd_name == "chmod" and cmd_parts[1] in ["+x", "-r", "755", "644"]:
                    fs[path]["permissions"] = cmd_parts[1] if cmd_parts[1] in ["+x", "-r"] else ("rwxr-xr-x" if cmd_parts[1] == "755" else "rw-r--r--")
                    save_filesystem(fs)
                    output = f"chmod: changed permissions of '{path}'"
                elif cmd_name == "chown" and cmd_parts[1] in PREDEFINED_USERS:
                    fs[path]["owner"] = cmd_parts[1]
                    save_filesystem(fs)
                    output = f"chown: changed owner of '{path}' to {cmd_parts[1]}"
                else:
                    output = LANGUAGES[current_language]["error"] + f"{cmd_name}: invalid argument"
            else:
                output = LANGUAGES[current_language]["error"] + f"{cmd_name}: cannot access '{cmd_parts[2]}': No such file or directory"
        else:
            output = LANGUAGES[current_language]["error"] + f"{cmd_name}: missing operand"
    elif cmd_name == "kill":
        if arg_str:
            output = f"kill: terminated process {arg_str}"
            send_alert(session_id, "Process Kill", f"Attempted to kill process {arg_str}", client_ip, username)
        else:
            output = LANGUAGES[current_language]["error"] + "kill: usage: kill -9 <pid>"
    elif cmd_name == "ping":
        if arg_str:
            delay = random.uniform(0.1, 5.0)
            output = f"PING {arg_str} (simulated): 64 bytes from {arg_str}: ttl=64 time={delay:.1f} ms"
            send_alert(session_id, "Ping Attempt", f"Ping to {arg_str} from {client_ip} with delay {delay:.1f}ms", client_ip, username)
            with open("network_traffic.log", "a") as f:
                f.write(f"{datetime.now()}: PING {arg_str} from {client_ip}\n")
        else:
            output = LANGUAGES[current_language]["error"] + "ping: missing hostname"
    elif cmd_name == "traceroute":
        if arg_str:
            hops = [f"{random.randint(1, 10)} {'.'.join(str(random.randint(0, 255)) for _ in range(4))}" for _ in range(3)]
            output = f"traceroute to {arg_str} (simulated): {' '.join(hops)}"
            send_alert(session_id, "Traceroute Attempt", f"Traceroute to {arg_str} from {client_ip}", client_ip, username)
            with open("network_traffic.log", "a") as f:
                f.write(f"{datetime.now()}: TRACEROUTE {arg_str} from {client_ip}\n")
        else:
            output = LANGUAGES[current_language]["error"] + "traceroute: missing hostname"
    elif cmd_name == "vim":
        chan.send(f"Entering vim mode... Press :q to exit\r\n".encode())
        while True:
            vim_input = read_line_advanced(chan, ":", history, current_dir, username, fs, session_log, session_id, client_ip, jobs, cmd_count, last_cmd_time)[0]
            if vim_input == "q":
                chan.send(b"\r\nExited vim mode\r\n")
                break
            send_alert(session_id, "Vim Attempt", f"User {username} attempted vim with input: {vim_input}", client_ip, username)
        return "", current_dir, jobs, cmd_count, last_cmd_time
    elif cmd_name == "nano":
        chan.send(f"Entering nano mode... Press Ctrl+X to exit\r\n".encode())
        while True:
            nano_input = read_line_advanced(chan, "", history, current_dir, username, fs, session_log, session_id, client_ip, jobs, cmd_count, last_cmd_time)[0]
            if nano_input == "\x18":
                chan.send(b"\r\nExited nano mode\r\n")
                break
            send_alert(session_id, "Nano Attempt", f"User {username} attempted nano with input: {nano_input}", client_ip, username)
        return "", current_dir, jobs, cmd_count, last_cmd_time
    elif cmd_name == "backup_data":
        output = "Backing up data to /tmp/backup.tar.gz (simulated)..."
        send_alert(session_id, "Backup Trigger", f"User {username} triggered backup from {client_ip}", client_ip, username)
        fs["/tmp/backup.tar.gz"] = {"type": "file", "content": "Simulated backup data", "owner": username, "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        if "/tmp" in fs and "backup.tar.gz" not in fs["/tmp"]["contents"]:
            fs["/tmp"]["contents"].append("backup.tar.gz")
        save_filesystem(fs)
    elif cmd_name == "systemctl":
        if "stop" in cmd_parts and "nginx" in cmd_parts:
            output = "nginx service stopped (simulated)"
            send_alert(session_id, "Service Stop", f"User {username} stopped nginx from {client_ip}", client_ip, username)
        elif "start" in cmd_parts and "nginx" in cmd_parts:
            output = "nginx service started (simulated)"
        else:
            output = LANGUAGES[current_language]["error"] + f"systemctl: unknown command or service '{arg_str}'"
    elif cmd_name == "fg":
        if arg_str and arg_str.isdigit() and int(arg_str) in jobs:
            job = jobs[int(arg_str)]
            output = f"Resuming job [{arg_str}] {job['cmd']}\n"
            del jobs[int(arg_str)]
        else:
            output = LANGUAGES[current_language]["error"] + "fg: no such job"
    elif cmd_name == "vuln_app":
        output = "Running vulnerable application (buffer overflow simulation)... Enter exploit data:"
        send_alert(session_id, "Vuln App Trigger", f"User {username} accessed vuln_app from {client_ip}", client_ip, username)
        exploit_input = read_line_advanced(chan, "> ", history, current_dir, username, fs, session_log, session_id, client_ip, jobs, cmd_count, last_cmd_time)[0]
        if len(exploit_input) > 100:
            send_alert(session_id, "Exploit Attempt", f"Buffer overflow attempt with: {exploit_input}", client_ip, username)
            output += f"\nSegmentation fault (core dumped) - Captured: {exploit_input[:50]}..."
        else:
            output += f"\nNo exploit detected: {exploit_input}"
        return output, new_dir, jobs, cmd_count, last_cmd_time
    elif cmd_name == "status_report":
        output = f"Status Report for {username} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}:\n"
        output += f"- Commands executed: {cmd_count}\n"
        output += f"- Current directory: {current_dir}\n"
        output += f"- Last 5 commands: {command_history[-5:]}\n"
        send_alert(session_id, "Status Report", output, client_ip, username)
    elif cmd_name == "install_malware":
        malware_id = str(uuid.uuid4())
        output = f"Installing malware (simulated) with ID: {malware_id}..."
        send_alert(session_id, "Malware Installation", f"User {username} attempted to install malware (ID: {malware_id})", client_ip, username)
        with open(f"{SESSION_LOG_DIR}/malware_{malware_id}.log", "w") as malware_log:
            malware_log.write(f"[{datetime.now()}] Malware simulation started by {username} from {client_ip}\n")
        fs[f"/tmp/malware_{malware_id}.bin"] = {"type": "file", "content": f"Malware simulation data {malware_id}", "owner": username, "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        if "/tmp" in fs and f"malware_{malware_id}.bin" not in fs["/tmp"]["contents"]:
            fs["/tmp"]["contents"].append(f"malware_{malware_id}.bin")
        save_filesystem(fs)
    elif cmd_name == "export_logs":
        if "--session" in cmd_parts:
            log_file = f"session_{session_id}.csv"
            with open(log_file, "w", newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Timestamp", "IP", "Username", "Command", "Output"])
                with open(f"{SESSION_LOG_DIR}/session_{session_id}.log", "r") as session_log_file:
                    for line in session_log_file:
                        parts = line.split("|")
                        if len(parts) == 5:
                            writer.writerow(parts)
            output = f"Session logs exported to {log_file}"
        elif "--system" in cmd_parts:
            log_file = f"system_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            with open(log_file, "w", newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Timestamp", "IP", "Username", "Event Type", "Details"])
                try:
                    with sqlite3.connect(DB_NAME) as conn:
                        cur = conn.cursor()
                        cur.execute("SELECT timestamp, ip, username, event_type, details FROM events ORDER BY timestamp DESC LIMIT 1000")
                        for row in cur.fetchall():
                            writer.writerow(row)
                except sqlite3.Error as e:
                    logging.error(f"[!] Erreur export logs: {e}")
            output = f"System logs exported to {log_file}"
        else:
            output = LANGUAGES[current_language]["error"] + "export_logs: specify --session or --system"
    elif cmd_name == "set_language":
        if arg_str in LANGUAGES:
            current_language = arg_str
            output = f"Language set to {arg_str}"
        else:
            output = LANGUAGES[current_language]["error"] + f"set_language: invalid language. Available: {', '.join(LANGUAGES.keys())}"
    elif cmd_name == "exit":
        return LANGUAGES[current_language]["exit"], new_dir, jobs, cmd_count, last_cmd_time
    else:
        if random.random() < 0.1 or cmd_count >= CMD_LIMIT_PER_SESSION:
            output = LANGUAGES[current_language]["error"] + f"{cmd_name}: {LANGUAGES[current_language]['cmd_not_found']} (system error: {'disk full' if random.random() < 0.5 else 'resource limit reached'})"
            send_alert(session_id, "System Error", f"Simulated error for {cmd_name} (cmd_count={cmd_count})", client_ip, username)
        else:
            output = LANGUAGES[current_language]["error"] + f"{cmd_name}: {LANGUAGES[current_language]['cmd_not_found']}"
    
    if cmd_count >= CMD_LIMIT_PER_SESSION:
        output += f"\n{LANGUAGES[current_language]['session_limit']}"
        send_alert(session_id, "Session Limit", f"User {username} hit command limit ({cmd_count})", client_ip, username)
    
    analyze_behavior(command_history, cmd_count, client_ip, username, session_id)
    return output, new_dir, jobs, cmd_count, last_cmd_time

class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, session_id):
        self.client_ip = client_ip
        self.session_id = session_id
        self.event = threading.Event()
        self.attempts = 0
        self.username = None
        self.cmd_count = 0

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_auth_password(self, username, password):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        check_brute_force(self.client_ip)
        hashed_pass = hashlib.sha256(password.encode()).hexdigest()
        if username in PREDEFINED_USERS and PREDEFINED_USERS[username]["password"] == hashed_pass:
            self.username = username
            try:
                with sqlite3.connect(DB_NAME) as conn:
                    cur = conn.cursor()
                    cur.execute("INSERT INTO login_attempts (timestamp, ip, username, password, success, redirected) VALUES (?, ?, ?, ?, ?, ?)",
                                (timestamp, self.client_ip, username, password, 1, 0 if not ENABLE_REDIRECTION else 1))
                    conn.commit()
            except sqlite3.Error:
                pass
            return paramiko.AUTH_SUCCESSFUL
        else:
            if check_brute_force(self.client_ip) > BRUTE_FORCE_THRESHOLD * 2:
                temp_user, temp_pass = generate_dynamic_user()
                if username == temp_user and hashed_pass == PREDEFINED_USERS[temp_user]["password"]:
                    self.username = temp_user
                    try:
                        with sqlite3.connect(DB_NAME) as conn:
                            cur = conn.cursor()
                            cur.execute("INSERT INTO login_attempts (timestamp, ip, username, password, success, redirected) VALUES (?, ?, ?, ?, ?, ?)",
                                        (timestamp, self.client_ip, username, password, 1, 0 if not ENABLE_REDIRECTION else 1))
                            conn.commit()
                    except sqlite3.Error:
                        pass
                    send_alert(self.session_id, "Dynamic User Created", f"Temp user {temp_user} created for {self.client_ip}", self.client_ip, "system")
                    return paramiko.AUTH_SUCCESSFUL
            try:
                with sqlite3.connect(DB_NAME) as conn:
                    cur = conn.cursor()
                    cur.execute("INSERT INTO login_attempts (timestamp, ip, username, password, success, redirected) VALUES (?, ?, ?, ?, ?, ?)",
                                (timestamp, self.client_ip, username, password, 0, 0))
                    conn.commit()
            except sqlite3.Error:
                pass
            return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

def handle_session(chan, client_ip, session_id, server_obj):
    try:
        username = "unknown"
        transport = chan.get_transport()
        username = transport.get_username() or "unknown"
        server = transport.get_server()
        session_log_path = os.path.join(SESSION_LOG_DIR, f"session_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        with open(session_log_path, "a", encoding="utf-8") as session_log:
            fs = FS.copy()
            current_dir = PREDEFINED_USERS.get(username, {}).get("home", f"/home/{username}")
            history = load_history(username)
            env_vars = {"PATH": "/bin:/usr/bin", "HOME": current_dir}
            theme_color = PREDEFINED_USERS[username]["theme"]
            motto = PREDEFINED_USERS[username]["motto"]
            prompt = f"\033[1;3{3 if theme_color == 'green' else 4 if theme_color == 'blue' else 1}m{username}@debian[{motto}]\033[0m:\033[1;34m{current_dir.replace('/home/' + username, '~')}\033[0m$ "
            login_time = (datetime.now() - timedelta(minutes=random.randint(1, 60))).strftime("%a %b %d %H:%M:%S %Y")
            chan.send(f"{LANGUAGES[current_language]['welcome']}\r\nLast login: {login_time} from 192.168.1.{random.randint(10, 50)}\r\n".encode())
            send_alert(session_id, "Session Started", f"New session started for {username}", client_ip, username)
            cmd_count = 0
            jobs = {}
            last_cmd_time = time.time()
            
            if ENABLE_REDIRECTION:
                chan.send(b"Redirecting to secure environment...\r\n")
                transport.close()
                redirect_ssh(client_ip, username, session_id)
                return
            
            while True:
                command, jobs, cmd_count, last_cmd_time = read_line_advanced(chan, prompt, history, current_dir, username, fs, session_log, session_id, client_ip, jobs, cmd_count, last_cmd_time)
                if not command:
                    time.sleep(0.1)
                    continue
                history.append(command)
                save_history(username, history)
                if command == LANGUAGES[current_language]["exit"] or cmd_count >= CMD_LIMIT_PER_SESSION:
                    break
                output, current_dir, jobs, cmd_count, last_cmd_time = process_command(command, current_dir, username, fs, client_ip, session_id, session_log, history, jobs, cmd_count, last_cmd_time)
                if output:
                    chan.send((output + "\r\n").encode())
                prompt = f"\033[1;3{3 if theme_color == 'green' else 4 if theme_color == 'blue' else 1}m{username}@debian[{motto}]\033[0m:\033[1;34m{current_dir.replace('/home/' + username, '~')}\033[0m$ "
                FS = fs
                save_filesystem(FS)
    except Exception as e:
        logging.error(f"[!] Session error {client_ip}: {e}")
        send_alert(session_id, "Session Failure", f"Session failed: {str(e)}", client_ip, username)

def redirect_ssh(client_ip, username, session_id):
    try:
        transport = paramiko.Transport((REAL_SSH_HOST, REAL_SSH_PORT))
        transport.connect(username=username, password=PREDEFINED_USERS.get(username, {}).get("password", ""))
        chan = transport.open_session()
        chan.get_pty()
        chan.invoke_shell()
        send_alert(session_id, "Redirection", f"User {username} redirected to {REAL_SSH_HOST}", client_ip, username)
        while True:
            if chan.recv_ready():
                data = chan.recv(1024)
                log_action(session_id, client_ip, username, "redirected_input", data.decode(errors='ignore'))
            if chan.exit_status_ready():
                break
        transport.close()
    except Exception as e:
        logging.error(f"[!] Redirection error {client_ip}: {e}")
        send_alert(session_id, "Redirection Failure", f"Failed to redirect: {str(e)}", client_ip, username)

def handle_connection(client, addr, server_obj):
    client_ip  = addr[0]
    session_id = server_obj.session_id

    logging.info(f"[*] Nouvelle connexion de {client_ip}:{addr[1]} (Session ID: {session_id})")
    send_alert(session_id, "Nouvelle Connexion", f"Connexion de {client_ip}", client_ip, "unknown")

    transport = paramiko.Transport(client)
    try:
        transport.add_server_key(paramiko.RSAKey.generate(bits=2048))
        transport.start_server(server=server_obj)

        chan = transport.accept(20)
        if chan is None:
            logging.error(f"[!] Échec accept SSH pour {client_ip}")
            return

        chan.send(SSH_BANNER.encode() + b"\r\n")
        # Tant que handle_session ne rentre pas dans la logique de redirection,
        # le shell du honeypot restera actif.
        handle_session(chan, client_ip, session_id, server_obj)

    except Exception as e:
        logging.error(f"[!] Erreur connexion {client_ip}: {e}")
        send_alert(session_id, "Connection Error", f"Connection failed: {e}", client_ip, "unknown")

    finally:
        try:
            transport.close()
        except:
            pass
        client.close()
        logging.info(f"[*] Connexion fermée pour {client_ip} (Session ID: {session_id})")


def fake_ftp_server(port, stop_event):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(5)
        server.settimeout(1.0)
        logging.info(f"[*] Faux serveur FTP démarré sur le port {port}")
        while not stop_event.is_set():
            try:
                readable, _, _ = select.select([server], [], [], 1.0)
                if server in readable:
                    client, addr = server.accept()
                    detect_port_scan(addr[0], port)
                    client.send(b"220 Welcome to Fake FTP Server\r\n")
                    try:
                        data = client.recv(1024).decode('utf-8', errors='ignore')
                        if data.startswith("USER"):
                            client.send(b"331 Please specify the password.\r\n")
                        elif data.startswith("PASS"):
                            client.send(b"530 Login incorrect.\r\n")
                    except:
                        pass
                    logging.info(f"[+] Connexion FTP de {addr[0]}")
                    send_alert(-1, "FTP Connection", f"Connection attempt to FTP server from {addr[0]}", addr[0], "unknown")
                    client.close()
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"[!] Erreur dans le serveur FTP: {e}")
    except Exception as e:
        logging.error(f"[!] Échec du démarrage du serveur FTP: {e}")
    finally:
        server.close()

def fake_http_server(port, stop_event):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(5)
        server.settimeout(1.0)
        logging.info(f"[*] Faux serveur HTTP démarré sur le port {port}")
        while not stop_event.is_set():
            try:
                readable, _, _ = select.select([server], [], [], 1.0)
                if server in readable:
                    client, addr = server.accept()
                    detect_port_scan(addr[0], port)
                    try:
                        client.recv(1024)
                        response = (
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/html\r\n"
                            "Server: nginx/1.18.0\r\n"
                            "\r\n"
                            "<html><body><h1>Welcome to Fake Web Server</h1><p>This is a simulated web server.</p></body></html>"
                        )
                        client.send(response.encode())
                    except:
                        pass
                    logging.info(f"[+] Connexion HTTP de {addr[0]}")
                    send_alert(-1, "HTTP Connection", f"Connection attempt to HTTP server from {addr[0]}", addr[0], "unknown")
                    client.close()
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"[!] Erreur dans le serveur HTTP: {e}")
    except Exception as e:
        logging.error(f"[!] Échec du démarrage du serveur HTTP: {e}")
    finally:
        server.close()

def fake_mysql_server(port, stop_event):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(5)
        server.settimeout(1.0)
        logging.info(f"[*] Faux serveur MySQL démarré sur le port {port}")
        while not stop_event.is_set():
            try:
                readable, _, _ = select.select([server], [], [], 1.0)
                if server in readable:
                    client, addr = server.accept()
                    detect_port_scan(addr[0], port)
                    client.send(b"\x0a5.7.30-fake\x00\x01\x00\x00\x00\x01\x21\x00\x00\x00")
                    logging.info(f"[+] Connexion MySQL de {addr[0]}")
                    send_alert(-1, "MySQL Connection", f"Connection attempt to MySQL server from {addr[0]}", addr[0], "unknown")
                    client.close()
            except socket.timeout:
                continue
            except Exception as e:
                logging.error(f"[!] Erreur dans le serveur MySQL: {e}")
    except Exception as e:
        logging.error(f"[!] Échec du démarrage du serveur MySQL: {e}")
    finally:
        server.close()

def signal_handler(sig, frame):
    logging.info("\n[*] Arrêt du honeypot SSH...")
    stop_event.set()
    sys.exit(0)

def start_honeypot():
    init_database()
    # Lancement des rapports en arrière-plan
    threading.Thread(target=send_weekly_report, daemon=True).start()
    threading.Thread(target=send_periodic_report, daemon=True).start()

    # Vérification SMTP
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
        logging.info("SMTP configuration validated successfully")
    except smtplib.SMTPAuthenticationError:
        logging.error("SMTP Authentication failed: Check SMTP_USER and SMTP_PASS")
        sys.exit(1)
    except Exception as e:
        logging.error(f"SMTP test failed: {e}")
        sys.exit(1)

    # Démarrage des faux services
    global stop_event
    stop_event = threading.Event()
    executor = ThreadPoolExecutor(max_workers=len(FAKE_SERVICES))
    for svc, port in FAKE_SERVICES.items():
        if svc == "ftp":
            executor.submit(fake_ftp_server, port, stop_event)
        elif svc == "http":
            executor.submit(fake_http_server, port, stop_event)
        elif svc == "mysql":
            executor.submit(fake_mysql_server, port, stop_event)

    # Boucle d’acceptation SSH
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    server_socket.settimeout(1.0)
    logging.info(f"Honeypot SSH démarré sur {HOST}:{PORT} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    while not stop_event.is_set():
        try:
            client, addr = server_socket.accept()
            client.settimeout(60)
            session_id = str(uuid.uuid4())
            server_obj = Server(addr[0], session_id)
            threading.Thread(
                target=handle_connection,
                args=(client, addr, server_obj),
                daemon=True
            ).start()
        except socket.timeout:
            continue
        except Exception as e:
            logging.error(f"[!] Erreur serveur accept: {e}")
            time.sleep(1)

    # Arrêt propre
    stop_event.set()
    executor.shutdown(wait=True)
    server_socket.close()
    logging.info("[*] Serveur arrêté")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    try:
        start_honeypot()
    except KeyboardInterrupt:
        logging.info("\n[*] Arrêt demandé par l'utilisateur")
        stop_event.set()