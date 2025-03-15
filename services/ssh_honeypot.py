#!/usr/bin/env python3
import socket
import threading
import paramiko
import sqlite3
import time
import random
from datetime import datetime
import os
import smtplib
from email.mime.text import MIMEText
from fpdf import FPDF  # Installer avec : pip3 install fpdf
import tarfile
import shutil

# =======================
# Configuration Variables
# =======================
HOST = ""  # écoute sur toutes interfaces
PORT = 2224
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
ENABLE_REDIRECTION = False
REAL_SSH_HOST = "192.168.1.100"
REAL_SSH_PORT = 22

DB_NAME = "honeypot_data.db"
BRUTE_FORCE_THRESHOLD = 5
_brute_force_alerted = set()
_brute_force_lock = threading.Lock()

# Répertoire pour stocker les logs de session avancés
SESSION_LOG_DIR = "session_logs"
if not os.path.exists(SESSION_LOG_DIR):
    os.makedirs(SESSION_LOG_DIR)

# =======================
# SMTP configuration (Gmail)
# =======================
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "honeycute896@gmail.com"    # Votre adresse Gmail
SMTP_PASS = "mgps uhqr ujux pbbf"       # Mot de passe d'application
ALERT_FROM = SMTP_USER
ALERT_TO = "admin@example.com"          # Adresse destinataire

# ================================
# Comptes utilisateurs préconfigurés
# ================================
PREDEFINED_USERS = {
    "admin": {
        "home": "/home/admin",
        "files": {
            "admin_credentials.txt": "admin:supersecret\nImportant credentials for admin account",
            "admin_sshkey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...admin_key",
            "projectA_config": "projectA: configuration data..."
        }
    },
    "devops": {
        "home": "/home/devops",
        "files": {
            "deploy_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD...devops_key",
            "jenkins_config.xml": "<jenkins><config>DevOps settings</config></jenkins>"
        }
    },
    "dbadmin": {
        "home": "/home/dbadmin",
        "files": {
            "db_backup.sql": "-- Fake SQL dump\nDROP TABLE IF EXISTS test;",
            "db_scripts.sh": "#!/bin/bash\necho 'Running DB maintenance...'"
        }
    }
}

# ================================
# Fichiers de logs
# ================================
KEYSTROKES_LOG = "keystrokes.log"
FILE_TRANSFER_LOG = "file_transfers.log"

# ================================
# Honeytokens (fichiers appât sensibles)
# ================================
HONEY_TOKEN_FILES = [
    "/home/admin/financial_report.pdf",
    "/home/admin/compromised_email.eml",
    "/home/admin/secret_plans.txt"
]

# ================================
# Simulated outputs for system commands
# ================================
FAKE_NETSTAT_OUTPUT = """Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      135/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      220/apache2
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      212/mysqld
udp        0      0 0.0.0.0:68              0.0.0.0:*                           500/dhclient"""

# ================================
# Fonctions dynamiques (df, uptime, ps, config)
# ================================
def get_dynamic_df():
    sizes = {"sda1": "50G", "tmpfs": "100M"}
    used = {"sda1": f"{random.randint(5,10)}G", "tmpfs": "0"}
    avail = {"sda1": f"{random.randint(30,45)}G", "tmpfs": "100M"}
    usep = {"sda1": f"{random.randint(10,20)}%", "tmpfs": "0%"}
    return f"""Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        {sizes['sda1']}   {used['sda1']}   {avail['sda1']}  {usep['sda1']} /
tmpfs           {sizes['tmpfs']}     {used['tmpfs']}  {avail['tmpfs']}   {usep['tmpfs']} /run/user/1000"""

def get_dynamic_uptime():
    now = datetime.now().strftime("%H:%M:%S")
    days = random.randint(3,10)
    hours = random.randint(0,23)
    minutes = random.randint(0,59)
    users = random.randint(1,5)
    la1 = f"{random.uniform(0.00, 1.00):.2f}"
    la2 = f"{random.uniform(0.00, 1.00):.2f}"
    la3 = f"{random.uniform(0.00, 1.00):.2f}"
    return f"{now} up {days} days, {hours}:{minutes:02d}, {users} user{'s' if users > 1 else ''}, load average: {la1}, {la2}, {la3}"

def get_dynamic_ps():
    lines = []
    lines.append("USER       PID %CPU %MEM    VSZ   RSS TTY   STAT START   TIME COMMAND")
    for i in range(1, 7):
        user = random.choice(["root", "admin", "devops", "dbadmin"])
        pid = random.randint(1, 5000)
        cpu = round(random.uniform(0.0, 5.0), 1)
        mem = round(random.uniform(0.5, 3.0), 1)
        vsz = random.randint(10000, 50000)
        rss = random.randint(1000, 5000)
        tty = random.choice(["pts/0", "pts/1", "?", "tty7"])
        stat = random.choice(["Ss", "S+", "R", "Z"])
        start = datetime.now().strftime("%b%d")
        time_str = f"{random.randint(0,2)}:{random.randint(0,59):02d}"
        command = random.choice(["/sbin/init", "/usr/sbin/sshd -D", "/usr/bin/python", "/usr/bin/nginx"])
        lines.append(f"{user:<10}{pid:<5}{cpu:<5}{mem:<5}{vsz:<7}{rss:<5}{tty:<7}{stat:<5}{start:<8}{time_str:<6}{command}")
    return "\r\n".join(lines)

def get_dynamic_config():
    max_conn = random.randint(50, 200)
    log_level = random.choice(["DEBUG", "INFO", "WARNING", "ERROR"])
    return f"max_connections={max_conn}\nlog_level={log_level}\n"

# ================================
# Population du système de fichiers
# ================================
def populate_predefined_users(fs):
    if "/home" not in fs:
        fs["/home"] = {"type": "dir", "contents": []}
    for user, info in PREDEFINED_USERS.items():
        home_dir = info["home"]
        fs[home_dir] = {"type": "dir", "contents": list(info["files"].keys())}
        if user not in fs["/home"]["contents"]:
            fs["/home"]["contents"].append(user)
        for filename, content in info["files"].items():
            fs[f"{home_dir}/{filename}"] = {"type": "file", "content": content}
    return fs

# ================================
# Système de fichiers enrichi
# ================================
BASE_FILE_SYSTEM = {
    "/": {"type": "dir", "contents": ["bin", "sbin", "usr", "var", "opt", "root", "home", "etc", "tmp"]},
    "/bin": {"type": "dir", "contents": ["bash", "ls", "cat", "grep"]},
    "/sbin": {"type": "dir", "contents": ["init", "sshd"]},
    "/usr": {"type": "dir", "contents": ["bin", "lib", "share"]},
    "/usr/bin": {"type": "dir", "contents": ["python", "gcc", "make", "apt-get"]},
    "/usr/sbin": {"type": "dir", "contents": ["apache2", "postfix"]},
    "/var": {"type": "dir", "contents": ["log", "mail", "www"]},
    "/var/log": {"type": "dir", "contents": ["syslog", "auth.log"]},
    "/var/www": {"type": "dir", "contents": ["index.html"]},
    "/opt": {"type": "dir", "contents": []},
    "/root": {"type": "dir", "contents": ["credentials.txt", "config_backup.zip", "ssh_keys.tar.gz", "rootkit_detector.sh"]},
    "/etc": {"type": "dir", "contents": ["passwd", "shadow", "apt", "service", "hosts", "myconfig.conf"]},
    "/tmp": {"type": "dir", "contents": []}
}

BASE_FILE_SYSTEM["/root/credentials.txt"] = {"type": "file", "content": "username=admin\npassword=admin123\napi_key=ABCD-1234-EFGH-5678"}
BASE_FILE_SYSTEM["/root/config_backup.zip"] = {"type": "file", "content": "PK\x03\x04...<binary zip content>..."}
BASE_FILE_SYSTEM["/root/ssh_keys.tar.gz"] = {"type": "file", "content": "...\x1F\x8B\x08...<binary tar.gz content>..."}
BASE_FILE_SYSTEM["/root/rootkit_detector.sh"] = {"type": "file", "content": "#!/bin/bash\necho 'Rootkit detector active'"}
BASE_FILE_SYSTEM["/etc/passwd"] = {"type": "file", "content": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash"}
BASE_FILE_SYSTEM["/etc/shadow"] = {"type": "file", "content": "root:*:18967:0:99999:7:::\nuser:*:18967:0:99999:7:::"}
BASE_FILE_SYSTEM["/etc/hosts"] = {"type": "file", "content": "127.0.0.1 localhost\n192.168.1.100 honeypot.local"}
BASE_FILE_SYSTEM["/etc/myconfig.conf"] = {"type": "file", "content": get_dynamic_config()}

BASE_FILE_SYSTEM = populate_predefined_users(BASE_FILE_SYSTEM)

# ================================
# Fonctions d'alerte et logs
# ================================
def trigger_alert(session_id, command, client_ip, username):
    """ Envoie une alerte (stockée en DB et par mail) pour une commande suspecte. """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[ALERTE] {timestamp} - {client_ip} a tenté : {command} (session_id={session_id})")
    try:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO events(timestamp, ip, username, event_type, details)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, client_ip, username, "Suspicious", command))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Erreur lors de l'enregistrement de l'alerte en DB: {e}")
    subject = f"[HONEYPOT] Alerte : {client_ip}"
    body = f"{timestamp} - {client_ip} a exécuté une commande suspecte : {command}\nUser: {username}"
    msg = MIMEText(body)
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_TO
    msg["Subject"] = subject
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
    except Exception as e:
        print(f"[!] Erreur lors de l'envoi du mail d'alerte: {e}")

# ======================================
# Fonctions pour historique persistant
# ======================================
def load_history(username):
    filename = f"history_{username}.txt"
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return [line.strip() for line in f if line.strip()]
    return []

def save_history(username, history):
    filename = f"history_{username}.txt"
    with open(filename, "w") as f:
        for cmd in history:
            f.write(cmd + "\n")

#########################################
# Fonctions de complétion et d'autocomplétion
#########################################
def get_completions(current_input, current_dir, username, fs):
    base_cmds = [
        "ls", "cd", "pwd", "whoami", "id", "uname", "echo", "cat", "rm",
        "ps", "netstat", "uptime", "df", "exit", "logout", "find", "grep",
        "head", "tail", "history", "sudo", "su", "apt-get", "dpkg", "make",
        "last", "who", "w", "scp", "sftp", "vulndb", "oldconfig", "vulnweb"
    ]
    if " " not in current_input:
        return sorted([cmd for cmd in base_cmds if cmd.startswith(current_input)])
    else:
        parts = current_input.split(" ", 1)
        partial = parts[1]
        return sorted([path for path in fs.keys() if path.startswith(partial)])

def autocomplete(current_input, current_dir, username, fs):
    completions = get_completions(current_input, current_dir, username, fs)
    if len(completions) == 1:
        if " " not in current_input:
            return completions[0]
        else:
            return current_input.split(" ", 1)[0] + " " + completions[0]
    return current_input

# ======================================
# Initialisation de la base SQLite
# ======================================
def init_database():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            username TEXT,
            password TEXT,
            success INTEGER,
            redirected INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            username TEXT,
            command TEXT,
            session_id INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            username TEXT,
            event_type TEXT,
            details TEXT
        )
    """)
    conn.commit()
    conn.close()

# ======================================
# Fonction de génération hebdomadaire de rapport PDF
# ======================================
def generate_weekly_report():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT * FROM events")
    events = cur.fetchall()
    conn.close()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Rapport Hebdomadaire du Honeypot SSH", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", size=10)
    for event in events:
        line = f"{event[1]} | {event[2]} | {event[3]} | {event[4]} | {event[5]}"
        pdf.multi_cell(0, 5, line)
    report_filename = f"weekly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(report_filename)
    subject = "Rapport Hebdomadaire Honeypot SSH"
    body = "Veuillez trouver en pièce jointe le rapport hebdomadaire des événements du Honeypot SSH."
    msg = MIMEText(body)
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_TO
    msg["Subject"] = subject
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
            print("[*] Rapport hebdomadaire envoyé par email.")
    except Exception as e:
        print(f"[!] Erreur lors de l'envoi du rapport hebdomadaire: {e}")

def weekly_report_thread():
    while True:
        time.sleep(7 * 24 * 3600)
        generate_weekly_report()

# ======================================
# Fonction de keylogging avancé
# ======================================
def advanced_keylog(session_log, key, delay):
    session_log.write(f"{datetime.now().isoformat()} - keystroke: {repr(key)} delay: {delay:.3f} sec\n")
    session_log.flush()

# ======================================
# Lecture interactive avancée (shell) avec keylogging avancé
# ======================================
def read_line_advanced(chan, prompt, history, current_dir, username, fs, session_log):
    line_buffer = []
    cursor_pos = 0
    history_index = len(history)
    last_was_tab = False

    colored_prompt = f"\033[1;32m{prompt.split('@')[0]}\033[0m@{prompt.split('@')[1]}"
    chan.send(colored_prompt.encode())

    def redraw_line():
        chan.send(b"\r\033[K")
        chan.send((colored_prompt + "".join(line_buffer)).encode())
        diff = len(line_buffer) - cursor_pos
        if diff > 0:
            chan.send(f"\033[{diff}D".encode())

    last_key_time = time.time()
    while True:
        try:
            byte = chan.recv(1)
        except Exception:
            break
        if not byte:
            break

        try:
            char = byte.decode("utf-8", errors="ignore")
        except Exception:
            continue

        current_time = time.time()
        delay = current_time - last_key_time
        last_key_time = current_time
        advanced_keylog(session_log, char, delay)

        if char in ("\r", "\n"):
            chan.send(b"\r\n")
            session_log.write("\n")
            break

        if char == "\x03":
            chan.send(b"^C\r\n")
            return ""
        if char in ("\x7f", "\x08"):
            if cursor_pos > 0:
                cursor_pos -= 1
                line_buffer.pop(cursor_pos)
                redraw_line()
            last_was_tab = False
            continue
        if char == "\x1b":
            seq = byte + chan.recv(2)
            if seq.endswith(b"[A"):
                if history_index > 0:
                    history_index -= 1
                    line_buffer = list(history[history_index])
                    cursor_pos = len(line_buffer)
                    redraw_line()
            elif seq.endswith(b"[B"):
                if history_index < len(history) - 1:
                    history_index += 1
                    line_buffer = list(history[history_index])
                else:
                    history_index = len(history)
                    line_buffer = []
                cursor_pos = len(line_buffer)
                redraw_line()
            elif seq.endswith(b"[C"):
                if cursor_pos < len(line_buffer):
                    cursor_pos += 1
                    redraw_line()
            elif seq.endswith(b"[D"):
                if cursor_pos > 0:
                    cursor_pos -= 1
                    redraw_line()
            last_was_tab = False
            continue
        if char == "\t":
            if last_was_tab:
                completions = get_completions("".join(line_buffer), current_dir, username, fs)
                if completions:
                    chan.send(b"\r\n")
                    for comp in completions:
                        chan.send((comp + "\r\n").encode())
                    redraw_line()
                last_was_tab = False
                continue
            else:
                current_str = "".join(line_buffer)
                suggestion = autocomplete(current_str, current_dir, username, fs)
                if suggestion and suggestion != current_str:
                    diff = suggestion[len(current_str):]
                    for ch in diff:
                        line_buffer.insert(cursor_pos, ch)
                        cursor_pos += 1
                    redraw_line()
                else:
                    chan.send(b"\x07")
                last_was_tab = True
                continue
        line_buffer.insert(cursor_pos, char)
        cursor_pos += 1
        redraw_line()
        last_was_tab = False
    return "".join(line_buffer)

# ======================================
# Traitement des commandes (process_command)
# ======================================
def process_command(cmd, current_dir, username, fs, client_ip):
    output = ""
    new_dir = current_dir
    cmd = cmd.strip()
    if not cmd:
        return "", new_dir
    parts = cmd.split(maxsplit=1)
    cmd_name = parts[0]
    arg_str = parts[1] if len(parts) > 1 else ""

    def resolve_path(path):
        if not path.startswith("/"):
            full = (current_dir.rstrip("/") + "/" + path) if current_dir != "/" else "/" + path
        else:
            full = path
        return full.rstrip("/") if len(full) > 1 and full.endswith("/") else full

    if cmd_name == "cd":
        target = arg_str if arg_str else "~"
        if target in ["", "~"]:
            new_dir = PREDEFINED_USERS.get(username, {}).get("home", "/root" if username=="root" else f"/home/{username}")
        else:
            target_path = resolve_path(target)
            if target_path == "/root" and username != "root":
                output = f"bash: cd: {target}: Permission denied"
            elif target_path in fs and fs[target_path]["type"] == "dir":
                new_dir = target_path
            else:
                output = f"bash: cd: {target}: No such file or directory"
    elif cmd_name == "ls":
        target_path = current_dir
        if arg_str and not arg_str.startswith("-"):
            target_path = resolve_path(arg_str)
            if target_path == "/root" and username != "root":
                output = "ls: cannot open directory '/root': Permission denied"
            elif target_path not in fs or fs[target_path]["type"] != "dir":
                output = f"ls: cannot access '{arg_str}': No such file or directory"
        if not output:
            contents = fs[target_path]["contents"] if target_path in fs and fs[target_path]["type"]=="dir" else []
            output = "\r\n".join(contents)
    elif cmd_name == "pwd":
        output = current_dir
    elif cmd_name == "whoami":
        output = username
    elif cmd_name == "id":
        if username=="root":
            output = "uid=0(root) gid=0(root) groups=0(root)"
        else:
            output = f"uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)"
    elif cmd_name == "uname":
        output = "Linux debian 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (Debian)" if arg_str else "Linux"
    elif cmd_name == "echo":
        output = arg_str
    elif cmd_name == "cat":
        if not arg_str:
            output = ""
        else:
            file_path = resolve_path(arg_str)
            if file_path == "/etc/myconfig.conf":
                output = get_dynamic_config()
            elif file_path == "/etc/shadow" and username != "root":
                output = f"cat: {arg_str}: Permission denied"
            elif file_path in fs:
                node = fs[file_path]
                if node["type"] == "file":
                    output = node["content"]
                    # Si un honeytoken est accédé, déclencher une alerte
                    if file_path in HONEY_TOKEN_FILES:
                        trigger_alert(-1, f"Honeytoken accessed: {file_path}", client_ip, username)
                else:
                    output = f"cat: {arg_str}: Is a directory"
            else:
                output = f"cat: {arg_str}: No such file or directory"
    elif cmd_name == "rm":
        if not arg_str:
            output = "rm: missing operand"
        else:
            target_path = resolve_path(arg_str)
            if target_path in ["/etc/passwd", "/etc/shadow", "/root/.ssh/authorized_keys", "/root/rootkit_detector.sh"]:
                output = f"rm: cannot remove '{arg_str}': Permission denied (critical file)"
                trigger_alert(-1, f"Tentative de suppression de {target_path}", client_ip, username)
            elif target_path in fs:
                node = fs[target_path]
                if node["type"] == "file":
                    parent_dir = target_path.rsplit("/", 1)[0] or "/"
                    if parent_dir=="/root" and username!="root":
                        output = f"rm: cannot remove '{arg_str}': Permission denied"
                    else:
                        fs.pop(target_path, None)
                        if parent_dir in fs and "contents" in fs[parent_dir]:
                            try:
                                fs[parent_dir]["contents"].remove(target_path.split("/")[-1])
                            except ValueError:
                                pass
                        output = ""
                else:
                    output = f"rm: cannot remove '{arg_str}': Is a directory"
            else:
                output = f"rm: cannot remove '{arg_str}': No such file or directory"
    elif cmd_name == "ps":
        output = get_dynamic_ps()
    elif cmd_name == "netstat":
        output = FAKE_NETSTAT_OUTPUT
    elif cmd_name == "uptime":
        output = get_dynamic_uptime()
    elif cmd_name == "df":
        output = get_dynamic_df()
    elif cmd_name == "find":
        args = arg_str.split()
        if not args:
            output = "find: missing argument"
        else:
            directory = args[0]
            pattern = args[1] if len(args) > 1 else ""
            results = [path for path in fs.keys() if path.startswith(directory) and (pattern=="" or pattern in path)]
            output = "\r\n".join(results)
    elif cmd_name == "grep":
        args = arg_str.split()
        if len(args) < 2:
            output = "Usage: grep pattern filename"
        else:
            pattern = args[0]
            filename = args[1]
            file_path = resolve_path(filename)
            if file_path in fs and fs[file_path]["type"] == "file":
                lines = fs[file_path]["content"].splitlines()
                matching = [line for line in lines if pattern in line]
                output = "\r\n".join(matching)
            else:
                output = f"grep: {filename}: No such file or directory"
    elif cmd_name == "head":
        args = arg_str.split()
        if not args:
            output = "head: missing operand"
        else:
            filename = args[-1]
            file_path = resolve_path(filename)
            if file_path in fs and fs[file_path]["type"] == "file":
                lines = fs[file_path]["content"].splitlines()
                output = "\r\n".join(lines[:10])
            else:
                output = f"head: cannot open '{filename}' for reading: No such file or directory"
    elif cmd_name == "tail":
        args = arg_str.split()
        if not args:
            output = "tail: missing operand"
        else:
            filename = args[-1]
            file_path = resolve_path(filename)
            if file_path in fs and fs[file_path]["type"] == "file":
                lines = fs[file_path]["content"].splitlines()
                output = "\r\n".join(lines[-10:])
            else:
                output = f"tail: cannot open '{filename}' for reading: No such file or directory"
    # --- Simulation de vulnérabilités ---
    elif cmd_name == "vulndb":
        output = ("Connecting to vulnerable database service...\n"
                  "Default credentials: username='root', password='toor'\n"
                  "Warning: SQL Injection vulnerability detected. No security measures are implemented.\n")
    elif cmd_name == "oldconfig":
        output = ("# Obsolete and vulnerable configuration file\n"
                  "DEBUG_MODE=true\n"
                  "password=123456\n"
                  "allow_remote_access=yes\n"
                  "Warning: This configuration exposes critical services and is known to be insecure.\n")
    elif cmd_name == "vulnweb":
        output = ("Vulnerable web server detected on port 80.\n"
                  "Default admin credentials: admin:admin123\n"
                  "Exploitable vulnerability: Remote Code Execution possible (CVE-XXXX-YYYY).\n")
    # -------------------------------------
    elif cmd_name == "history":
        output = "\r\n".join(load_history(username))
    elif cmd_name == "sudo":
        if username == "root":
            if arg_str:
                return process_command(arg_str, current_dir, username, fs, client_ip)
            else:
                output = ""
        else:
            output = (f"[sudo] password for {username}: \n"
                      "Sorry, try again.\nSorry, try again.\nSorry, try again.\nsudo: 3 incorrect password attempts\n")
    elif cmd_name in ["su", "su-"]:
        if username == "root":
            output = ""
        else:
            output = "Password: \nsu: Authentication failure\n"
    elif cmd_name == "apt-get":
        output = "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)"
    elif cmd_name == "dpkg":
        output = "dpkg: error: must be root to perform this command"
    elif cmd_name == "make":
        output = "make: Nothing to be done for 'all'."
    elif cmd_name in ["scp", "sftp"]:
        with open(FILE_TRANSFER_LOG, "a") as f:
            f.write(f"{datetime.now()} - {username} from {client_ip} attempted file transfer: {arg_str}\n")
        output = f"bash: {cmd_name}: command not found"
    elif cmd_name in ["wget", "curl"]:
        if "http" in arg_str:
            output = "Downloading large file... (simulation)\n"
            for i in range(1, 6):
                output += f"Downloaded {i*20}%...\n"
                time.sleep(0.5)
            output += "Download complete.\n"
            with open("downloads.log", "a") as f:
                f.write(f"{datetime.now()} - {username} from {client_ip} attempted download: {cmd_name}\n")
        else:
            output = f"bash: {cmd_name}: command not found"
    elif cmd_name in ["ftp", "tftp"]:
        output = f"bash: {cmd_name}: command not found"
    elif cmd_name in ["chmod", "bash", "sh", "netcat", "nc", "python"]:
        output = ""
    elif cmd_name in ["last", "who", "w"]:
        if cmd_name == "last":
            output = ("admin   pts/0        192.168.1.10    Wed May  3 10:01   still logged in\n"
                      "devops  pts/1        192.168.1.11    Wed May  3 09:55 - 10:15  (00:20)\n"
                      "dbadmin pts/2        192.168.1.12    Wed May  3 09:50 - 10:05  (00:15)")
        elif cmd_name == "who":
            output = ("admin    tty7         2023-05-03 10:00 (:0)\n"
                      "devops   pts/0        2023-05-03 09:55 (192.168.1.11)\n"
                      "dbadmin  pts/1        2023-05-03 09:50 (192.168.1.12)")
        elif cmd_name == "w":
            output = (" 10:01:00 up 5 days,  3 users,  load average: 0.15, 0.10, 0.05\n"
                      "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
                      "admin    tty7     :0               10:00   1:00m  0.20s  0.20s /usr/bin/startx\n"
                      "devops   pts/0    192.168.1.11     09:55   5:00   0.10s  0.10s bash\n"
                      "dbadmin  pts/1    192.168.1.12     09:50   3:00   0.15s  0.15s bash")
    elif cmd_name in ["exit", "logout"]:
        output = ""
    else:
        output = f"bash: {cmd_name}: command not found"
    return output, new_dir

# ======================================
# Classe SSH Server (Honeypot)
# ======================================
class HoneyPotServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.username = None
        self.password = None
        self.session_id = None
        self.redirect = False
        self.real_client = None
        self.exec_command = None
        super().__init__()
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def get_allowed_auths(self, username):
        return "publickey,password"
    def check_auth_publickey(self, username, key):
        try:
            fingerprint = key.get_fingerprint().hex()
        except Exception:
            fingerprint = "unknown"
        print(f"[!] Tentative d'auth SSH par clé publique de {self.client_ip} (user={username}, empreinte={fingerprint})")
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL
    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        success = 1
        redirected_flag = 0
        if ENABLE_REDIRECTION:
            try:
                real_client = paramiko.SSHClient()
                real_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                real_client.connect(REAL_SSH_HOST, REAL_SSH_PORT, username=username, password=password, timeout=5)
                self.redirect = True
                self.real_client = real_client
                redirected_flag = 1
                print(f"[+] Identifiants valides pour le vrai serveur: {username}@{REAL_SSH_HOST}")
            except Exception:
                self.redirect = False
                redirected_flag = 0
                try:
                    real_client.close()
                except Exception:
                    pass
        try:
            conn = sqlite3.connect(DB_NAME)
            conn.execute("PRAGMA busy_timeout = 3000")
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO login_attempts(timestamp, ip, username, password, success, redirected)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (timestamp, self.client_ip, username, password, success, redirected_flag))
            conn.commit()
            self.session_id = cur.lastrowid
            cur.execute("SELECT COUNT(*) FROM login_attempts WHERE ip = ?", (self.client_ip,))
            count = cur.fetchone()[0]
            if count >= BRUTE_FORCE_THRESHOLD:
                with _brute_force_lock:
                    if self.client_ip not in _brute_force_alerted:
                        cur.execute("""
                            INSERT INTO events(timestamp, ip, username, event_type, details)
                            VALUES (?, ?, ?, ?, ?)
                        """, (timestamp, self.client_ip, username, "Brute-force", f"Tentatives multiples depuis {self.client_ip}"))
                        conn.commit()
                        _brute_force_alerted.add(self.client_ip)
            conn.close()
        except Exception as e:
            print(f"[!] Erreur lors de l'enregistrement DB: {e}")
        return paramiko.AUTH_SUCCESSFUL
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    def check_channel_exec_request(self, channel, command):
        try:
            self.exec_command = command.decode('utf-8')
        except Exception:
            self.exec_command = str(command)
        self.event.set()
        return True

# ======================================
# Gestion d'une connexion SSH
# ======================================
def handle_connection(client_socket, client_addr):
    client_ip = client_addr[0]
    print(f"[+] Nouvelle connexion de {client_ip}")
    try:
        transport = paramiko.Transport(client_socket)
    except Exception as e:
        print(f"[!] Impossible d'initier le transport SSH pour {client_ip}: {e}")
        client_socket.close()
        return
    try:
        transport.local_version = SSH_BANNER
        host_key = paramiko.RSAKey(filename="my_host_key")
        transport.add_server_key(host_key)
        server = HoneyPotServer(client_ip)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            print(f"[!] Négociation SSH échouée avec {client_ip}: {e}")
            transport.close()
            return
        chan = transport.accept(20)
        if chan is None:
            print(f"[!] Aucun canal n'a été ouvert par {client_ip}")
            transport.close()
            return
        chan.settimeout(None)
        server.event.wait(10)
        if not server.event.is_set():
            print(f"[!] {client_ip} n'a pas demandé de shell/exec")
            chan.close()
            transport.close()
            return
        fs = {path: (value.copy() if isinstance(value, dict) else value)
              for path, value in BASE_FILE_SYSTEM.items()}
        if server.username and server.username in PREDEFINED_USERS:
            user_home = PREDEFINED_USERS[server.username]["home"]
            fs[user_home] = {"type": "dir", "contents": list(PREDEFINED_USERS[server.username]["files"].keys())}
            if server.username not in fs["/home"]["contents"]:
                fs["/home"]["contents"].append(server.username)
            for fname, fcontent in PREDEFINED_USERS[server.username]["files"].items():
                fs[f"{user_home}/{fname}"] = {"type": "file", "content": fcontent}
        elif server.username and server.username != "root":
            user_home = f"/home/{server.username}"
            fs[user_home] = {"type": "dir", "contents": ["credentials.txt", "config_backup.zip", "ssh_keys.tar.gz"]}
            if server.username not in fs["/home"]["contents"]:
                fs["/home"]["contents"].append(server.username)
            fs[f"{user_home}/credentials.txt"] = {"type": "file", "content": fs["/root/credentials.txt"]["content"]}
            fs[f"{user_home}/config_backup.zip"] = {"type": "file", "content": fs["/root/config_backup.zip"]["content"]}
            fs[f"{user_home}/ssh_keys.tar.gz"] = {"type": "file", "content": fs["/root/ssh_keys.tar.gz"]["content"]}
        # Ouverture du log de session avancé
        session_filename = os.path.join(SESSION_LOG_DIR, f"session_{client_ip}_{int(time.time())}.log")
        session_log = open(session_filename, "a")
        chan.send(b"Welcome to Debian GNU/Linux 10 (buster)\r\n\r\n")
        session_user = server.username if server.username else ""
        history = load_history(session_user)
        if session_user in PREDEFINED_USERS:
            current_dir = PREDEFINED_USERS[session_user]["home"]
        else:
            current_dir = "/root" if session_user == "root" else f"/home/{session_user}"
        session_log.write(f"{datetime.now().isoformat()} - Session started for user: {session_user}\n")
        while True:
            prompt = f"{session_user}@debian:{current_dir}$ "
            command = read_line_advanced(chan, prompt, history, current_dir, session_user, fs, session_log)
            if command == "":
                continue
            history.append(command)
            save_history(session_user, history)
            session_log.write(f"{datetime.now().isoformat()} - Command entered: {command}\n")
            output, new_dir = process_command(command, current_dir, session_user, fs, client_ip)
            current_dir = new_dir
            if output:
                if not output.endswith("\r\n"):
                    output += "\r\n"
                chan.send(output.encode())
                session_log.write(f"{datetime.now().isoformat()} - Command output: {output}\n")
            if command in ["exit", "logout"]:
                print(f"[-] {client_ip} a fermé la session via '{command}'")
                session_log.write(f"{datetime.now().isoformat()} - Session terminated by command: {command}\n")
                break
        session_log.close()
    except Exception as ex:
        print(f"[!] Exception dans handle_connection pour {client_ip}: {ex}")
    finally:
        try:
            chan.close()
        except Exception:
            pass
        transport.close()

# ======================================
# Création de l'arborescence et de l'archive
# ======================================
def create_file_structure_archive():
    base_dir = "honeypot"
    directories = [
        os.path.join(base_dir, "home"),
        os.path.join(base_dir, "home", "admin"),
        os.path.join(base_dir, "etc"),
        os.path.join(base_dir, "var"),
        os.path.join(base_dir, "var", "www"),
        os.path.join(base_dir, "scripts"),
        os.path.join(base_dir, "logs"),
    ]
    for d in directories:
        os.makedirs(d, exist_ok=True)
    #======================================
    # Fichier avec fausses connexions
    #======================================
    passwords_path = os.path.join(base_dir, "home", "admin", "passwords.txt")
    with open(passwords_path, "w") as f:
        for i in range(60):
            fake_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            fake_ip = f"192.168.1.{random.randint(2,254)}"
            f.write(f"{fake_time} - Failed login for user admin from {fake_ip}\n")
    #======================================
    # Historique factice des commandes
    #======================================
    bash_history_path = os.path.join(base_dir, "home", "admin", ".bash_history")
    with open(bash_history_path, "w") as f:
        fake_commands = [
            "ls -la", "cat /etc/passwd", "whoami", "sudo apt-get update",
            "tail -n 50 /var/log/syslog", "echo 'Hello World'",
            "ps aux", "cd /var/www", "vim index.php", "rm -rf /tmp/*"
        ]
        for _ in range(60):
            f.write(random.choice(fake_commands) + "\n")
    #======================================
    # Fichiers appât / Honeytokens
    #======================================
    confidential_notes_path = os.path.join(base_dir, "home", "admin", "confidential-notes.txt")
    with open(confidential_notes_path, "w") as f:
        f.write("Top Secret:\nNe divulguez sous aucun prétexte les informations suivantes...\nDétails sensibles ici.\n")
    ssh_config_backup_path = os.path.join(base_dir, "home", "admin", "ssh_config_backup.conf")
    with open(ssh_config_backup_path, "w") as f:
        f.write(
            "# SSH configuration backup\n"
            "Port 22\nPermitRootLogin no\nPasswordAuthentication yes\n"
            "ChallengeResponseAuthentication no\nUsePAM yes\nX11Forwarding yes\n"
            "PrintMotd no\nAcceptEnv LANG LC_*\nSubsystem sftp /usr/lib/openssh/sftp-server\n"
        )
    #======================================
    # Honeytokens supplémentaires
    #======================================
    fin_report_path = os.path.join(base_dir, "home", "admin", "financial_report.pdf")
    with open(fin_report_path, "w") as f:
        f.write("CONFIDENTIAL FINANCIAL REPORT\nMarker: FIN-REPORT-XYZ\nDo not distribute.")
    email_eml_path = os.path.join(base_dir, "home", "admin", "compromised_email.eml")
    with open(email_eml_path, "w") as f:
        f.write("Subject: Compromised Email\nMarker: COMP-EMAIL-ABC\nSensitive email content here.")
    secret_plans_path = os.path.join(base_dir, "home", "admin", "secret_plans.txt")
    with open(secret_plans_path, "w") as f:
        f.write("Top Secret Plans\nMarker: SECRET-PLANS-123\nInternal use only.")
    #======================================
    # Autres fichiers statiques
    #======================================
    db_config_path = os.path.join(base_dir, "etc", "db_config.ini")
    with open(db_config_path, "w") as f:
        f.write(
            "[database]\nhost = 127.0.0.1\nport = 3306\nuser = dbadmin\n"
            "password = secret123\ndbname = honeypot_db\n"
        )
    system_log_path = os.path.join(base_dir, "etc", "system.log")
    with open(system_log_path, "w") as f:
        f.write("Mar 15 12:00:00 debian systemd[1]: Starting system logging...\nMar 15 12:00:05 debian systemd[1]: Started system logging.\n")
    index_php_path = os.path.join(base_dir, "var", "www", "index.php")
    with open(index_php_path, "w") as f:
        f.write("<?php\n echo 'Welcome to the honeypot website!';\n?>\n")
    database_dump_path = os.path.join(base_dir, "var", "www", "database_dump.sql")
    with open(database_dump_path, "w") as f:
        f.write(
            "-- Fake SQL dump\nDROP TABLE IF EXISTS users;\n"
            "CREATE TABLE users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50));\n"
            "INSERT INTO users (id, username, password) VALUES (1, 'admin', 'supersecret');\n"
            "INSERT INTO users (id, username, password) VALUES (2, 'guest', 'guest');\n"
            "INSERT INTO users (id, username, password) VALUES (3, 'user1', 'password1');\n"
            "INSERT INTO users (id, username, password) VALUES (4, 'user2', 'password2');\n"
            "INSERT INTO users (id, username, password) VALUES (5, 'user3', 'password3');\n"
            "INSERT INTO users (id, username, password) VALUES (6, 'user4', 'password4');\n"
            "INSERT INTO users (id, username, password) VALUES (7, 'user5', 'password5');\n"
            "INSERT INTO users (id, username, password) VALUES (8, 'user6', 'password6');\n"
            "INSERT INTO users (id, username, password) VALUES (9, 'user7', 'password7');\n"
            "INSERT INTO users (id, username, password) VALUES (10, 'user8', 'password8');\n"
            "INSERT INTO users (id, username, password) VALUES (11, 'user9', 'password9');\n"
            "INSERT INTO users (id, username, password) VALUES (12, 'user10', 'password10');\n"
            "INSERT INTO users (id, username, password) VALUES (13, 'user11', 'password11');\n"
            "INSERT INTO users (id, username, password) VALUES (14, 'user12', 'password12');\n"
            "INSERT INTO users (id, username, password) VALUES (15, 'user13', 'password13');\n"
            "INSERT INTO users (id, username, password) VALUES (16, 'user14', 'password14');\n"
            "INSERT INTO users (id, username, password) VALUES (17, 'user15', 'password15');\n"
            "INSERT INTO users (id, username, password) VALUES (18, 'user16', 'password16');\n"
            "INSERT INTO users (id, username, password) VALUES (19, 'user17', 'password17');\n"
            "INSERT INTO users (id, username, password) VALUES (20, 'user18', 'password18');\n"
            "INSERT INTO users (id, username, password) VALUES (21, 'user19', 'password19');\n"
            "INSERT INTO users (id, username, password) VALUES (22, 'user20', 'password20');\n"
        )
    backup_sh_path = os.path.join(base_dir, "scripts", "backup.sh")
    with open(backup_sh_path, "w") as f:
        f.write("#!/bin/bash\n# Fake backup script\ntar -czf /backup/$(date +%F).tar.gz /important_data\n")
    deploy_sh_path = os.path.join(base_dir, "scripts", "deploy.sh")
    with open(deploy_sh_path, "w") as f:
        f.write("#!/bin/bash\n# Fake deploy script\nsystemctl restart apache2\n")
    auth_log_path = os.path.join(base_dir, "logs", "auth.log")
    with open(auth_log_path, "w") as f:
        f.write("Mar 15 12:00:10 debian sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 2222 ssh2\n")
    ssh_access_log_path = os.path.join(base_dir, "logs", "ssh_access.log")
    with open(ssh_access_log_path, "w") as f:
        f.write("Mar 15 12:01:00 debian sshd[1234]: Accepted password for admin from 192.168.1.51 port 2222 ssh2\n")
    archive_path = "/mnt/data/honeypot.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(base_dir, arcname=os.path.basename(base_dir))
    shutil.rmtree(base_dir)
    print(f"Archive created at {archive_path}")

# ======================================
# Boucle principale
# ======================================
if __name__ == "__main__":
    init_database()
    create_file_structure_archive()
    report_thread = threading.Thread(target=weekly_report_thread, daemon=True)
    report_thread.start()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((HOST, PORT))
    except Exception as e:
        print(f"*** Échec du bind sur le port {PORT}: {e}")
        exit(1)
    server_sock.listen(100)
    print(f"[*] Honeypot SSH en écoute sur le port {PORT}...")
    try:
        while True:
            client, addr = server_sock.accept()
            t = threading.Thread(target=handle_connection, args=(client, addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Arrêt du honeypot.")
    finally:
        server_sock.close()
