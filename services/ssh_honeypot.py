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
from fpdf import FPDF  # Pour la génération PDF

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

# SMTP configuration (Gmail)
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "honeycute896@gmail.com"    # Remplacez par votre adresse Gmail
SMTP_PASS = "mgps uhqr ujux pbbf"        # Mot de passe d'application

# Adresses mail pour alertes
ALERT_FROM = SMTP_USER
ALERT_TO = "admin@example.com"

# Fichiers de logs pour keylogger et transferts
KEYSTROKES_LOG = "keystrokes.log"
FILE_TRANSFER_LOG = "file_transfers.log"

# ================================
# Simulated outputs for system commands
# ================================
FAKE_PS_OUTPUT = """USER       PID %CPU %MEM    VSZ   RSS TTY   STAT START   TIME COMMAND
root         1  0.1  1.0  22532  4100 ?     Ss   Nov06   0:04 /sbin/init splash
root       135  0.0  0.5  16384  2048 ?     Ss   Nov06   0:01 /usr/sbin/sshd -D
mysql      212  0.2  4.0 257800 16384 ?    Ssl  Nov06   5:10 /usr/sbin/mysqld
srvssh    1025  0.0  0.1   6180   820 pts/0 S+   12:34   0:00 ps aux"""

FAKE_NETSTAT_OUTPUT = """Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      135/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      220/apache2
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      212/mysqld
udp        0      0 0.0.0.0:68              0.0.0.0:*                           500/dhclient"""

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

# ================================
# Fake File System (leurres) - Étoffé
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
    "/root/credentials.txt": {"type": "file", "content": "username=admin\npassword=admin123\napi_key=ABCD-1234-EFGH-5678"},
    "/root/config_backup.zip": {"type": "file", "content": "PK\x03\x04...<binary zip content>..."},
    "/root/ssh_keys.tar.gz": {"type": "file", "content": "...\x1F\x8B\x08...<binary tar.gz content>..."},
    "/root/rootkit_detector.sh": {"type": "file", "content": "#!/bin/bash\necho 'Rootkit detector active'"},
    "/home": {"type": "dir", "contents": []},
    "/etc": {"type": "dir", "contents": ["passwd", "shadow", "apt", "service", "hosts"]},
    "/etc/passwd": {"type": "file", "content": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash"},
    "/etc/shadow": {"type": "file", "content": "root:*:18967:0:99999:7:::\nuser:*:18967:0:99999:7:::"},
    "/etc/hosts": {"type": "file", "content": "127.0.0.1 localhost\n192.168.1.100 honeypot.local"},
    "/tmp": {"type": "dir", "contents": []}
}

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

# =====================================
# Fonction d'autocomplétion améliorée
# =====================================
def get_completions(current_input, current_dir, username, fs):
    base_cmds = ["ls", "cd", "pwd", "whoami", "id", "uname", "echo", "cat", "rm",
                 "ps", "netstat", "uptime", "df", "exit", "logout", "find", "grep",
                 "head", "tail", "history", "sudo", "su", "apt-get", "dpkg", "make",
                 "last", "who", "w", "scp", "sftp"]
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


# ==============================================
# Fonction Trigger_Alert
# ==============================================
def trigger_alert(session_id, command, client_ip, username):
    """
    Envoie une alerte par email via SMTP Gmail (port 587, TLS).
    Enregistre également un événement "Suspicious" dans la table events.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        # Enregistrement de l'événement dans la table events
        cur.execute("""
            INSERT INTO events(timestamp, ip, username, event_type, details)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, client_ip, username, "Suspicious", f"Commande exécutée: {command}"))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Erreur lors de l'enregistrement de l'alerte en DB: {e}")

    # Préparation du mail
    subject = f"[HONEYPOT] Alerte commande suspecte de {client_ip}"
    body = f"Utilisateur: {username}\nCommande: {command}\nHeure: {timestamp}"
    msg = MIMEText(body)
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_TO
    msg["Subject"] = subject

    # Envoi du mail via Gmail
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
    except Exception as e:
        print(f"[!] Erreur lors de l'envoi du mail d'alerte via Gmail: {e}")


# ==============================================
# Simulation des commandes système avancées
# ==============================================
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

    # Commandes basiques et de navigation
    if cmd_name == "cd":
        target = arg_str if arg_str else "~"
        if target in ["", "~"]:
            new_dir = "/root" if username == "root" else f"/home/{username}"
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
            contents = fs[target_path]["contents"] if target_path in fs and fs[target_path]["type"] == "dir" else []
            output = "\r\n".join(contents)
    elif cmd_name == "pwd":
        output = current_dir
    elif cmd_name == "whoami":
        output = username
    elif cmd_name == "id":
        output = "uid=0(root) gid=0(root) groups=0(root)" if username == "root" else f"uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)"
    elif cmd_name == "uname":
        output = "Linux debian 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (Debian)" if arg_str else "Linux"
    elif cmd_name == "echo":
        output = arg_str
    elif cmd_name == "cat":
        if not arg_str:
            output = ""
        else:
            file_path = resolve_path(arg_str)
            if file_path == "/etc/shadow" and username != "root":
                output = f"cat: {arg_str}: Permission denied"
            elif file_path in fs:
                node = fs[file_path]
                output = node["content"] if node["type"] == "file" else f"cat: {arg_str}: Is a directory"
            else:
                output = f"cat: {arg_str}: No such file or directory"
    elif cmd_name == "rm":
        if not arg_str:
            output = "rm: missing operand"
        else:
            target_path = resolve_path(arg_str)
            # Détection d'attaques sur fichiers critiques
            if target_path in ["/etc/passwd", "/etc/shadow", "/root/.ssh/authorized_keys", "/root/rootkit_detector.sh"]:
                output = f"rm: cannot remove '{arg_str}': Permission denied (critical file)"
                trigger_alert(-1, f"Tentative de suppression de {target_path}", client_ip, username)
            elif target_path in fs:
                node = fs[target_path]
                if node["type"] == "file":
                    parent_dir = target_path.rsplit("/", 1)[0] or "/"
                    if parent_dir == "/root" and username != "root":
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
        output = FAKE_PS_OUTPUT
    elif cmd_name == "netstat":
        output = FAKE_NETSTAT_OUTPUT
    elif cmd_name == "uptime":
        output = get_dynamic_uptime()
    elif cmd_name == "df":
        output = get_dynamic_df()
    # Commandes avancées
    elif cmd_name == "find":
        args = arg_str.split()
        if not args:
            output = "find: missing argument"
        else:
            directory = args[0]
            pattern = args[1] if len(args) > 1 else ""
            results = [path for path in fs.keys() if path.startswith(directory) and (pattern == "" or pattern in path)]
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
    elif cmd_name == "history":
        output = "\r\n".join(load_history(username))
    # Simulation de commandes de gestion de privilèges
    elif cmd_name == "sudo":
        if username == "root":
            if arg_str:
                return process_command(arg_str, current_dir, username, fs, client_ip)
            else:
                output = ""
        else:
            output = f"[sudo] password for {username}: \nSorry, try again.\nSorry, try again.\nSorry, try again.\nsudo: 3 incorrect password attempts\n"
    elif cmd_name in ["su", "su-"]:
        if username == "root":
            output = ""
        else:
            output = "Password: \nsu: Authentication failure\n"
    # Simulation de commandes d'installation
    elif cmd_name == "apt-get":
        output = "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)"
    elif cmd_name == "dpkg":
        output = "dpkg: error: must be root to perform this command"
    elif cmd_name == "make":
        output = "make: Nothing to be done for 'all'."
    # Simulation de commandes de transfert de fichiers
    elif cmd_name in ["scp", "sftp"]:
        # Capture de la tentative de transfert
        with open(FILE_TRANSFER_LOG, "a") as f:
            f.write(f"{datetime.now()} - {username} from {client_ip} attempted file transfer: {arg_str}\n")
        output = f"bash: {cmd_name}: command not found"
    # Simulation de téléchargement
    elif cmd_name in ["wget", "curl"]:
        if "http" in arg_str:
            with open("downloads.log", "a") as f:
                f.write(f"{datetime.now()} - {username} from {client_ip} attempted download: {arg_str.split()[0]}\n")
        output = f"bash: {cmd_name}: command not found"
    elif cmd_name in ["ftp", "tftp"]:
        output = f"bash: {cmd_name}: command not found"
    elif cmd_name in ["chmod", "bash", "sh", "netcat", "nc", "python"]:
        output = ""
    elif cmd_name in ["last", "who", "w"]:
        # Simulation de logs systèmes multi-utilisateurs
        if cmd_name == "last":
            output = "user1   pts/0        192.168.1.10    Wed May  3 10:01   still logged in\nuser2   pts/1        192.168.1.11    Wed May  3 09:55 - 10:15  (00:20)"
        elif cmd_name == "who":
            output = "user1    tty7         2023-05-03 10:00 (:0)\nuser2    pts/0        2023-05-03 09:55 (192.168.1.11)"
        elif cmd_name == "w":
            output = " 10:01:00 up 5 days,  2 users,  load average: 0.15, 0.10, 0.05\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nuser1    tty7     :0               10:00   1:00m  0.20s  0.20s /usr/bin/startx"
    elif cmd_name in ["exit", "logout"]:
        output = ""
    else:
        output = f"bash: {cmd_name}: command not found"
    return output, new_dir

# =====================================
# Initialisation de la base SQLite
# =====================================
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

# =====================================
# Fonction de génération hebdomadaire de rapport PDF
# =====================================
def generate_weekly_report():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT * FROM events")
    events = cur.fetchall()
    conn.close()
    
    # Création d'un PDF à l'aide de FPDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Rapport Hebdomadaire du Honeypot SSH", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", size=10)
    for event in events:
        # Chaque événement est tuple: (id, timestamp, ip, username, event_type, details)
        line = f"{event[1]} | {event[2]} | {event[3]} | {event[4]} | {event[5]}"
        pdf.multi_cell(0, 5, line)
    report_filename = f"weekly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(report_filename)
    
    # Envoyer le rapport par mail
    subject = "Rapport Hebdomadaire Honeypot SSH"
    body = "Veuillez trouver en pièce jointe le rapport hebdomadaire des événements du Honeypot SSH."
    msg = MIMEText(body)
    msg["From"] = SMTP_USER
    msg["To"] = ALERT_TO
    msg["Subject"] = subject
    # Pour joindre le PDF, vous pouvez utiliser la classe MIMEBase. (Simplifié ici)
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
        # Attendre 7 jours (7*24*3600 secondes)
        time.sleep(7 * 24 * 3600)
        generate_weekly_report()

# =====================================
# Fonction de Keylogger SSH
# =====================================
def log_keystroke(char):
    with open(KEYSTROKES_LOG, "a") as f:
        f.write(char)

# =====================================
# Classe SSH Server (Honeypot)
# =====================================
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
            # Détection brute-force
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

# =====================================
# Gestion d'une connexion SSH (thread)
# =====================================
def handle_connection(client_socket, client_addr):
    """
    Gère une nouvelle connexion SSH :
      - Historique (flèches haut/bas)
      - Autocomplétion (Tab + double Tab)
      - Keylogger
      - Session log
      - Alerte si commandes suspectes
    """
    client_ip = client_addr[0]
    print(f"[+] Nouvelle connexion de {client_ip}")
    try:
        transport = paramiko.Transport(client_socket)
    except Exception as e:
        print(f"[!] Impossible d'initier le transport SSH pour {client_ip}: {e}")
        client_socket.close()
        return

    try:
        # Bannière SSH factice
        transport.local_version = SSH_BANNER
        # Charger la clé host du honeypot
        host_key = paramiko.RSAKey(filename="my_host_key")
        transport.add_server_key(host_key)
        
        # Instancier notre serveur
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

        # -- Si redirection ENABLE_REDIRECTION est activée, gère le code de redirection éventuel --
        # (Non détaillé ici : server.redirect / server.exec_command)

        # Préparer le faux FS pour l'utilisateur
        fs = {path: (value.copy() if isinstance(value, dict) else value)
              for path, value in BASE_FILE_SYSTEM.items()}
        if server.username and server.username != "root":
            user_home = f"/home/{server.username}"
            fs[user_home] = {"type": "dir", "contents": ["credentials.txt", "config_backup.zip", "ssh_keys.tar.gz"]}
            fs["/home"]["contents"].append(server.username)
            fs[f"{user_home}/credentials.txt"] = {"type": "file", "content": fs["/root/credentials.txt"]["content"]}
            fs[f"{user_home}/config_backup.zip"] = {"type": "file", "content": fs["/root/config_backup.zip"]["content"]}
            fs[f"{user_home}/ssh_keys.tar.gz"] = {"type": "file", "content": fs["/root/ssh_keys.tar.gz"]["content"]}

        # Envoyer une bannière de bienvenue
        chan.send(b"Welcome to Debian GNU/Linux 10 (buster)\r\n\r\n")

        # Définir l'utilisateur + l'historique + le répertoire courant
        session_user = server.username if server.username else ""
        history = load_history(session_user)
        current_dir = "/root" if session_user == "root" else f"/home/{session_user}"

        # Fichier de session (pour la relecture)
        session_filename = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        session_log = open(session_filename, "w")

        # Index d'historique (on se place en fin d'historique)
        history_index = len(history)

        running = True
        while running:
            full_prompt = f"{session_user}@debian:{current_dir}$ "
            chan.send(full_prompt.encode())
            session_log.write(full_prompt + "\n")

            current_input = ""
            last_was_tab = False

            while True:
                try:
                    byte = chan.recv(1)
                except Exception:
                    running = False
                    break
                if not byte:
                    running = False
                    break

                try:
                    char = byte.decode("utf-8", errors="ignore")
                except Exception:
                    continue

                # Enregistrer la frappe (keylogger)
                log_keystroke(char)
                session_log.write(char)

                # Fin de ligne ?
                if char in ("\r", "\n"):
                    break

                # Ctrl+C
                if char == "\x03":
                    chan.send(b"^C\r\n")
                    current_input = ""
                    session_log.write("\n")
                    break

                # Backspace
                if char in ("\x7f", "\x08"):
                    if current_input:
                        current_input = current_input[:-1]
                        chan.send(b'\x08 \x08')
                    last_was_tab = False
                    continue

                # Séquence d'échappement (flèches, etc.)
                if char == "\x1b":
                    seq = chan.recv(2)  # Ex: "[A"
                    if seq == b"[A":  # Flèche haut
                        if history_index > 0:
                            history_index -= 1
                            chan.send(b"\r\033[K")  # Effacer la ligne
                            wanted_cmd = history[history_index]
                            chan.send(full_prompt.encode() + wanted_cmd.encode())
                            current_input = wanted_cmd
                    elif seq == b"[B":  # Flèche bas
                        if history_index < len(history):
                            history_index += 1
                            chan.send(b"\r\033[K")
                            if history_index == len(history):
                                # Ligne vide
                                chan.send(full_prompt.encode())
                                current_input = ""
                            else:
                                wanted_cmd = history[history_index]
                                chan.send(full_prompt.encode() + wanted_cmd.encode())
                                current_input = wanted_cmd
                    elif seq == b"[C":  # Flèche droite (optionnel)
                        pass  # On ignore ou bip
                    elif seq == b"[D":  # Flèche gauche (optionnel)
                        pass  # On ignore ou bip

                    last_was_tab = False
                    continue

                # Touche Tab => autocomplétion
                if char == "\t":
                    if last_was_tab:
                        # Double tab => liste des complétions
                        completions = get_completions(current_input, current_dir, session_user, fs)
                        if completions:
                            chan.send(b"\r\n" + "\r\n".join(completions).encode() + b"\r\n")
                            chan.send(full_prompt.encode() + current_input.encode())
                        last_was_tab = False
                        continue
                    else:
                        # Simple tab => autocompléter
                        suggestion = autocomplete(current_input, current_dir, session_user, fs)
                        if suggestion and suggestion != current_input:
                            to_add = suggestion[len(current_input):]
                            chan.send(to_add.encode())
                            current_input = suggestion
                        else:
                            chan.send(b"\x07")  # bip
                        last_was_tab = True
                        continue

                # Caractère normal
                chan.send(char.encode())
                current_input += char
                last_was_tab = False

            # On a la commande complète
            chan.send(b"\r\n")
            command = current_input.strip()
            session_log.write("\n")

            if not command:
                continue

            # Logger la commande dans commands.log
            with open("commands.log", "a") as f:
                f.write(f"{datetime.now()} - {client_ip} - {session_user}: {command}\n")

            # Mettre à jour l'historique
            history.append(command)
            save_history(session_user, history)
            # Se replacer en fin d'historique
            history_index = len(history)

            # Enregistrer la commande en DB
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                conn = sqlite3.connect(DB_NAME)
                conn.execute("PRAGMA busy_timeout = 3000")
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO commands(timestamp, ip, username, command, session_id)
                    VALUES (?, ?, ?, ?, ?)
                """, (ts, client_ip, session_user, command, server.session_id))
                conn.commit()
                conn.close()
            except Exception as e:
                print(f"[!] Erreur enregistrement commande DB: {e}")

            # Vérifier si commande suspecte => alerte
            suspicious_keywords = ["wget", "curl", "ftp", "scp", "sftp", "tftp", "chmod +x",
                                   "bash -c", "sh -c", "python -c", "netcat", "nc ", "sudo", "su"]
            if any(kw in command.lower() for kw in suspicious_keywords):
                trigger_alert(server.session_id, command, client_ip, session_user)

            # Commandes "exit" ou "logout"
            if command in ["exit", "logout"]:
                print(f"[-] {client_ip} a fermé la session via '{command}'")
                running = False
                break

            # Exécuter la commande simulée
            time.sleep(0.1)
            try:
                output, new_dir = process_command(command, current_dir, session_user, fs, client_ip)
            except Exception as e:
                output = f"Error executing command: {e}"
                new_dir = current_dir

            current_dir = new_dir
            if output:
                if not output.endswith("\r\n"):
                    output += "\r\n"
                time.sleep(random.uniform(0.05, 0.2))
                chan.send(output.encode())
                session_log.write(output)

        chan.send(b"logout\r\n")
        session_log.close()

    except Exception as ex:
        print(f"[!] Exception dans handle_connection pour {client_ip}: {ex}")

    finally:
        try:
            chan.close()
        except Exception:
            pass
        transport.close()

# =====================================
# Fonction de Keylogger
# =====================================
def log_keystroke(char):
    with open(KEYSTROKES_LOG, "a") as f:
        f.write(char)

# =====================================
# Thread de génération hebdomadaire de rapport PDF
# =====================================
def weekly_report_thread():
    while True:
        # Attendre 7 jours
        time.sleep(7 * 24 * 3600)
        generate_weekly_report()

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
        # event: (id, timestamp, ip, username, event_type, details)
        line = f"{event[1]} | {event[2]} | {event[3]} | {event[4]} | {event[5]}"
        pdf.multi_cell(0, 5, line)
    report_filename = f"weekly_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(report_filename)
    
    # Envoyer le rapport par email
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

# =====================================
# Boucle principale du serveur honeypot SSH
# =====================================
if __name__ == "__main__":
    init_database()
    # Démarrer le thread du rapport hebdomadaire
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
