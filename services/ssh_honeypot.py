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

# =======================
# SMTP configuration (Gmail)
# =======================
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "honeycute896@gmail.com"    # Votre adresse Gmail
SMTP_PASS = "mgps uhqr ujux pbbf"        # Mot de passe d'application
ALERT_FROM = SMTP_USER
ALERT_TO = "admin@example.com"           # Adresse destinataire

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

def trigger_alert(session_id, command, client_ip, username):
    """ Envoie une alerte (stockée en base et par mail) pour une commande suspecte. """
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
# Intégrer les comptes préconfigurés dans le système de fichiers
BASE_FILE_SYSTEM = populate_predefined_users(BASE_FILE_SYSTEM)

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
# Fonction interactive avancée de lecture de ligne
# ==============================================
def read_line_advanced(chan, prompt, history, current_dir, username, fs):
    """
    Lit une ligne de commande en mode interactif avec :
      - Navigation dans l'historique (flèches haut/bas)
      - Déplacement du curseur (flèches gauche/droite)
      - Autocomplétion via Tab (simple Tab pour compléter, double Tab pour afficher les suggestions)
    Retourne la ligne saisie.
    """
    line_buffer = []      # Liste des caractères de la ligne
    cursor_pos = 0        # Position du curseur dans la ligne_buffer
    history_index = len(history)  # On démarre à la fin de l'historique
    last_was_tab = False

    # Afficher le prompt initial
    chan.send(prompt.encode())

    def redraw_line():
        # Effacer la ligne actuelle et réafficher le prompt et la ligne
        chan.send(b"\r\033[K")  # Retour chariot + effacement de la ligne
        chan.send((prompt + "".join(line_buffer)).encode())
        # Repositionner le curseur si nécessaire
        diff = len(line_buffer) - cursor_pos
        if diff > 0:
            chan.send(f"\033[{diff}D".encode())

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

        # Fin de la ligne
        if char in ("\r", "\n"):
            chan.send(b"\r\n")
            break

        # Gestion de Ctrl+C
        if char == "\x03":
            chan.send(b"^C\r\n")
            return ""

        # Gestion du backspace
        if char in ("\x7f", "\x08"):
            if cursor_pos > 0:
                cursor_pos -= 1
                line_buffer.pop(cursor_pos)
                redraw_line()
            last_was_tab = False
            continue

        # Gestion des séquences d'échappement (flèches)
        if char == "\x1b":
            seq = byte + chan.recv(2)  # Par exemple, "[A" pour flèche haut
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
            elif seq.endswith(b"[C"):  # Flèche droite
                if cursor_pos < len(line_buffer):
                    cursor_pos += 1
                    redraw_line()
            elif seq.endswith(b"[D"):  # Flèche gauche
                if cursor_pos > 0:
                    cursor_pos -= 1
                    redraw_line()
            last_was_tab = False
            continue

        # Gestion de la tabulation
        if char == "\t":
            if last_was_tab:
                # Double tab : afficher les complétions
                completions = get_completions("".join(line_buffer), current_dir, username, fs)
                if completions:
                    chan.send(b"\r\n")
                    for comp in completions:
                        chan.send((comp + "\r\n").encode())
                    redraw_line()
                last_was_tab = False
                continue
            else:
                # Simple tab : tenter l'autocomplétion
                current_str = "".join(line_buffer)
                suggestion = autocomplete(current_str, current_dir, username, fs)
                if suggestion and suggestion != current_str:
                    diff = suggestion[len(current_str):]
                    for ch in diff:
                        line_buffer.insert(cursor_pos, ch)
                        cursor_pos += 1
                    redraw_line()
                else:
                    chan.send(b"\x07")  # bip
                last_was_tab = True
                continue

        # Insertion du caractère dans le buffer
        line_buffer.insert(cursor_pos, char)
        cursor_pos += 1
        redraw_line()
        last_was_tab = False

    return "".join(line_buffer)

# ==============================================
# Simulation des commandes système avancées
# (Fonction process_command identique à votre version)
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
    if cmd_name == "cd":
        target = arg_str if arg_str else "~"
        if target in ["", "~"]:
            if username in PREDEFINED_USERS:
                new_dir = PREDEFINED_USERS[username]["home"]
            else:
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
                f.write(f"{datetime.now()} - {username} from {client_ip} attempted download: {arg_str.split()[0]}\n")
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
# Fonction de Keylogger SSH
# ======================================
def log_keystroke(char):
    with open(KEYSTROKES_LOG, "a") as f:
        f.write(char)

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
# Boucle principale de gestion des connexions SSH
# ======================================
def handle_connection(client_socket, client_addr):
    """
    Gère une nouvelle connexion SSH avec les fonctionnalités avancées :
      - Navigation dans l'historique avec flèches haut/bas
      - Déplacement du curseur avec flèches gauche/droite
      - Autocomplétion avec Tab (simple et double Tab)
      - Enregistrement du keylogger et de la session
      - Exécution des commandes via process_command
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

        # Préparer le système de fichiers
        fs = {path: (value.copy() if isinstance(value, dict) else value)
              for path, value in BASE_FILE_SYSTEM.items()}
        # Intégrer les comptes préconfigurés si l'utilisateur existe
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

        chan.send(b"Welcome to Debian GNU/Linux 10 (buster)\r\n\r\n")
        session_user = server.username if server.username else ""
        history = load_history(session_user)
        if session_user in PREDEFINED_USERS:
            current_dir = PREDEFINED_USERS[session_user]["home"]
        else:
            current_dir = "/root" if session_user == "root" else f"/home/{session_user}"

        # Boucle principale interactive en utilisant read_line_advanced
        while True:
            prompt = f"{session_user}@debian:{current_dir}$ "
            command = read_line_advanced(chan, prompt, history, current_dir, session_user, fs)
            if command == "":
                continue
            history.append(command)
            save_history(session_user, history)
            output, new_dir = process_command(command, current_dir, session_user, fs, client_ip)
            current_dir = new_dir
            if output:
                if not output.endswith("\r\n"):
                    output += "\r\n"
                chan.send(output.encode())
            if command in ["exit", "logout"]:
                print(f"[-] {client_ip} a fermé la session via '{command}'")
                break
    except Exception as ex:
        print(f"[!] Exception dans handle_connection pour {client_ip}: {ex}")
    finally:
        try:
            chan.close()
        except Exception:
            pass
        transport.close()

# ======================================
# Thread de génération hebdomadaire de rapport PDF
# ======================================
def weekly_report_thread():
    while True:
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

# ======================================
# Fonction de Keylogger SSH
# ======================================
def log_keystroke(char):
    with open(KEYSTROKES_LOG, "a") as f:
        f.write(char)

# ======================================
# Classe SSH Server – version unique
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
# Boucle principale de gestion des connexions SSH
# ======================================
if __name__ == "__main__":
    init_database()
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
