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
import json
import logging
import csv
from logging.handlers import RotatingFileHandler
import gzip
import shutil
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from fpdf import FPDF
import uuid
import select
import signal
import sys
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import hashlib
import string
from io import StringIO

# Configuration
HOST = ""  # Écoute sur toutes les interfaces
PORT = 2224  # Port personnalisé
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
ENABLE_REDIRECTION = False
REAL_SSH_HOST = "192.168.1.100"
REAL_SSH_PORT = 22

DB_NAME = "file:honey?mode=memory&cache=shared"  # Base en mémoire partagée
DB_CONN = sqlite3.connect(DB_NAME, uri=True, check_same_thread=False)
FS_DB = "file:filesystem?mode=memory&cache=shared"  # FS en mémoire partagée
FS_CONN = sqlite3.connect(FS_DB, uri=True, check_same_thread=False)
DB_LOCK = threading.Lock()
FS_LOCK = threading.Lock()
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 300  # 5 minutes
CMD_LIMIT_PER_SESSION = 50
CONNECTION_LIMIT_PER_IP = 10
_brute_force_attempts = {}  # {ip: [(timestamp, username, password)]}
_brute_force_alerted = set()
_brute_force_lock = threading.Lock()
_connection_count = {}  # {ip: count}
_connection_lock = threading.Lock()

# Login policy for admin user
ADMIN_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()
ADMIN_MAX_ATTEMPTS = 3
ADMIN_BAN_DURATION = 300  # seconds
_admin_attempts = {}  # {ip: count}
_admin_bans = {}  # {ip: ban_until}

# Login attempts for other users
_user_attempts = {}  # {(ip, username): count}
USER_SUCCESS_ATTEMPTS = 10

SESSION_LOG_DIR = "session_logs"
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "honey.log")
ALERT_LOG_FILE = os.path.join(LOG_DIR, "alerts.log")

# Console key logging level: 'full', 'filtered'
KEY_DISPLAY_MODE = "filtered"
# Mapping of ANSI escape sequences to human readable labels
ANSI_KEY_LABELS = {
    "\x1b[A": "<UP>",
    "\x1b[B": "<DOWN>",
    "\x1b[C": "<RIGHT>",
    "\x1b[D": "<LEFT>",
}
USER_DEFINED_COMMANDS = set()

# Commandes disponibles pour l'attaquant
AVAILABLE_COMMANDS = [
    "ls",
    "cd",
    "touch",
    "mkdir",
    "rm",
    "ipconfig",
    "systeminfo",
    "tree",
    "clear",
    "cls",
    "ver",
    "echo",
    "hostname",
    "whoami",
    "whoami /groups",
    "history",
    "move",
    "mov",
    "grep",
    "type",
    "cat",
    "pwd",
    "get-process",
    "get-service",
    "net user",
    "ping",
    "traceroute",
    "tracepath",
    "dig",
    "nslookup",
    "tcpdump",
    "nc",
    "netcat",
    "ss",
    "yum",
    "dnf",
    "apk",
    "pip",
    "npm",
    "gcc",
    "make",
    "cmake",
    "python",
    "node",
    "git",
    "docker",
    "kubectl",
    "helm",
    "docker-compose",
    "iptables",
    "fortune",
    "cowsay",
    "exit",
    "quit",
    "less",
    "more",
    "head",
    "tail",
    "sed",
    "awk",
    "cut",
    "sort",
    "uniq",
    "vim",
    "nano",
    "tar",
    "gzip",
    "gunzip",
    "zip",
    "unzip",
    "dd",
    "htop",
    "journalctl",
    "vmstat",
    "iostat",
    "free",
    "ifconfig",
    "netstat",
    "route",
    "arping",
    "mtr",
    "users",
    "groups",
    "last",
    "lastb",
    "apt",
    "apt-cache",
    "snap",
    "flatpak",
    "date",
    "env",
    "printenv",
    "export",
    "cron",
    "crontab",
    "mount",
    "df",
    "ssh-keygen",
    "alias",
    "unalias",
]

# Commandes interdites renvoyant une erreur de droits
FORBIDDEN_COMMANDS = [
    "runas",
    "net localgroup",
    "net user /add",
    "net group",
    "net accounts",
    "net share",
    "net start",
    "net stop",
    "sc",
    "regedit",
    "reg",
    "gpedit.msc",
    "secedit",
    "msiexec",
    "choco",
    "winget",
    "apt",
    "apt-get",
    "scp",
    "shutdown",
    "taskkill",
    "format",
    "diskpart",
    "bcdedit",
    "bootrec",
    "icacls",
    "takeown",
    "dd",
    "snap",
    "flatpak",
    "mount",
    "ssh-keygen",
]


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        return json.dumps(log_record)


def setup_logging():
    """Configure le systeme de journalisation et renvoie l'objet logger."""
    os.makedirs(LOG_DIR, exist_ok=True)
    handler = RotatingFileHandler(LOG_FILE, maxBytes=10240, backupCount=5)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("honey")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


LOGGER = setup_logging()


# Helper to log alerts in a human readable CSV format
def log_human_readable(timestamp, client_ip, username, event_type, details):
    """Enregistre un evenement dans un fichier CSV lisible par un humain."""
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(ALERT_LOG_FILE, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([timestamp, client_ip, username, event_type, details])


FAKE_SERVICES = {
    "ftp": 21,
    "http": 80,
    "mysql": 3306,
    "telnet": 23,
}

# Simple list of iptables rules for the simulated firewall
IPTABLES_RULES = [
    {"chain": "INPUT", "rule": "-p tcp --dport 22 -j ACCEPT"},
]

# Identifiants SMTP via variables d'environnement
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER", "honeycute896@gmail.com")
SMTP_PASS = os.getenv("SMTP_PASS", "jawm fmcm dmaf qkyl")
ALERT_FROM = SMTP_USER
ALERT_TO = os.getenv("ALERT_TO", "alexandreuzan75@gmail.com")
PREDEFINED_USERS = {
    "admin": {
        "home": "/home/admin",
        "password": hashlib.sha256("admin123".encode()).hexdigest(),
        "files": {
            "credentials.txt": "admin:supersecret\n# Internal use only",
            "sshkey": "ssh-rsa AAAAB3NzaC1yc2E...admin_key",
            "project_config": "projectA: sensitive data...",
            "backup_pass.txt": "root:admin123\nbackup:backup456",
        },
        "uid": 1000,
        "groups": ["admin", "sudo"],
    },
    "devops": {
        "home": "/home/devops",
        "files": {
            "deploy_key": "ssh-rsa AAAAB3NzaC1yc2E...devops_key",
            "jenkins.yml": "jenkins: {url: http://localhost:8080, user: admin, pass: admin123}",
            ".bashrc": "alias ll='ls -la'\nexport PATH=$PATH:/usr/local/bin",
        },
        "uid": 1001,
        "groups": ["devops"],
    },
    "dbadmin": {
        "home": "/home/dbadmin",
        "files": {
            "backup.sql": "-- SQL dump\nDROP TABLE IF EXISTS users;",
            "scripts.sh": "#!/bin/bash\necho 'DB maintenance...'",
            "mysql_creds.txt": "mysql_user:root\nmysql_pass:password123",
        },
        "uid": 1002,
        "groups": ["dbadmin"],
    },
    "mysql": {"home": "/var/lib/mysql", "files": {}, "uid": 110, "groups": ["mysql"]},
    "www-data": {
        "home": "/var/www",
        "files": {"config.php": "<?php define('DB_PASS', 'weakpass123'); ?>"},
        "uid": 33,
        "groups": ["www-data"],
    },
}

KEYSTROKES_LOG = None  # Désactivé
FILE_TRANSFER_LOG = None  # Désactivé
SENSITIVE_FILES = [
    "/home/admin/credentials.txt",
    "/home/admin/backup_pass.txt",
    "/home/dbadmin/mysql_creds.txt",
    "/var/www/config.php",
    "/tmp/suspicious.sh",
]

FAKE_NETWORK_HOSTS = {
    "192.168.1.10": {"name": "webserver.local", "services": ["http", "https"]},
    "192.168.1.20": {"name": "dbserver.local", "services": ["mysql"]},
    "192.168.1.30": {"name": "backup.local", "services": ["ftp"]},
    "8.8.8.8": {"name": "dns.google", "services": []},
    "1.1.1.1": {"name": "cloudflare-dns.com", "services": []},
}

# Jeu de données MySQL fictif pour le sous-système SQL
FAKE_MYSQL_DATA = {
    "users_db": {
        "credentials": {
            "columns": ["id", "user", "password"],
            "rows": [
                (1, "admin", "hunter2"),
                (2, "guest", "guestpass"),
                (3, "john", "secret123"),
            ],
        },
        "access_logs": {
            "columns": ["id", "user", "time"],
            "rows": [
                (1, "admin", "2024-01-01 00:00:00"),
                (2, "guest", "2024-01-01 01:00:00"),
                (3, "john", "2024-01-02 12:34:00"),
            ],
        },
        "employees": {
            "columns": ["id", "name", "department"],
            "rows": [
                (1, "Alice", "IT"),
                (2, "Bob", "HR"),
                (3, "Charlie", "Finance"),
            ],
        },
    },
    "logs": {
        "events": {
            "columns": ["id", "event"],
            "rows": [
                (1, "login"),
                (2, "logout"),
                (3, "unauthorized"),
            ],
        },
        "connections": {
            "columns": ["id", "ip"],
            "rows": [
                (1, "192.168.1.10"),
                (2, "192.168.1.20"),
                (3, "192.168.1.30"),
            ],
        },
        "sys_logs": {
            "columns": ["id", "level", "message"],
            "rows": [
                (1, "INFO", "System boot"),
                (2, "WARN", "High load"),
                (3, "ERROR", "Disk failure"),
            ],
        },
    },
    "secrets": {
        "flags": {
            "columns": ["flag"],
            "rows": [
                ("FLAG{dummy_flag}",),
            ],
        },
        "users": {
            "columns": ["id", "username", "hash"],
            "rows": [
                (1, "root", "5f4dcc3b5aa765d61d8327deb882cf99"),
                (2, "service", "5ebe2294ecd0e0f08eab7690d2a6ee69"),
            ],
        },
    },
}

COMMAND_OPTIONS = {
    "ls": ["-l", "-a", "-n", "-la", "-ln", "-lh", "-lhS", "--help"],
    "cat": ["-n", "--help"],
    "grep": ["-i", "-r", "-n", "--help"],
    "find": ["-name", "-type", "-exec", "--help"],
    "chmod": ["-R", "+x", "755", "644", "--help"],
    "chown": ["-R", "--help"],
    "service": ["start", "stop", "status", "restart"],
    "systemctl": ["start", "stop", "status", "restart", "enable", "disable"],
    "ip": ["addr", "link", "route"],
    "apt-get": ["update", "upgrade", "install", "remove"],
    "scp": ["-r", "-P"],
    "curl": ["-O", "-L", "--help"],
    "wget": ["-O", "-q", "--help"],
    "telnet": [],
    "ping": ["-c", "-i"],
    "nmap": ["-sS", "-sV"],
    "man": ["--help", "-k", "-f"],
    "tree": [],
    "traceroute": [],
    "tracepath": [],
    "dig": [],
    "nslookup": [],
    "tcpdump": [],
    "nc": ["-l"],
    "netcat": ["-l"],
    "ss": [],
    "yum": ["install", "update", "remove"],
    "dnf": ["install", "update", "remove"],
    "apk": ["add", "del", "update"],
    "pip": ["install"],
    "npm": ["install"],
    "gcc": [],
    "make": [],
    "cmake": [],
    "python": [],
    "node": [],
    "git": ["status", "push", "pull"],
    "docker": ["ps", "images"],
    "kubectl": ["get", "describe"],
    "helm": ["list"],
    "docker-compose": ["up", "down"],
    "iptables": ["-L", "-A", "-D", "-I"],
    "less": ["+F", "-N", "--help"],
    "more": ["--help"],
    "head": ["-n", "--help"],
    "tail": ["-n", "-f", "--help"],
    "sed": ["-n", "-e", "-i"],
    "awk": ["-F", "-v"],
    "cut": ["-d", "-f"],
    "sort": ["-r", "-n"],
    "uniq": ["-c", "-d"],
    "vim": [],
    "nano": [],
    "tar": ["-xvf", "-cvf"],
    "gzip": ["-d", "-k"],
    "gunzip": ["-c", "-f"],
    "zip": ["-r"],
    "unzip": ["-l", "-o"],
    "dd": ["if=", "of=", "bs="],
    "htop": ["-d", "-p"],
    "journalctl": ["-u", "-f", "-n"],
    "vmstat": ["-s", "-d"],
    "iostat": ["-x", "-d"],
    "free": ["-h"],
    "ifconfig": [],
    "netstat": ["-r"],
    "route": [],
    "arping": [],
    "mtr": [],
    "users": [],
    "groups": [],
    "last": [],
    "lastb": [],
    "apt": ["update", "upgrade", "install", "remove"],
    "apt-cache": ["search", "show"],
    "snap": ["install", "remove", "list"],
    "flatpak": ["install", "remove", "list"],
    "date": ["+%F", "+%T"],
    "env": [],
    "printenv": [],
    "export": [],
    "cron": [],
    "crontab": ["-l", "-e"],
    "mount": ["-t", "-o"],
    "df": ["-h"],
    "ssh-keygen": ["-t", "-f"],
    "alias": [],
    "unalias": [],
}

# Minimal manual pages for built-in commands
MAN_PAGES = {
    "ls": """LS(1)\nNAME\n    ls - list directory contents\n\nSYNOPSIS\n    ls [OPTION]... [FILE]...\n\nDESCRIPTION\n    List information about the FILEs (the current directory by default).""",
    "cd": """CD(1)\nNAME\n    cd - change the shell working directory\n\nSYNOPSIS\n    cd [DIRECTORY]\n\nDESCRIPTION\n    Change the current directory to DIRECTORY.""",
    "pwd": """PWD(1)\nNAME\n    pwd - print name of current working directory\n\nSYNOPSIS\n    pwd\n\nDESCRIPTION\n    Display the full pathname of the current directory.""",
    "man": """MAN(1)\nNAME\n    man - an interface to the system reference manuals\n\nSYNOPSIS\n    man [COMMAND]\n\nDESCRIPTION\n    Display the manual page for COMMAND.""",
    "who": """WHO(1)\nNAME\n    who - show who is logged on\n\nSYNOPSIS\n    who\n\nDESCRIPTION\n    List logged in users.""",
}


# Colored prompt helper
def color_prompt(username, client_ip, current_dir):
    """Retourne l'invite de commande colorisee pour l'utilisateur."""
    user_color = "\033[1;31m" if username == "root" else "\033[1;32m"
    dir_color = (
        "\033[1;31m" if current_dir in ["/root", "/etc", "/var/log"] else "\033[1;34m"
    )
    return (
        f"{user_color}{username}@{client_ip}\033[0m:{dir_color}{current_dir}\033[0m$ "
    )


# Données dynamiques
@lru_cache(maxsize=10)
def get_dynamic_df():
    """Simule la commande 'df' avec des valeurs aleatoires."""
    sizes = {"sda1": "50G", "tmpfs": "100M"}
    used = {"sda1": f"{random.randint(5, 10)}G", "tmpfs": "0M"}
    avail = {"sda1": f"{random.randint(30, 45)}G", "tmpfs": "100M"}
    usep = {"sda1": f"{random.randint(10, 20)}%", "tmpfs": "0%"}
    return f"""Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        {sizes['sda1']}   {used['sda1']}   {avail['sda1']}  {usep['sda1']} /
tmpfs           {sizes['tmpfs']}     {used['tmpfs']}  {avail['tmpfs']}   {usep['tmpfs']} /tmp"""


@lru_cache(maxsize=10)
def get_dynamic_uptime():
    """Simule la sortie de la commande 'uptime'."""
    now = datetime.now().strftime("%H:%M:%S")
    days = random.randint(3, 10)
    hours = random.randint(0, 23)
    minutes = random.randint(0, 59)
    users = random.randint(1, 5)
    la1, la2, la3 = [f"{random.uniform(0.00, 1.00):.2f}" for _ in range(3)]
    return f"{now} up {days} days, {hours}:{minutes:02d}, {users} user{'s' if users > 1 else ''}, load average: {la1}, {la2}, {la3}"


@lru_cache(maxsize=10)
def get_dynamic_ps():
    """Genere une liste fictive de processus systeme."""
    processes = [
        ("root", "1", "/sbin/init"),
        ("root", "135", "/usr/sbin/sshd -D"),
        ("mysql", "220", "/usr/sbin/mysqld"),
        ("www-data", "300", "/usr/sbin/nginx -g 'daemon off;'"),
        ("admin", str(random.randint(1000, 5000)), "/bin/bash"),
        ("devops", str(random.randint(1000, 5000)), "/usr/bin/python3 app.py"),
        ("dbadmin", str(random.randint(1000, 5000)), "/bin/sh scripts.sh"),
    ]
    if random.random() < 0.3:
        processes.append(
            ("root", str(random.randint(6000, 7000)), "/usr/bin/find / -name '*.log'")
        )
    lines = ["USER       PID %CPU %MEM    VSZ   RSS TTY   STAT START   TIME COMMAND"]
    for user, pid, cmd in processes:
        cpu = round(random.uniform(0.0, 5.0), 1)
        mem = round(random.uniform(0.5, 3.0), 1)
        vsz = random.randint(10000, 50000)
        rss = random.randint(1000, 5000)
        tty = random.choice(["pts/0", "pts/1", "?", "tty7"])
        stat = random.choice(["Ss", "S+", "R"])
        start = (datetime.now() - timedelta(hours=random.randint(1, 24))).strftime(
            "%H:%M"
        )
        time_str = f"{random.randint(0, 2)}:{random.randint(0, 59):02d}"
        lines.append(
            f"{user:<10} {pid:<6} {cpu:<5} {mem:<5} {vsz:<7} {rss:<6} {tty:<6} {stat:<5} {start:<8} {time_str:<6} {cmd}"
        )
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_top():
    """Retourne une sortie type 'top' basee sur des donnees aleatoires."""
    header = (
        "top - %s up %d days, %02d:%02d, %d user%s, load average: %.2f, %.2f, %.2f\n"
        % (
            datetime.now().strftime("%H:%M:%S"),
            random.randint(3, 10),
            random.randint(0, 23),
            random.randint(0, 59),
            random.randint(1, 5),
            "s" if random.randint(1, 5) > 1 else "",
            random.uniform(0.0, 1.0),
            random.uniform(0.0, 1.0),
            random.uniform(0.0, 1.0),
        )
    )
    tasks = "Tasks: %d total, %d running, %d sleeping, %d stopped, %d zombie\n" % (
        random.randint(50, 100),
        random.randint(1, 5),
        random.randint(40, 80),
        0,
        0,
    )
    cpu = (
        "%%Cpu(s): %.1f us, %.1f sy, %.1f ni, %.1f id, %.1f wa, %.1f hi, %.1f si, %.1f st\n"
        % (
            random.uniform(0, 10),
            random.uniform(0, 5),
            0,
            random.uniform(80, 90),
            random.uniform(0, 2),
            random.uniform(0, 1),
            random.uniform(0, 1),
            0,
        )
    )
    mem = "MiB Mem : %d total, %d free, two %d used, %d buff/cache\n" % (
        random.randint(16000, 32000),
        random.randint(1000, 5000),
        random.randint(5000, 10000),
        random.randint(1000, 5000),
    )
    processes = get_dynamic_ps().split("\n")[1:]
    return header + tasks + cpu + mem + "\n" + "\n".join(processes[:5])


@lru_cache(maxsize=10)
def get_dynamic_netstat():
    """Cree un tableau de connexions reseau factices."""
    lines = [
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name"
    ]
    for _ in range(random.randint(2, 6)):
        local_ip = f"192.168.1.{random.randint(2, 254)}"
        local_port = random.choice([22, 80, 443, 3306, 8080])
        foreign_ip = f"10.0.0.{random.randint(2, 254)}"
        foreign_port = random.randint(1024, 65535)
        state = random.choice(["ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "LISTEN"])
        pid_prog = f"{random.randint(100, 999)}/app{random.randint(1, 5)}"
        lines.append(
            f"tcp        {random.randint(0, 10)}      {random.randint(0, 10)} {local_ip}:{local_port}  {foreign_ip}:{foreign_port}  {state:<10} {pid_prog}"
        )
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_messages():
    """Fournit des messages pour simuler /var/log/messages."""
    lines = []
    for _ in range(10):
        timestamp = (
            datetime.now() - timedelta(minutes=random.randint(0, 1440))
        ).strftime("%b %d %H:%M:%S")
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        service = random.choice(
            ["sshd", "systemd", "cron", "nginx", "apache2", "mysqld"]
        )
        message = random.choice(
            [
                f"{service}[{random.randint(1000, 9999)}]: Started {service} service.",
                f"{service}: Connection from {src_ip}",
                f"{service}: Configuration loaded successfully.",
                f"{service}: Warning: High CPU usage detected.",
                f"{service}: Failed login attempt from {src_ip}",
                f"{service}: Suspicious activity on port {random.randint(1024, 65535)}",
            ]
        )
        lines.append(f"{timestamp} debian {message}")
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_dmesg():
    """Genere de fausses lignes provenant du noyau."""
    lines = []
    for _ in range(10):
        timestamp = f"[{random.uniform(0, 1000):.6f}]"
        message = random.choice(
            [
                "kernel: [CPU0] microcode updated early to revision 0xca",
                "kernel: random: crng init done",
                "kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode",
                "kernel: ACPI: Power Button [PWRB]",
            ]
        )
        lines.append(f"{timestamp} {message}")
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_network_scan():
    """Simule les resultats d'un scan reseau."""
    lines = []
    for ip, info in FAKE_NETWORK_HOSTS.items():
        for service in info["services"]:
            port = FAKE_SERVICES.get(service, 0)
            if port:
                lines.append(f"{ip}:{port} open {service}")
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_traceroute(host):
    """Genere un traceroute fictif vers la cible."""
    hops = random.randint(5, 10)
    lines = [f"traceroute to {host} ({host}), {hops} hops max"]
    for i in range(1, hops + 1):
        ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
        latency = random.uniform(1.0, 100.0)
        lines.append(f" {i}  {ip}  {latency:.2f} ms")
    lines.append(f" {hops + 1}  {host}  {random.uniform(0.1, 1.0):.2f} ms")
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_dig(query):
    """Renvoie une reponse DNS fictive."""
    ip = f"203.0.113.{random.randint(1, 254)}"
    return (
        f"; <<>> DiG 9.18 <<>> {query}\n"
        ";; ANSWER SECTION:\n"
        f"{query}. 86400 IN A {ip}\n"
        f"{query}. 86400 IN NS ns1.example.com.\n"
        f"{query}. 86400 IN NS ns2.example.com."
    )


@lru_cache(maxsize=10)
def get_dynamic_tcpdump():
    """Genere quelques en-tetes de paquets simulés."""
    lines = []
    for _ in range(random.randint(3, 6)):
        src = f"192.168.1.{random.randint(2, 254)}"
        dst = f"10.0.0.{random.randint(1, 254)}"
        sport = random.randint(1024, 65535)
        dport = random.choice([22, 80, 443, 3306])
        proto = random.choice(["TCP", "UDP"])
        lines.append(
            f"{proto} {src}:{sport} > {dst}:{dport} Flags [S], length 0"
        )
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_ss():
    """Simule la commande 'ss' en reutilisant netstat."""
    return get_dynamic_netstat()


@lru_cache(maxsize=10)
def get_dynamic_arp():
    """Renvoie une table ARP fictive."""
    lines = [
        "Address                  HWtype  HWaddress           Flags Mask            Iface"
    ]
    for ip in FAKE_NETWORK_HOSTS:
        mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        lines.append(f"{ip:<24} ether   {mac}   C                     eth0")
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_who():
    """Simule la commande 'who'."""
    lines = []
    users = ["admin", "devops", "dbadmin"] + [
        f"temp_{''.join(random.choices(string.ascii_lowercase, k=6))}"
        for _ in range(random.randint(0, 3))
    ]
    for user in users:
        timestamp = (
            datetime.now() - timedelta(minutes=random.randint(0, 1440))
        ).strftime("%Y-%m-%d %H:%M")
        tty = random.choice(["pts/0", "pts/1", "tty7"])
        host = f"192.168.1.{random.randint(10, 50)}"
        lines.append(f"{user:<10} {tty:<8} {timestamp} {host}")
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_w():
    """Simule la commande 'w'."""
    return get_dynamic_who()


def get_dev_null():
    """Equivalent a /dev/null, renvoie une chaine vide."""
    return ""


def get_dev_zero():
    """Equivalent a /dev/zero, renvoie des octets nuls."""
    return "\0" * 1024


@lru_cache(maxsize=10)
def get_realistic_docker_ps():
    """Genere une sortie ressemblant a 'docker ps'."""
    lines = [
        "CONTAINER ID   IMAGE          COMMAND                  CREATED          STATUS          PORTS                    NAMES",
        "2f7b8c1d2e3f   nginx:latest   'nginx -g \"daemon off;\"'  2 hours ago      Up 2 hours      0.0.0.0:80->80/tcp       web",
        "7c9d0e1f2a3b   postgres:13    'docker-entrypoint.s…'   3 hours ago      Up 3 hours      0.0.0.0:5432->5432/tcp   db",
    ]
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_realistic_docker_compose_up():
    """Genere une sortie typee de 'docker-compose up'."""
    return (
        "Creating network \"myapp_default\" with the default driver\n"
        "Creating volume \"myapp_db_data\" with default driver\n"
        "Creating myapp_db_1 ... done\n"
        "Creating myapp_web_1 ... done"
    )


@lru_cache(maxsize=10)
def get_realistic_kubectl_get_pods():
    """Genere une sortie ressemblant a 'kubectl get pods'."""
    lines = [
        "NAME                         READY   STATUS    RESTARTS   AGE",
        "webserver-6d7ffbd4c8-wx4gm   1/1     Running   0          3d4h",
        "database-0                   1/1     Running   0          3d4h",
    ]
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_realistic_helm_list():
    """Genere une sortie pour 'helm list'."""
    lines = [
        "NAME       NAMESPACE  REVISION  UPDATED                                 STATUS    CHART                APP VERSION",
        "nginx      default    1         2024-06-01 12:00:00.000000 +0000 UTC     deployed  nginx-8.9.1          1.25.2",
        "postgres   default    2         2024-06-01 12:05:00.000000 +0000 UTC     deployed  postgresql-10.3.11   14.2.0",
    ]
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_realistic_git_status():
    """Genere une sortie realiste pour 'git status'."""
    return (
        "On branch main\n"
        "Your branch is up to date with 'origin/main'.\n\n"
        "nothing to commit, working tree clean"
    )


@lru_cache(maxsize=10)
def get_realistic_git_push():
    """Genere une sortie realiste pour 'git push' echouant."""
    return (
        "Enumerating objects: 5, done.\n"
        "Counting objects: 100% (5/5), done.\n"
        "Delta compression using up to 8 threads\n"
        "Compressing objects: 100% (3/3), done.\n"
        "Writing objects: 100% (3/3), 291 bytes | 291.00 KiB/s, done.\n"
        "Total 3 (delta 2), reused 0 (delta 0), pack-reused 0\n"
        "remote: error: insufficient permissions\n"
        "To github.com:fake/repo.git\n"
        " ! [remote rejected] main -> main (permission denied)\n"
        "error: failed to push some refs to 'github.com:fake/repo.git'"
    )


# Gestion du système de fichiers
def init_filesystem_db():
    """Cree la base de donnees representant le systeme de fichiers."""
    try:
        FS_CONN.execute(
            """
                CREATE TABLE IF NOT EXISTS filesystem (
                    path TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    content TEXT,
                    owner TEXT,
                    permissions TEXT,
                    mtime TEXT
                )
            """
        )
        FS_CONN.commit()
        print("[*] Filesystem database initialized successfully")
    except sqlite3.Error as e:
        print(f"[!] Filesystem DB init error: {e}")
        raise


def load_filesystem():
    """Charge l'etat du systeme de fichiers depuis la base."""
    fs = {}
    try:
        with FS_LOCK:
            FS_CONN.row_factory = sqlite3.Row
            cur = FS_CONN.cursor()
            cur.execute(
                "SELECT path, type, content, owner, permissions, mtime FROM filesystem"
            )
            for row in cur.fetchall():
                path = row["path"]
                fs[path] = {
                    "type": row["type"],
                    "content": row["content"] if row["content"] is not None else "",
                    "owner": row["owner"] or "root",
                    "permissions": row["permissions"] or "rw-r--r--",
                    "mtime": row["mtime"]
                    or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "contents": [] if row["type"] == "dir" else None,
                }
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if parent_dir not in fs:
                    fs[parent_dir] = {
                        "type": "dir",
                        "contents": [],
                        "owner": "root",
                        "permissions": "rwxr-xr-x",
                        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                if (
                    path != "/"
                    and row["type"] == "dir"
                    and path not in fs[parent_dir]["contents"]
                ):
                    fs[parent_dir]["contents"].append(path.split("/")[-1])
    except sqlite3.Error as e:
        print(f"[!] Filesystem load error: {e}")
    return fs


def save_filesystem(fs):
    """Sauvegarde le systeme de fichiers en base."""
    try:
        with FS_LOCK:
            FS_CONN.execute(
                "DELETE FROM filesystem"
            )  # Efface et réinsère pour simplicité
            for path, data in fs.items():
                FS_CONN.execute(
                    "INSERT INTO filesystem (path, type, content, owner, permissions, mtime) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        path,
                        data["type"],
                        (
                            data.get("content", "")
                            if not callable(data.get("content"))
                            else ""
                        ),
                        data.get("owner", "root"),
                        data.get("permissions", "rw-r--r--"),
                        data.get("mtime", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    ),
                )
            FS_CONN.commit()
    except sqlite3.Error as e:
        print(f"[!] Filesystem save error: {e}")


BASE_FILE_SYSTEM = {
    "/": {
        "type": "dir",
        "contents": [
            "bin",
            "sbin",
            "usr",
            "var",
            "opt",
            "root",
            "home",
            "etc",
            "tmp",
            "proc",
            "dev",
            "sys",
            "lib",
        ],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/bin": {
        "type": "dir",
        "contents": [
            "bash",
            "ls",
            "cat",
            "grep",
            "chmod",
            "chown",
            "mv",
            "cp",
            "top",
            "ifconfig",
            "ip",
            "find",
            "scp",
            "apt-get",
            "curl",
            "wget",
            "telnet",
            "ping",
            "nmap",
            "who",
            "w",
        ],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/sbin": {
        "type": "dir",
        "contents": ["init", "sshd", "iptables", "reboot"],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/var": {
        "type": "dir",
        "contents": ["log", "www"],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/var/log": {
        "type": "dir",
        "contents": ["syslog", "messages", "auth.log"],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/var/log/syslog": {
        "type": "file",
        "content": get_dynamic_messages,
        "owner": "root",
        "permissions": "rw-r--r--",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/var/log/messages": {
        "type": "file",
        "content": get_dynamic_messages,
        "owner": "root",
        "permissions": "rw-r--r--",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/var/log/auth.log": {
        "type": "file",
        "content": get_dynamic_messages,
        "owner": "root",
        "permissions": "rw-r-----",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/var/www": {
        "type": "dir",
        "contents": ["html"],
        "owner": "www-data",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/var/www/html": {
        "type": "dir",
        "contents": ["index.html", "config.php"],
        "owner": "www-data",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/var/www/html/index.html": {
        "type": "file",
        "content": "<html><body><h1>Welcome to Server</h1></body></html>",
        "owner": "www-data",
        "permissions": "rw-r--r--",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/tmp": {
        "type": "dir",
        "contents": [],
        "owner": "root",
        "permissions": "rwxrwxrwt",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/etc": {
        "type": "dir",
        "contents": ["passwd", "shadow", "group"],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/etc/passwd": {
        "type": "file",
        "content": "\n".join(
            f"{user}:x:{info['uid']}:1000::{info['home']}:/bin/bash"
            for user, info in PREDEFINED_USERS.items()
            if info.get("home", "").startswith("/home")
        ),
        "owner": "root",
        "permissions": "rw-r--r--",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/etc/shadow": {
        "type": "file",
        "content": "\n".join(
            f"{user}:$6$...:18264:0:99999:7:::"
            for user in PREDEFINED_USERS
            if user not in ["mysql", "www-data"]
        ),
        "owner": "root",
        "permissions": "rw-r-----",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/etc/group": {
        "type": "file",
        "content": "\n".join(
            f"{group}:x:{1000+i}:"
            for i, group in enumerate(
                set(
                    group
                    for user in PREDEFINED_USERS.values()
                    for group in user.get("groups", [])
                )
            )
        ),
        "owner": "root",
        "permissions": "rw-r--r--",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/proc": {
        "type": "dir",
        "contents": ["cpuinfo", "meminfo"],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/proc/cpuinfo": {
        "type": "file",
        "content": "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 142\nmodel name\t: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz",
        "owner": "root",
        "permissions": "rw-r--r--",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/proc/meminfo": {
        "type": "file",
        "content": f"MemTotal:       {random.randint(16000, 32000)} kB\nMemFree:        {random.randint(1000, 5000)} kB",
        "owner": "root",
        "permissions": "rw-r--r--",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/dev": {
        "type": "dir",
        "contents": ["null", "zero"],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/dev/null": {
        "type": "file",
        "content": get_dev_null,
        "owner": "root",
        "permissions": "rw-rw-rw-",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/dev/zero": {
        "type": "file",
        "content": get_dev_zero,
        "owner": "root",
        "permissions": "rw-rw-rw-",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/home": {
        "type": "dir",
        "contents": [],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/usr": {
        "type": "dir",
        "contents": ["bin", "local"],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/usr/bin": {
        "type": "dir",
        "contents": ["python3", "man"],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/usr/bin/python3": {
        "type": "file",
        "content": "#!/usr/bin/python3\n",
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/usr/bin/man": {
        "type": "file",
        "content": "#!/bin/sh\necho 'Use the built-in man command'\n",
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/usr/local": {
        "type": "dir",
        "contents": ["bin"],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/usr/local/bin": {
        "type": "dir",
        "contents": [],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/lib": {
        "type": "dir",
        "contents": [],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/sys": {
        "type": "dir",
        "contents": [],
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/root": {
        "type": "dir",
        "contents": [".bashrc"],
        "owner": "root",
        "permissions": "rwx------",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/root/.bashrc": {
        "type": "file",
        "content": "# .bashrc\n",
        "owner": "root",
        "permissions": "rw-r--r--",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
}


def populate_predefined_users(fs):
    """Ajoute les utilisateurs predefinis dans le FS."""
    if "/home" not in fs:
        fs["/home"] = {
            "type": "dir",
            "contents": [],
            "owner": "root",
            "permissions": "rwxr-xr-x",
            "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    for user, info in PREDEFINED_USERS.items():
        home_dir = info["home"]
        fs[home_dir] = {
            "type": "dir",
            "contents": list(info["files"].keys()),
            "owner": user,
            "permissions": "rwxr-xr-x",
            "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        if user not in fs["/home"]["contents"] and home_dir.startswith("/home/"):
            fs["/home"]["contents"].append(user)
        for filename, content in info["files"].items():
            fs[f"{home_dir}/{filename}"] = {
                "type": "file",
                "content": content,
                "owner": user,
                "permissions": "rw-r--r--",
                "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
    return fs


def add_vulnerabilities(fs):
    """Insere des fichiers vulnerables pour attirer l'attaquant."""
    fs["/tmp/suspicious.sh"] = {
        "type": "file",
        "content": "#!/bin/bash\necho 'Running script...'\ncurl http://example.com",
        "owner": "root",
        "permissions": "rwxr-xr-x",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    fs["/tmp"]["contents"].append("suspicious.sh")
    fs["/home/admin/backup_pass.txt"] = {
        "type": "file",
        "content": "root:admin123\nbackup_user:backup456",
        "owner": "admin",
        "permissions": "rw-rw-r--",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    fs["/home/admin"]["contents"].append("backup_pass.txt")


init_filesystem_db()
FS = load_filesystem()
if not FS:
    FS = populate_predefined_users(BASE_FILE_SYSTEM.copy())
    add_vulnerabilities(FS)
    save_filesystem(FS)

# Helper function to compute visible length of a string, ignoring ANSI escape sequences
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _visible_len(text: str) -> int:
    """Calcule la longueur visible d'une chaine sans codes ANSI."""
    return len(ANSI_RE.sub("", text))


# Autocomplétion
def get_completions(current_input, current_dir, username, fs, history):
    """Retourne la liste des mots possibles pour l'autocompletion."""
    base_cmds = (
        AVAILABLE_COMMANDS
        + list(COMMAND_OPTIONS.keys())
        + list(USER_DEFINED_COMMANDS)
        + [
            "whoami",
            "id",
            "uname",
            "pwd",
            "exit",
            "history",
            "sudo",
            "su",
            "curl",
            "wget",
            "telnet",
            "ping",
            "nmap",
            "traceroute",
            "tracepath",
            "dig",
            "nslookup",
            "tcpdump",
            "nc",
            "netcat",
            "ss",
            "man",
            "arp",
            "scp",
            "sftp",
            "who",
            "w",
            "touch",
            "rm",
            "mkdir",
            "rmdir",
            "cp",
            "mv",
            "backup_data",
            "systemctl",
            "fg",
            "app_status",
            "status_report",
            "jobs",
        ]
    )
    if current_dir == "__mysql__":
        mysql_words = [
            "SELECT",
            "FROM",
            "WHERE",
            "SHOW",
            "USE",
            "DESCRIBE",
            "EXIT",
            "\\q",
        ]
        mysql_words += list(FAKE_MYSQL_DATA.keys())
        for db in FAKE_MYSQL_DATA.values():
            mysql_words.extend(db.keys())
        if not current_input.strip():
            return sorted(mysql_words)
        partial = current_input.strip().split()[-1]
        return sorted([w for w in mysql_words if w.lower().startswith(partial.lower())])
    if not current_input.strip():
        return sorted(base_cmds)
    parts = current_input.strip().split()
    cmd = parts[0] if parts else ""
    partial = parts[-1] if parts else ""
    prev_parts = parts[:-1] if len(parts) > 1 else []
    completions = []

    redirect_match = re.search(r"(?:>>|>)\s*(\S*)$", current_input)
    if redirect_match:
        partial_path = redirect_match.group(1)
        base_path = (
            partial_path
            if partial_path.startswith("/")
            else (f"{current_dir}/{partial_path}" if current_dir != "/" else f"/{partial_path}")
        )
        path = os.path.normpath(base_path)
        if not partial_path or partial_path.endswith("/"):
            parent_dir = path
            base_name = ""
        else:
            parent_dir = os.path.dirname(path) or "/"
            base_name = os.path.basename(path)
        if parent_dir in fs and fs[parent_dir]["type"] == "dir" and "contents" in fs[parent_dir]:
            for item in fs[parent_dir]["contents"]:
                full_path = f"{parent_dir}/{item}" if parent_dir != "/" else f"/{item}"
                if full_path in fs and item.startswith(base_name):
                    completions.append(item)
        prefix = (
            partial_path
            if partial_path.endswith("/")
            else (partial_path.rsplit("/", 1)[0] + "/") if "/" in partial_path else ""
        )
        return sorted([f"{prefix}{c}" for c in completions])
    if len(parts) == 1 and not current_input.endswith(" "):
        completions = [c for c in base_cmds if c.startswith(partial)]
        return sorted(completions)
    if cmd in COMMAND_OPTIONS and (
        partial.startswith("-") or prev_parts and prev_parts[-1].startswith("-")
    ):
        completions = [opt for opt in COMMAND_OPTIONS[cmd] if opt.startswith(partial)]
        return sorted(completions)
    if cmd in [
        "cd",
        "ls",
        "cat",
        "rm",
        "scp",
        "find",
        "grep",
        "touch",
        "mkdir",
        "rmdir",
        "cp",
        "mv",
    ]:
        base_path = (
            partial
            if partial.startswith("/")
            else (f"{current_dir}/{partial}" if current_dir != "/" else f"/{partial}")
        )
        path = os.path.normpath(base_path)
        if partial.endswith("/"):
            parent_dir = path
            base_name = ""
        else:
            parent_dir = os.path.dirname(path) or "/"
            base_name = os.path.basename(path)
        if (
            parent_dir in fs
            and fs[parent_dir]["type"] == "dir"
            and "contents" in fs[parent_dir]
        ):
            for item in fs[parent_dir]["contents"]:
                full_path = f"{parent_dir}/{item}" if parent_dir != "/" else f"/{item}"
                if full_path in fs and item.startswith(base_name):
                    if cmd == "cd" and fs[full_path]["type"] == "dir":
                        completions.append(item)
                    elif cmd in [
                        "ls",
                        "cat",
                        "rm",
                        "scp",
                        "find",
                        "grep",
                        "touch",
                        "mkdir",
                        "rmdir",
                        "cp",
                        "mv",
                    ]:
                        completions.append(item)
        prefix = (
            partial
            if partial.endswith("/")
            else (partial.rsplit("/", 1)[0] + "/") if "/" in partial else ""
        )
        return sorted([f"{prefix}{c}" for c in completions])
    if cmd in [
        "ping",
        "telnet",
        "nmap",
        "traceroute",
        "tracepath",
        "dig",
        "nslookup",
        "scp",
        "curl",
        "wget",
    ]:
        for ip, info in FAKE_NETWORK_HOSTS.items():
            if info["name"].startswith(partial) or ip.startswith(partial):
                completions.append(info["name"])
                completions.append(ip)
    completions.extend([h for h in history[-10:] if h.startswith(partial)])
    return sorted(completions)


def autocomplete(
    current_input,
    current_dir,
    username,
    fs,
    chan,
    history,
    last_completions=None,
    tab_count=0,
    prompt="",
): 
    """Gere l'autocompletion facon bash pour la saisie utilisateur."""
    last_completions = last_completions or []
    completions = get_completions(current_input, current_dir, username, fs, history)

    parts = current_input.split()
    partial = ""
    if current_input.endswith(" "):
        partial = ""
    elif parts:
        partial = parts[-1]

    def _apply_completion(word):
        p = parts[:-1] if parts else []
        p.append(word)
        return " ".join(p)

    if not completions:
        return current_input, [], 0

    path_cmds = [
        "cd",
        "ls",
        "cat",
        "rm",
        "scp",
        "find",
        "grep",
        "touch",
        "mkdir",
        "rmdir",
        "cp",
        "mv",
    ]

    # Second TAB: show completions if nothing changed
    if tab_count > 0 and completions == last_completions:
        chan.send(b"\r\n")
        display_list = []
        for c in completions:
            norm = os.path.normpath(f"{current_dir}/{c}" if not c.startswith("/") else c)
            if norm in fs and fs[norm]["type"] == "dir":
                disp = f"\033[01;34m{c}\033[0m/"
            else:
                disp = c
            display_list.append(disp)
        max_len = max(_visible_len(it) for it in display_list) + 2
        per_row = max(1, 80 // max_len)
        for i, it in enumerate(display_list):
            pad = max_len - _visible_len(it)
            chan.send((it + " " * pad).encode())
            if (i + 1) % per_row == 0:
                chan.send(b"\r\n")
        if len(display_list) % per_row:
            chan.send(b"\r\n")
        chan.send(b"\r" + prompt.encode() + current_input.encode() + b"\x1b[K")
        return current_input, completions, 0

    if len(completions) == 1:
        completion = completions[0]
        cmd = parts[0] if parts else ""
        path = completion
        if cmd in path_cmds:
            if not completion.startswith("/"):
                path = os.path.normpath(
                    f"{current_dir}/{completion}" if current_dir != "/" else f"/{completion}"
                )
            if path in fs and fs[path]["type"] == "dir":
                completion += "/"
        return _apply_completion(completion), [], 0

    common = os.path.commonprefix(completions)
    if common and common != partial:
        path = os.path.normpath(
            f"{current_dir}/{common}" if not common.startswith("/") else common
        )
        if path in fs and fs[path]["type"] == "dir":
            common += "/"
        return _apply_completion(common), completions, 1

    return current_input, completions, 1


# Gestion des fichiers
def modify_file(fs, path, content, username, session_id, client_ip):
    """Modifie un fichier autorise et journalise l'operation."""
    allowed_paths = [
        f"{PREDEFINED_USERS[username]['home']}/{f}"
        for f in PREDEFINED_USERS.get(username, {}).get("files", {}).keys()
    ]
    if path.startswith("/tmp/") or path in allowed_paths:
        fs[path] = {
            "type": "file",
            "content": content,
            "owner": username,
            "permissions": "rw-r--r--",
            "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        trigger_alert(
            session_id, "File Modified", f"Modified file: {path}", client_ip, username
        )
        save_filesystem(fs)
        return True
    return False


# Alertes
def trigger_alert(session_id, event_type, details, client_ip, username):
    """Declenche une alerte et envoie un email si configure."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    print(
        f"\033[91m[ALERT]\033[0m {timestamp} {client_ip} {username}: {event_type} - {details}"
    )

    log_event = not (session_id < 0 or username == "system" or client_ip == "system")
    if log_event:
        log_human_readable(timestamp, client_ip, username, event_type, details)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            subject = f"ALERTE SÉCURITÉ - {event_type}"
            body = (
                f"🚨 [ALERTE SÉCURITÉ - {event_type}]\n\n"
                f"- Utilisateur      : {username}\n"
                f"- Adresse IP       : {client_ip}\n"
                f"- Heure exacte     : {timestamp}\n"
                f"- Session ID       : {session_id}\n\n"
                f"Détails : {details}"
            )
            msg = MIMEText(body)
            msg["From"] = ALERT_FROM
            msg["To"] = ALERT_TO
            msg["Subject"] = subject
            smtp.send_message(msg)
    except smtplib.SMTPException as e:
        print(f"[!] SMTP error: {str(e)}")
    if log_event:
        try:
            with sqlite3.connect(DB_NAME, uri=True) as conn:
                conn.execute(
                    "INSERT INTO events (timestamp, ip, username, event_type, details) VALUES (?, ?, ?, ?, ?)",
                    (timestamp, client_ip, username, event_type, details),
                )
        except sqlite3.Error as e:
            print(f"[!] DB error: {e}")


def log_activity(session_id, client_ip, username, key):
    """Enregistre chaque touche saisie par l'utilisateur."""
    key = ANSI_KEY_LABELS.get(key, key)
    if KEY_DISPLAY_MODE != "full":
        if (len(key) == 1 and key.isprintable()) or key in [
            "\n",
            "\r",
            "\t",
            "\x7f",
            "\x08",
        ]:
            return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    log_entry = {
        "event": "keypress",
        "time": timestamp,
        "session": session_id,
        "ip": client_ip,
        "user": username,
        "key": key,
    }
    LOGGER.info(json.dumps(log_entry))
    if KEY_DISPLAY_MODE == "full":
        print(f"\033[95m[KEY]\033[0m {timestamp} {username}@{client_ip}: {repr(key)}")
    elif KEY_DISPLAY_MODE == "filtered":
        print(f"\033[95m[KEY]\033[0m {username}@{client_ip}: {repr(key)}")


def log_session_activity(
    session_id,
    client_ip,
    username,
    command_line,
    output,
    success=None,
    cwd=None,
    cmd_index=None,
    start_time=None,
    end_time=None,
):
    """Journalise l'execution d'une commande et son resultat."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "event": "command",
        "time": timestamp,
        "session": session_id,
        "ip": client_ip,
        "user": username,
        "command": command_line,
        "output": output,
    }
    if cwd is not None:
        log_entry["cwd"] = cwd
    if cmd_index is not None:
        log_entry["index"] = cmd_index
    if start_time is not None:
        log_entry["start_time"] = start_time
    if end_time is not None:
        log_entry["end_time"] = end_time
        if start_time is not None:
            duration_ms = (
                datetime.fromisoformat(end_time) - datetime.fromisoformat(start_time)
            ).total_seconds() * 1000
            log_entry["duration_ms"] = int(duration_ms)
    if success is not None:
        log_entry["success"] = success
    LOGGER.info(json.dumps(log_entry))
    if success is None:
        status_text = "in-progress"
    else:
        status_text = "success" if success else "failure"
    duration_msg = ""
    if "duration_ms" in log_entry:
        duration_msg = f", {log_entry['duration_ms']}ms"
    index_msg = f"#{cmd_index} " if cmd_index is not None else ""
    cwd_msg = f"[{cwd}] " if cwd is not None else ""
    print(
        f"\033[96m[SESSION]\033[0m {timestamp} {username}@{client_ip} {cwd_msg}{index_msg}{command_line} -> {output} ({status_text}{duration_msg})"
    )


# Détection de bruteforce
def check_bruteforce(client_ip, username, password):
    """Verifie les tentatives repetees de connexion."""
    if username != "admin":
        return True
    timestamp = time.time()
    with _brute_force_lock:
        if client_ip not in _brute_force_attempts:
            _brute_force_attempts[client_ip] = []
        _brute_force_attempts[client_ip].append((timestamp, username, password))
        _brute_force_attempts[client_ip] = [
            attempt
            for attempt in _brute_force_attempts[client_ip]
            if timestamp - attempt[0] < BRUTE_FORCE_WINDOW
        ]
        if len(_brute_force_attempts[client_ip]) > BRUTE_FORCE_THRESHOLD:
            if client_ip not in _brute_force_alerted:
                trigger_alert(
                    -1,
                    "Bruteforce Detected",
                    f"Multiple login attempts from {client_ip}",
                    client_ip,
                    "unknown",
                )
                _brute_force_alerted.add(client_ip)
            return False
    return True


def cleanup_bruteforce_attempts():
    """Purge regulierement les anciennes tentatives de bruteforce."""
    while True:
        with _brute_force_lock:
            current_time = time.time()
            for ip in list(_brute_force_attempts.keys()):
                _brute_force_attempts[ip] = [
                    attempt
                    for attempt in _brute_force_attempts[ip]
                    if current_time - attempt[0] < BRUTE_FORCE_WINDOW
                ]
                if not _brute_force_attempts[ip]:
                    del _brute_force_attempts[ip]
                    _brute_force_alerted.discard(ip)
        time.sleep(3600)


# Détection des scans de ports
def detect_port_scan(ip, port):
    """Detecte les scans de ports suspects."""
    try:
        with sqlite3.connect(DB_NAME, uri=True) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM events WHERE ip = ? AND event_type LIKE '%Connection' AND timestamp > ?",
                (
                    ip,
                    (datetime.now() - timedelta(minutes=5)).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    ),
                ),
            )
            count = cur.fetchone()[0]
            if count >= 3:
                trigger_alert(
                    -1,
                    "Port Scan Detected",
                    f"Potential scan from {ip} on port {port}",
                    ip,
                    "unknown",
                )
    except sqlite3.Error as e:
        print(f"[!] Port scan detection error: {e}")


# Gestion de l'historique
def load_history(username):
    """Charge l'historique de commandes d'un utilisateur."""
    return []  # Pas de fichier, donc vide par défaut


def save_history(username, history):
    """Sauvegarde l'historique de commandes d'un utilisateur."""
    pass  # Pas de sauvegarde dans un fichier


# Initialisation de la base de données
def init_database():
    """Initialise les tables SQLite utilisees par le honeypot."""
    try:
        DB_CONN.executescript(
            """
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    ip TEXT NOT NULL,
                    username TEXT,
                    password TEXT,
                    success INTEGER,
                    redirected INTEGER
                );
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    username TEXT NOT NULL,
                    command TEXT NOT NULL,
                    session_id INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    username TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details TEXT NOT NULL
                )
            """
        )
        DB_CONN.commit()
        print("[*] Database initialized successfully")
    except sqlite3.Error as e:
        print(f"[!] DB init error: {e}")
        raise


# Rapports
def generate_report(period):
    """Genere un rapport PDF d'activite."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"System Activity Report - {period}", 0, 1, "C")
    pdf.set_font("Arial", size=12)
    start_time = (
        datetime.now()
        - timedelta(
            minutes=15 if period == "15min" else 60 if period == "hourly" else 10080
        )
    ).strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(
        0,
        10,
        f"Period: {start_time} to {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        0,
        1,
    )
    try:
        with sqlite3.connect(DB_NAME, uri=True) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM login_attempts WHERE timestamp > ?", (start_time,)
            )
            login_count = cur.fetchone()[0]
            pdf.cell(0, 10, f"Total Login Attempts: {login_count}", 0, 1)
            cur.execute(
                "SELECT ip, COUNT(*) as count FROM login_attempts WHERE timestamp > ? GROUP BY ip ORDER BY count DESC LIMIT 5",
                (start_time,),
            )
            for ip, count in cur.fetchall():
                pdf.cell(0, 10, f"IP: {ip} - {count} attempts", 0, 1)
            cur.execute(
                "SELECT command, COUNT(*) as count FROM commands WHERE timestamp > ? GROUP BY command ORDER BY count DESC LIMIT 5",
                (start_time,),
            )
            for cmd, count in cur.fetchall():
                pdf.cell(0, 10, f"Command: {cmd} - {count} executions", 0, 1)
            cur.execute(
                "SELECT timestamp, ip, username, event_type, details FROM events WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 10",
                (start_time,),
            )
            for timestamp, ip, username, event_type, details in cur.fetchall():
                pdf.cell(
                    0,
                    10,
                    f"{timestamp} - {ip} ({username}): {event_type} - {details}",
                    0,
                    1,
                )
    except sqlite3.Error as e:
        print(f"[!] Report error: {e}")
    report_filename = f"{period}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(report_filename)
    return report_filename


def has_recent_activity():
    """Determine s'il y a eu de l'activite recente."""
    start_time = (datetime.now() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        with sqlite3.connect(DB_NAME, uri=True) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM login_attempts WHERE timestamp > ?", (start_time,)
            )
            if cur.fetchone()[0] > 0:
                return True
            cur.execute(
                "SELECT COUNT(*) FROM commands WHERE timestamp > ?", (start_time,)
            )
            if cur.fetchone()[0] > 0:
                return True
            cur.execute(
                "SELECT COUNT(*) FROM events WHERE timestamp > ? AND username != 'system'",
                (start_time,),
            )
            if cur.fetchone()[0] > 0:
                return True
    except sqlite3.Error as e:
        print(f"[!] Activity check error: {e}")
    return False


def send_weekly_report():
    """Envoie chaque semaine un rapport d'activite."""
    while True:
        now = datetime.now()
        if now.weekday() == 0 and now.hour == 8:
            report_filename = generate_report("weekly")
            subject = f"Weekly System Report - {datetime.now().strftime('%Y-%m-%d')}"
            body = "Attached is the weekly system activity report."
            msg = MIMEMultipart()
            msg["From"] = ALERT_FROM
            msg["To"] = ALERT_TO
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            with open(report_filename, "rb") as f:
                part = MIMEApplication(f.read(), Name=os.path.basename(report_filename))
                part["Content-Disposition"] = (
                    f'attachment; filename="{os.path.basename(report_filename)}"'
                )
                msg.attach(part)
            try:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
                    smtp.starttls()
                    smtp.login(SMTP_USER, SMTP_PASS)
                    smtp.send_message(msg)
                print(f"Weekly report sent: {report_filename}")
            except Exception as e:
                print(f"Weekly report email error: {e}")
            finally:
                if os.path.exists(report_filename):
                    os.remove(report_filename)
        time.sleep(3600)


def send_periodic_report():
    """Envoie un rapport toutes les 15 minutes en cas d'activite."""
    while True:
        time.sleep(900)
        if not has_recent_activity():
            continue
        report_filename = generate_report("15min")
        subject = (
            f"15-Minute System Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        body = "Attached is the latest 15-minute activity report."
        msg = MIMEMultipart()
        msg["From"] = ALERT_FROM
        msg["To"] = ALERT_TO
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        with open(report_filename, "rb") as f:
            part = MIMEApplication(f.read(), Name=os.path.basename(report_filename))
            part["Content-Disposition"] = (
                f'attachment; filename="{os.path.basename(report_filename)}"'
            )
            msg.attach(part)
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)
            print(f"Periodic report sent: {report_filename}")
        except Exception as e:
            print(f"Periodic report email error: {e}")
        finally:
            if os.path.exists(report_filename):
                os.remove(report_filename)


# Nettoyage des fichiers pièges
def cleanup_trap_files(fs):
    """Supprime regulierement les fichiers pieges temporaires."""
    while True:
        current_time = time.time()
        for path in list(fs.keys()):
            if (
                ".trap_" in path
                and fs[path].get("expires", current_time) < current_time
            ):
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if (
                    parent_dir in fs
                    and path.split("/")[-1] in fs[parent_dir]["contents"]
                ):
                    fs[parent_dir]["contents"].remove(path.split("/")[-1])
                del fs[path]
                save_filesystem(fs)
        time.sleep(3600)


# Traitement des commandes
def _format_ls_columns(items, width=80):
    """Formate l'affichage de ls en colonnes."""
    if not items:
        return ""
    max_len = max(_visible_len(it) for it in items) + 2
    cols = max(1, width // max_len)
    lines = []
    for i in range(0, len(items), cols):
        row = items[i : i + cols]
        padded = [it + " " * (max_len - _visible_len(it)) for it in row]
        lines.append("".join(padded))
    return "\r\n".join(lines)


def _human_size(size):
    """Convertit une taille en representation lisible."""
    units = ["B", "K", "M", "G"]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size}{unit}"
        size //= 1024


def _random_permissions():
    """Retourne des droits d'acces aleatoires."""
    patterns = [
        "rwxr-xr-x",
        "rw-r--r--",
        "rwx------",
        "rwxrwxr-x",
        "rw-rw-r--",
        "rwxr-x---",
    ]
    return random.choice(patterns)


def ftp_session(chan, host, username, session_id, client_ip, session_log):
    """Emule une session FTP interactive avancee."""
    history = []
    jobs = []
    cmd_count = 0
    current_dir = PREDEFINED_USERS.get(username, {}).get("home", "/")
    chan.send(
        f"Connected to {host}.\r\n220 (vsFTPd 3.0.3)\r\nName ({host}:{username}): ".encode()
    )
    read_line_advanced(
        chan,
        "",
        history,
        current_dir,
        username,
        FS,
        session_log,
        session_id,
        client_ip,
        jobs,
        cmd_count,
    )
    chan.send(b"331 Please specify the password.\r\nPassword: ")
    read_line_advanced(
        chan,
        "",
        history,
        current_dir,
        username,
        FS,
        session_log,
        session_id,
        client_ip,
        jobs,
        cmd_count,
    )
    chan.send(
        b"230 Login successful.\r\nRemote system type is UNIX.\r\nUsing binary mode to transfer files.\r\n"
    )
    while True:
        ftp_cmd, _, _ = read_line_advanced(
            chan,
            "ftp> ",
            history,
            current_dir,
            username,
            FS,
            session_log,
            session_id,
            client_ip,
            jobs,
            cmd_count,
        )
        if ftp_cmd is None:
            break
        if not ftp_cmd:
            continue
        parts = ftp_cmd.strip().split()
        if not parts:
            continue
        command = parts[0].lower()
        args = parts[1:]
        if command in ["quit", "exit", "bye"]:
            chan.send(b"221 Goodbye.\r\n")
            break
        elif command in ["pwd"]:
            chan.send(f'257 "{current_dir}" is the current directory\r\n'.encode())
        elif command in ["cd", "cwd"]:
            dest = args[0] if args else "/"
            path = os.path.normpath(dest if dest.startswith("/") else f"{current_dir}/{dest}")
            if path in FS and FS[path]["type"] == "dir":
                current_dir = path
                chan.send(b"250 Directory successfully changed.\r\n")
            else:
                chan.send(b"550 Failed to change directory.\r\n")
        elif command == "ls":
            if current_dir in FS and FS[current_dir]["type"] == "dir":
                long_listing = "-l" in args
                for item in FS[current_dir]["contents"]:
                    item_path = (
                        f"{current_dir}/{item}" if current_dir != "/" else f"/{item}"
                    )
                    if long_listing and item_path in FS:
                        entry = FS[item_path]
                        perms = entry.get("permissions", "rwxr-xr-x")
                        owner = entry.get("owner", "root")
                        size = (
                            len(entry.get("content", ""))
                            if entry.get("type") == "file"
                            else 4096
                        )
                        mtime = entry.get("mtime", "")
                        chan.send(
                            f"{perms} 1 {owner} {owner} {size} {mtime} {item}\r\n".encode()
                        )
                    else:
                        chan.send(f"{item}\r\n".encode())
            chan.send(b"226 Directory send OK.\r\n")
        elif command == "get" and args:
            target = os.path.normpath(
                args[0] if args[0].startswith("/") else f"{current_dir}/{args[0]}"
            )
            if target in FS and FS[target]["type"] == "file":
                content = FS[target]["content"]
                if callable(content):
                    content = content()
                chan.send(b"150 Opening data connection.\r\n")
                chan.send(str(content).encode() + b"\r\n")
                chan.send(b"226 Transfer complete.\r\n")
            else:
                chan.send(b"550 Failed to open file.\r\n")
        elif command == "put" and args:
            dest = os.path.normpath(
                args[0] if args[0].startswith("/") else f"{current_dir}/{args[0]}"
            )
            FS[dest] = {
                "type": "file",
                "content": "",
                "owner": username,
                "permissions": "rw-r--r--",
                "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            parent = os.path.dirname(dest) or "/"
            name = os.path.basename(dest)
            if parent in FS and name not in FS[parent]["contents"]:
                FS[parent]["contents"].append(name)
            chan.send(b"150 Ok to send data.\r\n226 Transfer complete.\r\n")
        elif command == "mkdir" and args:
            new_dir = os.path.normpath(
                args[0] if args[0].startswith("/") else f"{current_dir}/{args[0]}"
            )
            if new_dir not in FS:
                FS[new_dir] = {
                    "type": "dir",
                    "contents": [],
                    "owner": username,
                    "permissions": "rwxr-xr-x",
                    "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
                parent = os.path.dirname(new_dir) or "/"
                name = os.path.basename(new_dir)
                if parent in FS and name not in FS[parent]["contents"]:
                    FS[parent]["contents"].append(name)
                chan.send(b"257 Directory created.\r\n")
            else:
                chan.send(b"550 Create directory operation failed.\r\n")
        elif command in ["delete", "rm"] and args:
            target = os.path.normpath(
                args[0] if args[0].startswith("/") else f"{current_dir}/{args[0]}"
            )
            if target in FS:
                parent = os.path.dirname(target) or "/"
                name = os.path.basename(target)
                FS.pop(target)
                if parent in FS and name in FS[parent]["contents"]:
                    FS[parent]["contents"].remove(name)
                chan.send(b"250 Delete operation successful.\r\n")
            else:
                chan.send(b"550 Delete operation failed.\r\n")
        elif command == "rename" and len(args) >= 2:
            src = os.path.normpath(
                args[0] if args[0].startswith("/") else f"{current_dir}/{args[0]}"
            )
            dest = os.path.normpath(
                args[1] if args[1].startswith("/") else f"{current_dir}/{args[1]}"
            )
            if src in FS:
                FS[dest] = FS.pop(src)
                src_parent = os.path.dirname(src) or "/"
                dest_parent = os.path.dirname(dest) or "/"
                src_name = os.path.basename(src)
                dest_name = os.path.basename(dest)
                if src_parent in FS and src_name in FS[src_parent]["contents"]:
                    FS[src_parent]["contents"].remove(src_name)
                if dest_parent in FS and dest_name not in FS[dest_parent]["contents"]:
                    FS[dest_parent]["contents"].append(dest_name)
                chan.send(b"250 Rename successful.\r\n")
            else:
                chan.send(b"550 File not found.\r\n")
        elif command == "help":
            chan.send(
                b"Commands: ls, cd, pwd, get, put, mkdir, delete, rename, quit\r\n"
            )
        else:
            chan.send(b"502 Command not implemented.\r\n")
        session_log.append(f"FTP command: {ftp_cmd}")
    session_log.append(f"FTP session to {host} closed")


def mysql_session(chan, username, session_id, client_ip, session_log):
    """Emule une console MySQL factice."""
    history = []
    jobs = []
    cmd_count = 0
    chan.send(b"Welcome to the MySQL monitor.  Commands end with ; or \g.\r\n")
    chan.send(b"Your MySQL connection id is 1\r\n")
    chan.send(b"Server version: 5.7.42 MySQL Community Server (fake)\r\n\r\n")
    current_db = None
    buffer = ""
    while True:
        prompt = b"mysql> " if not buffer else b"    -> "
        line, _, _ = read_line_advanced(
            chan,
            prompt.decode(),
            history,
            "__mysql__",
            username,
            FS,
            session_log,
            session_id,
            client_ip,
            jobs,
            cmd_count,
        )
        if line is None:
            break
        if not line:
            continue
        if line.strip().lower() in ["exit", "quit", "\\q"]:
            chan.send(b"Bye\r\n")
            break
        buffer += line.strip() + " "
        if not buffer.strip().endswith(";") and not buffer.strip().endswith("\\g"):
            continue
        mysql_cmd = buffer.strip().rstrip(";").rstrip("\\g").strip()
        buffer = ""
        cmd_l = mysql_cmd.lower()
        if cmd_l.startswith("show databases"):
            chan.send(
                b"+--------------------+\r\n| Database           |\r\n+--------------------+\r\n"
            )
            for db in FAKE_MYSQL_DATA.keys():
                chan.send(f"| {db.ljust(18)} |\r\n".encode())
            chan.send(b"+--------------------+\r\n")
            chan.send(f"{len(FAKE_MYSQL_DATA)} rows in set (0.00 sec)\r\n".encode())
        elif cmd_l.startswith("use"):
            db = mysql_cmd.split()[1] if len(mysql_cmd.split()) > 1 else None
            current_db = db if db in FAKE_MYSQL_DATA else None
            chan.send(b"Database changed\r\n")
        elif cmd_l.startswith("show tables"):
            if not current_db or current_db not in FAKE_MYSQL_DATA:
                chan.send(b"Empty set (0.00 sec)\r\n")
            else:
                tables = FAKE_MYSQL_DATA[current_db].keys()
                header = f"| Tables_in_{current_db} |"
                chan.send(b"+" + b"-" * (len(header) - 2) + b"+\r\n")
                chan.send(f"{header}\r\n".encode())
                chan.send(b"+" + b"-" * (len(header) - 2) + b"+\r\n")
                for t in tables:
                    chan.send(f"| {t.ljust(len(header)-4)} |\r\n".encode())
                chan.send(b"+" + b"-" * (len(header) - 2) + b"+\r\n")
                chan.send(f"{len(list(tables))} rows in set (0.00 sec)\r\n".encode())
        elif cmd_l.startswith("describe"):
            table = mysql_cmd.split()[1] if len(mysql_cmd.split()) > 1 else ""
            if current_db and table in FAKE_MYSQL_DATA.get(current_db, {}):
                cols = FAKE_MYSQL_DATA[current_db][table]["columns"]
                chan.send(b"+-------+\r\n| Field |\r\n+-------+\r\n")
                for c in cols:
                    chan.send(f"| {c.ljust(5)} |\r\n".encode())
                chan.send(b"+-------+\r\n")
                chan.send(f"{len(cols)} rows in set (0.00 sec)\r\n".encode())
            else:
                chan.send(b"Empty set (0.00 sec)\r\n")
        elif cmd_l.startswith("select") and "from" in cmd_l:
            parts = mysql_cmd.split()
            parts_lc = [p.lower() for p in parts]
            if "from" in parts_lc:
                table = parts[parts_lc.index("from") + 1]
                db = current_db
                if "." in table:
                    db, table = table.split(".", 1)
                table_lc = table.lower()
                if db in FAKE_MYSQL_DATA and table_lc in FAKE_MYSQL_DATA[db]:
                    data = FAKE_MYSQL_DATA[db][table_lc]
                    cols = data["columns"]
                    rows = data["rows"]
                    border = "+" + "+".join(["-" * (len(c) + 2) for c in cols]) + "+"
                    chan.send((border + "\r\n").encode())
                    chan.send(("| " + " | ".join(cols) + " |\r\n").encode())
                    chan.send((border + "\r\n").encode())
                    for r in rows:
                        chan.send(
                            ("| " + " | ".join(str(x) for x in r) + " |\r\n").encode()
                        )
                    chan.send(
                        (
                            border + f"\r\n{len(rows)} rows in set (0.00 sec)\r\n"
                        ).encode()
                    )
                else:
                    chan.send(b"Empty set (0.00 sec)\r\n")
            else:
                chan.send(b"Query OK, 0 rows affected (0.00 sec)\r\n")
        elif cmd_l.startswith("insert"):
            m = re.match(r"insert\s+into\s+([\w\.]+)\s+values\s*\((.+)\)", mysql_cmd, re.I)
            if m:
                tbl = m.group(1)
                values = [v.strip().strip("'\"") for v in m.group(2).split(',')]
                db = current_db
                if '.' in tbl:
                    db, tbl = tbl.split('.', 1)
                if db in FAKE_MYSQL_DATA and tbl in FAKE_MYSQL_DATA[db]:
                    FAKE_MYSQL_DATA[db][tbl]["rows"].append(tuple(values))
                    chan.send(b"Query OK, 1 row affected (0.00 sec)\r\n")
                else:
                    chan.send(b"ERROR 1146 (42S02): Table doesn't exist\r\n")
            else:
                chan.send(b"ERROR in INSERT syntax\r\n")
        elif cmd_l.startswith("update") and "set" in cmd_l:
            m = re.match(r"update\s+([\w\.]+)\s+set\s+(.+)\s+where\s+(.+)", mysql_cmd, re.I)
            if m:
                tbl = m.group(1)
                set_clause = m.group(2)
                where_clause = m.group(3)
                db = current_db
                if '.' in tbl:
                    db, tbl = tbl.split('.', 1)
                if db in FAKE_MYSQL_DATA and tbl in FAKE_MYSQL_DATA[db]:
                    rows = FAKE_MYSQL_DATA[db][tbl]['rows']
                    match = re.search(r'id\s*=\s*(\d+)', where_clause, re.I)
                    affected = 0
                    if match:
                        rid = match.group(1)
                        set_match = re.match(r"(\w+)\s*=\s*'?([^']*)'?", set_clause)
                        if set_match:
                            col = set_match.group(1)
                            val = set_match.group(2)
                            if col in FAKE_MYSQL_DATA[db][tbl]['columns']:
                                idx = FAKE_MYSQL_DATA[db][tbl]['columns'].index(col)
                                for i, r in enumerate(rows):
                                    if str(r[0]) == rid:
                                        lst = list(r)
                                        lst[idx] = val
                                        rows[i] = tuple(lst)
                                        affected = 1
                                        break
                    chan.send(f"Query OK, {affected} row affected (0.00 sec)\r\n".encode())
                else:
                    chan.send(b"ERROR 1146 (42S02): Table doesn't exist\r\n")
            else:
                chan.send(b"ERROR in UPDATE syntax\r\n")
        elif cmd_l.startswith("delete") and "from" in cmd_l:
            m = re.match(r"delete\s+from\s+([\w\.]+)\s+where\s+(.+)", mysql_cmd, re.I)
            if m:
                tbl = m.group(1)
                where_clause = m.group(2)
                db = current_db
                if '.' in tbl:
                    db, tbl = tbl.split('.', 1)
                if db in FAKE_MYSQL_DATA and tbl in FAKE_MYSQL_DATA[db]:
                    rows = FAKE_MYSQL_DATA[db][tbl]['rows']
                    match = re.search(r'id\s*=\s*(\d+)', where_clause, re.I)
                    affected = 0
                    if match:
                        rid = match.group(1)
                        new_rows = [r for r in rows if str(r[0]) != rid]
                        affected = len(rows) - len(new_rows)
                        FAKE_MYSQL_DATA[db][tbl]['rows'] = new_rows
                    chan.send(f"Query OK, {affected} row affected (0.00 sec)\r\n".encode())
                else:
                    chan.send(b"ERROR 1146 (42S02): Table doesn't exist\r\n")
            else:
                chan.send(b"ERROR in DELETE syntax\r\n")
        else:
            chan.send(b"Query OK, 0 rows affected (0.00 sec)\r\n")
    session_log.append("MySQL session closed")


def python_repl(chan, username, session_id, client_ip, session_log):
    """Ouvre un petit interpréteur Python fictif."""
    history = []
    jobs = []
    cmd_count = 0
    chan.send(b"Python 3.10.0 (default, fake)\r\nType 'exit()' to quit\r\n")
    while True:
        line, _, _ = read_line_advanced(
            chan,
            ">>> ",
            history,
            "",
            username,
            FS,
            session_log,
            session_id,
            client_ip,
            jobs,
            cmd_count,
        )
        if line is None:
            break
        if line.strip() in ["exit()", "quit()", "exit", "quit"]:
            chan.send(b"\r\n")
            break
        if not line:
            chan.send(b"\r\n")
            continue
        if any(ord(ch) < 32 for ch in line):
            display = "".join(
                f"^{chr(ord(ch)+64)}" if ord(ch) < 32 else ch for ch in line
            )
            chan.send(f"{display}\r\n".encode())
        else:
            chan.send(f"{line}\r\n".encode())
    session_log.append("Python REPL closed")


def node_repl(chan, username, session_id, client_ip, session_log):
    """Simule un shell Node.js minimal."""
    history = []
    jobs = []
    cmd_count = 0
    chan.send(b"Welcome to Node.js v18 (fake). Type 'exit' to quit.\r\n> ")
    while True:
        line, _, _ = read_line_advanced(
            chan,
            "> ",
            history,
            "",
            username,
            FS,
            session_log,
            session_id,
            client_ip,
            jobs,
            cmd_count,
        )
        if line is None or line.strip() in ["exit", "quit"]:
            chan.send(b"\r\n")
            break
        if not line:
            chan.send(b"\r\n")
            continue
        chan.send(f"{line}\r\n".encode())
    session_log.append("Node REPL closed")


def netcat_session(chan, listening, host, port, username, session_id, client_ip, session_log):
    """Session netcat tres simplifiee."""
    history = []
    jobs = []
    cmd_count = 0
    if listening:
        chan.send(f"Listening on port {port} (simulated)\r\n".encode())
    else:
        chan.send(f"Connected to {host}:{port} (simulated)\r\n".encode())
    while True:
        line, _, _ = read_line_advanced(
            chan,
            "",
            history,
            "",
            username,
            FS,
            session_log,
            session_id,
            client_ip,
            jobs,
            cmd_count,
        )
        if line is None or line.strip().lower() in ["exit", "quit"]:
            break
        if not line:
            continue
        chan.send(f"{line}\r\n".encode())
    chan.send(b"\r\n")
    session_log.append("Netcat session closed")


def process_command(
    cmd,
    current_dir,
    username,
    fs,
    client_ip,
    session_id,
    session_log,
    command_history,
    chan,
    jobs=None,
    cmd_count=0,
    allow_redirect=True,
):
    """Traite une commande utilisateur et renvoie le resultat."""
    if not cmd.strip():
        return "", current_dir, jobs or [], cmd_count, False
    new_dir = current_dir
    output = ""

    redirect_path = None
    append_mode = False
    if allow_redirect and ">" in cmd:
        if ">>" in cmd:
            base_cmd, redirect_path = cmd.split(">>", 1)
            append_mode = True
        else:
            base_cmd, redirect_path = cmd.split(">", 1)
        base_cmd = base_cmd.strip()
        redirect_path = redirect_path.strip()
        result = process_command(
            base_cmd,
            current_dir,
            username,
            fs,
            client_ip,
            session_id,
            session_log,
            command_history,
            chan,
            jobs,
            cmd_count,
            False,
        )
        output, new_dir, jobs, cmd_count, _ = result
        if not redirect_path.startswith("/"):
            redirect_path = (
                f"{current_dir}/{redirect_path}"
                if current_dir != "/"
                else f"/{redirect_path}"
            )
        redirect_path = os.path.normpath(redirect_path)
        existing = fs.get(redirect_path, {}).get("content", "")
        content = existing if append_mode else ""
        content += output + ("\n" if output and not output.endswith("\n") else "")
        modify_file(fs, redirect_path, content, username, session_id, client_ip)
        return "", new_dir, jobs, cmd_count, False

    cmd_parts = cmd.strip().split()
    cmd_name = cmd_parts[0].lower()
    arg_str = " ".join(cmd_parts[1:]) if len(cmd_parts) > 1 else ""
    jobs = jobs or []
    for forbidden in FORBIDDEN_COMMANDS:
        if cmd.lower().startswith(forbidden):
            output = f"{cmd_name}: permission denied"
            trigger_alert(
                session_id, "Forbidden Command", f"Tried '{cmd}'", client_ip, username
            )
            return output, new_dir, jobs, cmd_count, False
    session_log.append(
        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {username}@{client_ip}: {cmd}"
    )
    command_seq = " ".join(command_history[-5:] + [cmd])
    malicious_patterns = {
        "rm -rf /": 10,
        "rm -rf": 8,
        "wget": 3,
        "curl": 3,
        "format": 7,
        "reboot": 4,
        "nc -l": 8,
        "exploit_db": 8,
        "metasploit": 8,
        "reverse_shell": 8,
        "whoami.*sudo": 6,
    }
    risk_score = sum(
        malicious_patterns.get(pattern, 0)
        for pattern in malicious_patterns
        if pattern in command_seq.lower()
    )
    if risk_score > 5:
        trigger_alert(
            session_id,
            "High Risk Command",
            f"Command sequence '{command_seq}' scored {risk_score} risk points",
            client_ip,
            username,
        )
    try:
        with sqlite3.connect(DB_NAME, uri=True) as conn:
            conn.execute(
                "INSERT INTO commands (timestamp, ip, username, command, session_id) VALUES (?, ?, ?, ?, ?)",
                (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    client_ip,
                    username,
                    cmd,
                    session_id,
                ),
            )
    except sqlite3.Error as e:
        print(f"[!] Command logging error: {e}")
    if cmd_name in ["ls", "dir"]:
        options = set()
        targets = []
        for part in cmd_parts[1:]:
            if part.startswith("-"):
                options.update(part[1:])
            else:
                targets.append(part)
        path = targets[0] if targets else current_dir
        path = os.path.normpath(
            path if path.startswith("/") else f"{current_dir}/{path}"
        )
        if path in fs and fs[path]["type"] == "dir" and "contents" in fs[path]:
            items = fs[path]["contents"]
            display = (
                items if "a" in options else [i for i in items if not i.startswith(".")]
            )
            entries = []
            for name in display:
                full = f"{path}/{name}" if path != "/" else f"/{name}"
                if full in fs:
                    entry = fs[full]
                    size = (
                        len(
                            entry.get("content", "")
                            if entry["type"] == "file"
                            and not callable(entry.get("content"))
                            else ""
                        )
                        if entry["type"] == "file"
                        else 0
                    )
                    entries.append(
                        (
                            name,
                            entry["type"],
                            size,
                            entry.get("owner", username),
                            entry.get("mtime", datetime.now().strftime("%b %d %H:%M")),
                        )
                    )
            if "S" in options:
                entries.sort(key=lambda x: x[2], reverse=True)
            else:
                entries.sort(key=lambda x: x[0])
            if "l" in options:
                lines = []
                for name, typ, size, owner, mtime in entries:
                    item_type = "d" if typ == "dir" else "-"
                    perms = _random_permissions()
                    size_disp = _human_size(size) if "h" in options else str(size)
                    grp = owner
                    if "n" in options:
                        owner = str(PREDEFINED_USERS.get(owner, {}).get("uid", 1000))
                        grp = str(1000)
                    lines.append(
                        f"{item_type}{perms} 1 {owner} {grp} {size_disp:>8} {mtime} {name}"
                    )
                output = "\n".join(lines)
            else:
                names = []
                for name, typ, _, _, _ in entries:
                    if typ == "dir":
                        names.append(f"\033[01;34m{name}\033[0m")
                    else:
                        names.append(name)
                output = _format_ls_columns(names)
        else:
            output = f"ls: cannot access '{arg_str}': No such file or directory"
    elif cmd_name == "cd":
        path = arg_str if arg_str else f"/home/{username}"
        if path.startswith("~"):
            path = path.replace("~", f"/home/{username}", 1)
        path = os.path.normpath(
            path if path.startswith("/") else f"{current_dir}/{path}"
        )
        path_key = path.rstrip("/") or "/"
        if path_key in fs and fs[path_key]["type"] == "dir":
            new_dir = path_key
        else:
            output = f"cd: {arg_str}: No such file or directory"
    elif cmd_name == "cat":
        if not arg_str:
            output = "cat: missing operand"
        else:
            path = arg_str
            if path.startswith("~"):
                path = path.replace("~", f"/home/{username}", 1)
            if not path.startswith("/"):
                path = (
                    f"{current_dir}/{arg_str}" if current_dir != "/" else f"/{arg_str}"
                )
            path = os.path.normpath(path)
            if path in SENSITIVE_FILES:
                trigger_alert(
                    session_id,
                    "Sensitive File Access",
                    f"Accessed file: {path}",
                    client_ip,
                    username,
                )
            if path == "/etc/shadow" and username != "root":
                output = "cat: /etc/shadow: Permission denied"
                trigger_alert(
                    session_id,
                    "Permission Denied",
                    f"Attempted to access /etc/shadow",
                    client_ip,
                    username,
                )
            elif path in fs and fs[path]["type"] == "file":
                content = (
                    fs[path]["content"]()
                    if callable(fs[path]["content"])
                    else fs[path]["content"]
                )
                output = content
                trigger_alert(
                    session_id, "File Access", f"Read file: {path}", client_ip, username
                )
            else:
                output = f"cat: {arg_str}: No such file or directory"
    elif cmd_name == "rm":
        if not arg_str:
            output = "rm: missing operand"
        else:
            path = arg_str
            if not path.startswith("/"):
                path = (
                    f"{current_dir}/{arg_str}" if current_dir != "/" else f"/{arg_str}"
                )
            path = os.path.normpath(path)
            if path in fs and fs[path]["type"] == "file":
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if "-r" in cmd_parts and fs[path]["type"] == "dir":
                    trigger_alert(
                        session_id,
                        "Recursive Delete Attempt",
                        f"Attempted rm -r on {path}",
                        client_ip,
                        username,
                    )
                if (
                    parent_dir in fs
                    and "contents" in fs[parent_dir]
                    and path.split("/")[-1] in fs[parent_dir]["contents"]
                ):
                    fs[parent_dir]["contents"].remove(path.split("/")[-1])
                del fs[path]
                save_filesystem(fs)
                output = ""
                trigger_alert(
                    session_id,
                    "File Deleted",
                    f"Removed file: {path}",
                    client_ip,
                    username,
                )
            else:
                output = f"rm: cannot remove '{arg_str}': No such file or directory"
    elif cmd_name == "mkdir":
        if not arg_str:
            output = "mkdir: missing operand"
        else:
            path = arg_str
            if not path.startswith("/"):
                path = (
                    f"{current_dir}/{arg_str}" if current_dir != "/" else f"/{arg_str}"
                )
            path = os.path.normpath(path)
            fs[path] = {
                "type": "dir",
                "contents": fs.get(path, {}).get("contents", []),
                "owner": username,
                "permissions": "rwxr-xr-x",
                "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            parent_dir = os.path.dirname(path) or "/"
            if (
                parent_dir in fs
                and "contents" in fs[parent_dir]
                and os.path.basename(path) not in fs[parent_dir]["contents"]
            ):
                fs[parent_dir]["contents"].append(os.path.basename(path))
            save_filesystem(fs)
            output = ""
            trigger_alert(
                session_id,
                "Directory Created",
                f"Created directory {path}",
                client_ip,
                username,
            )
    elif cmd_name == "rmdir":
        if not arg_str:
            output = "rmdir: missing operand"
        else:
            path = arg_str
            if not path.startswith("/"):
                path = (
                    f"{current_dir}/{arg_str}" if current_dir != "/" else f"/{arg_str}"
                )
            path = os.path.normpath(path)
            if path in fs and fs[path]["type"] == "dir" and not fs[path]["contents"]:
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if (
                    parent_dir in fs
                    and "contents" in fs[parent_dir]
                    and path.split("/")[-1] in fs[parent_dir]["contents"]
                ):
                    fs[parent_dir]["contents"].remove(path.split("/")[-1])
                del fs[path]
                save_filesystem(fs)
                output = ""
                trigger_alert(
                    session_id,
                    "Directory Removed",
                    f"Removed directory: {path}",
                    client_ip,
                    username,
                )
            else:
                output = f"rmdir: failed to remove '{arg_str}': Directory not empty or does not exist"
    elif cmd_name in ["cp", "mv"]:
        if len(cmd_parts) >= 3:
            src = os.path.normpath(
                cmd_parts[1]
                if cmd_parts[1].startswith("/")
                else f"{current_dir}/{cmd_parts[1]}"
            )
            dst = os.path.normpath(
                cmd_parts[2]
                if cmd_parts[2].startswith("/")
                else f"{current_dir}/{cmd_parts[2]}"
            )
            if src in fs and fs[src]["type"] == "file":
                fs[dst] = fs[src].copy()
                fs[dst]["owner"] = username
                fs[dst]["mtime"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                parent_dir = "/".join(dst.split("/")[:-1]) or "/"
                if (
                    parent_dir in fs
                    and "contents" in fs[parent_dir]
                    and dst.split("/")[-1] not in fs[parent_dir]["contents"]
                ):
                    fs[parent_dir]["contents"].append(dst.split("/")[-1])
                if cmd_name == "mv":
                    parent_src_dir = "/".join(src.split("/")[:-1]) or "/"
                    if (
                        parent_src_dir in fs
                        and "contents" in fs[parent_src_dir]
                        and src.split("/")[-1] in fs[parent_src_dir]["contents"]
                    ):
                        fs[parent_src_dir]["contents"].remove(src.split("/")[-1])
                    del fs[src]
                save_filesystem(fs)
                output = f"{cmd_name}: {'copied' if cmd_name == 'cp' else 'moved'} '{src}' to '{dst}'"
                trigger_alert(
                    session_id,
                    f"File {cmd_name.upper()}",
                    f"{'Copied' if cmd_name == 'cp' else 'Moved'} file: {src} to {dst}",
                    client_ip,
                    username,
                )
            else:
                output = f"{cmd_name}: cannot stat '{cmd_parts[1]}': No such file or directory"
        else:
            output = f"{cmd_name}: missing file operand"
    elif cmd_name == "chmod":
        if len(cmd_parts) >= 3 and cmd_parts[1] in ["+x", "-w", "755", "644"]:
            path = os.path.normpath(
                cmd_parts[2]
                if cmd_parts[2].startswith("/")
                else f"{current_dir}/{cmd_parts[2]}"
            )
            if path in fs:
                fs[path]["permissions"] = (
                    cmd_parts[1]
                    if cmd_parts[1] in ["+x", "-w"]
                    else ("rwxr-xr-x" if cmd_parts[1] == "755" else "rw-r--r--")
                )
                save_filesystem(fs)
                output = ""
                trigger_alert(
                    session_id,
                    "Permission Change",
                    f"Changed permissions of {path} to {cmd_parts[1]}",
                    client_ip,
                    username,
                )
            else:
                output = (
                    f"chmod: cannot access '{cmd_parts[2]}': No such file or directory"
                )
        else:
            output = "chmod: invalid syntax or missing operand"
    elif cmd_name == "chown":
        if len(cmd_parts) >= 3 and cmd_parts[1] in PREDEFINED_USERS:
            path = os.path.normpath(
                cmd_parts[2]
                if cmd_parts[2].startswith("/")
                else f"{current_dir}/{cmd_parts[2]}"
            )
            if path in fs:
                fs[path]["owner"] = cmd_parts[1]
                save_filesystem(fs)
                output = ""
                trigger_alert(
                    session_id,
                    "Owner Change",
                    f"Changed owner of {path} to {cmd_parts[1]}",
                    client_ip,
                    username,
                )
            else:
                output = (
                    f"chown: cannot access '{cmd_parts[2]}': No such file or directory"
                )
        else:
            output = "chown: invalid user or missing operand"
    elif cmd_name == "kill":
        if arg_str:
            output = f"kill: process {arg_str} terminated (simulated)"
            trigger_alert(
                session_id,
                "Process Kill",
                f"Attempted to kill process {arg_str}",
                client_ip,
                username,
            )
        else:
            output = "kill: usage: kill -9 <pid>"
    elif cmd_name == "ping":
        if not arg_str:
            output = "ping: missing host operand"
        else:
            host = arg_str.split()[0]
            header = f"PING {host} ({host}) 56(84) bytes of data."
            lines = [header]
            if allow_redirect:
                chan.send((header + "\r\n").encode())
                time.sleep(0.5)
            for i in range(4):
                latency = random.uniform(0.1, 2.0)
                line = f"64 bytes from {host}: icmp_seq={i + 1} ttl=64 time={latency:.2f} ms"
                lines.append(line)
                if allow_redirect:
                    chan.send((line + "\r\n").encode())
                    time.sleep(1)
            stats = f"--- {host} ping statistics ---\n4 packets transmitted, 4 received, 0% packet loss"
            lines.append(stats)
            output = "\n".join(lines)
            trigger_alert(
                session_id,
                "Network Command",
                f"Pinged host: {host}",
                client_ip,
                username,
            )
    elif cmd_name == "nmap":
        if not arg_str:
            output = "nmap: missing target"
        else:
            output = get_dynamic_network_scan()
            trigger_alert(
                session_id,
                "Network Scan",
                f"Executed nmap with args: {arg_str}",
                client_ip,
                username,
            )
    elif cmd_name in ["traceroute", "tracepath"]:
        if not arg_str:
            output = f"{cmd_name}: missing host"
        else:
            host = arg_str.split()[0]
            output = get_dynamic_traceroute(host)
        trigger_alert(
            session_id,
            "Network Command",
            f"Executed {cmd_name} to {arg_str}",
            client_ip,
            username,
        )
    elif cmd_name in ["dig", "nslookup"]:
        if not arg_str:
            output = f"{cmd_name}: missing query"
        else:
            query = arg_str.split()[0]
            output = get_dynamic_dig(query)
        trigger_alert(
            session_id,
            "Network Command",
            f"Executed {cmd_name}: {arg_str}",
            client_ip,
            username,
        )
    elif cmd_name == "tcpdump":
        output = get_dynamic_tcpdump()
        trigger_alert(
            session_id,
            "Network Command",
            "Captured packets via tcpdump",
            client_ip,
            username,
        )
    elif cmd_name in ["nc", "netcat"]:
        if "-l" in cmd_parts:
            port = arg_str.split()[-1] if arg_str.split() else "1234"
            netcat_session(
                chan,
                True,
                "",
                port,
                username,
                session_id,
                client_ip,
                session_log,
            )
            return "", new_dir, jobs, cmd_count, False
        elif len(cmd_parts) >= 3:
            host = cmd_parts[1]
            port = cmd_parts[2]
            netcat_session(
                chan,
                False,
                host,
                port,
                username,
                session_id,
                client_ip,
                session_log,
            )
            return "", new_dir, jobs, cmd_count, False
        else:
            output = f"{cmd_name}: invalid arguments"
        trigger_alert(
            session_id,
            "Network Command",
            f"Executed {cmd_name}: {arg_str}",
            client_ip,
            username,
        )
    elif cmd_name == "ss":
        output = get_dynamic_ss()
        trigger_alert(
            session_id,
            "Network Command",
            "Displayed socket list via ss",
            client_ip,
            username,
        )
    elif cmd_name == "arp":
        output = get_dynamic_arp()
        trigger_alert(
            session_id, "Command Executed", "Displayed ARP table", client_ip, username
        )
    elif cmd_name == "curl" or cmd_name == "wget":
        if not arg_str:
            output = f"{cmd_name}: missing URL"
        else:
            output = f"{cmd_name}: downloaded data from {arg_str} (simulated)"
            trigger_alert(
                session_id,
                "Network Download Attempt",
                f"Attempted {cmd_name}: {arg_str}",
                client_ip,
                username,
            )
    elif cmd_name == "telnet":
        if not arg_str:
            output = "telnet: missing host"
        else:
            host = arg_str.split()[0]
            output = f"Trying {host}...\r\nConnection refused"
            trigger_alert(
                session_id,
                "Telnet Attempt",
                f"Attempted telnet to {host}",
                client_ip,
                username,
            )
    elif cmd_name == "scp":
        if not arg_str:
            output = "scp: missing arguments"
        else:
            output = "scp: connection refused (simulated)"
            trigger_alert(
                session_id,
                "File Transfer Attempt",
                f"Attempted scp: {arg_str}",
                client_ip,
                username,
            )
    elif cmd_name == "ftp":
        host = arg_str.strip() if arg_str else "localhost"
        ftp_session(chan, host, username, session_id, client_ip, session_log)
        return "", new_dir, jobs, cmd_count, False
    elif cmd_name in ["mysql", "sql"]:
        mysql_session(chan, username, session_id, client_ip, session_log)
        return "", new_dir, jobs, cmd_count, False
    elif cmd_name == "find":
        if not arg_str:
            output = "find: missing argument"
        else:
            path = arg_str.split()[-1] if arg_str else current_dir
            if path.startswith("~"):
                path = path.replace("~", f"/home/{username}", 1)
            if not path.startswith("/"):
                path = f"{current_dir}/{path}" if current_dir != "/" else f"/{path}"
            path = os.path.normpath(path)
            if path in fs and fs[path]["type"] == "dir" and "contents" in fs[path]:
                results = []

                def recursive_find(p):
                    """Fonction interne pour parcourir l'arborescence de fichiers."""
                    for item in fs[p]["contents"]:
                        full_path = f"{p}/{item}" if p != "/" else f"/{item}"
                        if full_path in fs:
                            if "-name" in arg_str and item in arg_str:
                                results.append(full_path)
                            if (
                                fs[full_path]["type"] == "dir"
                                and "contents" in fs[full_path]
                            ):
                                recursive_find(full_path)

                recursive_find(path)
                output = "\n".join(results)
                trigger_alert(
                    session_id,
                    "Command Executed",
                    f"Executed find in {path}",
                    client_ip,
                    username,
                )
            else:
                output = f"find: '{path}': No such file or directory"
    elif cmd_name == "grep":
        if not arg_str:
            output = "grep: missing pattern"
        else:
            parts = arg_str.split()
            pattern = parts[0].strip("'\"")
            files = parts[1:] if len(parts) > 1 else []
            results = []
            for file in files:
                path = file if file.startswith("/") else f"{current_dir}/{file}"
                path = os.path.normpath(path)
                if path in fs and fs[path]["type"] == "file":
                    content = (
                        fs[path]["content"]()
                        if callable(fs[path]["content"])
                        else fs[path]["content"]
                    )
                    for line in content.split("\n"):
                        if pattern in line:
                            results.append(f"{file}: {line}")
            output = (
                "\n".join(results) if results else f"grep: no matches for '{pattern}'"
            )
            trigger_alert(
                session_id,
                "Command Executed",
                f"Executed grep with pattern '{pattern}'",
                client_ip,
                username,
            )
    elif cmd_name == "tree":
        path = arg_str if arg_str else current_dir
        path = os.path.normpath(
            path if path.startswith("/") else f"{current_dir}/{path}"
        )

        def list_tree(p, prefix=""):
            """Fonction interne pour afficher l'arbre des fichiers."""
            lines = []
            if p in fs and fs[p]["type"] == "dir" and "contents" in fs[p]:
                for i, item in enumerate(fs[p]["contents"]):
                    full = f"{p}/{item}" if p != "/" else f"/{item}"
                    if full not in fs:
                        continue
                    connector = "└── " if i == len(fs[p]["contents"]) - 1 else "├── "
                    name = f"{item}/" if fs[full]["type"] == "dir" else item
                    lines.append(prefix + connector + name)
                    if fs[full]["type"] == "dir":
                        extension = (
                            "    " if i == len(fs[p]["contents"]) - 1 else "│   "
                        )
                        lines.extend(list_tree(full, prefix + extension))
            return lines

        if path in fs and fs[path]["type"] == "dir":
            root_name = os.path.basename(path.rstrip("/")) or "/"
            output = root_name + "\n" + "\n".join(list_tree(path))
        else:
            output = f"tree: {arg_str}: No such directory"
        trigger_alert(
            session_id,
            "Command Executed",
            f"Displayed tree for {path}",
            client_ip,
            username,
        )
    elif cmd_name == "touch":
        if not arg_str:
            output = "touch: missing file operand"
        else:
            path = arg_str
            if not path.startswith("/"):
                path = (
                    f"{current_dir}/{arg_str}" if current_dir != "/" else f"/{arg_str}"
                )
            path = os.path.normpath(path)
            fs[path] = {
                "type": "file",
                "content": "",
                "owner": username,
                "permissions": "rw-r--r--",
                "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            parent_dir = os.path.dirname(path) or "/"
            if (
                parent_dir in fs
                and "contents" in fs[parent_dir]
                and os.path.basename(path) not in fs[parent_dir]["contents"]
            ):
                fs[parent_dir]["contents"].append(os.path.basename(path))
            save_filesystem(fs)
            output = ""
            trigger_alert(
                session_id,
                "File Created",
                f"Created file: {path}",
                client_ip,
                username,
            )
    elif cmd_name == "apt-get":
        if not arg_str:
            output = "apt-get: missing command"
        else:
            if "install" in arg_str:
                output = f"apt-get: installing package(s) {arg_str.split('install')[-1].strip()} (simulated)"
            elif "update" in arg_str:
                output = "apt-get: updating package lists (simulated)"
            elif "upgrade" in arg_str:
                output = "apt-get: upgrading packages (simulated)"
            else:
                output = f"apt-get: unknown command '{arg_str}'"
            trigger_alert(
                session_id,
                "Package Manager Command",
                f"Executed apt-get: {cmd}",
                client_ip,
                username,
            )
    elif cmd_name in ["yum", "dnf", "apk"]:
        if not arg_str:
            output = f"{cmd_name}: missing command"
        else:
            action = arg_str.split()[0]
            pkg = " ".join(arg_str.split()[1:]) or "all packages"
            if action in ["install", "update", "remove"]:
                output = f"{cmd_name}: {action}ing {pkg} (simulated)"
            else:
                output = f"{cmd_name}: unknown command '{arg_str}'"
        trigger_alert(
            session_id,
            "Package Manager Command",
            f"Executed {cmd_name}: {cmd}",
            client_ip,
            username,
        )
    elif cmd_name == "pip" and arg_str.startswith("install"):
        pkg = arg_str.split("install", 1)[-1].strip() or "package"
        output = f"Collecting {pkg}\nSuccessfully installed {pkg.replace(' ', '-')}"
        trigger_alert(
            session_id,
            "Package Manager Command",
            f"Executed pip install: {pkg}",
            client_ip,
            username,
        )
    elif cmd_name == "npm" and arg_str.startswith("install"):
        pkg = arg_str.split("install", 1)[-1].strip() or "package"
        output = f"added 1 package in 0.0s\nSuccessfully installed {pkg}"
        trigger_alert(
            session_id,
            "Package Manager Command",
            f"Executed npm install: {pkg}",
            client_ip,
            username,
        )
    elif cmd_name == "man":
        args = cmd_parts[1:]
        if not args:
            output = "What manual page do you want?"
        elif "-k" in args:
            try:
                keyword = args[args.index("-k") + 1]
            except IndexError:
                keyword = ""
            results = [
                f"{name} - {page.splitlines()[1].strip()}"
                for name, page in MAN_PAGES.items()
                if keyword.lower() in page.lower()
            ]
            output = (
                "\n".join(results) if results else f"{keyword}: nothing appropriate."
            )
        elif "-f" in args:
            keywords = args[args.index("-f") + 1 :]
            lines = []
            for kw in keywords:
                if kw in MAN_PAGES:
                    desc = MAN_PAGES[kw].splitlines()[1].strip()
                    lines.append(f"{kw}: {desc}")
                else:
                    lines.append(f"{kw}: nothing appropriate.")
            output = "\n".join(lines)
        else:
            page = MAN_PAGES.get(args[0])
            if page:
                output = page
            else:
                output = f"No manual entry for {args[0]}"
        trigger_alert(
            session_id,
            "Command Executed",
            f"Requested man page for {arg_str if arg_str else 'none'}",
            client_ip,
            username,
        )
    elif cmd_name == "who":
        output = get_dynamic_who()
        trigger_alert(
            session_id, "Command Executed", "Displayed user list", client_ip, username
        )
    elif cmd_name == "w":
        output = get_dynamic_w()
        trigger_alert(
            session_id,
            "Command Executed",
            "Displayed user activity",
            client_ip,
            username,
        )
    elif cmd_name == "hostname":
        output = "honeypot"
        trigger_alert(
            session_id,
            "Command Executed",
            "Displayed hostname",
            client_ip,
            username,
        )
    elif cmd_name == "uptime":
        output = get_dynamic_uptime()
        trigger_alert(
            session_id,
            "Command Executed",
            "Displayed system uptime",
            client_ip,
            username,
        )
    elif cmd_name == "df":
        output = get_dynamic_df()
        trigger_alert(
            session_id,
            "Command Executed",
            "Displayed disk usage",
            client_ip,
            username,
        )
    elif cmd_name == "ps" or cmd_name == "get-process":
        output = get_dynamic_ps()
        trigger_alert(
            session_id,
            "Command Executed",
            "Displayed process list",
            client_ip,
            username,
        )
    elif cmd_name == "netstat":
        output = get_dynamic_netstat()
        trigger_alert(
            session_id,
            "Command Executed",
            "Displayed network stats",
            client_ip,
            username,
        )
    elif cmd_name == "get-service":
        services = [
            "ssh     running",
            "nginx   running",
            "mysql   stopped",
        ]
        output = "Service Name  Status\n" + "\n".join(services)
        trigger_alert(
            session_id,
            "Command Executed",
            "Displayed service list",
            client_ip,
            username,
        )
    elif cmd_name == "top":
        output = get_dynamic_top()
        trigger_alert(
            session_id,
            "Command Executed",
            "Displayed top processes",
            client_ip,
            username,
        )
    elif cmd_name == "backup_data":
        output = "Backing up data to /tmp/backup.tar.gz (simulated)..."
        fs["/tmp/backup.tar.gz"] = {
            "type": "file",
            "content": "Simulated backup data",
            "owner": username,
            "permissions": "rw-r--r--",
            "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        if (
            "/tmp" in fs
            and "contents" in fs["/tmp"]
            and "backup.tar.gz" not in fs["/tmp"]["contents"]
        ):
            fs["/tmp"]["contents"].append("backup.tar.gz")
        save_filesystem(fs)
        trigger_alert(
            session_id, "Backup Triggered", "Triggered backup", client_ip, username
        )
    elif cmd_name == "systemctl":
        if "stop" in cmd_parts and "nginx" in cmd_parts:
            output = "nginx service stopped (simulated)"
            trigger_alert(
                session_id, "Service Stop", "Stopped nginx service", client_ip, username
            )
        elif "start" in cmd_parts and "nginx" in cmd_parts:
            output = "nginx service started (simulated)"
        else:
            output = f"systemctl: unknown command or service '{arg_str}'"
        trigger_alert(
            session_id,
            "Service Command",
            f"Executed systemctl: {cmd}",
            client_ip,
            username,
        )
    elif cmd_name == "service":
        if len(cmd_parts) >= 3:
            svc = cmd_parts[1]
            action = cmd_parts[2]
            output = f"{svc} service {action}ed (simulated)"
        else:
            output = "service: usage: service <name> <action>"
        trigger_alert(
            session_id,
            "Service Command",
            f"Executed service: {cmd}",
            client_ip,
            username,
        )
    elif cmd_name == "iptables":
        if "-L" in cmd_parts:
            lines = ["Chain INPUT (policy ACCEPT)"]
            for idx, rule in enumerate(IPTABLES_RULES, 1):
                lines.append(f"{idx}: {rule['chain']} {rule['rule']}")
            output = "\n".join(lines)
        elif "-A" in cmd_parts or "-I" in cmd_parts:
            try:
                idx = cmd_parts.index("-A") if "-A" in cmd_parts else cmd_parts.index("-I")
                chain = cmd_parts[idx + 1]
                rule = " ".join(cmd_parts[idx + 2:])
                IPTABLES_RULES.append({"chain": chain, "rule": rule})
                output = "Rule added (simulated)"
            except Exception:
                output = "iptables: invalid rule"
        elif "-D" in cmd_parts:
            try:
                idx = cmd_parts.index("-D")
                chain = cmd_parts[idx + 1]
                num = int(cmd_parts[idx + 2]) - 1
                removed = False
                for i, r in enumerate(IPTABLES_RULES):
                    if i == num and r["chain"] == chain:
                        IPTABLES_RULES.pop(i)
                        removed = True
                        break
                output = "Rule deleted (simulated)" if removed else "No such rule"
            except Exception:
                output = "iptables: invalid rule"
        else:
            output = "iptables: command executed"
        trigger_alert(
            session_id,
            "Firewall Command",
            f"Executed iptables: {cmd}",
            client_ip,
            username,
        )
    elif cmd_name in ["gcc", "make", "cmake"]:
        output = "compiling...\n"
        if random.random() < 0.8:
            output += "build succeeded"
        else:
            output += "error: undefined reference"
        trigger_alert(
            session_id,
            "Build Tool",
            f"Executed {cmd_name}: {arg_str}",
            client_ip,
            username,
        )
    elif cmd_name == "python":
        python_repl(chan, username, session_id, client_ip, session_log)
        return "", new_dir, jobs, cmd_count, False
    elif cmd_name == "node":
        node_repl(chan, username, session_id, client_ip, session_log)
        return "", new_dir, jobs, cmd_count, False
    elif cmd_name == "git":
        if "push" in cmd_parts:
            output = get_realistic_git_push()
        elif "status" in cmd_parts:
            output = get_realistic_git_status()
        else:
            output = "Everything up-to-date"
        trigger_alert(
            session_id,
            "Git Command",
            f"Executed git: {cmd}",
            client_ip,
            username,
        )
    elif cmd_name == "docker":
        if "ps" in cmd_parts:
            output = get_realistic_docker_ps()
        else:
            output = "Docker command executed"
        trigger_alert(
            session_id,
            "Container Command",
            f"Executed docker: {arg_str}",
            client_ip,
            username,
        )
    elif cmd_name == "kubectl":
        if "get" in cmd_parts and "pods" in cmd_parts:
            output = get_realistic_kubectl_get_pods()
        else:
            output = "Kubectl command executed"
        trigger_alert(
            session_id,
            "Container Command",
            f"Executed kubectl: {arg_str}",
            client_ip,
            username,
        )
    elif cmd_name == "helm":
        if "list" in cmd_parts:
            output = get_realistic_helm_list()
        else:
            output = "Helm command executed"
        trigger_alert(
            session_id,
            "Container Command",
            f"Executed helm: {arg_str}",
            client_ip,
            username,
        )
    elif cmd_name == "docker-compose":
        if "up" in cmd_parts:
            output = get_realistic_docker_compose_up()
        else:
            output = "docker-compose command executed"
        trigger_alert(
            session_id,
            "Container Command",
            f"Executed docker-compose: {arg_str}",
            client_ip,
            username,
        )
    elif cmd_name == "fg":
        if arg_str and arg_str.isdigit() and int(arg_str) - 1 in range(len(jobs)):
            job = jobs[int(arg_str) - 1]
            output = f"Resuming job [{arg_str}]: {job['cmd']}\n"
            output += job.get("output", "")
            jobs.pop(int(arg_str) - 1)
        else:
            output = "fg: no such job"
    elif cmd_name == "jobs":
        if jobs:
            output = "\n".join(
                f"[{job['id']}]: {job['cmd']} {job['state']}" for job in jobs
            )
        else:
            output = "No jobs running"
    elif cmd_name == "app_status":
        output = "Checking application status...\n\tWebServer: Running\n\tDatabase: Running\n\tBackup: Active"
        trigger_alert(
            session_id,
            "App Status Check",
            "Checked application status",
            client_ip,
            username,
        )
    elif cmd_name == "status_report":
        output = f"System Status for {username} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}:\nCurrent Directory: {current_dir}\nActive Jobs: {len(jobs)}\nSystem Uptime: {get_dynamic_uptime()}\nDisk Usage:\n{get_dynamic_df()}"
        trigger_alert(
            session_id,
            "Status Report",
            "Generated system status report",
            client_ip,
            username,
        )
    elif cmd_name == "fortune":
        output = get_random_fortune()
        trigger_alert(
            session_id,
            "Fortune",
            "Displayed random fortune",
            client_ip,
            username,
        )
    elif cmd_name == "cowsay":
        message = arg_str if arg_str else "Moo!"
        output = cowsay(message)
        trigger_alert(
            session_id,
            "Cowsay",
            f"Displayed cowsay message: {message}",
            client_ip,
            username,
        )
    elif cmd_name == "whoami":
        output = f"{username}"
        trigger_alert(
            session_id,
            "Command Executed",
            "Displayed current user",
            client_ip,
            username,
        )
    elif cmd_name == "id":
        user_info = PREDEFINED_USERS.get(
            username, {"uid": "1000", "groups": [username]}
        )
        output = f"uid={user_info['uid']}({username}) gid=1000({username}) groups={','.join(user_info['groups'])}"
        trigger_alert(
            session_id,
            "Command Executed",
            "Displayed user ID info",
            client_ip,
            username,
        )
    elif cmd_name == "uname":
        output = f"Linux server 5.15.0-73-generic #80-Ubuntu SMP Mon May 15 10:15:39 UTC 2023 x86_64 GNU/Linux"
        trigger_alert(
            session_id, "Command Executed", "Displayed system info", client_ip, username
        )
    elif cmd_name == "pwd":
        output = f"{current_dir}"
        trigger_alert(
            session_id,
            "Command Executed",
            "Displayed current directory",
            client_ip,
            username,
        )
    elif cmd_name == "history":
        output = "\n".join(f"{i+1}  {cmd}" for i, cmd in enumerate(command_history))
        trigger_alert(
            session_id,
            "Command History",
            "Displayed command history",
            client_ip,
            username,
        )
    elif cmd_name == "sudo":
        attempts = 0
        while attempts < 3:
            chan.send(f"[sudo] password for {username}: ".encode())
            _ = read_password(chan)
            attempts += 1
            if attempts < 3:
                chan.send(b"Sorry, try again.\r\n")
        chan.send(b"sudo: 3 incorrect password attempts\r\n")
        trigger_alert(
            session_id,
            "Sudo Attempt",
            f"Attempted sudo command: {arg_str}",
            client_ip,
            username,
        )
        output = ""
    elif cmd_name == "su":
        output = "su: Authentication failure"
        trigger_alert(
            session_id, "SU Attempt", "Attempted su command", client_ip, username
        )
    elif cmd_name == "exit":
        output = "logout"
        chan.send(b"logout\r\n")
        chan.close()
        trigger_alert(
            session_id, "Session Exit", "User logged out", client_ip, username
        )
        return output, new_dir, jobs, cmd_count, True
    elif cmd_name in USER_DEFINED_COMMANDS:
        output = f"{cmd_name}: custom command executed (simulated output)"
        trigger_alert(
            session_id,
            "Custom Command",
            f"Executed custom command: {cmd}",
            client_ip,
            username,
        )
    elif cmd_name == "echo":
        args = cmd_parts[1:]
        newline = True
        if args and args[0] == "-n":
            newline = False
            args = args[1:]
        text = " ".join(arg.strip("'\"") for arg in args)
        output = text + ("" if not newline else "\n")
        trigger_alert(
            session_id,
            "Command Executed",
            f"Executed echo with args: {args}",
            client_ip,
            username,
        )
    else:
        output = f"{cmd_name}: command not found"
        trigger_alert(
            session_id,
            "Unknown Command",
            f"Attempted unknown command: {cmd}",
            client_ip,
            username,
        )

    cmd_count += 1
    if cmd_count >= CMD_LIMIT_PER_SESSION:
        output += "\nCommand limit reached for this session."
        trigger_alert(
            session_id,
            "Command Limit Exceeded",
            f"Reached {CMD_LIMIT_PER_SESSION} commands",
            client_ip,
            username,
        )
        chan.send(b"Command limit reached. Session terminated.\r\n")
        chan.close()
        return output, new_dir, jobs, cmd_count, True

    return output, new_dir, jobs, cmd_count, False


# Lecture interactive des lignes avec autocomplétion
def _read_escape_sequence(chan):
    """Lit une sequence d'echappement provenant du terminal."""
    seq = ""
    # Attend jusqu'a 200 ms pour capturer l'ensemble de la sequence
    # afin d'eviter la troncature lors d'une frappe rapide sur les fleches.
    end_time = time.time() + 0.2
    while time.time() < end_time:
        timeout = max(0, end_time - time.time())
        readable, _, _ = select.select([chan], [], [], timeout)
        if not readable:
            break
        try:
            ch = chan.recv(1).decode("utf-8", errors="ignore")
        except Exception:
            break
        if not ch:
            break
        seq += ch
        # Les sequences ESC O[A-D] utilisent deux lettres. On continue donc
        # apres le premier 'O' pour recuperer la lettre finale.
        if ch.isalpha() or ch == "~":
            if seq == "O":
                continue
            break
    return seq


def read_line_advanced(
    chan,
    prompt,
    history,
    current_dir,
    username,
    fs,
    session_log,
    session_id,
    client_ip,
    jobs,
    cmd_count,
):
    """Lecture avancee d'une ligne avec edition et autocompletion."""
    chan.send(prompt.encode())
    buffer = ""
    pos = 0
    history_index = len(history)
    last_completions = []
    tab_count = 0

    def redraw_line():
        """Redessine la ligne et place le curseur au bon endroit."""
        # Efface toute la ligne actuelle puis reaffiche le prompt et le buffer
        chan.send(b"\r\x1b[2K" + prompt.encode() + buffer.encode())
        diff = len(buffer) - pos
        if diff > 0:
            # Replace the cursor if we are editing in the middle of the buffer
            chan.send(f"\x1b[{diff}D".encode())
    while True:
        readable, _, _ = select.select([chan], [], [], 0.1)
        if readable:
            try:
                raw = chan.recv(1)
                if not raw:
                    return None, jobs, cmd_count
                try:
                    data = raw.decode("utf-8")
                except UnicodeDecodeError:
                    try:
                        data = raw.decode("latin-1")
                    except Exception:
                        continue
                if data == "\x1b":
                    data += _read_escape_sequence(chan)
                log_activity(session_id, client_ip, username, data)

                if data == "\r" or data == "\n":
                    chan.send(b"\r\n")
                    if buffer.strip():
                        history.append(buffer.strip())
                    return buffer.strip(), jobs, cmd_count
                elif data == "\t":
                    buffer, last_completions, tab_count = autocomplete(
                        buffer,
                        current_dir,
                        username,
                        fs,
                        chan,
                        history,
                        last_completions,
                        tab_count,
                        prompt,
                    )
                    pos = len(buffer)
                    chan.send(
                        b"\r" + prompt.encode() + buffer.encode() + b"\x1b[K"
                    )
                elif data == "\x7f" or data == "\x08":  # Backspace (DEL or BS)
                    if pos > 0:
                        buffer = buffer[: pos - 1] + buffer[pos:]
                        pos -= 1
                        redraw_line()
                    last_completions = []
                    tab_count = 0
                elif data == "\x03":  # Ctrl+C
                    chan.send(b"^C\r\n")
                    buffer = ""
                    pos = 0
                    history_index = len(history)
                    chan.send(prompt.encode())
                    last_completions = []
                    tab_count = 0
                    continue
                elif data == "\x04":  # Ctrl+D
                    chan.send(b"logout\r\n")
                    return "exit", jobs, cmd_count
                elif re.match(r"\x1b\[[0-9;]*[ABCD]$", data) or re.match(r"\x1bO[ABCD]$", data):  # Flèches directionnelles
                    key = data[-1]
                    if key == "A":  # Flèche haut
                        if history_index > 0:
                            history_index -= 1
                            buffer = (
                                history[history_index]
                                if 0 <= history_index < len(history)
                                else ""
                            )
                            pos = len(buffer)
                        redraw_line()
                    elif key == "B":  # Flèche bas
                        if history_index < len(history):
                            history_index += 1
                            buffer = (
                                history[history_index]
                                if 0 <= history_index < len(history)
                                else ""
                            )
                            pos = len(buffer)
                        else:
                            history_index = len(history)
                            buffer = ""
                            pos = 0
                        redraw_line()
                    elif key == "C":  # Flèche droite
                        if pos < len(buffer):
                            pos += 1
                            chan.send(b"\x1b[C")
                    elif key == "D":  # Flèche gauche
                        if pos > 0:
                            pos -= 1
                            chan.send(b"\x1b[D")
                    last_completions = []
                    tab_count = 0
                elif len(data) == 1 and 32 <= ord(data) <= 255:  # Caractères imprimables
                    buffer = buffer[:pos] + data + buffer[pos:]
                    pos += 1
                    redraw_line()
                    last_completions = []
                    tab_count = 0
            except UnicodeDecodeError:
                continue
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[!] Read line error: {e}")
                return "", jobs, cmd_count


# Lecture du mot de passe
def read_password(chan):
    """Lecture du mot de passe en masquant la saisie."""
    buffer = ""
    while True:
        readable, _, _ = select.select([chan], [], [], 0.1)
        if readable:
            try:
                data = chan.recv(1).decode("utf-8", errors="ignore")
                if data == "\x1b":
                    _read_escape_sequence(chan)
                    continue
                if data == "\r" or data == "\n":
                    chan.send(b"\r\n")
                    return buffer
                elif data == "\x7f" and buffer:
                    buffer = buffer[:-1]
                    chan.send(b"\b \b")
                elif len(data) == 1 and ord(data) >= 32:
                    buffer += data
                    chan.send(b"*")
            except UnicodeDecodeError:
                continue
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[!] Read password error: {e}")
                return ""


# Gestion de la session SSH
def handle_ssh_session(chan, client_ip, username, session_id, transport):
    """Boucle principale gerant une session SSH."""
    session_log = []
    current_dir = PREDEFINED_USERS.get(username, {}).get("home", "/home/" + username)
    history = load_history(username)
    jobs = []
    cmd_count = 0
    chan.settimeout(0.1)
    last_login = datetime.now().strftime("%a %b %d %H:%M:%S %Y")
    motd = (
        f"Last login: {last_login} from {client_ip}\r\n"
        "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-73-generic x86_64)\r\n"
        " * Documentation:  https://help.ubuntu.com\r\n"
        " * Management:     https://landscape.canonical.com\r\n"
        " * Support:        https://ubuntu.com/advantage\r\n\r\n"
    )
    chan.send(motd.encode())

    try:
        while True:
            prompt = color_prompt(username, client_ip, current_dir)
            cmd, jobs, cmd_count = read_line_advanced(
                chan,
                prompt,
                history,
                current_dir,
                username,
                FS,
                session_log,
                session_id,
                client_ip,
                jobs,
                cmd_count,
            )
            if cmd is None or cmd in ["exit", "logout"]:
                break
            if cmd == "":
                continue

            command_index = cmd_count + 1
            start_time = datetime.now().isoformat()
            log_session_activity(
                session_id,
                client_ip,
                username,
                cmd,
                "",
                success=None,
                cwd=current_dir,
                cmd_index=command_index,
                start_time=start_time,
            )

            output, current_dir, jobs, cmd_count, should_exit = process_command(
                cmd,
                current_dir,
                username,
                FS,
                client_ip,
                session_id,
                session_log,
                history,
                chan,
                jobs,
                cmd_count,
            )
            if output:
                # Normalize line endings to avoid duplicated carriage returns
                formatted = output.replace("\r\n", "\n").replace("\r", "\n")
                formatted = formatted.rstrip("\n")
                formatted = formatted.replace("\n", "\r\n") + "\r\n"
                chan.send(formatted.encode())
            error_keywords = [
                "not found",
                "no such file",
                "permission denied",
                "error",
                "failed",
                "missing",
            ]
            success = not any(k in output.lower() for k in error_keywords)
            end_time = datetime.now().isoformat()
            log_session_activity(
                session_id,
                client_ip,
                username,
                cmd,
                output,
                success,
                cwd=current_dir,
                cmd_index=command_index,
                start_time=start_time,
                end_time=end_time,
            )
            if should_exit:
                break

            save_history(username, history)

    except Exception as e:
        print(f"[!] Session error: {e}")
    finally:
        chan.close()
        transport.close()
        save_session_log(session_id, session_log)
        trigger_alert(
            session_id, "Session Closed", "Session terminated", client_ip, username
        )


def save_session_log(session_id, session_log):
    """Archive le journal d'une session sur disque."""
    os.makedirs(SESSION_LOG_DIR, exist_ok=True)
    log_file = os.path.join(SESSION_LOG_DIR, f"session_{session_id}.log")
    with open(log_file, "w") as f:
        f.write("\n".join(session_log))
    with open(log_file, "rb") as f_in:
        with gzip.open(log_file + ".gz", "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    os.remove(log_file)


# Classe de transport Paramiko
class HoneySSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, session_id):
        """Initialise le serveur SSH pour un client."""
        self.client_ip = client_ip
        self.session_id = session_id
        self.event = threading.Event()
        self.username = None

    def check_channel_request(self, kind, chanid):
        """Valide l'ouverture d'un canal SSH."""
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """Authentifie un utilisateur SSH."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        success = False
        redirected = False

        # Store username for later retrieval
        self.username = username

        if not check_bruteforce(self.client_ip, username, password):
            print(f"[!] Bruteforce detected from {self.client_ip}")
            return paramiko.AUTH_FAILED
        now = time.time()
        if username == "admin":
            ban_until = _admin_bans.get(self.client_ip, 0)
            if ban_until > now:
                return paramiko.AUTH_FAILED
            if hashlib.sha256(password.encode()).hexdigest() == ADMIN_PASSWORD_HASH:
                success = True
                _admin_attempts.pop(self.client_ip, None)
            else:
                _admin_attempts[self.client_ip] = (
                    _admin_attempts.get(self.client_ip, 0) + 1
                )
                if _admin_attempts[self.client_ip] >= ADMIN_MAX_ATTEMPTS:
                    _admin_bans[self.client_ip] = now + ADMIN_BAN_DURATION
                    _admin_attempts[self.client_ip] = 0
        else:
            key = (self.client_ip, username)
            _user_attempts[key] = _user_attempts.get(key, 0) + 1
            if _user_attempts[key] >= USER_SUCCESS_ATTEMPTS:
                success = True
                _user_attempts[key] = 0
        if success and ENABLE_REDIRECTION:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.connect((REAL_SSH_HOST, REAL_SSH_PORT))
                    redirected = True
            except Exception:
                pass

        try:
            with sqlite3.connect(DB_NAME, uri=True) as conn:
                conn.execute(
                    "INSERT INTO login_attempts (timestamp, ip, username, password, success, redirected) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        timestamp,
                        self.client_ip,
                        username,
                        password,
                        1 if success else 0,
                        1 if redirected else 0,
                    ),
                )
        except sqlite3.Error as e:
            print(f"[!] Login attempt logging error: {e}")

        trigger_alert(
            self.session_id,
            "Login Attempt",
            f"{'Successful' if success else 'Failed'} login: {username} from {self.client_ip}",
            self.client_ip,
            username,
        )

        if success and not redirected:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_authenticated_username(self):
        """Retourne le nom d'utilisateur authentifie."""
        return self.username

    def check_channel_shell_request(self, channel):
        """Accepte l'ouverture d'un shell distant."""
        self.event.set()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        """Accepte la demande de pseudo-terminal."""
        return True


# Serveur principal
def start_server():
    """Demarre le serveur SSH honeypot."""
    init_database()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)
    print(f"[*] Listening on {HOST}:{PORT}")

    host_key = paramiko.RSAKey.generate(2048)

    threading.Thread(target=cleanup_bruteforce_attempts, daemon=True).start()
    threading.Thread(target=send_weekly_report, daemon=True).start()
    threading.Thread(target=send_periodic_report, daemon=True).start()
    threading.Thread(target=cleanup_trap_files, args=(FS,), daemon=True).start()

    executor = ThreadPoolExecutor(max_workers=50)

    def signal_handler(sig, frame):
        print("\n[*] Shutting down server...")
        server_socket.close()
        DB_CONN.close()
        FS_CONN.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while True:
        try:
            client_socket, addr = server_socket.accept()
            client_ip = addr[0]
            print(f"[*] New connection from {client_ip}:{addr[1]}")

            # Vérification de la limite de connexions par IP
            with _connection_lock:
                _connection_count[client_ip] = _connection_count.get(client_ip, 0) + 1
                if _connection_count[client_ip] > CONNECTION_LIMIT_PER_IP:
                    print(f"[!] Connection limit exceeded for {client_ip}")
                    client_socket.close()
                    _connection_count[client_ip] -= 1
                    continue

            # Détection de scan de ports
            detect_port_scan(client_ip, PORT)

            # Création d'un identifiant de session unique
            session_id = int(uuid.uuid4().int & (1 << 32) - 1)

            # Création du transport SSH
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(host_key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer)

            server = HoneySSHServer(client_ip, session_id)
            try:
                transport.start_server(server=server)
            except paramiko.SSHException as e:
                print(f"[!] SSH negotiation failed for {client_ip}: {e}")
                client_socket.close()
                with _connection_lock:
                    _connection_count[client_ip] -= 1
                continue

            # Attente de l'ouverture du canal
            chan = transport.accept(20)
            if chan is None:
                print(f"[!] No channel opened for {client_ip}")
                transport.close()
                client_socket.close()
                with _connection_lock:
                    _connection_count[client_ip] -= 1
                continue

            # Vérification de l'authentification
            if server.event.wait(10):
                # Gestion de la session SSH
                executor.submit(
                    handle_ssh_session,
                    chan,
                    client_ip,
                    server.get_authenticated_username(),
                    session_id,
                    transport,
                )
            else:
                print(f"[!] Authentication timeout for {client_ip}")
                chan.close()
                transport.close()
                client_socket.close()

            # Nettoyage de la connexion
            with _connection_lock:
                _connection_count[client_ip] -= 1

        except socket.error as e:
            print(f"[!] Socket error: {e}")
            break
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            with _connection_lock:
                _connection_count[client_ip] -= 1
            continue

    # Nettoyage final
    server_socket.close()
    DB_CONN.close()
    FS_CONN.close()
    executor.shutdown(wait=True)
    print("[*] Server shutdown complete")


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("\n[*] Serveur arrêté proprement")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
    finally:
        DB_CONN.close()
        FS_CONN.close()
