from . import config
import hashlib
import os
ADMIN_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()
ADMIN_MAX_ATTEMPTS = 3
ADMIN_BAN_DURATION = 300  # seconds
_admin_attempts = {}  # {ip: count}
_admin_bans = {}  # {ip: ban_until}

# Login attempts for other users
_user_attempts = {}  # {(ip, username): count}
USER_SUCCESS_ATTEMPTS = 10

SESSION_LOG_DIR = config.SESSION_LOG_DIR
LOG_DIR = config.LOG_DIR
LOG_FILE = config.LOG_FILE
ALERT_LOG_FILE = config.ALERT_LOG_FILE

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
    "useradd",
    "adduser",
    "groupadd",
    "passwd",
]


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

