#!/usr/bin/env python3
import socket
import threading
import paramiko
import sqlite3
import time
import random
import re
import os
import gzip
import shutil
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
import fnmatch

from . import config
from .filesystem import FS, FS_CONN, save_filesystem
from .helpers import _format_ls_columns, _human_size, _random_permissions, has_wildcards, expand_wildcards
from .constants import *
from .dynamic import *
from .console import read_line_advanced, read_password
from .completion import autocomplete, _visible_len
from .logutils import (
    LOGGER,
    log_activity,
    log_session_activity,
    trigger_alert,
    send_weekly_report,
    send_periodic_report,
)

# Configuration
HOST = config.HOST
PORT = config.PORT
SSH_BANNER = config.SSH_BANNER
ENABLE_REDIRECTION = config.ENABLE_REDIRECTION
REAL_SSH_HOST = config.REAL_SSH_HOST
REAL_SSH_PORT = config.REAL_SSH_PORT

DB_NAME = config.DB_NAME  # Base en mémoire partagée
DB_CONN = sqlite3.connect(DB_NAME, uri=True, check_same_thread=False)
BRUTE_FORCE_THRESHOLD = 5
CMD_LIMIT_PER_SESSION = 50
CONNECTION_LIMIT_PER_IP = 10
_brute_force_attempts = {}  # {ip: [(timestamp, username, password)]}
_brute_force_alerted = set()
_brute_force_lock = threading.Lock()
_connection_count = {}  # {ip: count}
_connection_lock = threading.Lock()

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
    jobs = jobs or []
    if not cmd.strip():
        return "", current_dir, jobs, cmd_count, False
    new_dir = current_dir
    output = ""

    # --- Bloc de blocage d'exécution de code source ---
    watched_exts = {".py", ".sh", ".c", ".cpp", ".rs", ".js", ".rb", ".go", ".pl"}
    parts = cmd.strip().split()
    if parts:
        run_cmd = parts[0]
        if run_cmd.startswith("./"):
            _, ext = os.path.splitext(run_cmd)
            if ext in watched_exts:
                return (
                    f"{run_cmd}: Permission non accordée",
                    current_dir,
                    jobs,
                    cmd_count,
                    False,
                )

        interpreters = {
            "python",
            "sh",
            "bash",
            "gcc",
            "rustc",
            "go",
            "node",
            "ruby",
            "perl",
        }
        if run_cmd in interpreters and len(parts) > 1:
            _, ext = os.path.splitext(parts[1])
            if ext in watched_exts:
                return (
                    f"{run_cmd}: Permission non accordée pour {parts[1]}",
                    current_dir,
                    jobs,
                    cmd_count,
                    False,
                )

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
    if cmd_parts and cmd_parts[0].lower() != "find":
        expanded = [cmd_parts[0]]
        for a in cmd_parts[1:]:
            expanded.extend(expand_wildcards(a, current_dir, fs, username))
        cmd_parts = expanded
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
            parts = arg_str.split()
            start = current_dir
            pattern = None
            idx = 0
            if parts and not parts[0].startswith("-"):
                start = parts[0]
                idx = 1
            while idx < len(parts):
                if parts[idx] == "-name" and idx + 1 < len(parts):
                    pattern = parts[idx + 1].strip("'\"")
                    idx += 2
                else:
                    idx += 1
            if start.startswith("~"):
                start = start.replace("~", f"/home/{username}", 1)
            if not start.startswith("/"):
                start = f"{current_dir}/{start}" if current_dir != "/" else f"/{start}"
            start = os.path.normpath(start)
            if start in fs and fs[start]["type"] == "dir" and "contents" in fs[start]:
                results = []

                def recursive_find(p):
                    for item in fs[p]["contents"]:
                        full_path = f"{p}/{item}" if p != "/" else f"/{item}"
                        if full_path in fs:
                            if pattern is None or fnmatch.fnmatch(item, pattern):
                                results.append(full_path)
                            if fs[full_path]["type"] == "dir" and "contents" in fs[full_path]:
                                recursive_find(full_path)

                recursive_find(start)
                output = "\n".join(results)
                trigger_alert(
                    session_id,
                    "Command Executed",
                    f"Executed find in {start}",
                    client_ip,
                    username,
                )
            else:
                output = f"find: '{start}': No such file or directory"
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
            ext = os.path.splitext(path)[1]
            watched_exts = {".py", ".sh", ".c", ".cpp", ".rs", ".js", ".rb", ".go", ".pl"}
            if ext in watched_exts:
                trigger_alert(
                    session_id,
                    "Script Creation",
                    f"Created code file: {path}",
                    client_ip,
                    username,
                )
            else:
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


def main():
    """Entry point used by the top-level wrapper."""
    try:
        start_server()
    except KeyboardInterrupt:
        print("\n[*] Serveur arrêté proprement")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
    finally:
        DB_CONN.close()
        FS_CONN.close()
