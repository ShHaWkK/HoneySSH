from __future__ import annotations
import sqlite3
import threading
import os
from datetime import datetime
from . import config
from .dynamic import get_dynamic_messages
from .constants import PREDEFINED_USERS
from .logutils import trigger_alert

FS_CONN = sqlite3.connect(config.FS_DB, uri=True, check_same_thread=False)
FS_LOCK = threading.Lock()


def init_filesystem_db() -> None:
    """Create the SQLite table representing the fake filesystem."""
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
    except sqlite3.Error as e:
        print(f"[!] Filesystem DB init error: {e}")
        raise


def load_filesystem() -> dict:
    """Load the filesystem state from the database."""
    fs: dict[str, dict] = {}
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
                    "mtime": row["mtime"] or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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
                if path != "/" and row["type"] == "dir" and path not in fs[parent_dir]["contents"]:
                    fs[parent_dir]["contents"].append(path.split("/")[-1])
    except sqlite3.Error as e:
        print(f"[!] Filesystem load error: {e}")
    return fs


def save_filesystem(fs: dict) -> None:
    """Persist the filesystem state back to the database."""
    try:
        with FS_LOCK:
            FS_CONN.execute("DELETE FROM filesystem")
            for path, data in fs.items():
                FS_CONN.execute(
                    "INSERT INTO filesystem (path, type, content, owner, permissions, mtime) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        path,
                        data["type"],
                        data.get("content", "") if not callable(data.get("content")) else "",
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
        "content": "root:x:0:0:root:/root:/bin/bash\n",
        "owner": "root",
        "permissions": "rw-r--r--",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/etc/shadow": {
        "type": "file",
        "content": "root:*:17722:0:99999:7:::\n",
        "owner": "root",
        "permissions": "rw-------",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/etc/group": {
        "type": "file",
        "content": "root:x:0:\n",
        "owner": "root",
        "permissions": "rw-r--r--",
        "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    "/dev": {"type": "dir", "contents": [], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/proc": {"type": "dir", "contents": [], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/sys": {"type": "dir", "contents": [], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/lib": {"type": "dir", "contents": [], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/usr": {"type": "dir", "contents": ["bin", "local"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/usr/bin": {"type": "dir", "contents": ["python3", "man"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/usr/bin/python3": {"type": "file", "content": "#!/usr/bin/python3\n", "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/usr/bin/man": {"type": "file", "content": "#!/bin/sh\necho 'Use the built-in man command'\n", "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/usr/local": {"type": "dir", "contents": ["bin"], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/usr/local/bin": {"type": "dir", "contents": [], "owner": "root", "permissions": "rwxr-xr-x", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/root": {"type": "dir", "contents": [".bashrc"], "owner": "root", "permissions": "rwx------", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
    "/root/.bashrc": {"type": "file", "content": "# .bashrc\n", "owner": "root", "permissions": "rw-r--r--", "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
}


def populate_predefined_users(fs: dict) -> dict:
    """Insert predefined users and their files into the filesystem."""
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


def add_vulnerabilities(fs: dict) -> None:
    """Add some tempting vulnerable files."""
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


def modify_file(fs: dict, path: str, content: str, username: str, session_id: int, client_ip: str) -> bool:
    """Modify a permitted file and log the operation."""
    allowed_paths = [
        f"{PREDEFINED_USERS[username]['home']}/{f}"
        for f in PREDEFINED_USERS.get(username, {}).get("files", {}).keys()
    ]
    if path.startswith("/tmp/") or path in allowed_paths:
        is_new = path not in fs
        fs[path] = {
            "type": "file",
            "content": content,
            "owner": username,
            "permissions": "rw-r--r--",
            "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        ext = os.path.splitext(path)[1]
        watched_exts = {".py", ".sh", ".c", ".cpp", ".rs", ".js", ".rb", ".go", ".pl"}
        if is_new and ext in watched_exts:
            trigger_alert(session_id, "Script Creation", f"Created code file: {path}", client_ip, username)
        else:
            trigger_alert(session_id, "File Modified", f"Modified file: {path}", client_ip, username)
        save_filesystem(fs)
        return True
    return False


def cleanup_trap_files(fs: dict) -> None:
    """Periodically remove expired trap files."""
    while True:
        current_time = time.time()
        for path in list(fs.keys()):
            if ".trap_" in path and fs[path].get("expires", current_time) < current_time:
                parent_dir = "/".join(path.split("/")[:-1]) or "/"
                if parent_dir in fs and path.split("/")[-1] in fs[parent_dir]["contents"]:
                    fs[parent_dir]["contents"].remove(path.split("/")[-1])
                del fs[path]
                save_filesystem(fs)
        time.sleep(3600)


init_filesystem_db()
FS = load_filesystem()
if not FS:
    FS = populate_predefined_users(BASE_FILE_SYSTEM.copy())
    add_vulnerabilities(FS)
    save_filesystem(FS)

__all__ = [
    "FS",
    "FS_CONN",
    "FS_LOCK",
    "save_filesystem",
    "modify_file",
    "cleanup_trap_files",
]
