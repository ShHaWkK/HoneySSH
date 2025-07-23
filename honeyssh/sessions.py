from __future__ import annotations
import os
import re
from datetime import datetime
from .filesystem import FS, save_filesystem
from .constants import PREDEFINED_USERS, FAKE_MYSQL_DATA
from .logutils import trigger_alert
from .console import read_line_advanced


def ftp_session(chan, host, username, session_id, client_ip, session_log):
    history = []
    jobs = []
    cmd_count = 0
    current_dir = PREDEFINED_USERS.get(username, {}).get("home", "/")
    chan.send(f"Connected to {host}.\r\n220 (vsFTPd 3.0.3)\r\nName ({host}:{username}): ".encode())
    read_line_advanced(chan, "", history, current_dir, username, FS, session_log, session_id, client_ip, jobs, cmd_count)
    chan.send(b"331 Please specify the password.\r\nPassword: ")
    read_line_advanced(chan, "", history, current_dir, username, FS, session_log, session_id, client_ip, jobs, cmd_count)
    chan.send(b"230 Login successful.\r\nRemote system type is UNIX.\r\nUsing binary mode to transfer files.\r\n")
    while True:
        ftp_cmd, _, _ = read_line_advanced(chan, "ftp> ", history, current_dir, username, FS, session_log, session_id, client_ip, jobs, cmd_count)
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
                    item_path = f"{current_dir}/{item}" if current_dir != "/" else f"/{item}"
                    if long_listing and item_path in FS:
                        entry = FS[item_path]
                        perms = entry.get("permissions", "rwxr-xr-x")
                        owner = entry.get("owner", "root")
                        size = len(entry.get("content", "")) if entry.get("type") == "file" else 4096
                        mtime = entry.get("mtime", "")
                        chan.send(f"{perms} 1 {owner} {owner} {size} {mtime} {item}\r\n".encode())
                    else:
                        chan.send(f"{item}\r\n".encode())
            chan.send(b"226 Directory send OK.\r\n")
        elif command == "get" and args:
            target = os.path.normpath(args[0] if args[0].startswith("/") else f"{current_dir}/{args[0]}")
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
            dest = os.path.normpath(args[0] if args[0].startswith("/") else f"{current_dir}/{args[0]}")
            FS[dest] = {
                "type": "file",
                "content": "",
                "owner": username,
                "permissions": "rw-r--r--",
                "mtime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            ext = os.path.splitext(dest)[1]
            watched_exts = {".py", ".sh", ".c", ".cpp", ".rs", ".js", ".rb", ".go", ".pl"}
            if ext in watched_exts:
                trigger_alert(session_id, "Script Creation", f"Created code file: {dest}", client_ip, username)
            parent = os.path.dirname(dest) or "/"
            name = os.path.basename(dest)
            if parent in FS and name not in FS[parent]["contents"]:
                FS[parent]["contents"].append(name)
            chan.send(b"150 Ok to send data.\r\n226 Transfer complete.\r\n")
        elif command == "mkdir" and args:
            new_dir = os.path.normpath(args[0] if args[0].startswith("/") else f"{current_dir}/{args[0]}")
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
            target = os.path.normpath(args[0] if args[0].startswith("/") else f"{current_dir}/{args[0]}")
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
            src = os.path.normpath(args[0] if args[0].startswith("/") else f"{current_dir}/{args[0]}")
            dest = os.path.normpath(args[1] if args[1].startswith("/") else f"{current_dir}/{args[1]}")
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
            chan.send(b"Commands: ls, cd, pwd, get, put, mkdir, delete, rename, quit\r\n")
        else:
            chan.send(b"502 Command not implemented.\r\n")
        session_log.append(f"FTP command: {ftp_cmd}")
    session_log.append(f"FTP session to {host} closed")


def mysql_session(chan, username, session_id, client_ip, session_log):
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
        line, _, _ = read_line_advanced(chan, prompt.decode(), history, "__mysql__", username, FS, session_log, session_id, client_ip, jobs, cmd_count)
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
            chan.send(b"+--------------------+\r\n| Database           |\r\n+--------------------+\r\n")
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
                        chan.send(("| " + " | ".join(str(x) for x in r) + " |\r\n").encode())
                    chan.send((border + f"\r\n{len(rows)} rows in set (0.00 sec)\r\n").encode())
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
    history = []
    jobs = []
    cmd_count = 0
    chan.send(b"Python 3.10.0 (default, fake)\r\nType 'exit()' to quit\r\n")
    while True:
        line, _, _ = read_line_advanced(chan, ">>> ", history, "", username, FS, session_log, session_id, client_ip, jobs, cmd_count)
        if line is None:
            break
        if line.strip() in ["exit()", "quit()", "exit", "quit"]:
            chan.send(b"\r\n")
            break
        if not line:
            chan.send(b"\r\n")
            continue
        if any(ord(ch) < 32 for ch in line):
            display = "".join(f"^{chr(ord(ch)+64)}" if ord(ch) < 32 else ch for ch in line)
            chan.send(f"{display}\r\n".encode())
        else:
            chan.send(f"{line}\r\n".encode())
    session_log.append("Python REPL closed")


def node_repl(chan, username, session_id, client_ip, session_log):
    history = []
    jobs = []
    cmd_count = 0
    chan.send(b"Welcome to Node.js v18 (fake). Type 'exit' to quit.\r\n> ")
    while True:
        line, _, _ = read_line_advanced(chan, "> ", history, "", username, FS, session_log, session_id, client_ip, jobs, cmd_count)
        if line is None or line.strip() in ["exit", "quit"]:
            chan.send(b"\r\n")
            break
        if not line:
            chan.send(b"\r\n")
            continue
        chan.send(f"{line}\r\n".encode())
    session_log.append("Node REPL closed")


def netcat_session(chan, listening, host, port, username, session_id, client_ip, session_log):
    history = []
    jobs = []
    cmd_count = 0
    if listening:
        chan.send(f"Listening on port {port} (simulated)\r\n".encode())
    else:
        chan.send(f"Connected to {host}:{port} (simulated)\r\n".encode())
    while True:
        line, _, _ = read_line_advanced(chan, "", history, "", username, FS, session_log, session_id, client_ip, jobs, cmd_count)
        if line is None or line.strip().lower() in ["exit", "quit"]:
            break
        if not line:
            continue
        chan.send(f"{line}\r\n".encode())
    chan.send(b"\r\n")
    session_log.append("Netcat session closed")


__all__ = [
    "ftp_session",
    "mysql_session",
    "python_repl",
    "node_repl",
    "netcat_session",
]
