#!/usr/bin/env python3
import socket
import threading
import paramiko
import sqlite3
import time
from datetime import datetime
import os
import smtplib
from email.mime.text import MIMEText

# =======================
# Configuration Variables
# =======================
HOST = ""  # écoute sur toutes interfaces
PORT = 2222
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
ENABLE_REDIRECTION = False
REAL_SSH_HOST = "192.168.1.100"
REAL_SSH_PORT = 22

DB_NAME = "honeypot_data.db"
BRUTE_FORCE_THRESHOLD = 5

# Pour éviter de générer plusieurs alertes brute-force par IP
_brute_force_alerted = set()
_brute_force_lock = threading.Lock()

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

FAKE_DF_OUTPUT = """Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   7.5G   40G  16% /
tmpfs           100M     0  100M   0% /run/user/1000"""

# ================================
# Fake File System (leurres)
# ================================
BASE_FILE_SYSTEM = {
    "/": {"type": "dir", "contents": ["root", "home", "etc", "tmp"]},
    "/root": {"type": "dir", "contents": ["credentials.txt", "config_backup.zip", "ssh_keys.tar.gz"]},
    "/root/credentials.txt": {"type": "file", "content": "username=admin\npassword=admin123\napi_key=ABCD-1234-EFGH-5678"},
    "/root/config_backup.zip": {"type": "file", "content": "PK\x03\x04...<binary zip content>..."},
    "/root/ssh_keys.tar.gz": {"type": "file", "content": "...\x1F\x8B\x08...<binary tar.gz content>..."},
    "/home": {"type": "dir", "contents": []},
    "/etc": {"type": "dir", "contents": ["passwd", "shadow", "apt", "service"]},
    "/etc/passwd": {"type": "file", "content": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash"},
    "/etc/shadow": {"type": "file", "content": "root:*:18967:0:99999:7:::\nuser:*:18967:0:99999:7:::"},
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
                 "ps", "netstat", "uptime", "df", "exit", "logout", "find", "grep", "head", "tail", "history"]
    if " " not in current_input:
        return [cmd for cmd in base_cmds if cmd.startswith(current_input)]
    else:
        parts = current_input.split(" ", 1)
        partial = parts[1]
        return [path for path in fs.keys() if path.startswith(partial)]

def autocomplete(current_input, current_dir, username, fs):
    completions = get_completions(current_input, current_dir, username, fs)
    if len(completions) == 1:
        if " " not in current_input:
            return completions[0]
        else:
            return current_input.split(" ", 1)[0] + " " + completions[0]
    return current_input

# ==============================================
# Simulation des commandes système avancées
# ==============================================
def process_command(cmd, current_dir, username, fs, client_ip):
    output = ""
    new_dir = current_dir
    cmd = cmd.strip()
    if cmd == "":
        return "", new_dir
    parts = cmd.split(maxsplit=1)
    cmd_name = parts[0]
    arg_str = parts[1] if len(parts) > 1 else ""
    
    def resolve_path(path):
        if not path.startswith("/"):
            full = (current_dir.rstrip("/") + "/" + path) if current_dir != "/" else "/" + path
        else:
            full = path
        if len(full) > 1 and full.endswith("/"):
            full = full.rstrip("/")
        return full

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
        if output == "":
            contents = fs[target_path]["contents"] if target_path in fs and fs[target_path]["type"] == "dir" else []
            output = "\r\n".join(contents)
    elif cmd_name == "pwd":
        output = current_dir
    elif cmd_name == "whoami":
        output = username
    elif cmd_name == "id":
        if username == "root":
            output = "uid=0(root) gid=0(root) groups=0(root)"
        else:
            output = f"uid=1000({username}) gid=1000({username}) groups=1000({username}),27(sudo)"
    elif cmd_name == "uname":
        output = "Linux debian 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (Debian)" if arg_str else "Linux"
    elif cmd_name == "echo":
        output = arg_str
    elif cmd_name == "cat":
        if arg_str == "":
            output = ""
        else:
            file_path = resolve_path(arg_str)
            if file_path == "/etc/shadow" and username != "root":
                output = f"cat: {arg_str}: Permission denied"
            elif file_path in fs:
                node = fs[file_path]
                if node["type"] == "file":
                    output = node["content"]
                else:
                    output = f"cat: {arg_str}: Is a directory"
            else:
                output = f"cat: {arg_str}: No such file or directory"
    elif cmd_name == "rm":
        if arg_str == "":
            output = "rm: missing operand"
        else:
            target_path = resolve_path(arg_str)
            if target_path in fs:
                node = fs[target_path]
                if node["type"] == "file":
                    parent_dir = target_path.rsplit("/", 1)[0]
                    if parent_dir == "":
                        parent_dir = "/"
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
                elif node["type"] == "dir":
                    output = f"rm: cannot remove '{arg_str}': Is a directory"
            else:
                output = f"rm: cannot remove '{arg_str}': No such file or directory"
    elif cmd_name == "ps":
        output = FAKE_PS_OUTPUT
    elif cmd_name == "netstat":
        output = FAKE_NETSTAT_OUTPUT
    elif cmd_name == "uptime":
        now = datetime.now().strftime("%H:%M:%S")
        output = f"{now} up 5 days, 4:21, 2 users, load average: 0.00, 0.01, 0.05"
    elif cmd_name == "df":
        output = FAKE_DF_OUTPUT
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
        if len(args) == 0:
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
        if len(args) == 0:
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
    elif cmd_name in ["wget", "curl"]:
        if "http" in arg_str:
            with open("downloads.log", "a") as f:
                f.write(f"{datetime.now()} - {username} from {client_ip} attempted download: {arg_str.split()[0]}\n")
        output = f"bash: {cmd_name}: command not found"
    elif cmd_name in ["ftp", "tftp"]:
        output = f"bash: {cmd_name}: command not found"
    elif cmd_name in ["chmod", "bash", "sh", "netcat", "nc", "python"]:
        output = ""
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
# Fonction de déclenchement d'alertes
# =====================================
def trigger_alert(session_id, command, client_ip, username):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO events(timestamp, ip, username, event_type, details)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, client_ip, username, "Suspicious", f"Commande exécutée: {command}"))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[!] Erreur lors de l'enregistrement de l'alerte en DB: {e}")
    subject = f"[HONEYPOT] Alerte commande suspecte de {client_ip}"
    body = f"Utilisateur: {username}\nCommande: {command}\nHeure: {timestamp}"
    msg = MIMEText(body)
    msg["From"] = "alerte-honeypot@example.com"
    msg["To"] = "admin@example.com"
    msg["Subject"] = subject
    try:
        with smtplib.SMTP("localhost") as smtp:
            smtp.send_message(msg)
    except Exception as e:
        print(f"[!] Erreur lors de l'envoi du mail d'alerte: {e}")

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
        if server.redirect and server.exec_command is None:
            try:
                remote_channel = server.real_client.invoke_shell(width=80, height=24)
            except Exception as e:
                print(f"[!] Échec d'ouverture d'un shell sur le serveur réel pour {client_ip}: {e}")
                server.real_client.close()
                server.redirect = False
            if server.redirect:
                def forward(src, dst):
                    try:
                        while True:
                            data = src.recv(1024)
                            if not data:
                                break
                            dst.send(data)
                    except Exception:
                        pass
                t1 = threading.Thread(target=forward, args=(chan, remote_channel))
                t2 = threading.Thread(target=forward, args=(remote_channel, chan))
                t1.daemon = True
                t2.daemon = True
                t1.start()
                t2.start()
                t1.join()
                t2.join()
                try:
                    chan.close()
                except Exception:
                    pass
                try:
                    remote_channel.close()
                except Exception:
                    pass
                try:
                    server.real_client.close()
                except Exception:
                    pass
                transport.close()
                print(f"[-] Connexion {client_ip} terminée (session redirigée).")
                return
        if server.redirect and server.exec_command is not None:
            try:
                stdin_out, stdout_out, stderr_out = server.real_client.exec_command(server.exec_command, timeout=10)
            except Exception as e:
                out_data = f"Remote execution error: {e}".encode()
                exit_status = 1
            else:
                stdout_data = stdout_out.read()
                stderr_data = stderr_out.read()
                out_data = b""
                if stdout_data:
                    out_data += stdout_data
                if stderr_data:
                    if out_data:
                        out_data += b"\r\n"
                    out_data += stderr_data
                exit_status = stdout_out.channel.recv_exit_status()
            try:
                if out_data:
                    chan.send(out_data)
                chan.send_exit_status(exit_status)
            except Exception as e:
                print(f"[!] Erreur lors de l'envoi du résultat exec à {client_ip}: {e}")
            chan.close()
            try:
                server.real_client.close()
            except Exception:
                pass
            transport.close()
            print(f"[-] Connexion {client_ip} terminée (commande exec redirigée).")
            return

        fs = {path: (value.copy() if isinstance(value, dict) else value)
              for path, value in BASE_FILE_SYSTEM.items()}
        if server.username and server.username != "root":
            user_home = f"/home/{server.username}"
            fs[user_home] = {"type": "dir", "contents": ["credentials.txt", "config_backup.zip", "ssh_keys.tar.gz"]}
            fs["/home"]["contents"].append(server.username)
            fs[f"{user_home}/credentials.txt"] = {"type": "file", "content": fs["/root/credentials.txt"]["content"]}
            fs[f"{user_home}/config_backup.zip"] = {"type": "file", "content": fs["/root/config_backup.zip"]["content"]}
            fs[f"{user_home}/ssh_keys.tar.gz"] = {"type": "file", "content": fs["/root/ssh_keys.tar.gz"]["content"]}

        chan.send(b"Welcome to Debian GNU/Linux 10 (buster)\r\n\r\n")
        session_user = server.username if server.username else ""
        history = load_history(session_user)
        current_dir = "/root" if session_user == "root" else f"/home/{session_user}"
        
        running = True
        while running:
            full_prompt = f"{session_user}@debian:{current_dir}$ "
            chan.send(full_prompt.encode())
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
                if char in ("\r", "\n"):
                    break
                if char == "\x03":
                    chan.send(b"^C\r\n")
                    current_input = ""
                    break
                if char in ("\x7f", "\x08"):
                    if len(current_input) > 0:
                        current_input = current_input[:-1]
                        chan.send(b'\x08 \x08')
                    last_was_tab = False
                    continue
                if char == "\t":
                    if last_was_tab:
                        completions = get_completions(current_input, current_dir, session_user, fs)
                        if completions:
                            chan.send(b"\r\n" + "\r\n".join(completions).encode() + b"\r\n")
                            chan.send(full_prompt.encode() + current_input.encode())
                        last_was_tab = False
                        continue
                    else:
                        suggestion = autocomplete(current_input, current_dir, session_user, fs)
                        if suggestion and suggestion != current_input:
                            to_add = suggestion[len(current_input):]
                            chan.send(to_add.encode())
                            current_input = suggestion
                        else:
                            chan.send(b"\x07")
                        last_was_tab = True
                        continue
                chan.send(char.encode())
                current_input += char
                last_was_tab = False

            chan.send(b"\r\n")
            command = current_input.strip()
            if command == "":
                continue
            with open("commands.log", "a") as f:
                f.write(f"{datetime.now()} - {client_ip} - {session_user}: {command}\n")
            history.append(command)
            save_history(session_user, history)
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

            suspicious_keywords = ["wget", "curl", "ftp", "scp", "tftp", "chmod +x", "bash -c", "sh -c", "python -c", "netcat", "nc "]
            if any(kw in command.lower() for kw in suspicious_keywords):
                trigger_alert(server.session_id, command, client_ip, session_user)

            if command in ["exit", "logout"]:
                print(f"[-] {client_ip} a fermé la session via '{command}'")
                running = False
                break

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
                chan.send(output.encode())
        chan.send(b"logout\r\n")
    except Exception as ex:
        print(f"[!] Exception dans handle_connection pour {client_ip}: {ex}")
    finally:
        try:
            chan.close()
        except Exception:
            pass
        transport.close()

# =====================================
# Boucle principale du serveur honeypot SSH
# =====================================
if __name__ == "__main__":
    init_database()
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
