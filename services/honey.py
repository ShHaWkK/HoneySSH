import socket
import threading
import paramiko
import sqlite3
import time
from datetime import datetime

# =======================
# Configuration Variables
# =======================
HOST = ""        # Adresse d'écoute (vide = toutes interfaces)
PORT = 2222      # Port d'écoute du honeypot (22 nécessite root, on utilise 2222 par défaut)
# Bannière SSH pour simuler un vrai serveur (ex: OpenSSH sur Ubuntu)
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
# Activation optionnelle de la redirection vers un vrai serveur SSH
ENABLE_REDIRECTION = False
REAL_SSH_HOST = "192.168.1.100"
REAL_SSH_PORT = 22

# Fichier de base de données SQLite
DB_NAME = "honeypot_data.db"

# Seuil pour détection brute-force (tentatives par IP)
BRUTE_FORCE_THRESHOLD = 5

# Ensemble et verrou pour éviter duplications d'alertes brute-force
_brute_force_alerted = set()
_brute_force_lock = threading.Lock()

# ==========================
# Initialize SQLite Database
# ==========================
def init_database():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    # Table pour les tentatives de connexion
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
    # Table pour les commandes exécutées
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
    # Table pour les événements de sécurité détectés
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

# ============================
# Fake File System (Trap Files)
# ============================
# Structure de fichiers factices avec fichiers leurres
BASE_FILE_SYSTEM = {
    "/": {"type": "dir", "contents": ["root", "home", "etc", "tmp"]},
    "/root": {"type": "dir", "contents": ["credentials.txt", "config_backup.zip", "ssh_keys.tar.gz"]},
    "/root/credentials.txt": {"type": "file", "content": "username=admin\npassword=admin123\napi_key=ABCD-1234-EFGH-5678"},
    "/root/config_backup.zip": {"type": "file", "content": "PK\x03\x04...<binary zip content>..."},  # contenu binaire fictif
    "/root/ssh_keys.tar.gz": {"type": "file", "content": "...\x1F\x8B\x08...<binary tar.gz content>..."},
    "/home": {"type": "dir", "contents": []},  # les répertoires utilisateurs seront ajoutés dynamiquement
    "/etc": {"type": "dir", "contents": ["passwd", "shadow"]},
    "/etc/passwd": {"type": "file", "content": "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash"},
    "/etc/shadow": {"type": "file", "content": "root:*:18967:0:99999:7:::\nuser:*:18967:0:99999:7:::"},
    "/tmp": {"type": "dir", "contents": []}
}

# ======================
# SSH Server Interface
# ======================
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
        # N'accepter que les canaux de type "session"
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        # Indique qu'on accepte l'authentification par clé publique et par mot de passe
        return "publickey,password"

    def check_auth_publickey(self, username, key):
        # Accepter toutes les clés publiques (mais on demandera quand même un mot de passe)
        # On log l'empreinte de la clé pour information (non stockée en DB pour simplifier)
        try:
            fingerprint = key.get_fingerprint().hex()
        except Exception:
            fingerprint = "unknown"
        print(f"[!] Tentative d'auth SSH par clé publique de {self.client_ip} (user={username}, empreinte={fingerprint})")
        return paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def check_auth_password(self, username, password):
        # Enregistrement de la tentative de login en base SQLite
        self.username = username
        self.password = password
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        success = 1  # on considère la tentative réussie (honeypot accepte tous les mots de passe)
        redirected_flag = 0
        # Si la redirection est activée, on teste les identifiants sur le vrai serveur
        if ENABLE_REDIRECTION:
            try:
                real_client = paramiko.SSHClient()
                real_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                real_client.connect(REAL_SSH_HOST, REAL_SSH_PORT, username=username, password=password, timeout=5)
                # Si la connexion réelle réussit, on prépare la redirection
                self.redirect = True
                self.real_client = real_client
                redirected_flag = 1
                print(f"[+] Identifiants valides capturés pour le vrai serveur : {username}@{REAL_SSH_HOST}")
            except Exception:
                # Si échec auth sur le vrai serveur, on reste en mode honeypot
                self.redirect = False
                redirected_flag = 0
                try:
                    real_client.close()
                except Exception:
                    pass
        # Insérer la tentative de login en base de données
        try:
            conn = sqlite3.connect(DB_NAME)
            conn.execute("PRAGMA busy_timeout = 3000")
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO login_attempts(timestamp, ip, username, password, success, redirected)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (timestamp, self.client_ip, username, password, success, redirected_flag))
            conn.commit()
            # Récupérer l'ID de session (login) pour relier aux commandes
            self.session_id = cur.lastrowid
            # Détection brute-force : nombre de tentatives depuis cette IP
            cur.execute("SELECT COUNT(*) FROM login_attempts WHERE ip = ?", (self.client_ip,))
            count = cur.fetchone()[0]
            if count >= BRUTE_FORCE_THRESHOLD:
                with _brute_force_lock:
                    if self.client_ip not in _brute_force_alerted:
                        cur.execute("""
                            INSERT INTO events(timestamp, ip, username, event_type, details)
                            VALUES (?, ?, ?, ?, ?)
                        """, (timestamp, self.client_ip, username, "Brute-force",
                              f"Tentatives multiples de login depuis {self.client_ip}"))
                        conn.commit()
                        _brute_force_alerted.add(self.client_ip)
            conn.close()
        except Exception as e:
            print(f"[!] Erreur lors de l'enregistrement DB: {e}")
        # Toujours retourner AUTH_SUCCESSFUL pour accepter le mot de passe (piège)
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        # Le client demande un shell interactif
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        # Le client exécute une commande unique non-interactive
        try:
            self.exec_command = command.decode('utf-8')
        except Exception:
            self.exec_command = str(command)
        self.event.set()
        return True

# =====================================
# Fonction pour simuler l'exécution d'une commande
# =====================================
def process_command(cmd, current_dir, username, fs):
    """
    Simule l'exécution d'une commande shell dans le contexte du honeypot.
    Retourne (output, new_dir) correspondant à la sortie simulée et le nouveau répertoire courant.
    """
    output = ""
    new_dir = current_dir
    cmd = cmd.strip()
    if cmd == "":
        return "", new_dir
    parts = cmd.split(maxsplit=1)
    cmd_name = parts[0]
    arg_str = parts[1] if len(parts) > 1 else ""
    # Helper pour résoudre le chemin (relatif -> absolu)
    def resolve_path(path):
        if not path.startswith("/"):
            full = (current_dir.rstrip("/") + "/" + path) if current_dir != "/" else "/" + path
        else:
            full = path
        if len(full) > 1 and full.endswith("/"):
            full = full.rstrip("/")
        return full
    # Traitement des commandes simulées
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
            elif not (target_path in fs and fs[target_path]["type"] == "dir"):
                output = f"ls: cannot access '{arg_str}': No such file or directory"
        if output == "":
            contents = []
            if target_path in fs and fs[target_path]["type"] == "dir":
                contents = fs[target_path]["contents"]
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
        if arg_str:
            output = "Linux honeypot 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux"
        else:
            output = "Linux"
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
                        output = ""  # succès = pas de sortie
                elif node["type"] == "dir":
                    output = f"rm: cannot remove '{arg_str}': Is a directory"
            else:
                output = f"rm: cannot remove '{arg_str}': No such file or directory"
    elif cmd_name in ["wget", "curl", "ftp", "tftp"]:
        output = f"bash: {cmd_name}: command not found"
    elif cmd_name in ["chmod", "bash", "sh", "netcat", "nc", "python"]:
        # Ces commandes potentiellement malveillantes ne produisent pas de sortie visible (simulé)
        output = ""
    else:
        output = f"bash: {cmd_name}: command not found"
    return output, new_dir

# =========================================
# Gestion d'une connexion SSH entrante (thread)
# =========================================
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
        # Configurer la bannière et la clé hôte du serveur
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
        # Accepter le canal (session) du client
        chan = transport.accept(20)
        if chan is None:
            print(f"[!] Aucun canal n'a été ouvert par {client_ip}")
            transport.close()
            return
        chan.settimeout(None)
        # Attendre que le client demande un shell ou exécute une commande
        server.event.wait(10)
        if not server.event.is_set():
            print(f"[!] {client_ip} n'a pas demandé de shell/exec")
            chan.close()
            transport.close()
            return
        # Si redirection activée et que la session doit être redirigée (shell interactif)
        if server.redirect and server.exec_command is None:
            try:
                # Ouvrir un shell sur le vrai serveur SSH
                remote_channel = server.real_client.invoke_shell(width=80, height=24)
            except Exception as e:
                print(f"[!] Échec de l'ouverture d'un shell sur le serveur réel pour {client_ip}: {e}")
                # Si échec, on annule la redirection et on continue en mode honeypot
                server.real_client.close()
                server.redirect = False
            if server.redirect:
                # Fonction de transfert de données d'un canal à l'autre
                def forward(src_chan, dst_chan):
                    try:
                        while True:
                            data = src_chan.recv(1024)
                            if not data:
                                break
                            dst_chan.send(data)
                    except Exception:
                        pass
                # Démarrer deux threads de forward (client->réel et réel->client)
                t1 = threading.Thread(target=forward, args=(chan, remote_channel))
                t2 = threading.Thread(target=forward, args=(remote_channel, chan))
                t1.daemon = True
                t2.daemon = True
                t1.start()
                t2.start()
                # Attendre la fin de la session (fermeture des canaux)
                t1.join()
                t2.join()
                # Nettoyage
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
        # Si redirection activée pour une commande exec unique
        if server.redirect and server.exec_command is not None:
            try:
                stdin_out, stdout_out, stderr_out = server.real_client.exec_command(server.exec_command, timeout=10)
            except Exception as e:
                # En cas d'erreur lors de l'exécution distante
                out_data = f"Remote execution error: {e}".encode()
                exit_status = 1
            else:
                # Lire les sorties du vrai serveur
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
            # Envoyer la sortie combinée et le code de retour au client attaquant
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
        # Si pas de redirection -> on reste en mode honeypot interactif
        # Préparer le système de fichiers factice pour cette session
        fs = {path: (value.copy() if isinstance(value, dict) else value)
              for path, value in BASE_FILE_SYSTEM.items()}
        # Si l'utilisateur n'est pas root, créer son répertoire /home/<user> avec fichiers pièges
        if server.username and server.username != "root":
            user_home = f"/home/{server.username}"
            fs[user_home] = {"type": "dir", "contents": ["credentials.txt", "config_backup.zip", "ssh_keys.tar.gz"]}
            fs["/home"]["contents"].append(server.username)
            # Copier le contenu des fichiers leurres depuis /root vers le home utilisateur
            fs[f"{user_home}/credentials.txt"] = {"type": "file", "content": fs["/root/credentials.txt"]["content"]}
            fs[f"{user_home}/config_backup.zip"] = {"type": "file", "content": fs["/root/config_backup.zip"]["content"]}
            fs[f"{user_home}/ssh_keys.tar.gz"] = {"type": "file", "content": fs["/root/ssh_keys.tar.gz"]["content"]}
        # Envoyer une bannière de bienvenue simulant un système Ubuntu
        chan.send(b"Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-42-generic x86_64)\r\n\r\n")
        # Déterminer l'invite (root = #, user = $)
        prompt = "# " if server.username == "root" else "$ "
        try:
            current_dir = "/root" if server.username == "root" else f"/home/{server.username}"
            session_user = server.username if server.username else ""
            while True:
                chan.send(prompt.encode())
                command = ""
                # Lecture caractère par caractère pour gérer le backspace et les flèches
                while True:
                    data = chan.recv(1024)
                    if not data:
                        # Déconnexion du client
                        raise Exception("Client disconnected")
                    # Ignorer les codes des touches fléchées (historiques)
                    if data in [b'\x1b[A', b'\x1b[B', b'\x1b[C', b'\x1b[D']:
                        continue
                    # Gérer le backspace (0x7f ou 0x08)
                    if data == b'\x7f' or data == b'\x08':
                        if len(command) > 0:
                            command = command[:-1]
                            # Effacer le caractère du terminal client (retour arrière + espace + retour arrière)
                            chan.send(b'\x08 \x08')
                        continue
                    # Fin de ligne (Enter envoie '\r' ou '\r\n')
                    if data.endswith(b"\r") or data.endswith(b"\r\n"):
                        command += data.decode('utf-8', errors='ignore').replace("\r", "").replace("\n", "")
                        break
                    else:
                        # Caractère normal: renvoyer tel quel (écho) et ajouter au buffer
                        chan.send(data)
                        command += data.decode('utf-8', errors='ignore')
                # Envoyer un retour à la ligne (exécution de la commande)
                chan.send(b"\r\n")
                command = command.strip()
                if command == "":
                    # commande vide (juste "Enter"), on redonne l'invite sans rien faire
                    continue
                # Enregistrer la commande en base de données
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
                # Détection des commandes suspectes (exfiltration/payload)
                lower_cmd = command.lower()
                if any(tool in lower_cmd for tool in ["wget", "curl", "ftp", "scp", "tftp"]):
                    try:
                        conn = sqlite3.connect(DB_NAME)
                        cur = conn.cursor()
                        cur.execute("""
                            INSERT INTO events(timestamp, ip, username, event_type, details)
                            VALUES (?, ?, ?, ?, ?)
                        """, (ts, client_ip, session_user, "Exfiltration",
                              f"Command used: {command}"))
                        conn.commit()
                        conn.close()
                    except Exception as e:
                        print(f"[!] Erreur enregistrement event exfiltration: {e}")
                if ("chmod +x" in lower_cmd or "bash -c" in lower_cmd or "sh -c" in lower_cmd or
                        "python -c" in lower_cmd or "netcat" in lower_cmd or lower_cmd.startswith("nc ")):
                    try:
                        conn = sqlite3.connect(DB_NAME)
                        cur = conn.cursor()
                        cur.execute("""
                            INSERT INTO events(timestamp, ip, username, event_type, details)
                            VALUES (?, ?, ?, ?, ?)
                        """, (ts, client_ip, session_user, "Payload",
                              f"Command used: {command}"))
                        conn.commit()
                        conn.close()
                    except Exception as e:
                        print(f"[!] Erreur enregistrement event payload: {e}")
                # Si la commande est "exit" ou "logout", on ferme la session
                if command in ["exit", "logout"]:
                    print(f"[-] {client_ip} a fermé la session via '{command}'")
                    break
                # Simuler l'exécution de la commande
                time.sleep(0.1)  # délai simulé
                try:
                    output, new_dir = process_command(command, current_dir, session_user, fs)
                except Exception as e:
                    output = f"Error executing command: {e}"
                    new_dir = current_dir
                current_dir = new_dir  # mettre à jour le répertoire courant
                # Envoyer la sortie simulée au client
                if output:
                    if not output.endswith("\r\n"):
                        output += "\r\n"
                    chan.send(output.encode())
            # Sortie de la boucle shell (exit)
            chan.send(b"logout\r\n")
        except Exception as e:
            print(f"[!] Connexion {client_ip} terminée: {e}")
        finally:
            try:
                chan.close()
            except Exception:
                pass
            transport.close()
            return
    except Exception as ex:
        print(f"[!] Exception dans handle_connection pour {client_ip}: {ex}")
        try:
            transport.close()
        except:
            pass

# ===========================
# Boucle principale du serveur
# ===========================
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
