import socket
import threading
import os
import json
import sqlite3
import time
from database import log_ssh_attempt, get_fake_users, init_db

# Configuration
HOST = "127.0.0.1"
PORT = 2224
LOG_DIR = "logs/"
FS_FILE = os.path.join(os.path.dirname(__file__), "../config/fake_filesystem.json")
USER_FILE = os.path.join(os.path.dirname(__file__), "../config/fake_users.json")
DB_PATH = "logs/honeypot.db"
BLOCKED_IPS_FILE = LOG_DIR + "blocked_ips.log"
MAX_FAILED_ATTEMPTS = 5
BLOCK_TIME = 300  # 5 minutes de blocage

failed_attempts = {}
blocked_ips = {}

# Charger les fichiers JSON
def load_json(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Erreur chargement {file_path}: {e}")
        return {}

filesystem = load_json(FS_FILE)

# Vérifier si une IP est bloquée
def is_ip_blocked(ip):
    if ip in blocked_ips and (time.time() - blocked_ips[ip]) < BLOCK_TIME:
        return True
    return False

# Enregistrer une tentative échouée
def record_failed_attempt(ip):
    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    if failed_attempts[ip] >= MAX_FAILED_ATTEMPTS:
        blocked_ips[ip] = time.time()
        with open(BLOCKED_IPS_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ip} - Bloqué pour brute-force\n")
        return True
    return False

# Simuler un login SSH
def fake_login(client_socket, ip):
    client_socket.send(b"SSH-2.0-OpenSSH_7.9p1 Ubuntu-10\n")
    client_socket.send(b"login: ")
    username = client_socket.recv(1024).decode(errors="ignore").strip()

    client_socket.send(b"password: ")
    password = client_socket.recv(1024).decode(errors="ignore").strip()
    
    users = get_fake_users()
    if username in users and users[username] == password:
        return True
    else:
        record_failed_attempt(ip)
        return False

# Simuler un shell interactif avancé
def simulate_shell(client_socket, addr):
    ip = addr[0]
    current_path = ["/home", "admin"]

    if is_ip_blocked(ip):
        client_socket.send("Vous êtes bloqué pour 5 minutes.\n".encode("utf-8"))
        client_socket.close()
        return

    if not fake_login(client_socket, ip):
        client_socket.send("Accès refusé.\n".encode("utf-8"))
        client_socket.close()
        return

    print(f"[+] Connexion SSH de {ip}")
    with open(LOG_DIR + "ssh_interactions.log", "a", encoding="utf-8") as log:
        log.write(f"Connexion SSH de {ip}\n")

    client_socket.send("Bienvenue sur le serveur SSH factice.\n".encode("utf-8"))

    while True:
        try:
            client_socket.send(f"{'/'.join(current_path)} $ ".encode("utf-8"))
            command = client_socket.recv(1024).decode(errors="ignore").strip()
            
            if not command:
                break

            log_ssh_attempt(ip, command)  # Enregistrer en base de données

            if command == "ls":
                folder = filesystem
                for part in current_path:
                    folder = folder.get(part, {})
                response = "\n".join(folder.keys()) if folder else "(vide)"
                client_socket.send(f"{response}\n".encode("utf-8"))

            elif command.startswith("cd"):
                _, *path = command.split()
                if path and path[0] in filesystem:
                    current_path.append(path[0])
                else:
                    client_socket.send("Répertoire introuvable.\n".encode("utf-8"))

            elif command.startswith("cat"):
                _, filename = command.split()
                response = filesystem.get(filename, "Fichier introuvable.")
                client_socket.send(f"{response}\n".encode("utf-8"))

            elif command == "exit":
                client_socket.send(b"Bye!\n")
                break

            else:
                client_socket.send(b"Commande inconnue.\n")

        except ConnectionResetError:
            break

    client_socket.close()

# Démarrer le serveur SSH
def start_ssh_server():
    os.makedirs(LOG_DIR, exist_ok=True)
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Serveur SSH en écoute sur {HOST}:{PORT}")

    while True:
        client, addr = server.accept()
        threading.Thread(target=simulate_shell, args=(client, addr)).start()

if __name__ == "__main__":
    start_ssh_server()
