import socket
import threading
import os
import json
import sqlite3
import time
from database import log_ssh_attempt, get_fake_users, init_db

# Configuration
HOST = "0.0.0.0"
PORT = 2222
LOG_DIR = "logs/"
FS_FILE = "config/fake_filesystem.json"
DB_PATH = "logs/honeypot.db"
BLOCKED_IPS_FILE = LOG_DIR + "blocked_ips.log"
MAX_FAILED_ATTEMPTS = 5
BLOCK_TIME = 300  # 5 minutes de blocage

failed_attempts = {}
blocked_ips = {}

# Charger les fichiers JSON
def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

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
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(f"{ip} - Bloqué pour brute-force\n")
        return True
    return False

# Simuler un login SSH
def fake_login(client_socket, ip):
    client_socket.send(b"SSH-2.0-OpenSSH_7.9p1 Ubuntu-10\n")
    
    client_socket.send(b"login: ")
    username = client_socket.recv(1024).decode().strip()
    
    client_socket.send(b"password: ")
    password = client_socket.recv(1024).decode().strip()

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
        client_socket.send(b"Votre IP est bloquée. Connexion refusée.\n")
        client_socket.close()
        return

    if not fake_login(client_socket, ip):
        client_socket.send(b"Accès refusé.\n")
        client_socket.close()
        return

    print(f"[+] Connexion SSH de {ip}")
    with open(LOG_DIR + "ssh_interactions.log", "a") as log:
        log.write(f"Connexion SSH de {ip}\n")

    client_socket.send(b"Bienvenue sur le serveur SSH factice.\n")

    while True:
        try:
            client_socket.send(f"{'/'.join(current_path)} $ ".encode("utf-8"))
            command = client_socket.recv(1024).decode("utf-8").strip()

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
                    client_socket.send(b"Répertoire introuvable.\n")

            elif command.startswith("cat"):
                _, filename = command.split()
                response = filesystem.get(filename, "Fichier introuvable.")
                client_socket.send(f"{response}\n".encode("utf-8"))

            elif command == "exit":
                client_socket.send(b"Déconnexion...\n")
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
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Serveur SSH en écoute sur {HOST}:{PORT}")

    while True:
        client, addr = server.accept()
        threading.Thread(target=simulate_shell, args=(client, addr)).start()

if __name__ == "__main__":
    start_ssh_server()
