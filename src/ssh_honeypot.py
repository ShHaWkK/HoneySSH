import socket
import threading
import os
import json
import time
import sys
import logging


# Configuration du serveur SSH
HOST = "0.0.0.0"
PORT = 2222
LOG_DIR = "logs/"
FS_FILE = "config/fake_filesystem.json"
BLOCKED_IPS_FILE = LOG_DIR + "blocked_ips.log"
FAILED_ATTEMPTS_FILE = LOG_DIR + "failed_attempts.log"
MAX_FAILED_ATTEMPTS = 5
BLOCK_TIME = 300  # Temps de blocage en secondes

# Stockage des IP bloquées et tentatives échouées
failed_attempts = {}
blocked_ips = {}

# Charger le faux système de fichiers
def load_filesystem():
    with open(FS_FILE, "r") as f:
        return json.load(f)

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

# Fonction pour simuler un shell interactif
def simulate_shell(client_socket, addr):
    ip = addr[0]
    current_path = ["home", "user"]
    filesystem = load_filesystem()

    if is_ip_blocked(ip):
        client_socket.send("Connexion refusée. Votre IP est bloquée.\n".encode("utf-8"))
        client_socket.close()
        return

    print(f"[+] Connexion SSH de {addr}")
    with open(LOG_DIR + "ssh_interactions.log", "a") as log:
        log.write(f"Connexion SSH de {addr}\n")

    client_socket.send(b"Bienvenue sur le serveur SSH fictif.\n")

    while True:
        try:
            client_socket.send(f"{'/'.join(current_path)} $ ".encode("utf-8"))
            command = client_socket.recv(1024).decode("utf-8").strip()

            if not command:
                break

            with open(LOG_DIR + "ssh_interactions.log", "a") as log:
                log.write(f"{addr} -> {command}\n")

            if command == "ls":
                folder = filesystem
                for part in current_path:
                    folder = folder.get(part, {})
                response = "\n".join(folder.keys()) if folder else "(vide)"
                client_socket.send(f"{response}\n".encode("utf-8"))

            elif command.startswith("cd"):
                _, *path = command.split()
                if not path:
                    current_path = ["home", "user"]
                elif path[0] in filesystem.get(current_path[-1], {}):
                    current_path.append(path[0])
                else:
                    client_socket.send("Répertoire introuvable.\n".encode("utf-8"))

            elif command.startswith("cat"):
                _, filename = command.split()
                folder = filesystem
                for part in current_path:
                    folder = folder.get(part, {})
                response = folder.get(filename, "Fichier introuvable.")
                client_socket.send(f"{response}\n".encode("utf-8"))

            elif command == "exit":
                client_socket.send("Au revoir !\n".encode("utf-8"))
                break

            else:
                client_socket.send("Commande introuvable.\n".encode("utf-8"))

        except ConnectionResetError:
            break

    client_socket.close()

# Démarrer le serveur SSH
def start_ssh_server():
    os.makedirs(LOG_DIR, exist_ok=True)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Serveur SSH en écoute sur {HOST}:{PORT}")

    while True:
        client, addr = server.accept()
        if is_ip_blocked(addr[0]):
            client.send("Connexion refusée. Votre IP est bloquée.\n".encode("utf-8"))
            client.close()
        else:
            threading.Thread(target=simulate_shell, args=(client, addr)).start()

if __name__ == "__main__":
    start_ssh_server()
