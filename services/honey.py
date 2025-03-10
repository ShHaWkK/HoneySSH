import socket
import threading
import select
import time
import sqlite3
import paramiko

# --- Configuration ---

# Adresse IP et port d'écoute du honeypot SSH
LISTEN_HOST = ""         # Vide = toutes les interfaces
LISTEN_PORT = 22         # Port 22 par défaut (nécessite privilèges root si <1024)

# Configuration de redirection vers un vrai serveur SSH (optionnelle)
REAL_SSH_HOST = None     # Mettre une IP/hostname ici pour activer la redirection
REAL_SSH_PORT = 22       # Port du vrai serveur SSH
# Note: Si REAL_SSH_HOST est défini (non None), le honeypot tentera de rediriger la connexion.
# La redirection utilise les mêmes identifiants capturés pour se connecter au vrai serveur.

# Fichier base de données SQLite
DB_FILE = "honeypot_data.db"

# Détection brute force: seuil (tentatives par minute par IP) au-delà duquel on log une alerte
BRUTEFORCE_THRESHOLD = 5        # ex: >5 tentatives en moins de 60 sec -> alerte brute force
BRUTEFORCE_WINDOW_SEC = 60

# --- Initialisation de la base de données SQLite ---

conn = sqlite3.connect(DB_FILE, check_same_thread=False)
cur = conn.cursor()
# Création des tables si elles n'existent pas
cur.execute("""
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    ip TEXT,
    username TEXT,
    password TEXT,
    redirected INTEGER DEFAULT 0
)""")
cur.execute("""
CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    connection_id INTEGER,
    command TEXT
)""")
cur.execute("""
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER,
    ip TEXT,
    type TEXT,
    details TEXT
)""")
conn.commit()

# Pour assurer la cohérence en multithread
db_lock = threading.Lock()

# --- Génération/chargement de la clé host SSH du honeypot ---

# Le honeypot doit avoir une clé privée pour établir la connexion SSH.
# On génère une clé RSA de 2048 bits (ou on peut charger depuis un fichier si on a une clé fixe).
HOST_KEY = paramiko.RSAKey.generate(2048)

# Bannière SSH factice (pour ressembler à un vrai serveur SSH)
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"

# --- Classe serveur Paramiko pour gérer l'authentification et le shell ---

class HoneypotServer(paramiko.ServerInterface):
    """Serveur SSH factice qui accepte toutes les authentifications et enregistre les identifiants."""
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.username = None
        self.password = None
        self.connection_id = None

    def check_channel_request(self, kind, chanid):
        # Accepter les demandes de session interactive (shell)
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Accepter *tous* les mots de passe comme valides par défaut (on capture quand même les identifiants)
        # Enregistrer la tentative de connexion en base SQLite
        self.username = username.decode('utf-8', 'ignore') if isinstance(username, bytes) else username
        self.password = password.decode('utf-8', 'ignore') if isinstance(password, bytes) else password
        client_ip = self.client_ip
        # Timestamp actuel (epoch secondes)
        now = int(time.time())
        with db_lock:
            cur.execute("INSERT INTO connections(timestamp, ip, username, password, redirected) VALUES (?, ?, ?, ?, ?)",
                        (now, client_ip, self.username, self.password, 0))
            conn.commit()
            # Récupérer l'ID de connexion inséré
            self.connection_id = cur.lastrowid
            # Détection brute force: compter tentatives récentes depuis cette IP
            cutoff = now - BRUTEFORCE_WINDOW_SEC
            cur.execute("SELECT COUNT(*) FROM connections WHERE ip=? AND timestamp>=?", (client_ip, cutoff))
            count = cur.fetchone()[0]
            if count >= BRUTEFORCE_THRESHOLD:
                # Insérer une alerte brute force
                alert_text = f"{count} tentatives en moins de {BRUTEFORCE_WINDOW_SEC} sec"
                cur.execute("INSERT INTO attacks(timestamp, ip, type, details) VALUES (?, ?, ?, ?)",
                            (now, client_ip, "bruteforce", alert_text))
                conn.commit()
        # Toujours renvoyer succès (on piège l'attaquant en lui accordant l'accès)
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        # Préciser que le mot de passe est supporté (pour éviter que le client tente autre chose)
        return "password"

    def check_auth_publickey(self, username, key):
        # On n'accepte pas d'authentification par clé publique dans ce honeypot (seulement password)
        return paramiko.AUTH_FAILED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        # Accepter la demande d'allocation d'un pseudo-terminal (pty) de la part du client
        return True

    def check_channel_shell_request(self, channel):
        # Le client demande un shell interactif (on l'accorde et on signale l’event)
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        # Si le client demande l'exécution d'une commande non-interactive (exec),
        # on la logue également mais on ne permet pas son exécution réelle.
        try:
            cmd = command.decode('utf-8', 'ignore')
        except Exception:
            cmd = str(command)
        # Loguer la commande dans la base
        with db_lock:
            now = int(time.time())
            # Si on a un enregistrement de connexion pour ce channel, utiliser son ID, sinon -1
            conn_id = self.connection_id if self.connection_id is not None else -1
            cur.execute("INSERT INTO commands(timestamp, connection_id, command) VALUES (?, ?, ?)",
                        (now, conn_id, cmd))
            # Détection commande malveillante
            lower = cmd.lower()
            if any(keyword in lower for keyword in ["wget ", "curl ", "http://", "https://", "chmod ", "tftp ", "ftp ", "rm ", "netcat", "bash -c", "sh -c"]):
                detail = f"Commande suspecte : {cmd[:100]}"
                cur.execute("INSERT INTO attacks(timestamp, ip, type, details) VALUES (?, ?, ?, ?)",
                            (now, self.client_ip, "malicious_cmd", detail))
            conn.commit()
        # Refuser formellement l'exec (on n'exécute rien, on simule uniquement) 
        return False

# --- Fonction de gestion d'une connexion entrante ---

def handle_client(client_socket, client_addr):
    """Gère une nouvelle connexion SSH entrante (authentification, shell factice, éventuellement redirection)."""
    ip = client_addr[0]
    print(f"[+] Nouvelle connexion de {ip}")
    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        transport.local_version = SSH_BANNER  # Personnaliser la bannière version du serveur SSH
        server = HoneypotServer(client_ip=ip)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            print("[-] Négociation SSH échouée (SSHException)")
            return  # abandonner cette connexion

        # Attendre l'ouverture d'un channel (session) par le client après auth
        chan = transport.accept(20)  # attendre jusqu'à 20 secondes
        if chan is None:
            print("[-] Pas de channel ouvert par le client.")
            return
        # Attendre que le client demande un shell (pty + shell)
        server.event.wait(10)
        if not server.event.is_set():
            # Si aucun shell n'est demandé (ex: requête exec refusée), on ferme
            print("[-] Le client n'a pas demandé de shell interactif.")
            chan.close()
            return

        # A ce stade, on a un shell interactif ouvert
        username = server.username
        password = server.password
        print(f"[i] Authentification réussie capturée: {username}/{password} depuis {ip}")

        # Optionnel: Redirection vers un vrai serveur SSH si configuré
        if REAL_SSH_HOST:
            try:
                # Tenter de se connecter au vrai serveur SSH avec les mêmes identifiants
                real_client = paramiko.SSHClient()
                real_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                real_client.connect(REAL_SSH_HOST, REAL_SSH_PORT, username=username, password=password, allow_agent=False, look_for_keys=False, timeout=5)
                # Si la connexion réussit, on établit un canal shell sur le vrai serveur
                real_chan = real_client.invoke_shell(term='xterm')
                print(f"[>] Redirection de {ip} vers le serveur SSH réel {REAL_SSH_HOST}:{REAL_SSH_PORT}")
                # Marquer dans la base que cette connexion est redirigée
                with db_lock:
                    cur.execute("UPDATE connections SET redirected=1 WHERE id=?", (server.connection_id,))
                    conn.commit()
                # Boucle de relais entre l'attaquant (chan) et le vrai serveur (real_chan)
                chan.settimeout(0.0)
                real_chan.settimeout(0.0)
                # Relayer données dans les deux sens jusqu'à fermeture
                while True:
                    # Utiliser select pour attendre les données sur l'un ou l'autre canal
                    rlist, _, _ = select.select([chan, real_chan], [], [], 1.0)
                    for r in rlist:
                        try:
                            if r is chan:
                                data = chan.recv(1024)
                                if len(data) == 0:
                                    # Client a fermé le channel
                                    raise EOFError
                                # Transférer vers le vrai serveur
                                real_chan.send(data)
                            elif r is real_chan:
                                data = real_chan.recv(1024)
                                if len(data) == 0:
                                    # Serveur réel a fermé le channel
                                    raise EOFError
                                # Envoyer vers le client attaquant
                                chan.send(data)
                        except EOFError:
                            # Un des côtés a fermé la connexion
                            chan.close()
                            real_chan.close()
                            real_client.close()
                            print(f"[!] Connexion terminée (canal fermé) pour {ip}")
                            return
                        except Exception as e:
                            # Autre erreur (on sort)
                            print(f"[!] Erreur dans le relais SSH pour {ip}: {e}")
                            try:
                                chan.close()
                            except: pass
                            try:
                                real_chan.close()
                            except: pass
                            real_client.close()
                            return
            except Exception as e:
                # La connexion au vrai serveur a échoué (mauvais identifiants ou autre)
                # On continue en mode honeypot standalone.
                if isinstance(e, paramiko.AuthenticationException):
                    print(f"[i] Redirection annulée: identifiants invalides pour le vrai SSH ({username}/{password})")
                else:
                    print(f"[i] Redirection annulée: échec connexion au vrai SSH ({e})")
                # On ne quitte pas, on va passer en simulation locale du shell.

        # --- Simulation du shell interactif ---
        chan.send("Bienvenue sur le serveur honeypot!\r\n")
        chan.send(f"{username}@honeypot:~$ ")  # Afficher une invite factice
        buffer = b""
        while True:
            # Lecture des données envoyées par l'attaquant
            data = chan.recv(1024)
            if not data:
                # Fin de connexion (le client a fermé)
                break
            # Ajouter au tampon et écho immédiat des caractères tapés (pour simuler le terminal)
            buffer += data
            try:
                # Tentative de décodage en UTF-8
                text = data.decode('utf-8')
            except UnicodeDecodeError:
                # En cas d'erreur d'encodage, on ignore les caractères invalides
                text = data.decode('utf-8', 'ignore')
            chan.send(data)  # renvoyer tel quel (écho)
            # Si l'utilisateur appuie Entrée (nouvelle ligne), traiter la commande
            if "\r" in text or "\n" in text:
                # Décoder la commande complète
                try:
                    command = buffer.decode('utf-8').replace("\r", "").replace("\n", "")
                except UnicodeDecodeError:
                    command = buffer.decode('utf-8', 'ignore').replace("\r", "").replace("\n", "")
                buffer = b""  # réinitialiser le tampon pour la prochaine commande
                # Enregistrer la commande dans la base de données
                with db_lock:
                    now = int(time.time())
                    cur.execute("INSERT INTO commands(timestamp, connection_id, command) VALUES (?, ?, ?)",
                                (now, server.connection_id, command))
                    # Vérifier si la commande est malveillante (heuristique simple)
                    cmd_lower = command.lower()
                    if any(keyword in cmd_lower for keyword in ["wget ", "curl ", "http://", "https://", "chmod ", "tftp ", "ftp ", "rm ", "netcat", "bash -c", "sh -c"]):
                        detail = f"Commande suspecte : {command[:100]}"
                        cur.execute("INSERT INTO attacks(timestamp, ip, type, details) VALUES (?, ?, ?, ?)",
                                    (now, ip, "malicious_cmd", detail))
                    conn.commit()
                # Afficher (envoyer) une réponse factice ou un message d'erreur simulé
                response = ""
                if command.strip() == "":
                    response = ""  # commande vide (juste "Entrée")
                elif command in ["exit", "quit", "logout"]:
                    response = "Déconnexion...\r\n"
                    chan.send(response)
                    break  # sortir de la boucle pour fermer la connexion
                elif command.startswith("cd"):
                    # Simuler le changement de répertoire (on ne maintient pas réellement de contexte de répertoire)
                    response = ""  # (silencieux comme bash si succès, pas de sortie)
                elif command.startswith("ls"):
                    # Simuler un contenu de dossier
                    response = "file1.txt\nfile2.log\nscript.sh\r\n"
                elif command.startswith("pwd"):
                    response = "/home/" + username + "\r\n"
                elif command.startswith("whoami"):
                    response = username + "\r\n"
                elif command.startswith("uname"):
                    response = "Linux honeypot 5.4.0-42-generic #46-Ubuntu SMP x86_64 GNU/Linux\r\n"
                elif command.startswith("id"):
                    # On simule un utilisateur root pour l'exemple
                    response = "uid=0(root) gid=0(root) groups=0(root)\r\n"
                else:
                    # Commande non reconnue ou non simulée
                    response = f"bash: {command}: command not found\r\n"
                if response:
                    chan.send(response)
                # Renvoyer une nouvelle invite après la commande
                chan.send(f"{username}@honeypot:~$ ")
        # Fin de session interactive
        try:
            chan.close()
        except Exception:
            pass
        try:
            transport.close()
        except Exception:
            pass
        print(f"[-] Connexion terminée pour {ip}")
    except Exception as e:
        print(f"[!] Erreur dans handle_client pour {ip}: {e}")
        try:
            client_socket.close()
        except: pass

# --- Lancement du serveur honeypot ---

def start_honeypot(host=LISTEN_HOST, port=LISTEN_PORT):
    """Démarre le serveur SSH honeypot en écoutant sur l'adresse/port spécifiés."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((host, port))
    except Exception as e:
        print(f"Erreur: impossible de lier le socket sur {host}:{port} -> {e}")
        return
    server_sock.listen(100)
    print(f"[Honeypot] En écoute sur {host}:{port} (CTRL+C pour arrêter)")
    # Boucle principale d'acceptation des connexions
    while True:
        try:
            client, addr = server_sock.accept()
        except Exception as e:
            print(f"[!] Erreur à l'acceptation: {e}")
            break
        # Lancer un thread pour isoler chaque connexion
        th = threading.Thread(target=handle_client, args=(client, addr))
        th.daemon = True
        th.start()

# Démarrer le honeypot (utiliser REAL_SSH_HOST/PORT configurés plus haut si nécessaire)
if __name__ == "__main__":
    print("** Lancement du honeypot SSH **")
    if REAL_SSH_HOST:
        print(f"[i] Mode redirection activé: les connexions valides seront relayées vers {REAL_SSH_HOST}:{REAL_SSH_PORT}")
    start_honeypot()
