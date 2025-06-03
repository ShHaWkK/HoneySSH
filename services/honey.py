#!/usr/bin/env python3
import socket
import threading
import paramiko
import sqlite3
import time
import random
import re
from datetime import datetime, timedelta
import os
import smtplib
from email.mime.text import MIMEText
from fpdf import FPDF
import uuid
import select
import signal
import sys

# =======================
# Configuration Variables
# =======================
HOST = ""  # Écoute sur toutes les interfaces
PORT = 2224  # Port SSH (éviter 22 pour ne pas interférer avec un vrai serveur)
SSH_BANNER = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"
ENABLE_REDIRECTION = False  # Redirection vers un vrai serveur SSH (non utilisé ici)
REAL_SSH_HOST = "192.168.1.100"
REAL_SSH_PORT = 22

DB_NAME = "server_data.db"
BRUTE_FORCE_THRESHOLD = 5
_brute_force_alerted = set()
_brute_force_lock = threading.Lock()

# Répertoire pour les logs de session
SESSION_LOG_DIR = "session_logs"
if not os.path.exists(SESSION_LOG_DIR):
    os.makedirs(SESSION_LOG_DIR)

# Ports pour les faux services réseau
FAKE_SERVICES = {
    "ftp": 21,
    "http": 80,
    "mysql": 3306
}

# =======================
# SMTP Configuration (Gmail)
# =======================
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "your_email@gmail.com"  # Remplacer par votre adresse Gmail
SMTP_PASS = "your_app_password"  # Remplacer par votre mot de passe d'application
ALERT_FROM = SMTP_USER
ALERT_TO = "admin@example.com"

# ================================
# Comptes utilisateurs préconfigurés
# ================================
PREDEFINED_USERS = {
    "admin": {
        "home": "/home/admin",
        "files": {
            "admin_credentials.txt": "admin:supersecret\nImportant credentials for admin account",
            "admin_sshkey": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...admin_key",
            "projectA_config": "projectA: configuration data..."
        }
    },
    "devops": {
        "home": "/home/devops",
        "files": {
            "deploy_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD...devops_key",
            "jenkins_config.yml": "jenkins: {url: http://localhost:8080, user: admin, pass: admin123}"
        }
    },
    "dbadmin": {
        "home": "/home/dbadmin",
        "files": {
            "db_backup.sql": "-- Fake SQL dump\nDROP TABLE IF EXISTS test;",
            "db_scripts.sh": "#!/bin/bash\necho 'Running DB maintenance...'"
        }
    },
    "mysql": {
        "home": "/var/lib/mysql",
        "files": {}
    },
    "www-data": {
        "home": "/var/www",
        "files": {}
    }
}

# ================================
# Fichiers de logs
# ================================
KEYSTROKES_LOG = "keystrokes.log"
FILE_TRANSFER_LOG = "file_transfers.log"

# ================================
# Honeytokens (fichiers appât sensibles)
# ================================
HONEY_TOKEN_FILES = [
    "/home/admin/financial_report.pdf",
    "/home/admin/compromised_email.eml",
    "/home/admin/secret_plans.txt",
    "/secret/critical_data.txt"
]

# ================================
# Fonctions dynamiques pour simuler les fichiers et commandes
# ================================
def get_dynamic_df():
    sizes = {"sda1": "50G", "tmpfs": "100M"}
    used = {"sda1": f"{random.randint(5, 10)}G", "tmpfs": "0M"}
    avail = {"sda1": f"{random.randint(30, 45)}G", "tmpfs": "100M"}
    usep = {"sda1": f"{random.randint(10, 20)}%", "tmpfs": "0%"}
    return f"""Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        {sizes['sda1']}   {used['sda1']}   {avail['sda1']}  {usep['sda1']} /
tmpfs           {sizes['tmpfs']}     {used['tmpfs']}  {avail['tmpfs']}   {usep['tmpfs']} /tmp"""

def get_dynamic_uptime():
    now = datetime.now().strftime("%H:%M:%S")
    days = random.randint(3, 10)
    hours = random.randint(0, 23)
    minutes = random.randint(0, 59)
    users = random.randint(1, 5)
    la1 = f"{random.uniform(0.00, 1.00):.2f}"
    la2 = f"{random.uniform(0.00, 1.00):.2f}"
    la3 = f"{random.uniform(0.00, 1.00):.2f}"
    return f"{now} up {days} days, {hours}:{minutes:02d}, {users} user{'s' if users > 1 else ''}, load average: {la1}, {la2}, {la3}"

def get_dynamic_ps():
    processes = [
        ("root", "1", "/sbin/init"),
        ("root", "135", "/usr/sbin/sshd -D"),
        ("mysql", "220", "/usr/sbin/mysqld"),
        ("www-data", "300", "/usr/sbin/nginx -g 'daemon off;'"),
        ("admin", str(random.randint(1000, 5000)), "/bin/bash"),
        ("devops", str(random.randint(1000, 5000)), "/usr/bin/python3 app.py"),
        ("dbadmin", str(random.randint(1000, 5000)), "/bin/sh db_scripts.sh")
    ]
    lines = ["USER       PID %CPU %MEM    VSZ   RSS TTY   STAT START   TIME COMMAND"]
    for user, pid, cmd in processes:
        cpu = round(random.uniform(0.0, 5.0), 1)
        mem = round(random.uniform(0.5, 3.0), 1)
        vsz = random.randint(10000, 50000)
        rss = random.randint(1000, 5000)
        tty = random.choice(["pts/0", "pts/1", "?", "tty7"])
        stat = random.choice(["Ss", "S+", "R"])
        start = (datetime.now() - timedelta(hours=random.randint(1, 24))).strftime("%H:%M")
        time_str = f"{random.randint(0, 2)}:{random.randint(0, 59):02d}"
        lines.append(f"{user:<10} {pid:<6} {cpu:<5} {mem:<5} {vsz:<7} {rss:<6} {tty:<6} {stat:<5} {start:<8} {time_str:<6} {cmd}")
    return "\r\n".join(lines)

def get_dynamic_netstat():
    lines = [
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name",
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      135/sshd",
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      300/nginx",
        "tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      220/mysqld"
    ]
    for _ in range(random.randint(2, 4)):
        local_ip = f"192.168.1.{random.randint(2, 254)}"
        local_port = random.choice([22, 80, 443, 3306])
        foreign_ip = f"10.0.0.{random.randint(2, 254)}"
        foreign_port = random.randint(1024, 65535)
        state = random.choice(["ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT"])
        pid_prog = f"{random.randint(100, 999)}/app{random.randint(1, 5)}"
        lines.append(f"tcp        0      0 {local_ip}:{local_port}  {foreign_ip}:{foreign_port}  {state:<10} {pid_prog}")
    return "\r\n".join(lines)

def get_dynamic_config():
    max_conn = random.randint(50, 200)
    log_level = random.choice(["DEBUG", "INFO", "WARNING", "ERROR"])
    return f"max_connections={max_conn}\nlog_level={log_level}\n"

def get_dynamic_cpuinfo():
    return f"""processor   : 0
vendor_id   : GenuineIntel
cpu family  : 6
model       : 142
model name  : Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz
stepping    : 10
microcode   : 0xca
cpu MHz     : {random.uniform(1600, 3400):.3f}
cache size  : 6144 KB
physical id : 0
siblings    : 4
core id     : 0
cpu cores   : 4
bogomips    : {random.uniform(3000, 4000):.2f}
flags       : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov
"""

def get_dynamic_meminfo():
    total_mem = random.randint(4000000, 8000000)
    free_mem = random.randint(500000, total_mem // 2)
    available_mem = free_mem + random.randint(100000, 500000)
    buffers = random.randint(10000, 100000)
    cached = random.randint(500000, 2000000)
    return f"""MemTotal:       {total_mem} kB
MemFree:        {free_mem} kB
MemAvailable:   {available_mem} kB
Buffers:        {buffers} kB
Cached:         {cached} kB
SwapTotal:      {random.randint(1000000, 2000000)} kB
SwapFree:       {random.randint(500000, 1800000)} kB
"""

def get_dynamic_self_stat():
    pid = random.randint(1000, 9999)
    return f"{pid} (bash) S {random.randint(1, 1000)} 1 1 0 -1 4194304 {random.randint(100, 1000)} {random.randint(0, 100)} 0 0 0 0 {random.randint(0, 100)} {random.randint(0, 100)} 20 0 1 0 {random.randint(1000000, 9999999)} {random.randint(10000, 50000)} {random.randint(1000, 5000)} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"

def get_dynamic_mounts():
    return f"""sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
udev /dev devtmpfs rw,relatime,size=3958472k,nr_inodes=989618,mode=755 0 0
/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,relatime 0 0
"""

def get_dynamic_messages():
    lines = []
    for _ in range(10):
        timestamp = datetime.now().strftime("%b %d %H:%M:%S")
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        service = random.choice(["sshd", "systemd", "cron", "nginx", "apache2", "mysqld"])
        message = random.choice([
            f"{service}[{random.randint(1000, 9999)}]: Started {service} service.",
            f"{service}: Connection from {src_ip}",
            f"{service}: Configuration loaded successfully.",
            f"{service}: Warning: High CPU usage detected."
        ])
        lines.append(f"{timestamp} debian {message}")
    return "\n".join(lines)

def get_dynamic_dmesg():
    lines = []
    for _ in range(10):
        timestamp = f"[{random.uniform(0, 1000):.6f}]"
        message = random.choice([
            "kernel: [CPU0] microcode updated early to revision 0xca",
            "kernel: random: crng init done",
            "kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode",
            "kernel: ACPI: Power Button [PWRB]"
        ])
        lines.append(f"{timestamp} {message}")
    return "\n".join(lines)

def get_dev_null():
    return ""

def get_dev_zero():
    return "\0" * 1024

def get_dynamic_top():
    header = f"""top - {datetime.now().strftime("%H:%M:%S")} up {random.randint(3, 10)} days, {random.randint(0, 23)}:{random.randint(0, 59):02d}, {random.randint(1, 5)} users, load average: {random.uniform(0.00, 1.00):.2f}, {random.uniform(0.00, 1.00):.2f}, {random.uniform(0.00, 1.00):.2f}
Tasks: {random.randint(80, 120)} total, {random.randint(1, 3)} running, {random.randint(70, 100)} sleeping, {random.randint(0, 5)} stopped, {random.randint(0, 5)} zombie
%Cpu(s): {random.uniform(0.0, 10.0):.1f} us, {random.uniform(0.0, 5.0):.1f} sy, {random.uniform(0.0, 1.0):.1f} ni, {random.uniform(80.0, 95.0):.1f} id, {random.uniform(0.0, 2.0):.1f} wa, 0.0 hi, 0.0 si, 0.0 st
MiB Mem : {random.randint(4000, 8000)} total, {random.randint(500, 2000)} free, {random.randint(1000, 4000)} used, {random.randint(500, 1500)} buff/cache
MiB Swap: {random.randint(1000, 2000)} total, {random.randint(800, 1900)} free, {random.randint(0, 200)} used
"""
    lines = ["  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND"]
    processes = [
        ("root", "1", "/sbin/init"),
        ("root", "135", "/usr/sbin/sshd -D"),
        ("mysql", "220", "/usr/sbin/mysqld"),
        ("www-data", "300", "/usr/sbin/nginx -g 'daemon off;'"),
        ("admin", str(random.randint(1000, 5000)), "/bin/bash")
    ]
    for user, pid, cmd in processes:
        cpu = round(random.uniform(0.0, 5.0), 1)
        mem = round(random.uniform(0.5, 3.0), 1)
        virt = random.randint(10000, 50000)
        res = random.randint(1000, 5000)
        shr = random.randint(500, 2000)
        stat = random.choice(["S", "R"])
        time_str = f"{random.randint(0, 2)}:{random.randint(0, 59):02d}"
        lines.append(f"{pid:>5} {user:<8} 20   0 {virt:>7} {res:>6} {shr:>6} {stat} {cpu:>5} {mem:>5} {time_str:>8} {cmd}")
    return header + "\r\n".join(lines)

def get_dynamic_ifconfig():
    return f"""eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.{random.randint(100, 200)}  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::1ff:fe23:4567:890a  prefixlen 64  scopeid 0x20<link>
        ether 00:1f:23:45:67:89  txqueuelen 1000  (Ethernet)
        RX packets {random.randint(1000, 10000)}  bytes {random.randint(100000, 1000000)} ({random.randint(100, 1000)}.{random.randint(0, 9)} KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets {random.randint(500, 5000)}  bytes {random.randint(50000, 500000)} ({random.randint(50, 500)}.{random.randint(0, 9)} KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets {random.randint(100, 1000)}  bytes {random.randint(10000, 100000)} ({random.randint(10, 100)}.{random.randint(0, 9)} KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets {random.randint(100, 1000)}  bytes {random.randint(10000, 100000)} ({random.randint(10, 100)}.{random.randint(0, 9)} KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
"""

def get_dynamic_ip_addr():
    return f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:1f:23:45:67:89 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.{random.randint(100, 200)}/24 brd 192.168.1.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::1ff:fe23:4567:890a/64 scope link
       valid_lft forever preferred_lft forever
"""

def get_dynamic_iptables():
    return f"""Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  anywhere             anywhere
DROP       tcp  --  anywhere             anywhere            tcp dpt:23

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  anywhere             anywhere
"""

def get_dynamic_service_status(service_name):
    status = random.choice(["active (running)", "inactive (dead)"])
    since = (datetime.now() - timedelta(hours=random.randint(1, 24))).strftime("%Y-%m-%d %H:%M:%S")
    pid = random.randint(1000, 9999) if status == "active (running)" else ""
    return f"""● {service_name}.service - {service_name.capitalize()} Service
   Loaded: loaded (/lib/systemd/system/{service_name}.service; enabled; vendor preset: enabled)
   Active: {status} since {since}
{('  Main PID: ' + str(pid) + ' (' + service_name + ')') if pid else ''}"""

def get_dynamic_crontab():
    return f"""# Edit this file to introduce tasks to be run by cron.
# m h  dom mon dow   command
0 0 * * * /usr/local/bin/backup.sh
30 4 * * * /usr/bin/update_db.sh
* * * * * /usr/local/bin/monitor.sh
"""

def get_dynamic_who():
    users = ["admin", "devops", "dbadmin"]
    lines = []
    for _ in range(random.randint(1, 3)):
        user = random.choice(users)
        tty = random.choice(["pts/0", "pts/1", "tty7"])
        ip = f"192.168.1.{random.randint(10, 50)}"
        login_time = (datetime.now() - timedelta(minutes=random.randint(1, 360))).strftime("%Y-%m-%d %H:%M")
        lines.append(f"{user:<8} {tty:<8} {ip:<16} {login_time}")
    return "\r\n".join(lines)

def get_dynamic_w():
    users = ["admin", "devops", "dbadmin"]
    header = f"{datetime.now().strftime('%H:%M:%S')} up {random.randint(3, 10)} days, {random.randint(1, 5)} users, load average: {random.uniform(0.00, 1.00):.2f}, {random.uniform(0.00, 1.00):.2f}, {random.uniform(0.00, 1.00):.2f}\n"
    lines = ["USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT"]
    for _ in range(random.randint(1, 3)):
        user = random.choice(users)
        tty = random.choice(["pts/0", "pts/1", "tty7"])
        ip = f"192.168.1.{random.randint(10, 50)}"
        login_time = (datetime.now() - timedelta(minutes=random.randint(1, 360))).strftime("%H:%M")
        idle = f"{random.randint(0, 60)}:{random.randint(0, 59):02d}"
        what = random.choice(["bash", "/usr/bin/vim", "/usr/bin/top", "/usr/bin/python3 app.py"])
        lines.append(f"{user:<8} {tty:<8} {ip:<16} {login_time:<8} {idle:<6} 0.10s 0.10s {what}")
    return header + "\r\n".join(lines)

def get_dynamic_last():
    users = ["admin", "devops", "dbadmin"]
    lines = []
    for _ in range(random.randint(3, 6)):
        user = random.choice(users)
        tty = random.choice(["pts/0", "pts/1"])
        ip = f"192.168.1.{random.randint(10, 50)}"
        login_time = (datetime.now() - timedelta(hours=random.randint(1, 48))).strftime("%a %b %d %H:%M")
        duration = f"({random.randint(0, 2):02d}:{random.randint(0, 59):02d})"
        lines.append(f"{user:<8} {tty:<8} {ip:<16} {login_time:<20} {duration}")
    return "\r\n".join(lines)

def get_dynamic_ss():
    lines = [
        "Netid  State      Recv-Q Send-Q  Local Address:Port   Peer Address:Port",
        f"tcp    LISTEN     0      128     0.0.0.0:22           0.0.0.0:*",
        f"tcp    LISTEN     0      128     0.0.0.0:80           0.0.0.0:*",
        f"tcp    LISTEN     0      128     0.0.0.0:3306         0.0.0.0:*"
    ]
    return "\r\n".join(lines)

# ================================
# Faux services réseau
# ================================
def fake_ftp_server(port, stop_event):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(5)
        server.settimeout(1.0)
        print(f"[*] Faux serveur FTP démarré sur le port {port}")
        while not stop_event.is_set():
            try:
                readable, _, _ = select.select([server], [], [], 1.0)
                if server in readable:
                    client, addr = server.accept()
                    client.send(b"220 Welcome to Fake FTP Server\r\n")
                    try:
                        data = client.recv(1024).decode('utf-8', errors='ignore')
                        if data.startswith("USER"):
                            client.send(b"331 Please specify the password.\r\n")
                        elif data.startswith("PASS"):
                            client.send(b"530 Login incorrect.\r\n")
                    except:
                        pass
                    print(f"[+] Connexion FTP de {addr[0]}")
                    trigger_alert(-1, "FTP Connection", f"Connection attempt to FTP server from {addr[0]}", addr[0], "unknown")
                    client.close()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[!] Erreur dans le serveur FTP: {e}")
    except Exception as e:
        print(f"[!] Échec du démarrage du serveur FTP: {e}")
    finally:
        server.close()

def fake_http_server(port, stop_event):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(5)
        server.settimeout(1.0)
        print(f"[*] Faux serveur HTTP démarré sur le port {port}")
        while not stop_event.is_set():
            try:
                readable, _, _ = select.select([server], [], [], 1.0)
                if server in readable:
                    client, addr = server.accept()
                    try:
                        client.recv(1024)  # Lire la requête
                        response = (
                            "HTTP/1.1 200 OK\r\n"
                            "Content-Type: text/html\r\n"
                            "Server: nginx/1.18.0\r\n"
                            "\r\n"
                            "<html><body><h1>Welcome to Fake Web Server</h1><p>This is a simulated web server.</p></body></html>"
                        )
                        client.send(response.encode())
                    except:
                        pass
                    print(f"[+] Connexion HTTP de {addr[0]}")
                    trigger_alert(-1, "HTTP Connection", f"Connection attempt to HTTP server from {addr[0]}", addr[0], "unknown")
                    client.close()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[!] Erreur dans le serveur HTTP: {e}")
    except Exception as e:
        print(f"[!] Échec du démarrage du serveur HTTP: {e}")
    finally:
        server.close()

def fake_mysql_server(port, stop_event):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("0.0.0.0", port))
        server.listen(5)
        server.settimeout(1.0)
        print(f"[*] Faux serveur MySQL démarré sur le port {port}")
        while not stop_event.is_set():
            try:
                readable, _, _ = select.select([server], [], [], 1.0)
                if server in readable:
                    client, addr = server.accept()
                    # Simuler une bannière MySQL
                    client.send(b"\x0a5.7.30-fake\x00\x01\x00\x00\x00\x01\x21\x00\x00\x00")
                    print(f"[+] Connexion MySQL de {addr[0]}")
                    trigger_alert(-1, "MySQL Connection", f"Connection attempt to MySQL server from {addr[0]}", addr[0], "unknown")
                    client.close()
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[!] Erreur dans le serveur MySQL: {e}")
    except Exception as e:
        print(f"[!] Échec du démarrage du serveur MySQL: {e}")
    finally:
        server.close()

# ================================
# Construction du système de fichiers
# ================================
def populate_predefined_users(fs):
    if "/home" not in fs:
        fs["/home"] = {"type": "dir", "contents": []}
    for user, info in PREDEFINED_USERS.items():
        home_dir = info["home"]
        fs[home_dir] = {"type": "dir", "contents": list(info["files"].keys())}
        if user not in fs["/home"]["contents"] and home_dir.startswith("/home"):
            fs["/home"]["contents"].append(user)
        for filename, content in info["files"].items():
            fs[f"{home_dir}/{filename}"] = {"type": "file", "content": content}
    return fs

BASE_FILE_SYSTEM = {
    "/": {"type": "dir", "contents": ["bin", "sbin", "usr", "var", "opt", "root", "home", "etc", "tmp", "secret", "proc", "dev", "sys", "lib"]},
    "/bin": {"type": "dir", "contents": ["bash", "ls", "cat", "grep", "chmod", "chown", "mv", "cp", "top", "ifconfig", "ip"]},
    "/sbin": {"type": "dir", "contents": ["init", "sshd", "iptables", "reboot"]},
    "/usr": {"type": "dir", "contents": ["bin", "lib", "share", "local"]},
    "/usr/bin": {"type": "dir", "contents": ["python3", "gcc", "make", "apt-get", "vim", "nano", "curl", "wget", "telnet", "service", "systemctl", "crontab", "ss", "find", "head", "tail", "history"]},
    "/usr/sbin": {"type": "dir", "contents": ["apache2", "nginx", "mysqld", "postfix"]},
    "/usr/local": {"type": "dir", "contents": ["bin"]},
    "/usr/local/bin": {"type": "dir", "contents": ["backup.sh", "update_db.sh", "monitor.sh"]},
    "/var": {"type": "dir", "contents": ["log", "www", "run", "lib"]},
    "/var/log": {"type": "dir", "contents": ["syslog", "auth.log", "messages", "dmesg"]},
    "/var/www": {"type": "dir", "contents": ["html"]},
    "/var/www/html": {"type": "dir", "contents": ["index.html", "index.php"]},
    "/var/run": {"type": "dir", "contents": ["sshd.pid", "nginx.pid", "mysqld.pid"]},
    "/var/lib": {"type": "dir", "contents": ["mysql"]},
    "/var/lib/mysql": {"type": "dir", "contents": []},
    "/opt": {"type": "dir", "contents": ["backup"]},
    "/opt/backup": {"type": "dir", "contents": ["config_backup.tar.gz"]},
    "/root": {"type": "dir", "contents": ["credentials.txt", "config_backup.zip", "ssh_keys.tar.gz", "rootkit_detector.sh"]},
    "/etc": {"type": "dir", "contents": ["passwd", "shadow", "hosts", "myconfig.conf", "fstab", "resolv.conf", "hosts.allow", "ssh", "nginx", "apache2", "services"]},
    "/tmp": {"type": "dir", "contents": [".lockfile1", ".lockfile2", "tmpfile1.txt", "tmpsocket.sock"]},
    "/secret": {"type": "dir", "contents": ["critical_data.txt"]},
    "/proc": {"type": "dir", "contents": ["cpuinfo", "meminfo", "self", "mounts"]},
    "/proc/self": {"type": "dir", "contents": ["stat"]},
    "/dev": {"type": "dir", "contents": ["null", "zero", "random"]},
    "/sys": {"type": "dir", "contents": ["block", "kernel"]},
    "/lib": {"type": "dir", "contents": ["systemd"]},
    "/etc/ssh": {"type": "dir", "contents": ["sshd_config"]},
    "/etc/nginx": {"type": "dir", "contents": ["nginx.conf"]},
    "/etc/apache2": {"type": "dir", "contents": ["apache2.conf"]},
}

# Contenus des fichiers
BASE_FILE_SYSTEM["/root/credentials.txt"] = {"type": "file", "content": "username=admin\npassword=admin123\napi_key=ABCD-7890-EFGH-5678"}
BASE_FILE_SYSTEM["/root/config_backup.zip"] = {"type": "file", "content": "PK\x03\x04..."}
BASE_FILE_SYSTEM["/root/ssh_keys.tar.gz"] = {"type": "file", "content": "...\x1F\x8B\x08-..."}
BASE_FILE_SYSTEM["/root/rootkit_detector.sh"] = {"type": "file", "content": "#!/bin/bash\necho 'Rootkit detection active'"}
BASE_FILE_SYSTEM["/etc/passwd"] = {"type": "file", "content": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash\ndevops:x:1001:1001:DevOps User:/home/devops:/bin/bash\ndbadmin:x:1002:1002:DB Admin:/home/dbadmin:/bin/bash\nmysql:x:110:110:MySQL:/var/lib/mysql:/sbin/nologin\nwww-data:x:33:33:WWW:/var/www:/sbin/nologin"}
BASE_FILE_SYSTEM["/etc/shadow"] = {"type": "file", "content": "root:*:18967:0:99999:7:::\nadmin:*:18967:0:99999:7:::\ndevops:*:18967:0:99999:7:::\ndbadmin:*:18967:0:99999:7:::\nmysql:*:18967:0:99999:7:::\nwww-data:*:18967:0:99999:7:::"}
BASE_FILE_SYSTEM["/etc/hosts"] = {"type": "file", "content": "127.0.0.1 localhost\n192.168.1.100 server.local"}
BASE_FILE_SYSTEM["/etc/myconfig.conf"] = {"type": "file", "content": get_dynamic_config}
BASE_FILE_SYSTEM["/secret/critical_data.txt"] = {"type": "file", "content": "CRITICAL DATA: Marker: CRITICAL-DATA-999\nDo not share."}
BASE_FILE_SYSTEM["/proc/cpuinfo"] = {"type": "file", "content": get_dynamic_cpuinfo}
BASE_FILE_SYSTEM["/proc/meminfo"] = {"type": "file", "content": get_dynamic_meminfo}
BASE_FILE_SYSTEM["/proc/self/stat"] = {"type": "file", "content": get_dynamic_self_stat}
BASE_FILE_SYSTEM["/proc/mounts"] = {"type": "file", "content": get_dynamic_mounts}
BASE_FILE_SYSTEM["/dev/null"] = {"type": "file", "content": get_dev_null}
BASE_FILE_SYSTEM["/dev/zero"] = {"type": "file", "content": get_dev_zero}
BASE_FILE_SYSTEM["/var/log/messages"] = {"type": "file", "content": get_dynamic_messages}
BASE_FILE_SYSTEM["/var/log/dmesg"] = {"type": "file", "content": get_dynamic_dmesg}
BASE_FILE_SYSTEM["/var/log/syslog"] = {"type": "file", "content": get_dynamic_messages}
BASE_FILE_SYSTEM["/var/log/auth.log"] = {"type": "file", "content": get_dynamic_messages}
BASE_FILE_SYSTEM["/tmp/.lockfile1"] = {"type": "file", "content": "PID:12345\n"}
BASE_FILE_SYSTEM["/tmp/.lockfile2"] = {"type": "file", "content": "PID:67890\n"}
BASE_FILE_SYSTEM["/tmp/tmpfile1.txt"] = {"type": "file", "content": "Temporary file created by process\n"}
BASE_FILE_SYSTEM["/tmp/tmpsocket.sock"] = {"type": "file", "content": ""}
BASE_FILE_SYSTEM["/etc/fstab"] = {"type": "file", "content": """# /etc/fstab
/dev/sda1  /  ext4  defaults,errors=remount-ro  0  1
tmpfs  /tmp  tmpfs  nosuid,nodev  0  0
/dev/sdb1  /home  ext4  defaults  0  2
/dev/sda2  none  swap  sw  0  0
"""}
BASE_FILE_SYSTEM["/etc/resolv.conf"] = {"type": "file", "content": """nameserver 8.8.8.8
nameserver 8.8.4.4
"""}
BASE_FILE_SYSTEM["/etc/hosts.allow"] = {"type": "file", "content": """sshd: 192.168.1.0/24
all: localhost
"""}
BASE_FILE_SYSTEM["/etc/ssh/sshd_config"] = {"type": "file", "content": """# OpenSSH configuration
Port 22
Protocol 2
PermitRootLogin no
PasswordAuthentication yes
UsePAM yes
AllowTcpForwarding yes
X11Forwarding no
MaxAuthTries 6
ClientAliveInterval 120
ClientAliveCountMax 3
"""}
BASE_FILE_SYSTEM["/etc/nginx/nginx.conf"] = {"type": "file", "content": """user www-data;
worker_processes auto;
pid /run/nginx.pid;
events {
    worker_connections 768;
}
http {
    server {
        listen 80 default_server;
        server_name _;
        root /var/www/html;
        index index.html index.php;
    }
}
"""}
BASE_FILE_SYSTEM["/etc/apache2/apache2.conf"] = {"type": "file", "content": """ServerRoot "/etc/apache2"
Listen 80
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf
DocumentRoot /var/www/html
ErrorLog ${APACHE_LOG_DIR}/error.log
LogLevel warn
"""}
BASE_FILE_SYSTEM["/var/www/html/index.html"] = {"type": "file", "content": """<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body><h1>Fake Web Server</h1><p>This is a simulated web server.</p></body>
</html>
"""}
BASE_FILE_SYSTEM["/var/www/html/index.php"] = {"type": "file", "content": "<?php phpinfo(); ?>"}
BASE_FILE_SYSTEM["/usr/local/bin/backup.sh"] = {"type": "file", "content": """#!/bin/bash
echo 'Running system backup...'
tar -czf /opt/backup/config_backup.tar.gz /etc
"""}
BASE_FILE_SYSTEM["/usr/local/bin/update_db.sh"] = {"type": "file", "content": """#!/bin/bash
echo 'Updating database...'
"""}
BASE_FILE_SYSTEM["/usr/local/bin/monitor.sh"] = {"type": "file", "content": """#!/bin/bash
echo 'Monitoring system resources...'
"""}
BASE_FILE_SYSTEM["/etc/services"] = {"type": "file", "content": """# /etc/services: Common network services
ftp             21/tcp
ftp             21/udp
ssh             22/tcp
telnet          23/tcp
smtp            25/tcp
http            80/tcp
pop3            110/tcp
imap            143/tcp
https           443/tcp
mysql           3306/tcp
"""}
BASE_FILE_SYSTEM = populate_predefined_users(BASE_FILE_SYSTEM)

# ================================
# Alerte avec logging
# ================================
def trigger_alert(session_id, event_type, details, client_ip, username):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[ALERT] {timestamp} - {client_ip} ({username}) : {event_type} - {details}")
    try:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO events (timestamp, ip, username, event_type, details)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, client_ip, username, event_type, details))
        conn.commit()
    except sqlite3.Error as e:
        print(f"[!] Erreur lors de la journalisation dans la DB: {e}")
    finally:
        conn.close()

    subject = f"[SERVEUR SSH] Alerte: {client_ip} (user={username})"
    body = (
        f"Date/Heure   : {timestamp}\n"
        f"Client IP}    : {client_ip}\n"
        f"Utilisateur : {username}\n"
        f"Événement type : {event_type}\n"
        f"Détails      : {details}\n"
        f"Session ID    : {session_id}\n"
        "\n"
        "Informations supplémentaires :\n"
        "- Serveur SSH sous surveillance\n"
        "- Activité enregistrée pour analyse\n"
    )
    msg = MIMEText(body)
    msg["From"] = ALERT_FROM
    msg["To"] = ALERT_TO
    msg["Subject"] = subject
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
            print(f"[*] Alerte envoyée par email.")
    except Exception as e:
        print(f"[!] Erreur lors de l'envoi de l'email d'alerte : {e}")

# ===============================
# Historique persistant
# ===============================
def load_history(username):
    filename = f"history_{username.replace('/', '_')}.txt"
    try:
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Erreur lors du chargement de l'historique pour {username}: {e}")
    return []

def save_history(username, history):
    filename = f"history_{username.replace('/', '_')}.txt"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            for cmd in history[-1000:]:  # Limiter à 1000 commandes
                f.write(cmd + "\n")
    except Exception as e:
        print(f"[!] Erreur lors de la sauvegarde de l'historique pour {username}: {e}")

# ===============================
# Autocomplétion
# ===============================
def get_completions(current_input, current_dir, username, fs):
    base_cmds = [
        "ls", "cd", "pwd", "whoami", "id", "uname", "cat", "rm", "ps", "netstat",
        "top", "ifconfig", "ip", "uptime", "df", "exit", "iptables", "service",
        "systemctl", "crontab", "dmesg", "grep", "find", "head", "tail", "history",
        "sudo", "su", "curl", "wget", "telnet", "apt-get", "dpkg", "make", "scp",
        "sftp", "ftp", "db", "smb", "who", "w", "last", "ss", "chmod", "chown",
        "vim", "nano"
    ]
    if " " not in current_input:
        return sorted([cmd for cmd in base_cmds if cmd.startswith(current_input)])
    else:
        parts = current_input.split(" ", 1)
        cmd = parts[0]
        partial = parts[1] if len(parts) > 1 else ""
        if cmd in ["cd", "ls", "cat", "rm"]:
            resolved_path = partial if partial.startswith("/") else (current_dir.rstrip("/") + "/" + partial) if current_dir != "/" else "/" + partial
            completions = []
            for path in fs:
                if path.startswith(resolved_path) and fs[path]["type"] == ("dir" if cmd == "cd" else fs[path]["type"]):
                    completions.append(path)
            dir_contents = fs.get(current_dir, {}).get("contents", [])
            for content in dir_contents:
                if content.startswith(partial.split("/")[-1]):
                    full = f"{current_dir}/{content}" if current_dir != "/" else f"/{content}"
                    completions.append(full)
            return sorted(completions)
        return []

def autocomplete(current_input, current_dir, username, fs):
    completions = get_completions(current_input, current_dir, username, fs)
    if len(completions) == 1:
        if " " not in current_input:
            return completions[0]
        else:
            return current_input.split(" ", 1)[0] + " " + completions[0]
    elif len(completions) > 1:
        return current_input  # Afficher les options possibles lors de la double tabulation
    return current_input

# ==============================
# Initialisation de la base de données
# ==============================
def init_database():
    try:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT NOT NULL,
                username TEXT,
                password TEXT,
                success INTEGER,
                redirected INTEGER
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                command TEXT NOT NULL,
                session_id INTEGER NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        print(f"[!] Erreur lors de l'initialisation de la base de données : {e}")
    finally:
        conn.close()

# ==============================
# Rapport PDF hebdomadaire
# ==============================
def generate_weekly_report():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Rapport Hebdomadaire - Serveur SSH", 0, 1, "C")
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Période: {datetime.now() - timedelta(days=7)} à {datetime.now()}", 0, 1)
    
    try:
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()
        
        # Résumé des tentatives de connexion
        cur.execute("SELECT COUNT(*) FROM login_attempts WHERE timestamp > ?", 
                    ((datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S"),))
        login_count = cur.fetchone()[0]
        pdf.cell(0, 10, f"Total des tentatives de connexion: {login_count}", 0, 1)
        
        # Tentatives par IP
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Tentatives par adresse IP:", 0, 1)
        pdf.set_font("Arial", size=12)
        cur.execute("SELECT ip, COUNT(*) as count FROM login_attempts WHERE timestamp > ? GROUP BY ip ORDER BY count DESC LIMIT 5",
                    ((datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S"),))
        for ip, count in cur.fetchall():
            pdf.cell(0, 10, f"IP: {ip} - {count} tentatives", 0, 1)
        
        # Commandes exécutées
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Commandes les plus exécutées:", 0, 1)
        pdf.set_font("Arial", size=12)
        cur.execute("SELECT command, COUNT(*) as count FROM commands WHERE timestamp > ? GROUP BY command ORDER BY count DESC LIMIT 5",
                    ((datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S"),))
        for cmd, count in cur.fetchall():
            pdf.cell(0, 10, f"Commande: {cmd} - {count} exécutions", 0, 1)
        
        # Événements critiques
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Événements critiques:", 0, 1)
        pdf.set_font("Arial", size=12)
        cur.execute("SELECT timestamp, ip, username, event_type, details FROM events WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 5",
                    ((datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S"),))
        for timestamp, ip, username, event_type, details in cur.fetchall():
            pdf.cell(0, 10, f"{timestamp} - {ip} ({username}): {event_type} - {details}", 0, 1)
        
        conn.close()
    except sqlite3.Error as e:
        print(f"[!] Erreur lors de la génération du rapport: {e}")
    
    report_filename = f"weekly_report_{datetime.now().strftime('%Y%m%d')}.pdf"
    pdf.output(report_filename)
    return report_filename

def send_weekly_report():
    while not stop_event.is_set():
        now = datetime.now()
        if now.weekday() == 0 and now.hour == 8:  # Lundi à 8h
            report_filename = generate_weekly_report()
            subject = f"Rapport Hebdomadaire Serveur SSH - {datetime.now().strftime('%Y-%m-%d')}"
            body = "Veuillez trouver ci-joint le rapport hebdomadaire des activités du serveur SSH."
            msg = MIMEText(body)
            msg["From"] = ALERT_FROM
            msg["To"] = ALERT_TO
            msg["Subject"] = subject
            
            try:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
                    smtp.starttls()
                    smtp.login(SMTP_USER, SMTP_PASS)
                    smtp.send_message(msg)
                    print(f"[*] Rapport hebdomadaire envoyé par email: {report_filename}")
            except Exception as e:
                print(f"[!] Erreur lors de l'envoi du rapport: {e}")
            os.remove(report_filename)  # Nettoyage
        time.sleep(3600)  # Vérifier toutes les heures

def weekly_report_thread():
    threading.Thread(target=send_weekly_report, daemon=True).start()

# ==============================
# Keylogging avancé
# ==============================
def log_keystroke(session_id, client_ip, username, key, timestamp):
    try:
        with open(KEYSTROKES_LOG, "a", encoding="utf-8") as f:
            f.write(f"{timestamp},{session_id},{client_ip},{username},{key}\n")
    except Exception as e:
        print(f"[!] Erreur lors de l'enregistrement des frappes: {e}")

# ==============================
# Gestion SFTP
# ==============================
class SFTPServer(paramiko.SFTPServer):
    def __init__(self, channel, name, server, sftp_si, *args, **kwargs):
        super().__init__(channel, name, server, sftp_si, *args, **kwargs)
        self.fs = BASE_FILE_SYSTEM.copy()
        self.session_id = server.session_id
        self.client_ip = server.client_ip
        self.username = server.transport.get_username() or "unknown"

    def open(self, path, flags, attr):
        trigger_alert(self.session_id, "SFTP File Open", f"Opened file: {path}", self.client_ip, self.username)
        if path not in self.fs or self.fs[path]["type"] != "file":
            raise OSError("No such file")
        return paramiko.SFTPHandle(self)

    def list_folder(self, path):
        trigger_alert(self.session_id, "SFTP List Directory", f"Listed directory: {path}", self.client_ip, self.username)
        if path not in self.fs or self.fs[path]["type"] != "dir":
            raise OSError("No such directory")
        contents = []
        for item in self.fs[path]["contents"]:
            full_path = f"{path}/{item}" if path != "/" else f"/{item}"
            if full_path in self.fs:
                sftp_attr = paramiko.SFTPAttributes()
                sftp_attr.filename = item
                sftp_attr.st_mode = 0o755 if self.fs[full_path]["type"] == "dir" else 0o644
                sftp_attr.st_size = len(self.fs[full_path].get("content", "")) if self.fs[full_path]["type"] == "file" else 0
                contents.append(sftp_attr)
        return contents

    def stat(self, path):
        trigger_alert(self.session_id, "SFTP Stat", f"Queried stats for: {path}", self.client_ip, self.username)
        if path not in self.fs:
            raise OSError("No such file or directory")
        sftp_attr = paramiko.SFTPAttributes()
        sftp_attr.filename = path.split("/")[-1]
        sftp_attr.st_mode = 0o755 if self.fs[path]["type"] == "dir" else 0o644
        sftp_attr.st_size = len(self.fs[path].get("content", "")) if self.fs[path]["type"] == "file" else 0
        return sftp_attr

    def remove(self, path):
        trigger_alert(self.session_id, "SFTP File Delete", f"Attempted to delete: {path}", self.client_ip, self.username)
        raise OSError("Operation not permitted")

    def rename(self, oldpath, newpath):
        trigger_alert(self.session_id, "SFTP File Rename", f"Attempted to rename {oldpath} to {newpath}", self.client_ip, self.username)
        raise OSError("Operation not permitted")

    def mkdir(self, path, attr):
        trigger_alert(self.session_id, "SFTP Create Directory", f"Attempted to create directory: {path}", self.client_ip, self.username)
        raise OSError("Operation not permitted")

    def rmdir(self, path):
        trigger_alert(self.session_id, "SFTP Remove Directory", f"Attempted to remove directory: {path}", self.client_ip, self.username)
        raise OSError("Operation not permitted")

# ==============================
# Lecture de ligne avec autocomplétion et keylogging
# ==============================
def read_line_advanced(chan, prompt, history, current_dir, username, fs, session_log, session_id, client_ip):
    chan.send(prompt.encode())
    command = ""
    cursor_pos = 0
    history_index = len(history)
    start_time = time.time()
    
    while True:
        try:
            char = chan.recv(1).decode('utf-8', errors='ignore')
            if not char:
                break
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            log_keystroke(session_id, client_ip, username, char.encode().hex(), timestamp)
            session_log.write(f"{timestamp}: {char.encode().hex()}\n")
            
            if char == "\r":  # Enter
                chan.send(b"\r\n")
                session_log.write(f"Command: {command}\n")
                try:
                    conn = sqlite3.connect(DB_NAME)
                    cur = conn.cursor()
                    cur.execute("INSERT INTO commands (timestamp, ip, username, command, session_id) VALUES (?, ?, ?, ?, ?)",
                                (timestamp, client_ip, username, command, session_id))
                    conn.commit()
                    conn.close()
                except sqlite3.Error as e:
                    print(f"[!] Erreur lors de l'enregistrement de la commande: {e}")
                return command.strip()
            
            elif char == "\x7f":  # Backspace
                if cursor_pos > 0:
                    command = command[:cursor_pos-1] + command[cursor_pos:]
                    cursor_pos -= 1
                    chan.send(b"\b \b")
                    chan.send(command[cursor_pos:].encode() + b" \b" * (len(command) - cursor_pos))
            
            elif char == "\t":  # Tabulation
                completed = autocomplete(command, current_dir, username, fs)
                if completed != command:
                    chan.send(b"\b" * len(command) + b" " * len(command) + b"\b" * len(command))
                    command = completed
                    cursor_pos = len(command)
                    chan.send(command.encode())
            
            elif char == "\x03":  # Ctrl+C
                chan.send(b"^C\r\n")
                command = ""
                cursor_pos = 0
                chan.send(prompt.encode())
            
            elif char in "\x1b":  # Flèches (séquences ANSI)
                next_chars = chan.recv(2).decode('utf-8', errors='ignore')
                if next_chars == "[A" and history_index > 0:  # Flèche haut
                    history_index -= 1
                    chan.send(b"\b" * len(command) + b" " * len(command) + b"\b" * len(command))
                    command = history[history_index] if history_index < len(history) else ""
                    cursor_pos = len(command)
                    chan.send(command.encode())
                elif next_chars == "[B" and history_index < len(history):  # Flèche bas
                    history_index += 1
                    chan.send(b"\b" * len(command) + b" " * len(command) + b"\b" * len(command))
                    command = history[history_index] if history_index < len(history) else ""
                    cursor_pos = len(command)
                    chan.send(command.encode())
                elif next_chars == "[C" and cursor_pos < len(command):  # Flèche droite
                    cursor_pos += 1
                    chan.send(b"\x1b[C")
                elif next_chars == "[D" and cursor_pos > 0:  # Flèche gauche
                    cursor_pos -= 1
                    chan.send(b"\x1b[D")
            
            elif char.isprintable():
                command = command[:cursor_pos] + char + command[cursor_pos:]
                cursor_pos += 1
                chan.send(char.encode())
                if cursor_pos < len(command):
                    chan.send(command[cursor_pos:].encode() + b"\b" * (len(command) - cursor_pos))
        
        except Exception as e:
            print(f"[!] Erreur dans read_line_advanced: {e}")
            trigger_alert(session_id, "Session Error", f"Error in input handling: {str(e)}", client_ip, username)
            break
    
    return ""

# ==============================
# Traitement des commandes
# ==============================
def process_command(cmd, current_dir, username, fs, client_ip, session_id, session_log):
    if not cmd.strip():
        return "", current_dir
    
    new_dir = current_dir
    output = ""
    
    # Séparer la commande et les arguments
    cmd_parts = cmd.strip().split()
    cmd_name = cmd_parts[0].lower()
    arg_str = " ".join(cmd_parts[1:]) if len(cmd_parts) > 1 else ""
    
    # Journaliser la commande
    session_log.write(f"[{datetime.now()}] {username}@{client_ip}: {cmd}\n")
    
    if cmd_name == "ls" or cmd_name == "dir":
        path = arg_str if arg_str else current_dir
        if path.startswith("~"):
            path = path.replace("~", f"/home/{username}", 1)
        if not path.startswith("/"):
            path = f"{current_dir}/{path}" if current_dir != "/" else f"/{path}"
        path = os.path.normpath(path)
        
        if path in fs and fs[path]["type"] == "dir":
            if arg_str == "-l":
                lines = []
                for item in fs[path]["contents"]:
                    full_path = f"{path}/{item}" if path != "/" else f"/{item}"
                    if full_path in fs:
                        item_type = "d" if fs[full_path]["type"] == "dir" else "-"
                        perms = "rwxr-xr-x" if item_type == "d" else "rw-r--r--"
                        size = len(fs[full_path].get("content", "")) if fs[full_path]["type"] == "file" else 0
                        mod_time = datetime.now().strftime("%b %d %H:%M")
                        lines.append(f"{item_type}{perms} 1 {username} {username} {size:>8} {mod_time} {item}")
                output = "\n".join(lines)
            else:
                output = " ".join(fs[path]["contents"])
            trigger_alert(session_id, "Command Executed", f"Listed directory: {path}", client_ip, username)
        else:
            output = f"ls: cannot access '{arg_str}': No such file or directory"
            trigger_alert(session_id, "Invalid Path", f"Attempted to list non-existent directory: {path}", client_ip, username)
    
    elif cmd_name == "cd":
        path = arg_str if arg_str else f"/home/{username}"
        if path.startswith("~"):
            path = path.replace("~", f"/home/{username}", 1)
        if not path.startswith("/"):
            path = f"{current_dir}/{path}" if current_dir != "/" else f"/{path}"
        path = os.path.normpath(path)
        
        if path in fs and fs[path]["type"] == "dir":
            new_dir = path
            trigger_alert(session_id, "Directory Changed", f"Changed directory to {path}", client_ip, username)
        else:
            output = f"cd: {arg_str}: No such file or directory"
            trigger_alert(session_id, "Invalid Path", f"Attempted to change to non-existent directory: {path}", client_ip, username)
    
    elif cmd_name == "pwd":
        output = current_dir
        trigger_alert(session_id, "Command Executed", "Displayed current directory", client_ip, username)
    
    elif cmd_name == "whoami":
        output = username
        trigger_alert(session_id, "Command Executed", "Displayed current user", client_ip, username)
    
    elif cmd_name == "id":
        uid = 1000 if username == "admin" else 1001 if username == "devops" else 1002 if username == "dbadmin" else 0
        output = f"uid={uid}({username}) gid={uid}({username}) groups={uid}({username})"
        trigger_alert(session_id, "Command Executed", "Displayed user ID", client_ip, username)
    
    elif cmd_name == "uname":
        if arg_str == "-a":
            output = "Linux debian 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 GNU/Linux"
        else:
            output = "Linux"
        trigger_alert(session_id, "Command Executed", "Displayed system information", client_ip, username)
    
    elif cmd_name == "cat":
        if not arg_str:
            output = "cat: missing file operand"
            trigger_alert(session_id, "Command Error", "cat executed without arguments", client_ip, username)
        else:
            path = arg_str
            if path.startswith("~"):
                path = path.replace("~", f"/home/{username}", 1)
            if not path.startswith("/"):
                path = f"{current_dir}/{path}" if current_dir != "/" else f"/{path}"
            path = os.path.normpath(path)
            
            if path in HONEY_TOKEN_FILES:
                trigger_alert(session_id, "Honeytoken Access", f"Accessed sensitive file: {path}", client_ip, username)
            
            if path == "/etc/shadow" and username != "root":
                output = "cat: /etc/shadow: Permission denied"
                trigger_alert(session_id, "Permission Denied", f"Attempted to access /etc/shadow", client_ip, username)
            elif path in fs and fs[path]["type"] == "file":
                content = fs[path]["content"]
                output = content() if callable(content) else content
                trigger_alert(session_id, "File Access", f"Read file: {path}", client_ip, username)
            else:
                output = f"cat: {arg_str}: No such file or directory"
                trigger_alert(session_id, "Invalid File", f"Attempted to read non-existent file: {path}", client_ip, username)
    
    elif cmd_name == "rm":
        if not arg_str:
            output = "rm: missing operand"
            trigger_alert(session_id, "Command Error", "rm executed without arguments", client_ip, username)
        else:
            path = arg_str
            if path.startswith("~"):
                path = path.replace("~", f"/home/{username}", 1)
            if not path.startswith("/"):
                path = f"{current_dir}/{path}" if current_dir != "/" else f"/{path}"
            path = os.path.normpath(path)
            
            if path in fs:
                if fs[path]["type"] == "file":
                    parent_dir = "/".join(path.split("/")[:-1]) or "/"
                    if username != "root" and path in HONEY_TOKEN_FILES:
                        output = "rm: cannot remove '{}': Permission denied".format(arg_str)
                        trigger_alert(session_id, "Access Denied", f"Attempted to delete {path}", client_ip, username)
                    else:
                        fs[parent_dir]["contents"].remove(path.rsplit("/", 1)[1])
                        del fs[path]
                        trigger_alert(session_id, "File Deletion", f"Deleted file {path}", client_ip, username)
                else:
                    output = f"rm: cannot remove '{arg_str}': Is a directory"
                    trigger_alert(session_id, "Invalid Operation", f"Attempted to delete directory {path}", client_ip, username)
            else:
                output = f"rm: cannot remove '{arg_str}': No such file or directory"
                trigger_alert(session_id, "Invalid File", f"Attempted to delete non-existent file {path}", client_ip, username)
    
    elif cmd_name == "ps":
        output = get_dynamic_ps()
        trigger_alert(session_id, "Command Executed", "Listed processes", client_ip, username)
    
    elif cmd_name == "netstat":
        output = get_dynamic_netstat()
        trigger_alert(session_id, "Command Executed", "Displayed network connections", client_ip, username)
    
    elif cmd_name == "uptime":
        output = get_dynamic_uptime()
        trigger_alert(session_id, "Command Executed", "Displayed system uptime", client_ip, username)
    
    elif cmd_name == "df":
        output = get_dynamic_df()
        trigger_alert(session_id, "Command Executed", "Displayed disk usage", client_ip, username)
    
    elif cmd_name == "top":
        output = get_dynamic_top()
        trigger_alert(session_id, "Command Executed", "Displayed process monitor", client_ip, username)
    
    elif cmd_name == "ifconfig":
        output = get_dynamic_ifconfig()
        trigger_alert(session_id, "Command Executed", "Displayed network interfaces", client_ip, username)
    
    elif cmd_name == "ip":
        if arg_str == "addr" or arg_str == "a":
            output = get_dynamic_ip_addr()
            trigger_alert(session_id, "Command Executed", "Displayed IP addresses", client_ip, username)
        else:
            output = f"ip: invalid option -- '{arg_str}'"
            trigger_alert(session_id, "Command Error", f"Invalid ip option: {arg_str}", client_ip, username)
    
    elif cmd_name == "iptables":
        if arg_str == "-L":
            output = get_dynamic_iptables()
            trigger_alert(session_id, "Command Executed", "Listed firewall rules", client_ip, username)
        else:
            output = f"iptables: unrecognized option '{arg_str}'"
            trigger_alert(session_id, "Command Error", f"Invalid iptables option: {arg_str}", client_ip, username)
    
    elif cmd_name in ["service", "systemctl"]:
        if arg_str:
            args = arg_str.split()
            if len(args) >= 2 and args[1] == "status":
                output = get_dynamic_service_status(args[0])
                trigger_alert(session_id, "Command Executed", f"Checked status of service {args[0]}", client_ip, username)
            else:
                output = f"{cmd_name}: invalid command '{arg_str}'"
                trigger_alert(session_id, "Command Error", f"Invalid {cmd_name} command: {arg_str}", client_ip, username)
        else:
            output = f"{cmd_name}: missing arguments"
            trigger_alert(session_id, "Command Error", f"{cmd_name} executed without arguments", client_ip, username)
    
    elif cmd_name == "crontab":
        if arg_str == "-l":
            output = get_dynamic_crontab()
            trigger_alert(session_id, "Command Executed", "Listed scheduled tasks", client_ip, username)
        else:
            output = f"crontab: invalid option '{arg_str}'"
            trigger_alert(session_id, "Command Error", f"Invalid crontab option: {arg_str}", client_ip, username)
    
    elif cmd_name == "dmesg":
        output = get_dynamic_dmesg()
        trigger_alert(session_id, "Command Executed", "Displayed kernel messages", client_ip, username)
    
    elif cmd_name == "grep":
        if not arg_str:
            output = "grep: missing pattern"
            trigger_alert(session_id, "Command Error", "grep executed without arguments", client_ip, username)
        else:
            output = f"grep: pattern '{arg_str}' not found"
            trigger_alert(session_id, "Command Executed", f"Executed grep with pattern: {arg_str}", client_ip, username)
    
    elif cmd_name == "who":
        output = get_dynamic_who()
        trigger_alert(session_id, "Command Executed", "Listed active users", client_ip, username)
    
    elif cmd_name == "w":
        output = get_dynamic_w()
        trigger_alert(session_id, "Command Executed", "Displayed user activity", client_ip, username)
    
    elif cmd_name == "last":
        output = get_dynamic_last()
        trigger_alert(session_id, "Command Executed", "Displayed login history", client_ip, username)
    
    elif cmd_name == "ss":
        output = get_dynamic_ss()
        trigger_alert(session_id, "Command Executed", "Displayed socket statistics", client_ip, username)
    
    elif cmd_name in ["curl", "wget", "telnet"]:
        output = f"{cmd_name}: connection refused (simulated)"
        trigger_alert(session_id, "Network Command", f"Attempted {cmd_name} with args: {arg_str}", client_ip, username)
    
    elif cmd_name in ["chmod", "chown"]:
        output = f"{cmd_name}: operation not supported in this environment"
        trigger_alert(session_id, "Command Executed", f"Attempted {cmd_name} with args: {arg_str}", client_ip, username)
    
    elif cmd_name in ["vim", "nano"]:
        output = f"{cmd_name}: editing not supported in this environment"
        trigger_alert(session_id, "Command Executed", f"Attempted to use editor {cmd_name}", client_ip, username)
    
    elif cmd_name in ["sudo", "su"]:
        output = f"{cmd_name}: permission denied"
        trigger_alert(session_id, "Permission Denied", f"Attempted to execute {cmd_name}", client_ip, username)
    
    elif cmd_name == "history":
        history = load_history(username)
        output = "\n".join(f"{i+1}  {cmd}" for i, cmd in enumerate(history))
        trigger_alert(session_id, "Command Executed", "Displayed command history", client_ip, username)
    
    elif cmd_name == "exit":
        return "exit", new_dir
    
    else:
        output = f"bash: {cmd_name}: command not found"
        trigger_alert(session_id, "Unknown Command", f"Attempted unknown command: {cmd}", client_ip, username)
    
    return output, new_dir

# ==============================
# Authentification SSH
# ==============================
class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, session_id):
        self.client_ip = client_ip
        self.session_id = session_id
        self.event = threading.Event()
        self.attempts = 0

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.attempts += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        success = 0
        redirected = 0
        
        with _brute_force_lock:
            try:
                conn = sqlite3.connect(DB_NAME)
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND timestamp > ?",
                            (self.client_ip, (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")))
                count = cur.fetchone()[0]
                if count >= BRUTE_FORCE_THRESHOLD and self.client_ip not in _brute_force_alerted:
                    _brute_force_alerted.add(self.client_ip)
                    trigger_alert(self.session_id, "Brute Force Detected", f"Multiple login attempts from {self.client_ip}", self.client_ip, username)
                cur.execute("""
                    INSERT INTO login_attempts(timestamp, ip, username, password, success, redirected)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (timestamp, self.client_ip, username, password, success, redirected))
                conn.commit()
                conn.close()
            except sqlite3.Error as e:
                print(f"[!] Erreur lors de l'enregistrement de la tentative de connexion: {e}")
        
        trigger_alert(self.session_id, "Login Attempt", f"Username: {username}, Password: {password}", self.client_ip, username)
        return paramiko.AUTH_SUCCESSFUL  # Accepter toutes les connexions pour capturer les tentatives

    def get_allowed_auths(self, username):
        return "password"

# ==============================
# Gestion de la session SSH
# ==============================
def handle_session(chan, client_ip, session_id):
    try:
        username = "unknown"
        transport = chan.get_transport()
        username = transport.get_username() or "unknown"
        session_log_path = os.path.join(SESSION_LOG_DIR, f"session_{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        with open(session_log_path, "a", encoding="utf-8") as session_log:
            home_dir = PREDEFINED_USERS.get(username, {}).get("home", f"/home/{username}")
            current_dir = home_dir
            history = load_history(username)
            prompt = f"{username}@debian:{current_dir.replace('/home/' + username, '~')}$ "
            chan.send(f"Last login: {(datetime.now() - timedelta(minutes=random.randint(1, 60))).strftime('%a %b %d %H:%M:%S %Y')} from 192.168.1.{random.randint(10, 50)}\r\n".encode())
            trigger_alert(session_id, "Session Started", f"New session started for {username}", client_ip, username)
            
            while True:
                try:
                    command = read_line_advanced(chan, prompt, history, current_dir, username, BASE_FILE_SYSTEM, session_log, session_id, client_ip)
                    if command:
                        history.append(command)
                        save_history(username, history)
                    if command == "exit":
                        break
                    output, current_dir = process_command(command, current_dir, username, BASE_FILE_SYSTEM, client_ip, session_id, session_log)
                    if output:
                        chan.send((output + "\r\n").encode())
                    prompt = f"{username}@debian:{current_dir.replace('/home/' + username, '~')}$ "
                except Exception as e:
                    print(f"[!] Erreur dans la session: {e}")
                    chan.send(f"Error: {e}\r\n".encode())
                    trigger_alert(session_id, "Session Error", f"Error during session: {str(e)}", client_ip, username)
    finally:
        chan.close()
        trigger_alert(session_id, "Session Ended", f"Session ended for {username}", client_ip, username)

# ==============================
# Gestion des connexions clientes
# ==============================
def handle_client(client, addr):
    session_id = str(uuid.uuid4())
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(paramiko.RSAKey.generate(bits=2048))
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, SFTPServer)
        transport.banner = SSH_BANNER
        server = Server(addr[0], session_id)
        transport.start_server(server=server)
        chan = transport.accept(20)
        if chan is None:
            print(f"[!] Aucun canal pour {addr[0]}")
            return
        print(f"[+] Nouvelle connexion de {addr[0]}")
        trigger_alert(session_id, "Connection", f"New connection from {addr[0]}", addr[0], "unknown")
        handle_session(chan, addr[0], session_id)
    except Exception as e:
        print(f"[!] Exception lors de la gestion du client {addr[0]}: {e}")
        trigger_alert(session_id, "Connection Error", f"Error handling client: {str(e)}", addr[0], "unknown")
    finally:
        client.close()

# ==============================
# Gestion des signaux
# ==============================
def signal_handler(sig, frame):
    print("[*] Arrêt du serveur...")
    stop_event.set()
    sys.exit(0)

# ==============================
# Démarrage du serveur
# ==============================
def start_server():
    global stop_event
    stop_event = threading.Event()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(100)
        print(f"[*] Serveur SSH démarré sur le port {PORT}")
        init_database()
        weekly_report_thread()
        
        # Démarrer les faux services réseau
        for service, port in FAKE_SERVICES.items():
            if service == "ftp":
                threading.Thread(target=fake_ftp_server, args=(port, stop_event), daemon=True).start()
            elif service == "http":
                threading.Thread(target=fake_http_server, args=(port, stop_event), daemon=True).start()
            elif service == "mysql":
                threading.Thread(target=fake_mysql_server, args=(port, stop_event), daemon=True).start()
        
        while not stop_event.is_set():
            readable, _, _ = select.select([server_socket], [], [], 1.0)
            if server_socket in readable:
                client, addr = server_socket.accept()
                threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()
    except Exception as e:
        print(f"[!] Erreur du serveur: {e}")
    finally:
        server_socket.close()
        stop_event.set()
        print("[*] Serveur arrêté")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    start_server()
