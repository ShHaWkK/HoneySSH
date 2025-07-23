import random
import string
from datetime import datetime, timedelta
from functools import lru_cache
from .constants import FAKE_NETWORK_HOSTS, FAKE_SERVICES

def color_prompt(username, client_ip, current_dir):
    """Retourne l'invite de commande colorisee pour l'utilisateur."""
    user_color = "\033[1;31m" if username == "root" else "\033[1;32m"
    dir_color = (
        "\033[1;31m" if current_dir in ["/root", "/etc", "/var/log"] else "\033[1;34m"
    )
    return (
        f"{user_color}{username}@{client_ip}\033[0m:{dir_color}{current_dir}\033[0m$ "
    )


# Données dynamiques
@lru_cache(maxsize=10)
def get_dynamic_df():
    """Simule la commande 'df' avec des valeurs aleatoires."""
    sizes = {"sda1": "50G", "tmpfs": "100M"}
    used = {"sda1": f"{random.randint(5, 10)}G", "tmpfs": "0M"}
    avail = {"sda1": f"{random.randint(30, 45)}G", "tmpfs": "100M"}
    usep = {"sda1": f"{random.randint(10, 20)}%", "tmpfs": "0%"}
    return f"""Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        {sizes['sda1']}   {used['sda1']}   {avail['sda1']}  {usep['sda1']} /
tmpfs           {sizes['tmpfs']}     {used['tmpfs']}  {avail['tmpfs']}   {usep['tmpfs']} /tmp"""


@lru_cache(maxsize=10)
def get_dynamic_uptime():
    """Simule la sortie de la commande 'uptime'."""
    now = datetime.now().strftime("%H:%M:%S")
    days = random.randint(3, 10)
    hours = random.randint(0, 23)
    minutes = random.randint(0, 59)
    users = random.randint(1, 5)
    la1, la2, la3 = [f"{random.uniform(0.00, 1.00):.2f}" for _ in range(3)]
    return f"{now} up {days} days, {hours}:{minutes:02d}, {users} user{'s' if users > 1 else ''}, load average: {la1}, {la2}, {la3}"


@lru_cache(maxsize=10)
def get_dynamic_ps():
    """Genere une liste fictive de processus systeme."""
    processes = [
        ("root", "1", "/sbin/init"),
        ("root", "135", "/usr/sbin/sshd -D"),
        ("mysql", "220", "/usr/sbin/mysqld"),
        ("www-data", "300", "/usr/sbin/nginx -g 'daemon off;'"),
        ("admin", str(random.randint(1000, 5000)), "/bin/bash"),
        ("devops", str(random.randint(1000, 5000)), "/usr/bin/python3 app.py"),
        ("dbadmin", str(random.randint(1000, 5000)), "/bin/sh scripts.sh"),
    ]
    if random.random() < 0.3:
        processes.append(
            ("root", str(random.randint(6000, 7000)), "/usr/bin/find / -name '*.log'")
        )
    lines = ["USER       PID %CPU %MEM    VSZ   RSS TTY   STAT START   TIME COMMAND"]
    for user, pid, cmd in processes:
        cpu = round(random.uniform(0.0, 5.0), 1)
        mem = round(random.uniform(0.5, 3.0), 1)
        vsz = random.randint(10000, 50000)
        rss = random.randint(1000, 5000)
        tty = random.choice(["pts/0", "pts/1", "?", "tty7"])
        stat = random.choice(["Ss", "S+", "R"])
        start = (datetime.now() - timedelta(hours=random.randint(1, 24))).strftime(
            "%H:%M"
        )
        time_str = f"{random.randint(0, 2)}:{random.randint(0, 59):02d}"
        lines.append(
            f"{user:<10} {pid:<6} {cpu:<5} {mem:<5} {vsz:<7} {rss:<6} {tty:<6} {stat:<5} {start:<8} {time_str:<6} {cmd}"
        )
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_top():
    """Retourne une sortie type 'top' basee sur des donnees aleatoires."""
    header = (
        "top - %s up %d days, %02d:%02d, %d user%s, load average: %.2f, %.2f, %.2f\n"
        % (
            datetime.now().strftime("%H:%M:%S"),
            random.randint(3, 10),
            random.randint(0, 23),
            random.randint(0, 59),
            random.randint(1, 5),
            "s" if random.randint(1, 5) > 1 else "",
            random.uniform(0.0, 1.0),
            random.uniform(0.0, 1.0),
            random.uniform(0.0, 1.0),
        )
    )
    tasks = "Tasks: %d total, %d running, %d sleeping, %d stopped, %d zombie\n" % (
        random.randint(50, 100),
        random.randint(1, 5),
        random.randint(40, 80),
        0,
        0,
    )
    cpu = (
        "%%Cpu(s): %.1f us, %.1f sy, %.1f ni, %.1f id, %.1f wa, %.1f hi, %.1f si, %.1f st\n"
        % (
            random.uniform(0, 10),
            random.uniform(0, 5),
            0,
            random.uniform(80, 90),
            random.uniform(0, 2),
            random.uniform(0, 1),
            random.uniform(0, 1),
            0,
        )
    )
    mem = "MiB Mem : %d total, %d free, two %d used, %d buff/cache\n" % (
        random.randint(16000, 32000),
        random.randint(1000, 5000),
        random.randint(5000, 10000),
        random.randint(1000, 5000),
    )
    processes = get_dynamic_ps().split("\n")[1:]
    return header + tasks + cpu + mem + "\n" + "\n".join(processes[:5])


@lru_cache(maxsize=10)
def get_dynamic_netstat():
    """Cree un tableau de connexions reseau factices."""
    lines = [
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name"
    ]
    for _ in range(random.randint(2, 6)):
        local_ip = f"192.168.1.{random.randint(2, 254)}"
        local_port = random.choice([22, 80, 443, 3306, 8080])
        foreign_ip = f"10.0.0.{random.randint(2, 254)}"
        foreign_port = random.randint(1024, 65535)
        state = random.choice(["ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "LISTEN"])
        pid_prog = f"{random.randint(100, 999)}/app{random.randint(1, 5)}"
        lines.append(
            f"tcp        {random.randint(0, 10)}      {random.randint(0, 10)} {local_ip}:{local_port}  {foreign_ip}:{foreign_port}  {state:<10} {pid_prog}"
        )
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_messages():
    """Fournit des messages pour simuler /var/log/messages."""
    lines = []
    for _ in range(10):
        timestamp = (
            datetime.now() - timedelta(minutes=random.randint(0, 1440))
        ).strftime("%b %d %H:%M:%S")
        src_ip = f"192.168.1.{random.randint(2, 254)}"
        service = random.choice(
            ["sshd", "systemd", "cron", "nginx", "apache2", "mysqld"]
        )
        message = random.choice(
            [
                f"{service}[{random.randint(1000, 9999)}]: Started {service} service.",
                f"{service}: Connection from {src_ip}",
                f"{service}: Configuration loaded successfully.",
                f"{service}: Warning: High CPU usage detected.",
                f"{service}: Failed login attempt from {src_ip}",
                f"{service}: Suspicious activity on port {random.randint(1024, 65535)}",
            ]
        )
        lines.append(f"{timestamp} debian {message}")
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_dmesg():
    """Genere de fausses lignes provenant du noyau."""
    lines = []
    for _ in range(10):
        timestamp = f"[{random.uniform(0, 1000):.6f}]"
        message = random.choice(
            [
                "kernel: [CPU0] microcode updated early to revision 0xca",
                "kernel: random: crng init done",
                "kernel: EXT4-fs (sda1): mounted filesystem with ordered data mode",
                "kernel: ACPI: Power Button [PWRB]",
            ]
        )
        lines.append(f"{timestamp} {message}")
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_network_scan():
    """Simule les resultats d'un scan reseau."""
    lines = []
    for ip, info in FAKE_NETWORK_HOSTS.items():
        for service in info["services"]:
            port = FAKE_SERVICES.get(service, 0)
            if port:
                lines.append(f"{ip}:{port} open {service}")
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_traceroute(host):
    """Genere un traceroute fictif vers la cible."""
    hops = random.randint(5, 10)
    lines = [f"traceroute to {host} ({host}), {hops} hops max"]
    for i in range(1, hops + 1):
        ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
        latency = random.uniform(1.0, 100.0)
        lines.append(f" {i}  {ip}  {latency:.2f} ms")
    lines.append(f" {hops + 1}  {host}  {random.uniform(0.1, 1.0):.2f} ms")
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_dig(query):
    """Renvoie une reponse DNS fictive."""
    ip = f"203.0.113.{random.randint(1, 254)}"
    return (
        f"; <<>> DiG 9.18 <<>> {query}\n"
        ";; ANSWER SECTION:\n"
        f"{query}. 86400 IN A {ip}\n"
        f"{query}. 86400 IN NS ns1.example.com.\n"
        f"{query}. 86400 IN NS ns2.example.com."
    )


@lru_cache(maxsize=10)
def get_dynamic_tcpdump():
    """Genere quelques en-tetes de paquets simulés."""
    lines = []
    for _ in range(random.randint(3, 6)):
        src = f"192.168.1.{random.randint(2, 254)}"
        dst = f"10.0.0.{random.randint(1, 254)}"
        sport = random.randint(1024, 65535)
        dport = random.choice([22, 80, 443, 3306])
        proto = random.choice(["TCP", "UDP"])
        lines.append(
            f"{proto} {src}:{sport} > {dst}:{dport} Flags [S], length 0"
        )
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_ss():
    """Simule la commande 'ss' en reutilisant netstat."""
    return get_dynamic_netstat()


@lru_cache(maxsize=10)
def get_dynamic_arp():
    """Renvoie une table ARP fictive."""
    lines = [
        "Address                  HWtype  HWaddress           Flags Mask            Iface"
    ]
    for ip in FAKE_NETWORK_HOSTS:
        mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        lines.append(f"{ip:<24} ether   {mac}   C                     eth0")
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_who():
    """Simule la commande 'who'."""
    lines = []
    users = ["admin", "devops", "dbadmin"] + [
        f"temp_{''.join(random.choices(string.ascii_lowercase, k=6))}"
        for _ in range(random.randint(0, 3))
    ]
    for user in users:
        timestamp = (
            datetime.now() - timedelta(minutes=random.randint(0, 1440))
        ).strftime("%Y-%m-%d %H:%M")
        tty = random.choice(["pts/0", "pts/1", "tty7"])
        host = f"192.168.1.{random.randint(10, 50)}"
        lines.append(f"{user:<10} {tty:<8} {timestamp} {host}")
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_dynamic_w():
    """Simule la commande 'w'."""
    return get_dynamic_who()


def get_dev_null():
    """Equivalent a /dev/null, renvoie une chaine vide."""
    return ""


def get_dev_zero():
    """Equivalent a /dev/zero, renvoie des octets nuls."""
    return "\0" * 1024


@lru_cache(maxsize=10)
def get_realistic_docker_ps():
    """Genere une sortie ressemblant a 'docker ps'."""
    lines = [
        "CONTAINER ID   IMAGE          COMMAND                  CREATED          STATUS          PORTS                    NAMES",
        "2f7b8c1d2e3f   nginx:latest   'nginx -g \"daemon off;\"'  2 hours ago      Up 2 hours      0.0.0.0:80->80/tcp       web",
        "7c9d0e1f2a3b   postgres:13    'docker-entrypoint.s…'   3 hours ago      Up 3 hours      0.0.0.0:5432->5432/tcp   db",
    ]
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_realistic_docker_compose_up():
    """Genere une sortie typee de 'docker-compose up'."""
    return (
        "Creating network \"myapp_default\" with the default driver\n"
        "Creating volume \"myapp_db_data\" with default driver\n"
        "Creating myapp_db_1 ... done\n"
        "Creating myapp_web_1 ... done"
    )


@lru_cache(maxsize=10)
def get_realistic_kubectl_get_pods():
    """Genere une sortie ressemblant a 'kubectl get pods'."""
    lines = [
        "NAME                         READY   STATUS    RESTARTS   AGE",
        "webserver-6d7ffbd4c8-wx4gm   1/1     Running   0          3d4h",
        "database-0                   1/1     Running   0          3d4h",
    ]
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_realistic_helm_list():
    """Genere une sortie pour 'helm list'."""
    lines = [
        "NAME       NAMESPACE  REVISION  UPDATED                                 STATUS    CHART                APP VERSION",
        "nginx      default    1         2024-06-01 12:00:00.000000 +0000 UTC     deployed  nginx-8.9.1          1.25.2",
        "postgres   default    2         2024-06-01 12:05:00.000000 +0000 UTC     deployed  postgresql-10.3.11   14.2.0",
    ]
    return "\r\n".join(lines)


@lru_cache(maxsize=10)
def get_realistic_git_status():
    """Genere une sortie realiste pour 'git status'."""
    return (
        "On branch main\n"
        "Your branch is up to date with 'origin/main'.\n\n"
        "nothing to commit, working tree clean"
    )


@lru_cache(maxsize=10)
def get_realistic_git_push():
    """Genere une sortie realiste pour 'git push' echouant."""
    return (
        "Enumerating objects: 5, done.\n"
        "Counting objects: 100% (5/5), done.\n"
        "Delta compression using up to 8 threads\n"
        "Compressing objects: 100% (3/3), done.\n"
        "Writing objects: 100% (3/3), 291 bytes | 291.00 KiB/s, done.\n"
        "Total 3 (delta 2), reused 0 (delta 0), pack-reused 0\n"
        "remote: error: insufficient permissions\n"
        "To github.com:fake/repo.git\n"
        " ! [remote rejected] main -> main (permission denied)\n"
        "error: failed to push some refs to 'github.com:fake/repo.git'"
    )


