# HoneySSH

HoneySSH is a lightweight SSH honeypot written in Python. It simulates a Unix environment with fake filesystem, network commands and a MySQL shell to lure attackers.

## Usage

```bash
pip install -r requirements.txt
python3 services/honey.py
```

## Features

- Simulated filesystem with common directories and files
- Fake network tools: `ping`, `traceroute`, `dig`, `ftp`, `telnet`, `curl`, `wget`
- Basic system commands: `ls`, `cd`, `cat`, `mkdir`, `rm`, `ps`, `df`, `uptime`, `hostname`
- Simulated firewall management via `iptables`
- Enhanced FTP client with directory management and file transfers
- Service management via `service` and `systemctl`
- Interactive `mysql` monitor supporting `SELECT`, `DESCRIBE`, `INSERT`, `UPDATE`, and `DELETE`
- Output redirection with `>` or `>>` to save command output into files

This project is intended for educational and demonstration purposes only.

### Docker Compose

A `docker-compose.yml` is provided to run HoneySSH in a container. Start it with color output:

```bash
docker compose up --build --ansi always
```

The honeypot listens on port **2224**.

### Interactive REPLs

Inside an SSH session you can run:

- `mysql` to enter a fake MySQL monitor with support for `SHOW`, `USE`, `DESCRIBE`, `SELECT`, `INSERT`, `UPDATE`, and `DELETE`.
- `python` to open a minimal Python interpreter.

These REPLs allow attackers to interact with the environment in a more realistic way.
