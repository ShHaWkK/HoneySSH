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

This project is intended for educational and demonstration purposes only.
