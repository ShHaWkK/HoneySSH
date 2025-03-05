#!/bin/bash

# Activer l'IP forwarding pour la communication entre les services
echo 1 > /proc/sys/net/ipv4/ip_forward

# Réinitialiser les règles
iptables -F
iptables -X
iptables -Z

# Bloquer les connexions de certaines IPs connues (honeypot détecteurs)
iptables -A INPUT -s 45.33.32.156 -j DROP
iptables -A INPUT -s 185.220.101.0/24 -j DROP

# Bloquer le SSH réel (si le port 22 est actif)
iptables -A INPUT -p tcp --dport 22 -j DROP

# Autoriser uniquement notre honeypot SSH (port 2222)
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT

# Activer le logging des connexions SSH suspectes
iptables -A INPUT -p tcp --dport 2222 -m limit --limit 5/min -j LOG --log-prefix "SSH Honeypot Attempt: "

# Rediriger les tentatives SSH (22 → 2222)
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Permettre les connexions entre les services (HTTP, FTP, RDP)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT  # HTTP
iptables -A INPUT -p tcp --dport 21 -j ACCEPT  # FTP
iptables -A INPUT -p tcp --dport 3389 -j ACCEPT  # RDP

# Bloquer tout le reste
iptables -A INPUT -j DROP

echo "🔒 Firewall Honeypot SSH Configuré !"
