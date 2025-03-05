#!/bin/bash

# Activer l'IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Réinitialiser les règles
iptables -F
iptables -X
iptables -Z

# Bloquer SSH réel et rediriger le trafic vers le honeypot
iptables -A INPUT -p tcp --dport 22 -j DROP
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Autoriser les autres services
iptables -A INPUT -p tcp --dport 80 -j ACCEPT  # HTTP
iptables -A INPUT -p tcp --dport 21 -j ACCEPT  # FTP
iptables -A INPUT -p tcp --dport 3389 -j ACCEPT  # RDP

# Bloquer le reste
iptables -A INPUT -j DROP

echo "🔒 Firewall SSH Honeypot Configuré !"
