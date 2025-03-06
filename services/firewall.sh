#!/bin/bash

# Activer l'IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Réinitialiser les règles existantes
iptables -F
iptables -X
iptables -Z
iptables -t nat -F

# Autoriser les connexions existantes et associées
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Autoriser le trafic DNS (évite les problèmes de résolution)
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --sport 53 -j ACCEPT

# Autoriser le ping (utile pour le diagnostic)
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

# Bloquer SSH réel et rediriger vers le honeypot
iptables -A INPUT -p tcp --dport 22 -j DROP
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Autoriser HTTP(S) pour mises à jour et logs web
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --sport 443 -j ACCEPT

# Autoriser d'autres services (exemple FTP, RDP si besoin)
iptables -A INPUT -p tcp --dport 21 -j ACCEPT  # FTP
iptables -A INPUT -p tcp --dport 3389 -j ACCEPT  # RDP

# Bloquer tout le reste
iptables -A INPUT -j DROP

echo "🔒 Firewall SSH Honeypot Configuré !"

# Sauvegarder les règles
iptables-save > /etc/iptables.rules
