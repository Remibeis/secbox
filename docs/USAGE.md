# 📖 SecBox — Guide d'Utilisation Détaillé

## Lancement rapide

```bash
# Builder + lancer l'interface web
docker build -t secbox .
docker run -it --rm -p 5000:5000 --cap-add NET_RAW --cap-add NET_ADMIN secbox web

# Ou avec docker-compose
docker compose up --build
```

## Les 12 outils — Exemples concrets

### 🔍 Nmap — Scanner de ports

```bash
# Scan SYN rapide sur les 1000 premiers ports
nmap -sS -p 1-1000 scanme.nmap.org

# Scan complet avec versions et OS
nmap -sS -sV -O scanme.nmap.org

# Découverte d'hôtes sur un réseau
nmap -sn 192.168.1.0/24
```

### 🔍 Masscan — Scanner ultra-rapide

```bash
# Scanner tout le range /24 sur les ports web
masscan 192.168.1.0/24 -p80,443 --rate=1000
```

### 🛡️ Nikto — Vulnérabilités web

```bash
# Scan d'un serveur web
nikto -h http://example.com -maxtime 120s
```

### 🛡️ Nuclei — Templates de vulnérabilités

```bash
# Scan avec sévérité haute et critique
nuclei -u https://example.com -severity high,critical
```

### 🔑 Hydra — Brute-force

```bash
# SSH brute-force
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.10 -t 4

# FTP brute-force
hydra -l admin -P /usr/share/wordlists/dirb/common.txt ftp://192.168.1.10
```

### 🔑 Medusa — Brute-force parallèle

```bash
# SSH
medusa -h 192.168.1.10 -u admin -P /usr/share/wordlists/rockyou.txt -M ssh -t 4
```

### 📡 Tcpdump — Capture paquets

```bash
# Capturer 50 paquets HTTP
tcpdump -i eth0 -c 50 -nn port 80

# Capturer tout le trafic vers un fichier
tcpdump -i eth0 -w /app/results/capture.pcap
```

### 📡 Tshark — Wireshark CLI

```bash
# Capturer et filtrer le trafic HTTP
tshark -i eth0 -c 50 -Y http

# Statistiques DNS
tshark -i eth0 -c 100 -Y dns
```

### 🕵️ theHarvester — OSINT

```bash
# Récolter les emails et sous-domaines
theHarvester -d example.com -b google -l 200
```

### 🕵️ Amass — Enumération de sous-domaines

```bash
# Mode passif (rapide)
amass enum -passive -d example.com

# Mode actif (plus complet)
amass enum -d example.com
```

### 🌐 SQLmap — Injection SQL

```bash
# Test automatique d'injection
sqlmap -u "http://target.com/page?id=1" --batch --level=3 --random-agent
```

### 🌐 WhatWeb — Fingerprinting

```bash
# Identification des technologies
whatweb https://example.com -a 3
```

## Récupérer les résultats

Avec docker-compose, les résultats sont automatiquement montés dans `./results/` sur votre machine hôte.

Sans docker-compose :
```bash
# Copier les résultats depuis le conteneur
docker cp secbox:/app/results ./results
```

## Cibles de test légales

- `scanme.nmap.org` — Serveur officiel de test Nmap
- `testphp.vulnweb.com` — Application web vulnérable (Acunetix)
- `HackTheBox.com` — Plateforme CTF
- `TryHackMe.com` — Labs de pentest







kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk
