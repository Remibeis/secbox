# ⚡ SecBox — Boîte à Outils Sécurité Dockerisée

> **Un conteneur Docker tout-en-un embarquant 12 outils offensifs, pilotable via une interface web stylée ou un menu terminal interactif.**

[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](https://www.docker.com/)
[![Kali](https://img.shields.io/badge/Base-Kali%20Rolling-557C94?logo=kalilinux)](https://www.kali.org/)
[![Tools](https://img.shields.io/badge/Outils-12%20intégrés-red)]()
[![Interface](https://img.shields.io/badge/Interface-Web%20%2B%20Bash-green)]()

---

## 📋 Table des Matières

- [Présentation](#-présentation)
- [Outils Intégrés](#-outils-intégrés)
- [Pré-requis](#-pré-requis)
- [Installation & Lancement](#-installation--lancement)
- [Utilisation — Interface Web](#-utilisation--interface-web)
- [Utilisation — Menu Bash](#-utilisation--menu-bash)
- [Architecture du Projet](#-architecture-du-projet)
- [Exemples d'Utilisation](#-exemples-dutilisation)
- [Sécurité & Bonnes Pratiques](#-sécurité--bonnes-pratiques)
- [Auteur](#-auteur)

---

## 🎯 Présentation

**SecBox** est un environnement portable de pentest et d'audit sécurité, packagé dans un unique conteneur Docker. Il regroupe **12 outils** couvrant 6 domaines de la cybersécurité, accessibles via :

- 🌐 **Interface Web** (Flask + WebSockets) — Formulaires visuels, résultats en temps réel, historique des scans
- 🖥️ **Menu Bash** (whiptail) — Interface terminal interactive pour les puristes CLI

**Pourquoi SecBox ?**
- **Zéro installation** — Un `docker build` et c'est prêt
- **Portable** — Fonctionne sur Windows, Mac, Linux
- **Isolé** — Tout tourne dans le conteneur, rien ne touche votre système
- **Sécurisé** — Validation des entrées, pas d'injection de commandes

---

## 🧰 Outils Intégrés

| # | Catégorie | Outil | Description |
|---|---|---|---|
| 1 | 🔍 Scan réseau | **Nmap** | Scanner de ports et détection d'OS/services |
| 2 | 🔍 Scan réseau | **Masscan** | Scanner de ports ultra-rapide (async) |
| 3 | 🛡️ Vulnérabilités | **Nikto** | Scanner de vulnérabilités web |
| 4 | 🛡️ Vulnérabilités | **Nuclei** | Scanner de vulnérabilités basé sur templates |
| 5 | 🔑 Brute-force | **Hydra** | Attaque par dictionnaire multi-protocoles |
| 6 | 🔑 Brute-force | **Medusa** | Brute-force rapide et parallélisé |
| 7 | 📡 Analyse trafic | **Tcpdump** | Capture de paquets réseau en CLI |
| 8 | 📡 Analyse trafic | **Tshark** | Wireshark en ligne de commande |
| 9 | 🕵️ OSINT | **theHarvester** | Récolte d'emails, sous-domaines, IPs |
| 10 | 🕵️ OSINT | **Amass** | Enumération de sous-domaines avancée |
| 11 | 🌐 Web | **SQLmap** | Détection et exploitation d'injections SQL |
| 12 | 🌐 Web | **WhatWeb** | Fingerprinting de technologies web |

---

## ⚙️ Pré-requis

- **Docker** installé ([Get Docker](https://docs.docker.com/get-docker/))
- **4 Go de RAM** minimum disponibles
- **5 Go d'espace disque** (image Kali + outils)

Vérifier que Docker fonctionne :
```bash
docker --version
docker run hello-world
```

---

## 🚀 Installation & Lancement

### 1. Cloner le repo

```bash
git clone https://github.com/TON_USER/secbox.git
cd secbox
```

### 2. Builder l'image Docker

```bash
docker build -t secbox .
```

> ⏱️ Le premier build prend **5-10 minutes** (téléchargement des outils). Les builds suivants utilisent le cache.

### 3. Lancer le conteneur

#### Option A — Interface Web (recommandé)

```bash
docker run -it --rm -p 5000:5000 --name secbox secbox web
```

Puis ouvrir **http://localhost:5000** dans le navigateur.

#### Option B — Menu Bash interactif

```bash
docker run -it --rm --name secbox secbox bash-menu
```

#### Option C — Shell direct (mode libre)

```bash
docker run -it --rm --name secbox secbox /bin/bash
```

---

## 🌐 Utilisation — Interface Web

L'interface web tourne sur le port **5000** et offre :

- **Dashboard** — Vue d'ensemble des outils disponibles par catégorie
- **Formulaires** — Un formulaire dédié par outil avec les paramètres principaux
- **Résultats live** — Sortie en temps réel via WebSockets (pas besoin de rafraîchir)
- **Historique** — Tous les scans passés consultables avec leurs résultats
- **Export** — Copier les résultats en un clic

### Captures d'écran

*Ajouter vos captures dans le dossier `screenshots/`*

---

## 🖥️ Utilisation — Menu Bash

Le menu bash interactif utilise `whiptail` pour une navigation au clavier :

```
┌──────────────────────────────────────┐
│         ⚡ SecBox — Menu Principal    │
│                                      │
│  1. Scan Réseau (Nmap / Masscan)     │
│  2. Vulnérabilités (Nikto / Nuclei)  │
│  3. Brute-force (Hydra / Medusa)     │
│  4. Analyse Trafic (Tcpdump/Tshark)  │
│  5. OSINT (theHarvester / Amass)     │
│  6. Web (SQLmap / WhatWeb)           │
│  7. Quitter                          │
│                                      │
└──────────────────────────────────────┘
```

Chaque outil propose un sous-menu avec les paramètres configurables.

---

## 📁 Architecture du Projet

```
secbox/
├── Dockerfile                 # Image Docker (base Kali + 12 outils)
├── docker-compose.yml         # Orchestration (optionnel)
├── README.md                  # Ce fichier
├── LICENSE                    # Licence MIT
├── .dockerignore              # Fichiers exclus du build
│
├── web/                       # Interface Web Flask
│   ├── app.py                 # Serveur Flask + WebSockets
│   ├── requirements.txt       # Dépendances Python
│   ├── templates/
│   │   └── index.html         # Interface utilisateur
│   └── static/
│       └── style.css          # Styles
│
├── bash/
│   └── menu.sh                # Menu interactif whiptail
│
├── entrypoint.sh              # Point d'entrée Docker (web/bash/shell)
│
├── docs/
│   └── USAGE.md               # Exemples d'utilisation détaillés
│
└── screenshots/               # Captures pour la présentation
```

---

## 💡 Exemples d'Utilisation

### Scan Nmap rapide
```
Cible : scanme.nmap.org
Type : SYN Scan (-sS)
Ports : 1-1000
→ Résultat : ports 22, 80 ouverts
```

### Fingerprint web avec WhatWeb
```
Cible : https://example.com
→ Résultat : Apache 2.4, PHP 8.1, WordPress 6.4
```

### Récolte OSINT avec theHarvester
```
Domaine : example.com
Source : google, bing, dnsdumpster
→ Résultat : 15 emails, 8 sous-domaines
```

> ⚠️ **Toujours tester uniquement sur des cibles autorisées** (vos propres serveurs ou des plateformes de test comme scanme.nmap.org, HackTheBox, TryHackMe).

---

## 🔒 Sécurité & Bonnes Pratiques

- **Validation des entrées** — Toutes les saisies utilisateur sont sanitizées (regex whitelist) pour empêcher l'injection de commandes
- **Pas de `shell=True`** — Les commandes sont exécutées via `subprocess` avec des listes d'arguments
- **Conteneur éphémère** — Utiliser `--rm` pour supprimer le conteneur après usage
- **Réseau isolé** — Le conteneur n'a pas accès au réseau hôte par défaut (sauf les ports exposés)
- **Aucun secret** — Pas de credentials en dur dans le code

---

## 🧑‍💻 Auteur

**Remi (PNJ)** — Étudiant YNOV Bordeaux

---

## 📄 Licence

Ce projet est sous licence MIT — voir le fichier [LICENSE](LICENSE).

---

> 💡 **Pour la démo** : Lancer l'interface web, scanner `scanme.nmap.org` en live, montrer les résultats en temps réel + le menu bash en parallèle.
