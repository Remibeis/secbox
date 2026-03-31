"""
SecBox — Interface Web Flask + WebSockets
Serveur principal : formulaires d'outils + résultats en temps réel
"""

import os
import re
import subprocess
import threading
import uuid
from datetime import datetime

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__,
            template_folder="templates",
            static_folder="static")
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

# ============================================================================
# Stockage en mémoire des résultats
# ============================================================================

scan_history = []

# ============================================================================
# Validation des entrées (anti-injection de commandes)
# ============================================================================

def validate_target(target: str) -> bool:
    """Valide une cible (IP, domaine, CIDR). Bloque toute injection."""
    pattern = r'^[a-zA-Z0-9\.\-\_\:\/]+$'
    return bool(re.match(pattern, target)) and len(target) < 256

def validate_ports(ports: str) -> bool:
    """Valide une spécification de ports (ex: 80, 1-1000, 22,80,443)."""
    pattern = r'^[0-9,\-]+$'
    return bool(re.match(pattern, ports)) and len(ports) < 64

def validate_wordlist(path: str) -> bool:
    """Valide un chemin de wordlist prédéfini."""
    allowed = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirb/big.txt",
        "/usr/share/wordlists/nmap.lst",
        "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
    ]
    return path in allowed

ALLOWED_WORDLISTS = [
    {"path": "/usr/share/wordlists/rockyou.txt", "name": "rockyou.txt (14M mots)"},
    {"path": "/usr/share/wordlists/dirb/common.txt", "name": "dirb/common.txt (4.6K mots)"},
    {"path": "/usr/share/wordlists/dirb/big.txt", "name": "dirb/big.txt (20K mots)"},
]

# ============================================================================
# Définition des outils
# ============================================================================

TOOLS = {
    "nmap": {
        "name": "Nmap",
        "category": "Scan Réseau",
        "icon": "🔍",
        "description": "Scanner de ports, OS et services",
        "fields": [
            {"name": "target", "label": "Cible (IP/domaine)", "type": "text", "placeholder": "scanme.nmap.org", "required": True},
            {"name": "scan_type", "label": "Type de scan", "type": "select", "options": [
                {"value": "-sS", "label": "SYN Scan (rapide)"},
                {"value": "-sT", "label": "TCP Connect"},
                {"value": "-sV", "label": "Version Detection"},
                {"value": "-sS -sV -O", "label": "Complet (SYN + Version + OS)"},
                {"value": "-sn", "label": "Ping Sweep (découverte)"},
            ]},
            {"name": "ports", "label": "Ports", "type": "text", "placeholder": "1-1000", "required": False},
        ]
    },
    "masscan": {
        "name": "Masscan",
        "category": "Scan Réseau",
        "icon": "🔍",
        "description": "Scanner de ports ultra-rapide (asynchrone)",
        "fields": [
            {"name": "target", "label": "Cible (IP/CIDR)", "type": "text", "placeholder": "192.168.1.0/24", "required": True},
            {"name": "ports", "label": "Ports", "type": "text", "placeholder": "0-1000", "required": True},
            {"name": "rate", "label": "Paquets/sec", "type": "text", "placeholder": "1000", "required": False},
        ]
    },
    "nikto": {
        "name": "Nikto",
        "category": "Vulnérabilités",
        "icon": "🛡️",
        "description": "Scanner de vulnérabilités serveurs web",
        "fields": [
            {"name": "target", "label": "URL cible", "type": "text", "placeholder": "http://example.com", "required": True},
        ]
    },
    "nuclei": {
        "name": "Nuclei",
        "category": "Vulnérabilités",
        "icon": "🛡️",
        "description": "Scanner de vulnérabilités basé sur templates",
        "fields": [
            {"name": "target", "label": "URL cible", "type": "text", "placeholder": "https://example.com", "required": True},
            {"name": "severity", "label": "Sévérité min.", "type": "select", "options": [
                {"value": "info", "label": "Info"},
                {"value": "low", "label": "Low"},
                {"value": "medium", "label": "Medium"},
                {"value": "high", "label": "High"},
                {"value": "critical", "label": "Critical"},
            ]},
        ]
    },
    "hydra": {
        "name": "Hydra",
        "category": "Brute-force",
        "icon": "🔑",
        "description": "Attaque par dictionnaire multi-protocoles",
        "fields": [
            {"name": "target", "label": "Cible (IP/domaine)", "type": "text", "placeholder": "192.168.1.10", "required": True},
            {"name": "service", "label": "Service", "type": "select", "options": [
                {"value": "ssh", "label": "SSH"},
                {"value": "ftp", "label": "FTP"},
                {"value": "http-get", "label": "HTTP GET"},
                {"value": "mysql", "label": "MySQL"},
                {"value": "rdp", "label": "RDP"},
            ]},
            {"name": "username", "label": "Utilisateur", "type": "text", "placeholder": "admin", "required": True},
            {"name": "wordlist", "label": "Wordlist", "type": "select", "options": [
                {"value": w["path"], "label": w["name"]} for w in ALLOWED_WORDLISTS
            ]},
        ]
    },
    "medusa": {
        "name": "Medusa",
        "category": "Brute-force",
        "icon": "🔑",
        "description": "Brute-force rapide et parallélisé",
        "fields": [
            {"name": "target", "label": "Cible (IP)", "type": "text", "placeholder": "192.168.1.10", "required": True},
            {"name": "module", "label": "Module", "type": "select", "options": [
                {"value": "ssh", "label": "SSH"},
                {"value": "ftp", "label": "FTP"},
                {"value": "http", "label": "HTTP"},
                {"value": "mysql", "label": "MySQL"},
            ]},
            {"name": "username", "label": "Utilisateur", "type": "text", "placeholder": "admin", "required": True},
            {"name": "wordlist", "label": "Wordlist", "type": "select", "options": [
                {"value": w["path"], "label": w["name"]} for w in ALLOWED_WORDLISTS
            ]},
        ]
    },
    "tcpdump": {
        "name": "Tcpdump",
        "category": "Analyse Trafic",
        "icon": "📡",
        "description": "Capture de paquets réseau",
        "fields": [
            {"name": "interface", "label": "Interface", "type": "text", "placeholder": "eth0", "required": False},
            {"name": "count", "label": "Nombre de paquets", "type": "text", "placeholder": "50", "required": False},
            {"name": "filter", "label": "Filtre BPF", "type": "text", "placeholder": "port 80", "required": False},
        ]
    },
    "tshark": {
        "name": "Tshark",
        "category": "Analyse Trafic",
        "icon": "📡",
        "description": "Wireshark en ligne de commande",
        "fields": [
            {"name": "interface", "label": "Interface", "type": "text", "placeholder": "eth0", "required": False},
            {"name": "count", "label": "Nombre de paquets", "type": "text", "placeholder": "50", "required": False},
            {"name": "filter", "label": "Filtre d'affichage", "type": "text", "placeholder": "http", "required": False},
        ]
    },
    "theharvester": {
        "name": "theHarvester",
        "category": "OSINT",
        "icon": "🕵️",
        "description": "Récolte d'emails, sous-domaines, IPs",
        "fields": [
            {"name": "domain", "label": "Domaine", "type": "text", "placeholder": "example.com", "required": True},
            {"name": "source", "label": "Source", "type": "select", "options": [
                {"value": "google", "label": "Google"},
                {"value": "bing", "label": "Bing"},
                {"value": "dnsdumpster", "label": "DNSDumpster"},
                {"value": "crtsh", "label": "crt.sh"},
                {"value": "rapiddns", "label": "RapidDNS"},
            ]},
            {"name": "limit", "label": "Limite de résultats", "type": "text", "placeholder": "100", "required": False},
        ]
    },
    "amass": {
        "name": "Amass",
        "category": "OSINT",
        "icon": "🕵️",
        "description": "Enumération de sous-domaines avancée",
        "fields": [
            {"name": "domain", "label": "Domaine", "type": "text", "placeholder": "example.com", "required": True},
            {"name": "mode", "label": "Mode", "type": "select", "options": [
                {"value": "passive", "label": "Passif (rapide, discret)"},
                {"value": "active", "label": "Actif (complet)"},
            ]},
        ]
    },
    "sqlmap": {
        "name": "SQLmap",
        "category": "Web",
        "icon": "🌐",
        "description": "Détection et exploitation d'injections SQL",
        "fields": [
            {"name": "url", "label": "URL avec paramètre", "type": "text", "placeholder": "http://target.com/page?id=1", "required": True},
            {"name": "level", "label": "Niveau", "type": "select", "options": [
                {"value": "1", "label": "1 (rapide)"},
                {"value": "2", "label": "2"},
                {"value": "3", "label": "3 (complet)"},
            ]},
        ]
    },
    "whatweb": {
        "name": "WhatWeb",
        "category": "Web",
        "icon": "🌐",
        "description": "Fingerprinting de technologies web",
        "fields": [
            {"name": "target", "label": "URL cible", "type": "text", "placeholder": "https://example.com", "required": True},
            {"name": "aggression", "label": "Agressivité", "type": "select", "options": [
                {"value": "1", "label": "1 — Furtif (1 requête)"},
                {"value": "3", "label": "3 — Agressif"},
            ]},
        ]
    },
}

# ============================================================================
# Construction sécurisée des commandes
# ============================================================================

def build_command(tool: str, params: dict) -> list:
    """Construit la commande en liste (pas de shell=True). Retourne None si invalide."""

    if tool == "nmap":
        if not validate_target(params.get("target", "")):
            return None
        cmd = ["nmap"]
        scan_type = params.get("scan_type", "-sS")
        if scan_type in ["-sS", "-sT", "-sV", "-sS -sV -O", "-sn"]:
            cmd.extend(scan_type.split())
        ports = params.get("ports", "")
        if ports and validate_ports(ports):
            cmd.extend(["-p", ports])
        cmd.append(params["target"])
        return cmd

    elif tool == "masscan":
        if not validate_target(params.get("target", "")):
            return None
        if not validate_ports(params.get("ports", "0-1000")):
            return None
        cmd = ["masscan", params["target"], "-p", params.get("ports", "0-1000")]
        rate = params.get("rate", "1000")
        if rate.isdigit():
            cmd.extend(["--rate", rate])
        return cmd

    elif tool == "nikto":
        if not validate_target(params.get("target", "")):
            return None
        return ["nikto", "-h", params["target"], "-maxtime", "120s"]

    elif tool == "nuclei":
        if not validate_target(params.get("target", "")):
            return None
        cmd = ["nuclei", "-u", params["target"], "-silent"]
        severity = params.get("severity", "info")
        if severity in ["info", "low", "medium", "high", "critical"]:
            cmd.extend(["-severity", severity])
        return cmd

    elif tool == "hydra":
        if not validate_target(params.get("target", "")):
            return None
        username = params.get("username", "admin")
        if not re.match(r'^[a-zA-Z0-9\._\-]+$', username):
            return None
        wordlist = params.get("wordlist", "")
        if not validate_wordlist(wordlist):
            return None
        service = params.get("service", "ssh")
        if service not in ["ssh", "ftp", "http-get", "mysql", "rdp"]:
            return None
        return ["hydra", "-l", username, "-P", wordlist, "-t", "4", "-V",
                f"{service}://{params['target']}"]

    elif tool == "medusa":
        if not validate_target(params.get("target", "")):
            return None
        username = params.get("username", "admin")
        if not re.match(r'^[a-zA-Z0-9\._\-]+$', username):
            return None
        wordlist = params.get("wordlist", "")
        if not validate_wordlist(wordlist):
            return None
        module = params.get("module", "ssh")
        if module not in ["ssh", "ftp", "http", "mysql"]:
            return None
        return ["medusa", "-h", params["target"], "-u", username, "-P", wordlist,
                "-M", module, "-t", "4"]

    elif tool == "tcpdump":
        cmd = ["tcpdump", "-nn"]
        interface = params.get("interface", "eth0")
        if re.match(r'^[a-zA-Z0-9]+$', interface):
            cmd.extend(["-i", interface])
        count = params.get("count", "50")
        if count.isdigit() and int(count) <= 500:
            cmd.extend(["-c", count])
        else:
            cmd.extend(["-c", "50"])
        bpf = params.get("filter", "")
        if bpf and re.match(r'^[a-zA-Z0-9\.\s\:\/\-]+$', bpf) and len(bpf) < 100:
            cmd.extend(bpf.split())
        return cmd

    elif tool == "tshark":
        cmd = ["tshark"]
        interface = params.get("interface", "eth0")
        if re.match(r'^[a-zA-Z0-9]+$', interface):
            cmd.extend(["-i", interface])
        count = params.get("count", "50")
        if count.isdigit() and int(count) <= 500:
            cmd.extend(["-c", count])
        else:
            cmd.extend(["-c", "50"])
        display_filter = params.get("filter", "")
        if display_filter and re.match(r'^[a-zA-Z0-9\.\s\:\/\-\=\!\&\|]+$', display_filter) and len(display_filter) < 100:
            cmd.extend(["-Y", display_filter])
        return cmd

    elif tool == "theharvester":
        domain = params.get("domain", "")
        if not validate_target(domain):
            return None
        source = params.get("source", "google")
        if source not in ["google", "bing", "dnsdumpster", "crtsh", "rapiddns"]:
            return None
        cmd = ["theHarvester", "-d", domain, "-b", source]
        limit = params.get("limit", "100")
        if limit.isdigit() and int(limit) <= 500:
            cmd.extend(["-l", limit])
        return cmd

    elif tool == "amass":
        domain = params.get("domain", "")
        if not validate_target(domain):
            return None
        mode = params.get("mode", "passive")
        if mode == "passive":
            return ["amass", "enum", "-passive", "-d", domain]
        else:
            return ["amass", "enum", "-d", domain]

    elif tool == "sqlmap":
        url = params.get("url", "")
        if not re.match(r'^https?://[a-zA-Z0-9\.\-\_\:\/\?\=\&\%\+]+$', url) or len(url) > 500:
            return None
        cmd = ["sqlmap", "-u", url, "--batch", "--random-agent"]
        level = params.get("level", "1")
        if level in ["1", "2", "3"]:
            cmd.extend(["--level", level])
        return cmd

    elif tool == "whatweb":
        if not validate_target(params.get("target", "")):
            return None
        cmd = ["whatweb", params["target"]]
        aggression = params.get("aggression", "1")
        if aggression in ["1", "3"]:
            cmd.extend(["-a", aggression])
        return cmd

    return None

# ============================================================================
# Exécution asynchrone avec streaming WebSocket
# ============================================================================

def run_tool_async(tool: str, params: dict, scan_id: str):
    """Exécute un outil et stream la sortie via WebSocket."""
    cmd = build_command(tool, params)

    if cmd is None:
        socketio.emit("scan_error", {
            "scan_id": scan_id,
            "error": "Paramètres invalides — vérifiez vos entrées."
        })
        return

    tool_info = TOOLS.get(tool, {})
    scan_record = {
        "id": scan_id,
        "tool": tool,
        "tool_name": tool_info.get("name", tool),
        "icon": tool_info.get("icon", "🔧"),
        "params": params,
        "command": " ".join(cmd),
        "started_at": datetime.now().isoformat(),
        "output": "",
        "status": "running"
    }
    scan_history.insert(0, scan_record)

    socketio.emit("scan_started", {
        "scan_id": scan_id,
        "tool": tool_info.get("name", tool),
        "command": " ".join(cmd)
    })

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        full_output = []
        for line in iter(process.stdout.readline, ""):
            full_output.append(line)
            socketio.emit("scan_output", {
                "scan_id": scan_id,
                "line": line.rstrip("\n")
            })

        process.wait(timeout=300)
        output_text = "".join(full_output)
        scan_record["output"] = output_text
        scan_record["status"] = "completed"
        scan_record["finished_at"] = datetime.now().isoformat()

        socketio.emit("scan_complete", {
            "scan_id": scan_id,
            "exit_code": process.returncode
        })

    except subprocess.TimeoutExpired:
        process.kill()
        scan_record["status"] = "timeout"
        socketio.emit("scan_error", {
            "scan_id": scan_id,
            "error": "Timeout — le scan a dépassé 5 minutes."
        })
    except Exception as e:
        scan_record["status"] = "error"
        socketio.emit("scan_error", {
            "scan_id": scan_id,
            "error": str(e)
        })

# ============================================================================
# Routes Flask
# ============================================================================

@app.route("/")
def index():
    return render_template("index.html", tools=TOOLS)

@app.route("/api/tools")
def api_tools():
    return jsonify(TOOLS)

@app.route("/api/history")
def api_history():
    return jsonify(scan_history[:50])

# ============================================================================
# WebSocket Events
# ============================================================================

@socketio.on("run_scan")
def handle_run_scan(data):
    tool = data.get("tool", "")
    params = data.get("params", {})

    if tool not in TOOLS:
        emit("scan_error", {"error": f"Outil inconnu : {tool}"})
        return

    scan_id = str(uuid.uuid4())[:8]

    thread = threading.Thread(
        target=run_tool_async,
        args=(tool, params, scan_id),
        daemon=True
    )
    thread.start()

# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    print("\n  🌐 SecBox Web Interface")
    print("  → http://0.0.0.0:5000\n")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
