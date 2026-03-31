# ============================================================================
# SecBox — Dockerfile
# Base : Kali Linux Rolling
# Outils : 12 outils de sécurité (6 catégories)
# Interfaces : Web (Flask) + Bash (whiptail)
# ============================================================================

FROM kalilinux/kali-rolling

LABEL maintainer="Remi (PNJ) — YNOV Bordeaux"
LABEL description="SecBox — Boîte à Outils Sécurité Dockerisée"
LABEL version="1.0"

# ============================================================================
# 1. Mise à jour et dépendances système
# ============================================================================

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Utilitaires de base
    curl \
    wget \
    git \
    ca-certificates \
    whiptail \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    # ── Catégorie 1 : Scan réseau ──
    nmap \
    masscan \
    # ── Catégorie 2 : Analyse de vulnérabilités ──
    nikto \
    # ── Catégorie 3 : Brute-force et Auth ──
    hydra \
    medusa \
    # ── Catégorie 4 : Analyse de trafic ──
    tcpdump \
    tshark \
    # ── Catégorie 5 : OSINT ──
    theharvester \
    amass \
    # ── Catégorie 6 : Web ──
    sqlmap \
    whatweb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# 2. Installation de Nuclei (binaire Go — pas dans les repos Kali)
# ============================================================================

RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(curl -sSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | jq -r '.tag_name' | tr -d 'v')_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip \
    && nuclei -update-templates 2>/dev/null || true

# ============================================================================
# 3. Interface Web Flask
# ============================================================================

WORKDIR /app

COPY web/requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /app/requirements.txt

COPY web/ /app/web/
COPY bash/ /app/bash/
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh /app/bash/menu.sh

# ============================================================================
# 4. Configuration
# ============================================================================

# Dossier pour les résultats de scans
RUN mkdir -p /app/results /app/logs

# Port pour l'interface web
EXPOSE 5000

# ============================================================================
# 5. Entrypoint
# ============================================================================

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["web"]
kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk