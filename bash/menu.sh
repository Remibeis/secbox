#!/bin/bash
# ============================================================================
# SecBox — Menu Bash Interactif (whiptail)
# Navigation clavier pour lancer les 12 outils de sécurité
# ============================================================================

set -u

# Couleurs pour la sortie directe
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

RESULTS_DIR="/app/results"
mkdir -p "$RESULTS_DIR"

# ============================================================================
# Validation des entrées
# ============================================================================

validate_target() {
    local input="$1"
    if [[ "$input" =~ ^[a-zA-Z0-9\.\-\_\:\/]+$ ]] && [ ${#input} -lt 256 ]; then
        return 0
    fi
    whiptail --msgbox "❌ Cible invalide.\nCaractères autorisés : lettres, chiffres, . - _ : /" 10 50
    return 1
}

validate_ports() {
    local input="$1"
    if [[ "$input" =~ ^[0-9,\-]+$ ]] && [ ${#input} -lt 64 ]; then
        return 0
    fi
    whiptail --msgbox "❌ Ports invalides.\nFormat : 80 ou 1-1000 ou 22,80,443" 10 50
    return 1
}

# ============================================================================
# Fonctions outils
# ============================================================================

run_nmap() {
    local target
    target=$(whiptail --inputbox "🔍 Nmap — Cible (IP ou domaine)" 10 50 "scanme.nmap.org" 3>&1 1>&2 2>&3) || return
    validate_target "$target" || return

    local scan_type
    scan_type=$(whiptail --menu "Type de scan :" 16 50 5 \
        "-sS" "SYN Scan (rapide)" \
        "-sT" "TCP Connect" \
        "-sV" "Version Detection" \
        "-sS -sV -O" "Complet (SYN+Version+OS)" \
        "-sn" "Ping Sweep" \
        3>&1 1>&2 2>&3) || return

    local ports
    ports=$(whiptail --inputbox "Ports (vide = défaut Nmap)" 10 50 "1-1000" 3>&1 1>&2 2>&3) || return

    local cmd="nmap $scan_type"
    if [ -n "$ports" ]; then
        validate_ports "$ports" || return
        cmd="$cmd -p $ports"
    fi
    cmd="$cmd $target"

    echo -e "\n${CYAN}[*] Exécution : $cmd${NC}\n"
    eval "$cmd" 2>&1 | tee "$RESULTS_DIR/nmap_$(date +%s).txt"
    echo -e "\n${GREEN}[✓] Résultat sauvé dans $RESULTS_DIR/${NC}"
    read -p "Appuyez sur Entrée pour continuer..."
}

run_masscan() {
    local target
    target=$(whiptail --inputbox "🔍 Masscan — Cible (IP/CIDR)" 10 50 "192.168.1.0/24" 3>&1 1>&2 2>&3) || return
    validate_target "$target" || return

    local ports
    ports=$(whiptail --inputbox "Ports" 10 50 "0-1000" 3>&1 1>&2 2>&3) || return
    validate_ports "$ports" || return

    local rate
    rate=$(whiptail --inputbox "Paquets/sec" 10 50 "1000" 3>&1 1>&2 2>&3) || return

    echo -e "\n${CYAN}[*] Exécution : masscan $target -p$ports --rate=$rate${NC}\n"
    masscan "$target" -p"$ports" --rate="$rate" 2>&1 | tee "$RESULTS_DIR/masscan_$(date +%s).txt"
    echo -e "\n${GREEN}[✓] Terminé${NC}"
    read -p "Appuyez sur Entrée pour continuer..."
}

run_nikto() {
    local target
    target=$(whiptail --inputbox "🛡️ Nikto — URL cible" 10 50 "http://example.com" 3>&1 1>&2 2>&3) || return
    validate_target "$target" || return

    echo -e "\n${CYAN}[*] Exécution : nikto -h $target${NC}\n"
    nikto -h "$target" -maxtime 120s 2>&1 | tee "$RESULTS_DIR/nikto_$(date +%s).txt"
    echo -e "\n${GREEN}[✓] Terminé${NC}"
    read -p "Appuyez sur Entrée pour continuer..."
}

run_nuclei() {
    local target
    target=$(whiptail --inputbox "🛡️ Nuclei — URL cible" 10 50 "https://example.com" 3>&1 1>&2 2>&3) || return
    validate_target "$target" || return

    local severity
    severity=$(whiptail --menu "Sévérité minimum :" 14 50 5 \
        "info" "Info" \
        "low" "Low" \
        "medium" "Medium" \
        "high" "High" \
        "critical" "Critical" \
        3>&1 1>&2 2>&3) || return

    echo -e "\n${CYAN}[*] Exécution : nuclei -u $target -severity $severity${NC}\n"
    nuclei -u "$target" -severity "$severity" 2>&1 | tee "$RESULTS_DIR/nuclei_$(date +%s).txt"
    echo -e "\n${GREEN}[✓] Terminé${NC}"
    read -p "Appuyez sur Entrée pour continuer..."
}

run_hydra() {
    local target
    target=$(whiptail --inputbox "🔑 Hydra — Cible (IP)" 10 50 "192.168.1.10" 3>&1 1>&2 2>&3) || return
    validate_target "$target" || return

    local service
    service=$(whiptail --menu "Service :" 14 50 5 \
        "ssh" "SSH" \
        "ftp" "FTP" \
        "http-get" "HTTP GET" \
        "mysql" "MySQL" \
        "rdp" "RDP" \
        3>&1 1>&2 2>&3) || return

    local user
    user=$(whiptail --inputbox "Nom d'utilisateur" 10 50 "admin" 3>&1 1>&2 2>&3) || return

    local wordlist
    wordlist=$(whiptail --menu "Wordlist :" 14 60 3 \
        "/usr/share/wordlists/rockyou.txt" "rockyou.txt (14M)" \
        "/usr/share/wordlists/dirb/common.txt" "common.txt (4.6K)" \
        "/usr/share/wordlists/dirb/big.txt" "big.txt (20K)" \
        3>&1 1>&2 2>&3) || return

    echo -e "\n${CYAN}[*] Exécution : hydra -l $user -P $wordlist $service://$target${NC}\n"
    hydra -l "$user" -P "$wordlist" -t 4 -V "$service://$target" 2>&1 | tee "$RESULTS_DIR/hydra_$(date +%s).txt"
    echo -e "\n${GREEN}[✓] Terminé${NC}"
    read -p "Appuyez sur Entrée pour continuer..."
}

run_medusa() {
    local target
    target=$(whiptail --inputbox "🔑 Medusa — Cible (IP)" 10 50 "192.168.1.10" 3>&1 1>&2 2>&3) || return
    validate_target "$target" || return

    local module
    module=$(whiptail --menu "Module :" 12 50 4 \
        "ssh" "SSH" \
        "ftp" "FTP" \
        "http" "HTTP" \
        "mysql" "MySQL" \
        3>&1 1>&2 2>&3) || return

    local user
    user=$(whiptail --inputbox "Nom d'utilisateur" 10 50 "admin" 3>&1 1>&2 2>&3) || return

    local wordlist
    wordlist=$(whiptail --menu "Wordlist :" 14 60 3 \
        "/usr/share/wordlists/rockyou.txt" "rockyou.txt (14M)" \
        "/usr/share/wordlists/dirb/common.txt" "common.txt (4.6K)" \
        "/usr/share/wordlists/dirb/big.txt" "big.txt (20K)" \
        3>&1 1>&2 2>&3) || return

    echo -e "\n${CYAN}[*] Exécution : medusa -h $target -u $user -P $wordlist -M $module${NC}\n"
    medusa -h "$target" -u "$user" -P "$wordlist" -M "$module" -t 4 2>&1 | tee "$RESULTS_DIR/medusa_$(date +%s).txt"
    echo -e "\n${GREEN}[✓] Terminé${NC}"
    read -p "Appuyez sur Entrée pour continuer..."
}

run_tcpdump() {
    local iface
    iface=$(whiptail --inputbox "📡 Tcpdump — Interface" 10 50 "eth0" 3>&1 1>&2 2>&3) || return

    local count
    count=$(whiptail --inputbox "Nombre de paquets" 10 50 "50" 3>&1 1>&2 2>&3) || return

    echo -e "\n${CYAN}[*] Exécution : tcpdump -i $iface -c $count -nn${NC}\n"
    tcpdump -i "$iface" -c "$count" -nn 2>&1 | tee "$RESULTS_DIR/tcpdump_$(date +%s).txt"
    echo -e "\n${GREEN}[✓] Terminé${NC}"
    read -p "Appuyez sur Entrée pour continuer..."
}

run_tshark() {
    local iface
    iface=$(whiptail --inputbox "📡 Tshark — Interface" 10 50 "eth0" 3>&1 1>&2 2>&3) || return

    local count
    count=$(whiptail --inputbox "Nombre de paquets" 10 50 "50" 3>&1 1>&2 2>&3) || return

    echo -e "\n${CYAN}[*] Exécution : tshark -i $iface -c $count${NC}\n"
    tshark -i "$iface" -c "$count" 2>&1 | tee "$RESULTS_DIR/tshark_$(date +%s).txt"
    echo -e "\n${GREEN}[✓] Terminé${NC}"
    read -p "Appuyez sur Entrée pour continuer..."
}

run_theharvester() {
    local domain
    domain=$(whiptail --inputbox "🕵️ theHarvester — Domaine" 10 50 "example.com" 3>&1 1>&2 2>&3) || return
    validate_target "$domain" || return

    local source
    source=$(whiptail --menu "Source :" 14 50 5 \
        "google" "Google" \
        "bing" "Bing" \
        "dnsdumpster" "DNSDumpster" \
        "crtsh" "crt.sh" \
        "rapiddns" "RapidDNS" \
        3>&1 1>&2 2>&3) || return

    echo -e "\n${CYAN}[*] Exécution : theHarvester -d $domain -b $source${NC}\n"
    theHarvester -d "$domain" -b "$source" -l 100 2>&1 | tee "$RESULTS_DIR/harvester_$(date +%s).txt"
    echo -e "\n${GREEN}[✓] Terminé${NC}"
    read -p "Appuyez sur Entrée pour continuer..."
}

run_amass() {
    local domain
    domain=$(whiptail --inputbox "🕵️ Amass — Domaine" 10 50 "example.com" 3>&1 1>&2 2>&3) || return
    validate_target "$domain" || return

    local mode
    mode=$(whiptail --menu "Mode :" 10 50 2 \
        "passive" "Passif (rapide)" \
        "active" "Actif (complet)" \
        3>&1 1>&2 2>&3) || return

    local flag=""
    [ "$mode" = "passive" ] && flag="-passive"

    echo -e "\n${CYAN}[*] Exécution : amass enum $flag -d $domain${NC}\n"
    amass enum $flag -d "$domain" 2>&1 | tee "$RESULTS_DIR/amass_$(date +%s).txt"
    echo -e "\n${GREEN}[✓] Terminé${NC}"
    read -p "Appuyez sur Entrée pour continuer..."
}

run_sqlmap() {
    local url
    url=$(whiptail --inputbox "🌐 SQLmap — URL avec paramètre" 10 60 "http://target.com/page?id=1" 3>&1 1>&2 2>&3) || return

    local level
    level=$(whiptail --menu "Niveau :" 12 50 3 \
        "1" "Rapide" \
        "2" "Moyen" \
        "3" "Complet" \
        3>&1 1>&2 2>&3) || return

    echo -e "\n${CYAN}[*] Exécution : sqlmap -u '$url' --level=$level --batch${NC}\n"
    sqlmap -u "$url" --level="$level" --batch --random-agent 2>&1 | tee "$RESULTS_DIR/sqlmap_$(date +%s).txt"
    echo -e "\n${GREEN}[✓] Terminé${NC}"
    read -p "Appuyez sur Entrée pour continuer..."
}

run_whatweb() {
    local target
    target=$(whiptail --inputbox "🌐 WhatWeb — URL cible" 10 50 "https://example.com" 3>&1 1>&2 2>&3) || return
    validate_target "$target" || return

    local aggression
    aggression=$(whiptail --menu "Agressivité :" 10 50 2 \
        "1" "Furtif (1 requête)" \
        "3" "Agressif" \
        3>&1 1>&2 2>&3) || return

    echo -e "\n${CYAN}[*] Exécution : whatweb $target -a $aggression${NC}\n"
    whatweb "$target" -a "$aggression" 2>&1 | tee "$RESULTS_DIR/whatweb_$(date +%s).txt"
    echo -e "\n${GREEN}[✓] Terminé${NC}"
    read -p "Appuyez sur Entrée pour continuer..."
}

# ============================================================================
# Menus
# ============================================================================

menu_scan() {
    local choice
    choice=$(whiptail --menu "🔍 Scan Réseau" 14 50 2 \
        "1" "Nmap — Scanner de ports" \
        "2" "Masscan — Scanner rapide" \
        3>&1 1>&2 2>&3) || return
    case $choice in
        1) run_nmap ;;
        2) run_masscan ;;
    esac
}

menu_vuln() {
    local choice
    choice=$(whiptail --menu "🛡️ Vulnérabilités" 14 50 2 \
        "1" "Nikto — Vulns web" \
        "2" "Nuclei — Templates" \
        3>&1 1>&2 2>&3) || return
    case $choice in
        1) run_nikto ;;
        2) run_nuclei ;;
    esac
}

menu_brute() {
    local choice
    choice=$(whiptail --menu "🔑 Brute-force" 14 50 2 \
        "1" "Hydra — Multi-protocoles" \
        "2" "Medusa — Parallélisé" \
        3>&1 1>&2 2>&3) || return
    case $choice in
        1) run_hydra ;;
        2) run_medusa ;;
    esac
}

menu_traffic() {
    local choice
    choice=$(whiptail --menu "📡 Analyse Trafic" 14 50 2 \
        "1" "Tcpdump — Capture paquets" \
        "2" "Tshark — Wireshark CLI" \
        3>&1 1>&2 2>&3) || return
    case $choice in
        1) run_tcpdump ;;
        2) run_tshark ;;
    esac
}

menu_osint() {
    local choice
    choice=$(whiptail --menu "🕵️ OSINT" 14 50 2 \
        "1" "theHarvester — Emails/Subdomains" \
        "2" "Amass — Enum subdomains" \
        3>&1 1>&2 2>&3) || return
    case $choice in
        1) run_theharvester ;;
        2) run_amass ;;
    esac
}

menu_web() {
    local choice
    choice=$(whiptail --menu "🌐 Web" 14 50 2 \
        "1" "SQLmap — Injection SQL" \
        "2" "WhatWeb — Fingerprinting" \
        3>&1 1>&2 2>&3) || return
    case $choice in
        1) run_sqlmap ;;
        2) run_whatweb ;;
    esac
}

# ============================================================================
# Menu Principal
# ============================================================================

main_menu() {
    while true; do
        local choice
        choice=$(whiptail --title "⚡ SecBox — Boîte à Outils Sécurité" \
            --menu "Choisissez une catégorie :" 20 55 7 \
            "1" "🔍  Scan Réseau (Nmap / Masscan)" \
            "2" "🛡️  Vulnérabilités (Nikto / Nuclei)" \
            "3" "🔑  Brute-force (Hydra / Medusa)" \
            "4" "📡  Analyse Trafic (Tcpdump / Tshark)" \
            "5" "🕵️  OSINT (theHarvester / Amass)" \
            "6" "🌐  Web (SQLmap / WhatWeb)" \
            "7" "❌  Quitter" \
            3>&1 1>&2 2>&3)

        case $? in
            1|255) break ;; # Cancel or Escape
        esac

        case $choice in
            1) menu_scan ;;
            2) menu_vuln ;;
            3) menu_brute ;;
            4) menu_traffic ;;
            5) menu_osint ;;
            6) menu_web ;;
            7) break ;;
        esac
    done

    echo -e "\n${GREEN}👋 À bientôt ! Résultats sauvés dans $RESULTS_DIR/${NC}\n"
}

main_menu
