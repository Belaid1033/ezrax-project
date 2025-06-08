#!/bin/bash

# Script d'installation EZRAX Central Server v2.0 
# Compatible Ubuntu/Debian 20.04+ et dérivés

set -e  

# Variables globales
SCRIPT_VERSION="2.0.0"
EZRAX_DIR="/opt/ezrax-server"
EZRAX_USER="ezrax"
LOG_FILE="/var/log/ezrax-server-install.log"
PYTHON_MIN_VERSION="3.8"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Fonctions utilitaires
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case $level in
        "INFO")
            echo -e "${BLUE}[*]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[+]${NC} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}[!]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[!]${NC} $message"
            ;;
        "DEBUG")
            if [[ "${DEBUG:-}" == "1" ]]; then
                echo -e "${PURPLE}[D]${NC} $message"
            fi
            ;;
    esac
}

banner() {
    echo -e "${CYAN}"
    cat << "EOF"
EZRAX Central Server v2.0 - Installation
Système centralisé de gestion IDS/IPS
EOF
    echo -e "${NC}"
    echo -e "${WHITE}Version du script: $SCRIPT_VERSION${NC}"
    echo
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log "ERROR" "Ce script doit être exécuté en tant que root"
        exit 1
    fi
}

detect_system() {
    log "INFO" "Détection du système d'exploitation..."
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_NAME="$NAME"
        OS_VERSION="$VERSION_ID"
        OS_CODENAME="${VERSION_CODENAME:-unknown}"
        
        log "INFO" "Système détecté: $OS_NAME $OS_VERSION ($OS_CODENAME)"
        
        # Vérifier la compatibilité
        case "$ID" in
            ubuntu|debian|linuxmint|pop)
                log "SUCCESS" "Système compatible détecté"
                ;;
            *)
                log "WARNING" "Système non testé: $ID. Installation en mode best-effort."
                ;;
        esac
    else
        log "ERROR" "Impossible de détecter le système d'exploitation"
        exit 1
    fi
}

check_python_version() {
    log "INFO" "Vérification de la version Python..."
    
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        log "INFO" "Python $PYTHON_VERSION détecté"
        
        # Comparer les versions
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
            log "SUCCESS" "Version Python compatible"
        else
            log "ERROR" "Python $PYTHON_MIN_VERSION+ requis, $PYTHON_VERSION détecté"
            exit 1
        fi
    else
        log "ERROR" "Python 3 non trouvé"
        exit 1
    fi
}

install_system_dependencies() {
    log "INFO" "Mise à jour du système..."
    apt update && apt upgrade -y
    
    log "INFO" "Installation des dépendances système..."
    
    # Dépendances de base
    local base_packages=(
        "python3"
        "python3-pip"
        "python3-venv"
        "python3-dev"
        "sqlite3"
        "git"
        "curl"
        "wget"
        "jq"
        "htop"
        "iotop"
        "net-tools"
        "lsof"
        "build-essential"
        "pkg-config"
        "libffi-dev"
        "libssl-dev"
    )
    
    # Dépendances pour Pillow (importantes pour éviter les erreurs de build)
    local pillow_deps=(
        "libjpeg-dev"
        "zlib1g-dev"
        "libpng-dev"
        "libtiff-dev"
        "libfreetype6-dev"
        "libwebp-dev"
    )
    
    # Dépendances optionnelles pour interface graphique
    local gui_packages=(
        "python3-tk"
        "python3-pil"
        "python3-pil.imagetk"
    )
    
    # Installation des paquets de base
    log "INFO" "Installation des dépendances de base..."
    apt install -y "${base_packages[@]}"
    
    # Installation des dépendances Pillow
    log "INFO" "Installation des dépendances pour l'image processing..."
    apt install -y "${pillow_deps[@]}" || {
        log "WARNING" "Certaines dépendances Pillow n'ont pas pu être installées"
    }
    
    # Installation des dépendances GUI (optionnel)
    log "INFO" "Installation des dépendances GUI (optionnel)..."
    for package in "${gui_packages[@]}"; do
        if apt install -y "$package" 2>/dev/null; then
            log "SUCCESS" "Paquet GUI $package installé"
        else
            log "WARNING" "Paquet GUI $package non disponible (interface graphique limitée)"
        fi
    done
    
    log "SUCCESS" "Dépendances système installées"
}

create_ezrax_user() {
    log "INFO" "Création de l'utilisateur dédié $EZRAX_USER..."
    
    if id "$EZRAX_USER" &>/dev/null; then
        log "INFO" "Utilisateur $EZRAX_USER existe déjà"
    else
        useradd -m -s /bin/bash -d "/home/$EZRAX_USER" -c "EZRAX Server User" "$EZRAX_USER"
        log "SUCCESS" "Utilisateur $EZRAX_USER créé"
    fi
    
    # Ajouter aux groupes nécessaires
    usermod -a -G adm,systemd-journal "$EZRAX_USER" 2>/dev/null || true
    sudo usermod -a -G ezrax $(whoami)
    # Créer les répertoires utilisateur
    mkdir -p "/home/$EZRAX_USER/.ezrax"
    chown -R "$EZRAX_USER:$EZRAX_USER" "/home/$EZRAX_USER"
}

setup_application_directory() {
    log "INFO" "Configuration du répertoire de l'application..."
    
    # Créer les répertoires
    mkdir -p "$EZRAX_DIR"/{logs,data,config,backups,reports}
    mkdir -p "$EZRAX_DIR/logs"/{api,database,monitoring}
    
    # Copier les fichiers depuis le répertoire courant
    log "INFO" "Copie des fichiers de l'application..."
    if [[ -f "server.py" ]]; then
        cp -r ./* "$EZRAX_DIR/"
        log "SUCCESS" "Fichiers copiés depuis le répertoire courant"
    else
        log "ERROR" "Fichiers sources non trouvés dans le répertoire courant"
        exit 1
    fi
    
    # Supprimer les fichiers de développement
    rm -f "$EZRAX_DIR"/{setup_server.sh,*.md,*.log}
    
    # Permissions
    
    chown -R "$EZRAX_USER:$EZRAX_USER" "$EZRAX_DIR"
    chmod -R 755 "$EZRAX_DIR"
    chmod 600 "$EZRAX_DIR"/*.py 2>/dev/null || true
    
    log "SUCCESS" "Répertoire de l'application configuré"
}

setup_python_environment() {
    log "INFO" "Configuration de l'environnement Python..."
    
    # Créer l'environnement virtuel
    sudo -u "$EZRAX_USER" python3 -m venv "$EZRAX_DIR/venv"
    
    # Activer et mettre à jour pip
    sudo -u "$EZRAX_USER" "$EZRAX_DIR/venv/bin/pip" install --upgrade pip wheel setuptools
    
    # Installer les dépendances
    if [[ -f "$EZRAX_DIR/requirements.txt" ]]; then
        log "INFO" "Installation des dépendances Python depuis requirements.txt..."
        sudo -u "$EZRAX_USER" "$EZRAX_DIR/venv/bin/pip" install -r "$EZRAX_DIR/requirements.txt"
    else
        log "INFO" "Installation des dépendances Python de base..."
        local python_packages=(
            "flask==2.3.3"
            "werkzeug==2.3.7"
            "requests==2.31.0"
            "ttkthemes==3.2.2"
            "pyjwt==2.8.0"
            "Pillow==10.0.1"
            "python-dateutil==2.8.2"
        )
        
        sudo -u "$EZRAX_USER" "$EZRAX_DIR/venv/bin/pip" install "${python_packages[@]}"
    fi
    
    log "SUCCESS" "Environnement Python configuré"
}

generate_configuration() {
    log "INFO" "Génération de la configuration..."
    
    # Détecter l'IP du serveur
    SERVER_IP=$(ip route get 8.8.8.8 | grep -oP 'src \K\S+' 2>/dev/null || echo "127.0.0.1")
    
    # Générer des secrets sécurisés
    API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    
    # Créer le fichier de configuration
    cat > "$EZRAX_DIR/server_config.json" << EOF
{
  "server": {
    "host": "0.0.0.0",
    "port": 5000,
    "debug": false,
    "max_content_length": 16777216,
    "request_timeout": 30
  },
  "database": {
    "path": "$EZRAX_DIR/data/ezrax_server.db",
    "pool_size": 15,
    "backup_enabled": true,
    "backup_interval": 86400,
    "retention_days": 30
  },
  "security": {
    "api_key": "$API_KEY",
    "jwt_secret": "$JWT_SECRET",
    "admin_api_enabled": true,
    "rate_limiting": {
      "agents": {"max_requests": 1000, "window_seconds": 60},
      "admin": {"max_requests": 200, "window_seconds": 60},
      "public": {"max_requests": 50, "window_seconds": 60}
    }
  },
  "logging": {
    "level": "INFO",
    "file": "$EZRAX_DIR/logs/ezrax_server.log",
    "max_size": 10485760,
    "backup_count": 5,
    "console_enabled": true
  },
  "monitoring": {
    "metrics_enabled": true,
    "performance_alerts": true,
    "health_check_interval": 60
  }
}
EOF
    
    # Permissions sécurisées pour la configuration
    chown "$EZRAX_USER:$EZRAX_USER" "$EZRAX_DIR/server_config.json"
    chmod 600 "$EZRAX_DIR/server_config.json"
    
    log "SUCCESS" "Configuration générée"
    log "INFO" "Clé API: $API_KEY"
    log "WARNING" "Sauvegardez cette clé API dans un endroit sûr!"
}

create_ezraxtl_command() {
    log "INFO" "Création de la commande ezraxtl..."
    
    cat > /usr/local/bin/ezraxtl << 'EOF'
#!/bin/bash

# Commande de gestion EZRAX Central Server v2.0
# Usage: ezraxtl {start|stop|restart|status|logs|config|backup|restore|update}

EZRAX_DIR="/opt/ezrax-server"
EZRAX_USER="ezrax"
LOGS_DIR="$EZRAX_DIR/logs"
PID_FILE="$LOGS_DIR/ezrax.pid"
LOG_FILE="$LOGS_DIR/ezrax_server.log"
CONFIG_FILE="$EZRAX_DIR/server_config.json"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_message() {
    local level=$1
    shift
    local message="$*"
    
    case $level in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
    esac
}

check_permissions() {
    if [[ $EUID -ne 0 ]]; then
        log_message "ERROR" "Cette commande doit être exécutée en tant que root"
        exit 1
    fi
}

ensure_directories() {
    mkdir -p "$LOGS_DIR"
    chown -R "$EZRAX_USER:$EZRAX_USER" "$LOGS_DIR"
}

is_running() {
    if [[ -f "$PID_FILE" ]]; then
        local pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        else
            rm -f "$PID_FILE"
        fi
    fi
    return 1
}

start_server() {
    if is_running; then
        log_message "INFO" "Le serveur EZRAX est déjà en cours d'exécution"
        return 0
    fi
    
    log_message "INFO" "Démarrage du serveur EZRAX..."
    ensure_directories
    
    # Vérifier la configuration
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_message "ERROR" "Fichier de configuration manquant: $CONFIG_FILE"
        return 1
    fi
    
    # Vérifier l'environnement Python
    if [[ ! -f "$EZRAX_DIR/venv/bin/python" ]]; then
        log_message "ERROR" "Environnement Python manquant: $EZRAX_DIR/venv"
        return 1
    fi
    
    # Démarrer le serveur
    cd "$EZRAX_DIR"
    sudo -u "$EZRAX_USER" sh -c "nohup '$EZRAX_DIR/venv/bin/python' '$EZRAX_DIR/server.py' \
        --config '$CONFIG_FILE' --daemon > '$LOG_FILE' 2>&1 & echo \$! > '$PID_FILE'"
    
    sleep 1 
    if [[ ! -f "$PID_FILE" ]]; then
        log_message "WARNING" "Fichier PID non créé après 1s. Le démarrage a peut-être échoué."
    fi
    
    # Vérifier que le démarrage a réussi
    sleep 2
    if is_running; then
        log_message "SUCCESS" "Serveur EZRAX démarré (PID: $(cat $PID_FILE))"
        
        # Afficher les informations de connexion
        local port=$(jq -r '.server.port' "$CONFIG_FILE" 2>/dev/null || echo "5000")
        local api_key=$(jq -r '.security.api_key' "$CONFIG_FILE" 2>/dev/null || echo "N/A")
        
        echo
        log_message "INFO" "Serveur accessible sur: http://localhost:$port"
        log_message "INFO" "Clé API: ${api_key:0:8}..."
        echo
    else
        log_message "ERROR" "Échec du démarrage du serveur. Vérifiez les logs:"
        log_message "INFO" "ezraxtl logs"
        if [[ -f "$LOG_FILE" ]]; then
            log_message "INFO" "Dernières lignes du log:"
            tail -n 10 "$LOG_FILE"
        fi
        return 1

    fi
}


start_gui() {
    log_message "INFO" "Tentative de démarrage du serveur EZRAX avec interface graphique..."
    ensure_directories 
    
    # Vérifier si X11 est disponible pour l'utilisateur courant
    if [ -z "$DISPLAY" ]; then
        log_message "ERROR" "Variable DISPLAY non définie. L'interface graphique ne peut pas être lancée."
        log_message "INFO" "Assurez-vous d'être dans une session graphique ou utilisez X11 forwarding (ssh -X)."
        return 1
    fi
    
    if ! xset q &>/dev/null; then
        log_message "ERROR" "Serveur X11 non disponible ou non accessible. Interface graphique impossible."
        return 1
    fi
    
    # Vérifier les dépendances Tkinter dans le venv
    if ! sudo -u "$EZRAX_USER" "$EZRAX_DIR/venv/bin/python" -c "import tkinter; import ttkthemes" &>/dev/null; then
        log_message "ERROR" "Modules Tkinter ou ttkthemes manquants dans l'environnement virtuel de l'utilisateur '$EZRAX_USER'."
        log_message "INFO" "Assurez-vous que python3-tk est installé sur le système et que ttkthemes est dans requirements.txt."
        return 1
    fi

    cd "$EZRAX_DIR"
    log_message "INFO" "Lancement de server.py en mode GUI (en tant qu'utilisateur '$EZRAX_USER')..."
    log_message "INFO" "Le serveur restera au premier plan. Fermez la fenêtre GUI pour arrêter le serveur."
    log_message "INFO" "Les logs du serveur iront dans la console et dans $LOG_FILE."

    # Essayer de passer les credentials X11 à l'utilisateur ezrax
    # Cela suppose que l'utilisateur qui lance `sudo ezraxtl gui` a un Xauthority valide.
    local current_xauthority_file
    if [ -n "$XAUTHORITY" ] && [ -f "$XAUTHORITY" ]; then
        current_xauthority_file="$XAUTHORITY"
    elif [ -f "$HOME/.Xauthority" ]; then
        current_xauthority_file="$HOME/.Xauthority"
    else
        log_message "WARNING" "Fichier XAUTHORITY non trouvé. La GUI pourrait ne pas se lancer pour l'utilisateur '$EZRAX_USER'."
        # Tenter sans, DISPLAY est la variable la plus critique.
    fi

    # Construire la commande
  
    # On s'assure que server_config.json est utilisé.
    local server_cmd_gui="'$EZRAX_DIR/venv/bin/python' '$EZRAX_DIR/server.py' --config '$CONFIG_FILE'"

    if [ -n "$current_xauthority_file" ]; then
        # Exécuter avec sudo -u, en passant DISPLAY et XAUTHORITY
        # Rediriger stdout et stderr vers le log principal du serveur et la console actuelle
        sudo -u "$EZRAX_USER" \
             DISPLAY="$DISPLAY" \
             XAUTHORITY="$current_xauthority_file" \
             sh -c "$server_cmd_gui 2>&1 | tee -a '$LOG_FILE'"
    else
        # Tenter sans XAUTHORITY spécifique (moins de chances de succès pour les permissions X)
        sudo -u "$EZRAX_USER" \
             DISPLAY="$DISPLAY" \
             sh -c "$server_cmd_gui 2>&1 | tee -a '$LOG_FILE'"
    fi

    
    log_message "INFO" "Serveur EZRAX (mode GUI) terminé."
}

stop_server() {
    if ! is_running; then
        log_message "INFO" "Le serveur EZRAX n'est pas en cours d'exécution"
        return 0
    fi
    
    local pid=$(cat "$PID_FILE")
    log_message "INFO" "Arrêt du serveur EZRAX (PID: $pid)..."
    
    # Tentative d'arrêt gracieux
    kill "$pid" 2>/dev/null
    
    # Attendre l'arrêt avec un timeout plus long
    local count=0
    while is_running && [[ $count -lt 20 ]]; do
        sleep 1
        ((count++))
    done
    
    # Vérifier si le processus existe toujours, quelle que soit la valeur dans le fichier PID
    if kill -0 "$pid" 2>/dev/null; then
        log_message "WARNING" "Arrêt forcé du serveur..."
        # Utiliser SIGKILL
        kill -9 "$pid" 2>/dev/null
        sleep 2
        
        # Vérifier à nouveau
        if kill -0 "$pid" 2>/dev/null; then
            log_message "WARNING" "Le processus résiste! Tentative avec killall..."
            # Dernière tentative avec killall
            killall -9 python3 2>/dev/null || true
        fi
    fi
    
    # Supprimer le fichier PID même si le kill échoue
    rm -f "$PID_FILE"
    log_message "SUCCESS" "Serveur EZRAX arrêté"
    
    # Nettoyer les processus orphelins liés à EZRAX
    pkill -f "ezrax.*python" 2>/dev/null || true
}

show_status() {
    echo "=== STATUT DU SERVEUR EZRAX ==="
    echo
    
    # Statut du processus
    if is_running; then
        local pid=$(cat "$PID_FILE")
        log_message "SUCCESS" "Serveur: EN FONCTIONNEMENT (PID: $pid)"
        
        # Informations sur le processus
        if command -v ps >/dev/null 2>&1; then
            echo
            echo "Informations du processus:"
            ps -p "$pid" -o pid,user,etime,cpu,mem,cmd 2>/dev/null | sed 's/^/  /'
        fi
    else
        log_message "ERROR" "Serveur: ARRÊTÉ"
    fi
    
    echo
    
    # Configuration
    if [[ -f "$CONFIG_FILE" ]]; then
        local port=$(jq -r '.server.port' "$CONFIG_FILE" 2>/dev/null || echo "N/A")
        local host=$(jq -r '.server.host' "$CONFIG_FILE" 2>/dev/null || echo "N/A")
        local admin_api=$(jq -r '.security.admin_api_enabled' "$CONFIG_FILE" 2>/dev/null || echo "N/A")
        
        echo "Configuration:"
        echo "  Adresse: $host:$port"
        echo "  API Admin: $admin_api"
    fi
    
    # Base de données
    if [[ -f "$CONFIG_FILE" ]]; then
        local db_path=$(jq -r '.database.path' "$CONFIG_FILE" 2>/dev/null || echo "N/A")
        if [[ -f "$db_path" ]]; then
            local db_size=$(du -h "$db_path" 2>/dev/null | cut -f1)
            echo "  Base de données: $db_size"
        fi
    fi
    
    # Ports en écoute
    echo
    echo "Ports en écoute:"
    netstat -tuln 2>/dev/null | grep -E ':(5000|80|443)' | sed 's/^/  /' || echo "  Aucun port EZRAX détecté"
    
    # Logs récents
    echo
    echo "Dernières entrées de log:"
    if [[ -f "$LOG_FILE" ]]; then
        tail -n 3 "$LOG_FILE" 2>/dev/null | sed 's/^/  /' || echo "  Aucun log disponible"
    else
        echo "  Fichier de log non trouvé"
    fi
}

show_logs() {
    local log_type="${1:-server}"
    
    case "$log_type" in
        "server"|"main")
            if [[ -f "$LOG_FILE" ]]; then
                log_message "INFO" "Logs du serveur (Ctrl+C pour quitter):"
                tail -f "$LOG_FILE"
            else
                log_message "ERROR" "Fichier de log non trouvé: $LOG_FILE"
            fi
            ;;
        "error"|"errors")
            if [[ -f "$LOG_FILE" ]]; then
                log_message "INFO" "Erreurs dans les logs:"
                grep -i "error\|exception\|failed\|critical" "$LOG_FILE" | tail -20
            else
                log_message "ERROR" "Fichier de log non trouvé"
            fi
            ;;
        "api")
            local api_log="$LOGS_DIR/api/api.log"
            if [[ -f "$api_log" ]]; then
                log_message "INFO" "Logs de l'API:"
                tail -f "$api_log"
            else
                log_message "WARNING" "Logs API non trouvés, affichage des logs principaux"
                show_logs "server"
            fi
            ;;
        *)
            log_message "ERROR" "Type de log non reconnu: $log_type"
            echo "Types disponibles: server, error, api"
            ;;
    esac
}

show_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log_message "INFO" "Configuration actuelle:"
        echo
        
        # Masquer les secrets
        jq '. | .security.api_key = "***MASKED***" | .security.jwt_secret = "***MASKED***"' "$CONFIG_FILE" 2>/dev/null || {
            log_message "WARNING" "jq non disponible, affichage brut:"
            cat "$CONFIG_FILE"
        }
    else
        log_message "ERROR" "Fichier de configuration non trouvé: $CONFIG_FILE"
    fi
}

backup_data() {
    local backup_dir="$EZRAX_DIR/backups"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_file="$backup_dir/ezrax_backup_$timestamp.tar.gz"
    
    log_message "INFO" "Création d'une sauvegarde..."
    
    mkdir -p "$backup_dir"
    
    # Arrêter temporairement le serveur si en cours d'exécution
    local was_running=false
    if is_running; then
        was_running=true
        log_message "INFO" "Arrêt temporaire du serveur pour la sauvegarde..."
        stop_server
    fi
    
    # Créer l'archive
    cd "$EZRAX_DIR"
    tar -czf "$backup_file" \
        --exclude="venv" \
        --exclude="logs/*.log" \
        --exclude="backups" \
        data/ config/ server_config.json *.py 2>/dev/null
    
    if [[ -f "$backup_file" ]]; then
        local size=$(du -h "$backup_file" | cut -f1)
        log_message "SUCCESS" "Sauvegarde créée: $backup_file ($size)"
        
        # Nettoyer les anciennes sauvegardes (garder 7 jours)
        find "$backup_dir" -name "ezrax_backup_*.tar.gz" -mtime +7 -delete 2>/dev/null
        
        chown "$EZRAX_USER:$EZRAX_USER" "$backup_file"
    else
        log_message "ERROR" "Échec de la création de la sauvegarde"
    fi
    
    # Redémarrer le serveur si nécessaire
    if [[ "$was_running" == "true" ]]; then
        log_message "INFO" "Redémarrage du serveur..."
        start_server
    fi
}


show_help() {
    echo "Usage: ezraxtl {command} [options]"
    echo
    echo "Commandes disponibles:"
    echo "  start         Démarrer le serveur EZRAX"
    echo "  gui           Démarrer le serveur EZRAX avec interface graphique(éxécutée après : xhost +si:localuser:ezrax)"
    echo "  stop          Arrêter le serveur EZRAX"
    echo "  restart       Redémarrer le serveur EZRAX"
    echo "  status        Afficher le statut du serveur"
    echo "  logs [type]   Afficher les logs (server|error|api)"
    echo "  config        Afficher la configuration"
    echo "  backup        Créer une sauvegarde"
    echo "  help          Afficher cette aide"
    echo
    echo "Exemples:"
    echo "  ezraxtl start"
    echo "  ezraxtl logs error"
    echo "  ezraxtl status"
}

# Point d'entrée principal
main() {
    case "${1:-}" in
        "start")
            check_permissions
            start_server
            ;;
        "gui")
            check_permissions
            start_gui
            ;;
        "stop")
            check_permissions
            stop_server
            ;;
        "restart")
            check_permissions
            stop_server
            sleep 2
            start_server
            ;;
        "status")
            show_status
            ;;
        "logs")
            show_logs "${2:-server}"
            ;;
        "config")
            show_config
            ;;
        "backup")
            check_permissions
            backup_data
            ;;
        "update")
            check_permissions
            update_server
            ;;
        "help"|"--help"|"-h")
            show_help
            ;;
        "")
            log_message "ERROR" "Commande manquante"
            show_help
            exit 1
            ;;
        *)
            log_message "ERROR" "Commande inconnue: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
EOF
    
    chmod +x /usr/local/bin/ezraxtl
    log "SUCCESS" "Commande ezraxtl créée"
}

setup_logrotate() {
    log "INFO" "Configuration de la rotation des logs..."
    
    cat > /etc/logrotate.d/ezrax-server << EOF
$EZRAX_DIR/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
    su $EZRAX_USER $EZRAX_USER
}
EOF
    
    log "SUCCESS" "Rotation des logs configurée"
}

create_firewall_rules() {
    log "INFO" "Configuration du pare-feu (optionnel)..."
    
    # Vérifier si ufw est disponible
    if command -v ufw >/dev/null 2>&1; then
        # Port API (5000)
        ufw allow 5000/tcp comment "EZRAX API" 2>/dev/null || true
        
        log "SUCCESS" "Règles pare-feu ajoutées (port 5000)"
    else
        log "WARNING" "UFW non disponible, configuration manuelle du pare-feu requise"
        log "INFO" "Ouvrez le port 5000/tcp pour l'API EZRAX"
    fi
}

run_post_install_tests() {
    log "INFO" "Exécution des tests post-installation..."
    
    local tests_passed=0
    local tests_total=6
    
    # Test 1: Fichiers de l'application
    if [[ -f "$EZRAX_DIR/server.py" ]]; then
        log "SUCCESS" "Test 1/6: Fichiers de l'application présents"
        ((tests_passed++))
    else
        log "ERROR" "Test 1/6: Fichiers de l'application manquants"
    fi
    
    # Test 2: Environnement Python
    if sudo -u "$EZRAX_USER" "$EZRAX_DIR/venv/bin/python" --version >/dev/null 2>&1; then
        log "SUCCESS" "Test 2/6: Environnement Python fonctionnel"
        ((tests_passed++))
    else
        log "ERROR" "Test 2/6: Problème avec l'environnement Python"
    fi
    
    # Test 3: Dépendances Python
    if sudo -u "$EZRAX_USER" "$EZRAX_DIR/venv/bin/python" -c "import flask, requests, jwt" 2>/dev/null; then
        log "SUCCESS" "Test 3/6: Dépendances Python installées"
        ((tests_passed++))
    else
        log "ERROR" "Test 3/6: Dépendances Python manquantes"
    fi
    
    # Test 4: Configuration
    if [[ -f "$EZRAX_DIR/server_config.json" ]] && jq empty < "$EZRAX_DIR/server_config.json" 2>/dev/null; then
        log "SUCCESS" "Test 4/6: Configuration valide"
        ((tests_passed++))
    else
        log "ERROR" "Test 4/6: Configuration invalide"
    fi
    
    # Test 5: Permissions
    if [[ -O "$EZRAX_DIR" ]] || [[ "$(stat -c '%U' "$EZRAX_DIR")" == "$EZRAX_USER" ]]; then
        log "SUCCESS" "Test 5/6: Permissions correctes"
        ((tests_passed++))
    else
        log "ERROR" "Test 5/6: Problème de permissions"
    fi
    
    # Test 6: Commande ezraxtl
    if command -v ezraxtl >/dev/null 2>&1; then
        log "SUCCESS" "Test 6/6: Commande ezraxtl disponible"
        ((tests_passed++))
    else
        log "ERROR" "Test 6/6: Commande ezraxtl non disponible"
    fi
    
    echo
    if [[ $tests_passed -eq $tests_total ]]; then
        log "SUCCESS" "Tous les tests post-installation réussis ($tests_passed/$tests_total)"
        return 0
    else
        log "WARNING" "Certains tests ont échoué ($tests_passed/$tests_total)"
        return 1
    fi
}

show_installation_summary() {
    echo
    echo -e "${GREEN}=================================${NC}"
    echo -e "${GREEN}  INSTALLATION TERMINÉE${NC}"
    echo -e "${GREEN}=================================${NC}"
    echo
    echo -e "${WHITE}Répertoire d'installation:${NC} $EZRAX_DIR"
    echo -e "${WHITE}Utilisateur:${NC} $EZRAX_USER"
    echo -e "${WHITE}Configuration:${NC} $EZRAX_DIR/server_config.json"
    echo -e "${WHITE}Logs:${NC} $EZRAX_DIR/logs/"
    echo
    echo -e "${YELLOW}Commandes de gestion:${NC}"
    echo "  ezraxtl start      - Démarrer le serveur"
    echo "  ezraxtl gui        - Démarrer avec interface graphique(éxécutée après : xhost +si:localuser:ezrax)"
    echo "  ezraxtl stop       - Arrêter le serveur"
    echo "  ezraxtl status     - Vérifier le statut"
    echo "  ezraxtl logs       - Afficher les logs"
    echo "  ezraxtl backup     - Créer une sauvegarde"
    echo "  ezraxtl help       - Aide complète"
    
    # Afficher les informations de sécurité
    if [[ -f "$EZRAX_DIR/server_config.json" ]]; then
        local api_key=$(jq -r '.security.api_key' "$EZRAX_DIR/server_config.json" 2>/dev/null)
        local port=$(jq -r '.server.port' "$EZRAX_DIR/server_config.json" 2>/dev/null || echo "5000")
        
        echo -e "${YELLOW}Informations de connexion:${NC}"
        echo "  URL du serveur: http://$(hostname -I | awk '{print $1}'):$port"
        echo "  Clé API: $api_key"
        echo
        echo -e "${RED}IMPORTANT: Sauvegardez la clé API dans un endroit sûr!${NC}"
    fi
    
    echo
    echo -e "${CYAN}Pour démarrer le serveur maintenant:${NC}"
    echo "  sudo ezraxtl start"
    echo
}

cleanup_on_error() {
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        log "ERROR" "Installation échouée (code: $exit_code)"
        log "INFO" "Logs d'installation disponibles: $LOG_FILE"
        
        # Nettoyer partiellement si nécessaire
        if [[ -d "$EZRAX_DIR" ]] && [[ "$EZRAX_DIR" != "/" ]]; then
            log "INFO" "Nettoyage partiel disponible avec: rm -rf $EZRAX_DIR"
        fi
    fi
}

# Fonction principale
main() {
    # Initialiser le fichier de log
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    
    # Gestionnaire d'erreur
    trap cleanup_on_error EXIT
    
    # Bannière
    banner
    
    # Vérifications préliminaires
    check_root
    detect_system
    check_python_version
    
    # Installation
    log "INFO" "Début de l'installation EZRAX Central Server v$SCRIPT_VERSION"
    
    install_system_dependencies
    create_ezrax_user
    setup_application_directory
    setup_python_environment
    generate_configuration
    create_ezraxtl_command
    setup_logrotate
    create_firewall_rules
    
    # Tests post-installation
    if run_post_install_tests; then
        show_installation_summary
        log "SUCCESS" "Installation complétée avec succès!"
    else
        log "WARNING" "Installation complétée avec des avertissements"
        log "INFO" "Vérifiez les logs pour plus de détails: $LOG_FILE"
    fi
    
    # Supprimer le gestionnaire d'erreur
    trap - EXIT
}


if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
