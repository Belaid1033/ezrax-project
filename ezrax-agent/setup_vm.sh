#!/bin/bash

# Script d'installation automatisée pour l'agent EZRAX IDS/IPS
# À exécuter sur Ubuntu Server +24.10

set -e  # Arrêter l'exécution en cas d'erreur

echo "[*] Début de l'installation de l'agent EZRAX..."

# Vérifier que le script est exécuté en tant que root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Ce script doit être exécuté en tant que root"
  exit 1
fi

# Mise à jour du système
echo "[*] Mise à jour du système..."
apt update && apt upgrade -y

# Installation des dépendances système
echo "[*] Installation des dépendances système..."
apt install -y python3 python3-pip python3-venv iptables sqlite3 tcpdump git net-tools libcap2-bin

# Création des répertoires de l'application
echo "[*] Création des répertoires de l'application..."
mkdir -p /opt/ezrax-agent
mkdir -p /opt/ezrax-agent/logs
mkdir -p /opt/ezrax-agent/storage
mkdir -p /opt/ezrax-agent/reports

# Copie des fichiers depuis le répertoire actuel
echo "[*] Utilisation des fichiers du répertoire courant..."
cp -r ./* /opt/ezrax-agent/

# Création d'un environnement virtuel Python
echo "[*] Création d'un environnement virtuel Python..."
python3 -m venv /opt/ezrax-agent/venv
source /opt/ezrax-agent/venv/bin/activate

# Installation des dépendances Python
echo "[*] Installation des dépendances Python..."
pip install --upgrade pip
if [ -f /opt/ezrax-agent/requirements.txt ]; then
    pip install -r /opt/ezrax-agent/requirements.txt
else
    echo "[!] Fichier requirements.txt non trouvé, installation des dépendances de base..."
    pip install scapy paramiko requests psutil python-dotenv pyyaml schedule jinja2
fi

# Détection automatique de l'interface réseau active
echo "[*] Détection de l'interface réseau active..."
ACTIVE_INTERFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+' | head -1)
if [ -z "$ACTIVE_INTERFACE" ]; then
    ACTIVE_INTERFACE="enp0s3"
    echo "[!] Interface réseau non détectée, utilisation de eth0 par défaut"
else
    echo "[*] Interface réseau détectée: $ACTIVE_INTERFACE"
fi

# Configuration des permissions pour la capture réseau
echo "[*] Configuration des permissions pour la capture réseau..."

# Donner les capacités nécessaires au binaire Python pour la capture réseau
SYSTEM_PYTHON=$(readlink -f $(which python3))
setcap cap_net_raw,cap_net_admin+eip "$SYSTEM_PYTHON"


# Configuration des permissions iptables pour l'agent
echo "[*] Configuration des permissions iptables..."
mkdir -p /etc/ezrax
cat > /etc/sudoers.d/ezrax-agent << EOF
# Permissions pour l'agent EZRAX
ezrax ALL=(ALL) NOPASSWD: /sbin/iptables
ezrax ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump
ezrax ALL=(ALL) NOPASSWD: /opt/ezrax-agent/venv/bin/python
EOF
chmod 440 /etc/sudoers.d/ezrax-agent

# Création d'un utilisateur dédié
echo "[*] Création d'un utilisateur dédié..."
useradd -m -s /bin/bash -d /home/ezrax ezrax 2>/dev/null || true

# Ajouter l'utilisateur ezrax au groupe netdev pour l'accès réseau
usermod -a -G netdev ezrax 2>/dev/null || true

mkdir -p /home/ezrax/.ezrax
chown -R ezrax:ezrax /home/ezrax/.ezrax
chown -R ezrax:ezrax /opt/ezrax-agent

# Création de l'ID unique de l'agent s'il n'existe pas
echo "[*] Vérification de l'ID de l'agent..."
AGENT_ID_FILE="/opt/ezrax-agent/.agent_id"
if [ ! -f "$AGENT_ID_FILE" ]; then
    echo "[*] Génération d'un nouvel ID pour l'agent..."
    AGENT_ID=$(python3 -c "import uuid; print(str(uuid.uuid4()))")
    echo "$AGENT_ID" > "$AGENT_ID_FILE"
    chown ezrax:ezrax "$AGENT_ID_FILE"
    chmod 644 "$AGENT_ID_FILE"
    echo "[*] ID de l'agent généré: $AGENT_ID"
fi

# Création de l'outil de gestion ezraxtl-agent
echo "[*] Création de l'outil de gestion ezraxtl-agent..."
cat > /usr/local/bin/ezraxtl-agent << 'EOF'
#!/bin/bash

# Outil de gestion pour l'agent EZRAX IDS/IPS
EZRAX_DIR="/opt/ezrax-agent"
LOGS_DIR="$EZRAX_DIR/logs"
PID_FILE="$LOGS_DIR/agent.pid"
LOG_FILE="$LOGS_DIR/agent.log"

# Créer le répertoire de logs s'il n'existe pas
mkdir -p "$LOGS_DIR"

# Fonction pour démarrer l'agent
start() {
    # Vérifier si l'agent est déjà en cours d'exécution
    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo "L'agent EZRAX est déjà en cours d'exécution."
        return
    fi
    
    echo "Démarrage de l'agent EZRAX..."
    cd "$EZRAX_DIR"
    
    # S'assurer que l'utilisateur ezrax a les permissions nécessaires
    if [ "$(stat -c '%U' $LOGS_DIR)" != "ezrax" ]; then
        chown -R ezrax:ezrax "$LOGS_DIR"
    fi
    
    # Vérifier les capacités sur le binaire Python
    SYSTEM_PYTHON=$(readlink -f "$(which python3)")
    if ! getcap "$SYSTEM_PYTHON" | grep -q "cap_net_raw,cap_net_admin"; then
        echo "[*] Mise à jour des capacités réseau pour Python système ($SYSTEM_PYTHON)..."
        sudo setcap cap_net_raw,cap_net_admin+eip "$SYSTEM_PYTHON"
    fi
    
    # Démarrer l'agent avec l'utilisateur ezrax
    sudo -u ezrax nohup "$EZRAX_DIR/venv/bin/python3" "$EZRAX_DIR/main.py" > "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    echo "Agent démarré avec PID $(cat $PID_FILE)"
    
    # Vérifier le statut après le démarrage
    sleep 3
    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        # Vérifier si des erreurs de permissions sont présentes dans le log
        if grep -q "Operation not permitted" "$LOG_FILE"; then
            echo "AVERTISSEMENT: Erreurs de permissions détectées. Vérifiez la configuration réseau."
            echo "  Utilisez: ezraxtl-agent fix"
        else
            echo "L'agent EZRAX est en cours d'exécution avec succès."
        fi
    else
        echo "ERREUR: L'agent n'a pas pu démarrer correctement. Consultez les logs pour plus d'informations."
        echo "  ezraxtl-agent logs"
    fi
}

# Fonction pour arrêter l'agent
stop() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 $PID 2>/dev/null; then
            echo "Arrêt de l'agent EZRAX (PID: $PID)..."
            kill $PID
            sleep 2
            
            # Vérifier si le processus est toujours en cours
            if kill -0 $PID 2>/dev/null; then
                echo "L'agent ne répond pas, arrêt forcé..."
                kill -9 $PID
            fi
            
            rm -f "$PID_FILE"
            echo "Agent EZRAX arrêté"
        else
            echo "L'agent EZRAX n'est pas en cours d'exécution (PID invalide)"
            rm -f "$PID_FILE"
        fi
    else
        echo "Aucun PID trouvé, l'agent EZRAX n'est pas en cours d'exécution"
    fi
}

# Fonction pour vérifier le statut de l'agent
status() {
    echo "Statut de l'agent EZRAX:"
    
    # Vérifier le processus
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 $PID 2>/dev/null; then
            echo " - Agent: En cours d'exécution (PID: $PID)"
            ps -p $PID -o pid,user,etime,cmd | sed 1d
        else
            echo " - Agent: Arrêté (PID invalide: $PID)"
        fi
    else
        echo " - Agent: Arrêté (aucun PID trouvé)"
    fi
    
    # Vérifier les capacités réseau
    echo " - Capacités réseau:"
    CAPS=$(getcap "$EZRAX_DIR/venv/bin/python3" 2>/dev/null)
    if [ -n "$CAPS" ]; then
        echo "   - $CAPS"
    else
        echo "   - Aucune capacité définie (PROBLÈME)"
    fi
    
    # Vérifier les scanners actifs (à travers les logs)
    if [ -f "$LOG_FILE" ]; then
        echo " - Scanners actifs:"
        grep -o "Démarrage du scanner [A-Za-z]*Scanner" "$LOG_FILE" | sort | uniq | sed 's/Démarrage du scanner/  -/'
        
        # Vérifier les erreurs de permissions
        ERROR_COUNT=$(grep -c "Operation not permitted" "$LOG_FILE" 2>/dev/null || echo "0")
        if [ "$ERROR_COUNT" -gt 0 ]; then
            echo " - Erreurs de permissions: $ERROR_COUNT (PROBLÈME)"
        else
            echo " - Erreurs de permissions: 0"
        fi
    fi
    
    # Afficher les IPs bloquées
    BLOCKED_COUNT=$(sudo iptables -L EZRAX_IPS -n 2>/dev/null | grep -c DROP || echo "0")
    echo " - IPs bloquées: $BLOCKED_COUNT"
    
    # Afficher les interfaces réseau disponibles
    echo " - Interfaces réseau:"
    ip link show | grep "state UP" | awk '{print "   - " $2}' | sed 's/:$//'
    
    # Afficher la connexion au serveur central
    CENTRAL_SERVER=$(grep -o "host.*:.*" "$EZRAX_DIR/agent_config.yaml" 2>/dev/null | sed 's/.*: *"\([^"]*\)".*/\1/')
    if [ -n "$CENTRAL_SERVER" ]; then
        echo " - Serveur central: $CENTRAL_SERVER"
        ping -c 1 -w 1 $CENTRAL_SERVER >/dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo "   - Connectivité: OK"
        else
            echo "   - Connectivité: ÉCHEC"
        fi
    fi
}

# Fonction pour afficher les logs
logs() {
    if [ "$1" = "error" ]; then
        echo "Affichage des erreurs uniquement:"
        grep -i "error\|exception\|failed\|operation not permitted" "$LOG_FILE"
    elif [ "$1" = "attacks" ]; then
        echo "Affichage des attaques détectées:"
        grep -i "attaque.*détectée" "$LOG_FILE"
    else
        echo "Affichage des logs complets:"
        tail -n 50 -f "$LOG_FILE"
    fi
}

# Fonction pour afficher les informations de configuration
config() {
    echo "Configuration de l'agent EZRAX:"
    
    # Afficher l'ID de l'agent
    AGENT_ID_FILE="$EZRAX_DIR/.agent_id"
    if [ -f "$AGENT_ID_FILE" ]; then
        echo " - ID de l'agent: $(cat $AGENT_ID_FILE)"
    fi
    
    # Afficher la configuration du serveur central
    echo " - Serveur central:"
    grep -A5 "central_server:" "$EZRAX_DIR/agent_config.yaml" | sed 's/^/   /'
    
    # Afficher les scanners activés
    echo " - Scanners activés:"
    grep -A1 "enabled:" "$EZRAX_DIR/agent_config.yaml" | grep -v "^--" | sed 's/^/   /'
    
    # Afficher la configuration IPS
    echo " - Configuration IPS:"
    grep -A5 "ips:" "$EZRAX_DIR/agent_config.yaml" | sed 's/^/   /'
}

# Fonction pour déboguer et corriger les erreurs courantes
fix() {
    echo "Vérification et correction des problèmes courants..."
    
    # Vérifier l'existence du fichier .agent_id
    AGENT_ID_FILE="$EZRAX_DIR/.agent_id"
    if [ ! -f "$AGENT_ID_FILE" ]; then
        echo "[*] Fichier .agent_id manquant, création..."
        AGENT_ID=$(python3 -c "import uuid; print(str(uuid.uuid4()))")
        echo "$AGENT_ID" > "$AGENT_ID_FILE"
        chown ezrax:ezrax "$AGENT_ID_FILE"
        chmod 644 "$AGENT_ID_FILE"
        echo "[+] ID de l'agent généré: $AGENT_ID"
    else
        echo "[*] Fichier .agent_id existe: $(cat $AGENT_ID_FILE)"
    fi
    
    # Corriger les capacités réseau
    echo "[*] Correction des capacités réseau..."
    SYSTEM_PYTHON=$(readlink -f "$(which python3)")
    echo "[*] Application des capacités réseau sur $SYSTEM_PYTHON..."
    sudo setcap cap_net_raw,cap_net_admin+eip "$SYSTEM_PYTHON"
    echo "[+] Capacités réseau configurées."
    
    # Détecter et corriger l'interface réseau dans la configuration
    echo "[*] Détection de l'interface réseau active..."
    ACTIVE_INTERFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+' | head -1)
    if [ -n "$ACTIVE_INTERFACE" ]; then
        echo "[*] Interface active détectée: $ACTIVE_INTERFACE"
        # Mettre à jour la configuration
        sed -i "s/interfaces: \[\".*\"\]/interfaces: [\"$ACTIVE_INTERFACE\"]/" "$EZRAX_DIR/agent_config.yaml"
        echo "[+] Configuration de l'interface mise à jour."
    fi
    
    # Vérifier le fichier config.py
    CONFIG_FILE="$EZRAX_DIR/config.py"
    if [ -f "$CONFIG_FILE" ]; then
        # Vérifier si l'import logging.handlers est présent
        if ! grep -q "import logging.handlers" "$CONFIG_FILE"; then
            echo "[*] Ajout de l'import logging.handlers..."
            sed -i '/^import logging$/a import logging.handlers' "$CONFIG_FILE"
        fi
        
        # Vérifier si AGENT_ID est ajouté à CONFIG
        if ! grep -q "CONFIG\[\"AGENT_ID\"\] = AGENT_ID" "$CONFIG_FILE"; then
            echo "[*] Correction de la configuration pour AGENT_ID..."
            sed -i '/^CONFIG = load_config()$/a\
\
# Ajouter AGENT_ID et AGENT_HOSTNAME à CONFIG\
CONFIG["AGENT_ID"] = AGENT_ID\
CONFIG["AGENT_HOSTNAME"] = AGENT_HOSTNAME' "$CONFIG_FILE"
            echo "[+] Configuration corrigée."
        fi
    fi
    
    # Vérifier les permissions
    echo "[*] Vérification des permissions..."
    chown -R ezrax:ezrax "$EZRAX_DIR"
    chmod -R 755 "$EZRAX_DIR"
    echo "[+] Permissions corrigées."
    
    echo "Vérification terminée. Voulez-vous redémarrer l'agent? (o/n)"
    read -r RESTART_AGENT
    if [[ "$RESTART_AGENT" =~ ^[Oo]$ ]]; then
        stop
        sleep 2
        start
    fi
}

# Traitement des arguments
case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        sleep 2
        start
        ;;
    status)
        status
        ;;
    logs)
        logs "$2"
        ;;
    config)
        config
        ;;
    fix)
        fix
        ;;
    *)
        echo "Usage: ezraxtl-agent {start|stop|restart|status|logs|config|fix}"
        echo "  start      - Démarrer l'agent"
        echo "  stop       - Arrêter l'agent"
        echo "  restart    - Redémarrer l'agent"
        echo "  status     - Afficher le statut de l'agent"
        echo "  logs       - Afficher les logs (logs [error|attacks])"
        echo "  config     - Afficher la configuration"
        echo "  fix        - Tenter de corriger les problèmes courants"
        exit 1
        ;;
esac

exit 0
EOF

chmod +x /usr/local/bin/ezraxtl-agent

# Création d'un fichier de configuration par défaut avec l'interface détectée
if [ ! -f /opt/ezrax-agent/agent_config.yaml ]; then
    echo "[*] Création d'un fichier de configuration par défaut..."
    cat > /opt/ezrax-agent/agent_config.yaml << EOF
# Configuration par défaut de l'agent EZRAX IDS/IPS

central_server:
  host: "192.168.1.100"  # Adresse IP du serveur central
  port: 5000
  api_key: "changez_moi_en_production"  # Clé API du serveur central
  use_ssl: false
  check_interval: 30  # Secondes

scanners:
  enabled: true
  syn_flood:
    enabled: true
    threshold: 100
    time_window: 5
    interfaces: ["$ACTIVE_INTERFACE"]  # Interface réseau détectée automatiquement

  udp_flood:
    enabled: true
    threshold: 200
    time_window: 5

  port_scan:
    enabled: true
    threshold: 15
    time_window: 10

  ping_flood:
    enabled: true
    threshold: 30
    time_window: 5

ips:
  enabled: true
  block_duration: 3600  # Durée de blocage en secondes (1 heure)
  auto_block: true
  whitelist: ["127.0.0.1", "192.168.1.100"]  # Liste d'IPs à ne jamais bloquer

database:
  path: "/opt/ezrax-agent/storage/ezrax.db"
  retention_days: 30

reporting:
  enabled: true
  interval: 3600  # Secondes (1 heure)
  output_dir: "/opt/ezrax-agent/reports"

logging:
  level: "INFO"
  file: "/opt/ezrax-agent/logs/ezrax-agent.log"
  max_size: 10485760  # 10 MB
  backup_count: 5
EOF
    chown ezrax:ezrax /opt/ezrax-agent/agent_config.yaml
fi

echo "[+] Installation terminée avec succès!"
echo "[+] L'agent EZRAX est maintenant configuré."
echo "[+] Interface réseau détectée: $ACTIVE_INTERFACE"
echo "[+] Utilisez les commandes suivantes pour gérer l'agent:"
echo "    ezraxtl-agent start    - Démarrer l'agent"
echo "    ezraxtl-agent stop     - Arrêter l'agent"
echo "    ezraxtl-agent restart  - Redémarrer l'agent"
echo "    ezraxtl-agent status   - Vérifier le statut de l'agent"
echo "    ezraxtl-agent logs     - Afficher les logs"
echo "    ezraxtl-agent config   - Afficher la configuration"
echo "    ezraxtl-agent fix      - Tenter de corriger les problèmes courants"
echo ""
echo "[*] Pour démarrer l'agent maintenant, exécutez:"
echo "    ezraxtl-agent start"
