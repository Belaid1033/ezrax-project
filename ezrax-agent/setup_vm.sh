#!/bin/bash

# =============================================================================
# Script d'installation pour l'agent EZRAX IDS/IPS
# Sur Ubuntu Server 24.10+
# =============================================================================

set -e  

echo "[*] Début de l'installation de l'agent EZRAX..."


if [ "$EUID" -ne 0 ]; then
  echo "[!] Ce script doit être exécuté en tant que root"
  exit 1
fi

# ──────────────────────────────────────────────────────────────────────────────
# 1. Mise à jour du système et installation des dépendances
# ──────────────────────────────────────────────────────────────────────────────
echo "[*] Mise à jour du système..."
apt update && apt upgrade -y

echo "[*] Installation des dépendances système..."
apt install -y python3 python3-pip python3-venv iptables sqlite3 tcpdump git net-tools libcap2-bin

# ──────────────────────────────────────────────────────────────────────────────
# 2. Création des répertoires de l'application
# ──────────────────────────────────────────────────────────────────────────────
echo "[*] Création des répertoires de l'application..."
mkdir -p /opt/ezrax-agent
mkdir -p /opt/ezrax-agent/logs
mkdir -p /opt/ezrax-agent/storage
mkdir -p /opt/ezrax-agent/reports

# ──────────────────────────────────────────────────────────────────────────────
# 3. Copie des fichiers sources
# ──────────────────────────────────────────────────────────────────────────────
echo "[*] Copie des fichiers source dans /opt/ezrax-agent..."
cp -r ./* /opt/ezrax-agent/
chown -R root:root /opt/ezrax-agent

# ──────────────────────────────────────────────────────────────────────────────
# 4. Création de l'environnement virtuel Python
# ──────────────────────────────────────────────────────────────────────────────
echo "[*] Création d'un environnement virtuel Python..."
python3 -m venv /opt/ezrax-agent/venv
source /opt/ezrax-agent/venv/bin/activate

echo "[*] Mise à jour de pip et installation des dépendances Python..."
pip install --upgrade pip
if [ -f /opt/ezrax-agent/requirements.txt ]; then
    pip install -r /opt/ezrax-agent/requirements.txt
else
    echo "[!] requirements.txt non trouvé – installation des dépendances de base..."
    pip install scapy paramiko requests psutil python-dotenv pyyaml schedule jinja2
fi

deactivate

# ──────────────────────────────────────────────────────────────────────────────
# 5. Détection automatique de l'interface réseau active
# ──────────────────────────────────────────────────────────────────────────────
echo "[*] Détection de l'interface réseau active..."
ACTIVE_INTERFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+' | head -1)
if [ -z "$ACTIVE_INTERFACE" ]; then
    ACTIVE_INTERFACE="enp0s3"
    echo "[!] Interface réseau non détectée, utilisation de enp0s3 par défaut"
else
    echo "[*] Interface réseau détectée : $ACTIVE_INTERFACE"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 6. Configuration des permissions réseau pour Python (capture & iptables)
# ──────────────────────────────────────────────────────────────────────────────
echo "[*] Configuration des permissions pour la capture réseau..."
SYSTEM_PYTHON=$(readlink -f "$(which python3)")
setcap cap_net_raw,cap_net_admin+eip "$SYSTEM_PYTHON" || true

echo "[*] Configuration des permissions iptables pour l'agent..."
mkdir -p /etc/ezrax
cat > /etc/sudoers.d/ezrax-agent << 'EOF'
# Permissions sudo pour l'agent EZRAX
ezrax ALL=(ALL) NOPASSWD: /sbin/iptables
ezrax ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump
ezrax ALL=(ALL) NOPASSWD: /opt/ezrax-agent/venv/bin/python3
EOF
chmod 440 /etc/sudoers.d/ezrax-agent

# ──────────────────────────────────────────────────────────────────────────────
# 7. Création d'un utilisateur dédié et réglage des droits
# ──────────────────────────────────────────────────────────────────────────────
echo "[*] Création d'un utilisateur dédié 'ezrax'..."
useradd -m -s /bin/bash -d /home/ezrax ezrax 2>/dev/null || true
usermod -a -G netdev ezrax 2>/dev/null || true

mkdir -p /home/ezrax/.ezrax
chown -R ezrax:ezrax /home/ezrax/.ezrax
chown -R ezrax:ezrax /opt/ezrax-agent

# ──────────────────────────────────────────────────────────────────────────────
# 8. Création de l'ID unique de l'agent
# ──────────────────────────────────────────────────────────────────────────────
echo "[*] Vérification de l'ID de l'agent…"
AGENT_ID_FILE="/opt/ezrax-agent/.agent_id"
if [ ! -f "$AGENT_ID_FILE" ]; then
    echo "[*] Génération d'un nouvel ID pour l'agent…"
    AGENT_ID=$(python3 - << 'PYCODE'
import uuid
print(str(uuid.uuid4()))
PYCODE
)
    echo "$AGENT_ID" > "$AGENT_ID_FILE"
    chown ezrax:ezrax "$AGENT_ID_FILE"
    chmod 644 "$AGENT_ID_FILE"
    echo "[*] ID de l'agent généré : $AGENT_ID"
else
    echo "[*] ID de l'agent existe déjà : $(cat $AGENT_ID_FILE)"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 9. Création du fichier .env système (variables sensibles)
# ──────────────────────────────────────────────────────────────────────────────
# On place ce .env sous /etc/ezrax-agent pour des raisons de sécurité.
ENV_DIR="/etc/ezrax-agent"
ENV_FILE="$ENV_DIR/.env"

echo "[*] Création du répertoire pour le fichier .env : $ENV_DIR"
mkdir -p "$ENV_DIR"
chown ezrax:ezrax "$ENV_FILE" # ezrax devient propriétaire
chmod 600 "$ENV_FILE"

if [ ! -f "$ENV_FILE" ]; then
    echo "[*] Création du fichier .env par défaut : $ENV_FILE"
    cat > "$ENV_FILE" << EOF
# Fichier .env pour l'agent EZRAX (informations sensibles)
# Remplacez la valeur ci-dessous par la clé API issue du serveur central (server_config.json)
CENTRAL_SERVER_API_KEY="changez_moi_en_production"
# Vous pouvez ajouter d'autres variables ici, par ex :
# CENTRAL_SERVER_HOST="127.0.0.1"
# CENTRAL_SERVER_PORT="5000"
EOF
    chown root:root "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    echo "[!] IMPORTANT : éditez $ENV_FILE pour y coller votre vraie clé API avant de démarrer l'agent."
else
    echo "[*] Fichier .env existant détecté : $ENV_FILE"
fi

# ──────────────────────────────────────────────────────────────────────────────
# 10. Création du binaire de gestion : ezraxtl-agent
# ──────────────────────────────────────────────────────────────────────────────
echo "[*] Création de l'outil de gestion ezraxtl-agent..."
cat > /usr/local/bin/ezraxtl-agent << 'EOFSCRIPT'
#!/bin/bash
#
# Outil de gestion pour l'agent EZRAX IDS/IPS
#

EZRAX_DIR="/opt/ezrax-agent"
LOGS_DIR="$EZRAX_DIR/logs"
PID_FILE="$LOGS_DIR/agent.pid"
LOG_FILE="$LOGS_DIR/agent.log"
ENV_FILE="/etc/ezrax-agent/.env"

# Charger le fichier .env s'il existe
if [ -f "$ENV_FILE" ]; then
    # On utilise set -a pour exporter automatiquement toute variable
    set -o allexport
    source "$ENV_FILE"
    set +o allexport
fi

# Vérifier que la variable CENTRAL_SERVER_API_KEY est définie
if [ -z "$CENTRAL_SERVER_API_KEY" ] || [[ "$CENTRAL_SERVER_API_KEY" == "changez_moi_en_production" ]]; then
    echo "[!] Erreur : CENTRAL_SERVER_API_KEY non définie ou par défaut."
    echo "    Éditez $ENV_FILE et remplacez la valeur par celle du serveur."
    exit 1
fi

# Créer le répertoire de logs s'il n'existe pas
mkdir -p "$LOGS_DIR"
chown ezrax:ezrax "$LOGS_DIR"

# Fonction pour démarrer l'agent
start() {
    # Vérifier si l’agent est déjà en cours d’exécution
    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo "L'agent EZRAX est déjà en cours d'exécution."
        return
    fi

    echo "Démarrage de l'agent EZRAX…"
    cd "$EZRAX_DIR"

    # Vérifier que l’utilisateur ezrax a les permissions nécessaires
    if [ "$(stat -c '%U' "$LOGS_DIR")" != "ezrax" ]; then
        chown -R ezrax:ezrax "$LOGS_DIR"
    fi

    # Vérifier/set les capacités réseau sur python3 système
    SYSTEM_PYTHON=$(readlink -f "$(which python3)")
    if ! getcap "$SYSTEM_PYTHON" | grep -q "cap_net_raw,cap_net_admin"; then
        echo "[*] Application des capacités réseau sur $SYSTEM_PYTHON…"
        sudo setcap cap_net_raw,cap_net_admin+eip "$SYSTEM_PYTHON"
    fi

    # Lancer l’agent en tant qu’utilisateur ezrax
    sudo -u ezrax nohup "$EZRAX_DIR/venv/bin/python3" "$EZRAX_DIR/main.py" \
        > "$LOG_FILE" 2>&1 &

    echo $! > "$PID_FILE"
    echo "Agent démarré avec PID $(cat "$PID_FILE")"

    # Laisser quelques secondes pour vérifier le démarrage
    sleep 3

    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        if grep -q "Operation not permitted" "$LOG_FILE" 2>/dev/null; then
            echo "AVERTISSEMENT : Erreurs de permissions détectées. Veuillez exécuter 'ezraxtl-agent fix'."
        else
            echo "L'agent EZRAX fonctionne correctement."
        fi
    else
        echo "ERREUR : L'agent n'a pas pu démarrer correctement. Consultez les logs pour plus d'infos."
        echo "    Commande : ezraxtl-agent logs"
    fi
}

# Fonction pour arrêter l'agent
stop() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "Arrêt de l'agent EZRAX (PID: $PID)…"
            kill "$PID"
            sleep 2
            if kill -0 "$PID" 2>/dev/null; then
                echo "L'agent ne répond pas, arrêt forcé…"
                kill -9 "$PID"
            fi
            rm -f "$PID_FILE"
            echo "Agent EZRAX arrêté."
        else
            echo "L'agent EZRAX n'est pas en cours (PID invalide : $PID)."
            rm -f "$PID_FILE"
        fi
    else
        echo "Aucun PID trouvé, l'agent EZRAX n'est pas démarré."
    fi
}

# Fonction pour vérifier le statut
status() {
    echo "Statut de l'agent EZRAX :"
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo " - Agent : En cours (PID: $PID)"
            ps -p "$PID" -o pid,user,etime,cmd 2>/dev/null | sed 1d
        else
            echo " - Agent : Arrêté (PID invalide : $PID)"
        fi
    else
        echo " - Agent : Arrêté (aucun PID trouvé)"
    fi

    # Capacités réseau
    echo " - Capacités réseau :"
    SYSTEM_PYTHON=$(readlink -f "$(which python3)")
    CAPS=$(getcap "$SYSTEM_PYTHON" 2>/dev/null)
    if [ -n "$CAPS" ]; then
        echo "   - $CAPS"
    else
        echo "   - Aucune capacité définie (PROBLÈME)"
    fi

    # Scanners actifs (analyse du fichier de logs)
    if [ -f "$LOG_FILE" ]; then
        echo " - Scanners actifs :"
        SCANNERS=$(grep -o "Scanner.*démarré" "$LOG_FILE" 2>/dev/null | sort | uniq | wc -l)
        if [ "$SCANNERS" -gt 0 ]; then
            grep -o "Scanner.*démarré" "$LOG_FILE" 2>/dev/null | sort | uniq | sed 's/^/   - /'
        else
            echo "   - Aucun scanner détecté."
        fi
        # Erreurs de permissions dans le log
        ERROR_COUNT=$(grep -c "Operation not permitted" "$LOG_FILE" 2>/dev/null || echo "0")
        echo " - Erreurs de permissions : $ERROR_COUNT"
    fi

    # IPs bloquées
    BLOCKED_COUNT=$(sudo iptables -L EZRAX_IPS -n 2>/dev/null | grep -c DROP || echo "0")
    echo " - IPs bloquées : $BLOCKED_COUNT"

    # Interfaces réseau disponibles
    echo " - Interfaces réseau :"
    ip link show | grep "state UP" | awk '{print $2}' | sed 's/:$//' | sed 's/^/   - /'

    # Connectivité au serveur central
    if [ -f "$EZRAX_DIR/agent_config.yaml" ]; then
        CENTRAL_SERVER=$(grep -A1 "host:" "$EZRAX_DIR/agent_config.yaml" | grep -v "host:" | sed 's/.*"\([^"]*\)".*/\1/' | tr -d ' "')
        if [ -n "$CENTRAL_SERVER" ]; then
            echo " - Serveur central : $CENTRAL_SERVER"
            if ping -c 1 -w 1 "$CENTRAL_SERVER" >/dev/null 2>&1; then
                echo "   - Connectivité : OK"
            else
                echo "   - Connectivité : ÉCHEC"
            fi
        fi
    fi
}

# Fonction pour afficher les logs
logs() {
    if [ "$1" = "error" ]; then
        echo "Affichage des erreurs uniquement :"
        grep -i "error\|exception\|failed\|operation not permitted" "$LOG_FILE" 2>/dev/null
    elif [ "$1" = "attacks" ]; then
        echo "Affichage des attaques détectées :"
        grep -i "attaque.*détectée\|attack.*detected" "$LOG_FILE" 2>/dev/null
    else
        echo "Affichage des 50 dernières lignes de log (suivi en temps réel) :"
        tail -n 50 -f "$LOG_FILE"
    fi
}

# Fonction pour afficher la configuration
config() {
    echo "Configuration de l'agent EZRAX :"
    AGENT_ID_FILE="$EZRAX_DIR/.agent_id"
    if [ -f "$AGENT_ID_FILE" ]; then
        echo " - ID de l'agent : $(cat "$AGENT_ID_FILE")"
    fi
    if [ -f "$EZRAX_DIR/agent_config.yaml" ]; then
        echo " - Serveur central :"
        grep -A5 "central_server:" "$EZRAX_DIR/agent_config.yaml" | sed 's/^/   /'
        echo " - Scanners activés :"
        grep -A1 "enabled:" "$EZRAX_DIR/agent_config.yaml" | grep -v "^--" | sed 's/^/   /'
        echo " - Configuration IPS :"
        grep -A5 "ips:" "$EZRAX_DIR/agent_config.yaml" | sed 's/^/   /'
    else
        echo " - Fichier agent_config.yaml non trouvé"
    fi
}

# Fonction pour déboguer et corriger
fix() {
    echo "Vérification et correction des problèmes courants…"
    # Vérification du fichier .agent_id
    AGENT_ID_FILE="$EZRAX_DIR/.agent_id"
    if [ ! -f "$AGENT_ID_FILE" ]; then
        echo "[*] .agent_id manquant, création…"
        AGENT_ID=$(python3 - << 'PYCODE'
import uuid
print(str(uuid.uuid4()))
PYCODE
)
        echo "$AGENT_ID" > "$AGENT_ID_FILE"
        chown ezrax:ezrax "$AGENT_ID_FILE"
        chmod 644 "$AGENT_ID_FILE"
        echo "[+] ID généré : $AGENT_ID"
    else
        echo "[*] .agent_id existe : $(cat "$AGENT_ID_FILE")"
    fi

    # Correction des capacités réseau
    echo "[*] Application des capacités réseau…"
    SYSTEM_PYTHON=$(readlink -f "$(which python3)")
    sudo setcap cap_net_raw,cap_net_admin+eip "$SYSTEM_PYTHON"
    echo "[+] Capacités appliquées."

    # Mise à jour de l'interface réseau dans agent_config.yaml
    echo "[*] Détection de l'interface réseau active…"
    ACTIVE_INTERFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+' | head -1)
    if [ -n "$ACTIVE_INTERFACE" ] && [ -f "$EZRAX_DIR/agent_config.yaml" ]; then
        sed -i "s/interfaces: \[\".*\"/interfaces: [\"$ACTIVE_INTERFACE\"/" "$EZRAX_DIR/agent_config.yaml"
        echo "[+] Interface réseau mise à jour dans agent_config.yaml"
    fi

    # Réglage des permissions
    echo "[*] Correction des permissions sur $EZRAX_DIR…"
    chown -R ezrax:ezrax "$EZRAX_DIR"
    chmod -R 755 "$EZRAX_DIR"
    echo "[+] Permissions corrigées."

    echo "Vérification terminée. Redémarrer l'agent ? (o/n)"
    read -r RESTART_AGENT
    if [[ "$RESTART_AGENT" =~ ^[Oo]$ ]]; then
        stop
        sleep 2
        start
    fi
}

# ──────────────────────────────────────────────────────────────────────────────
# Traitement des arguments (start|stop|restart|status|logs|config|fix)
# ──────────────────────────────────────────────────────────────────────────────
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
        echo "Usage : ezraxtl-agent {start|stop|restart|status|logs|config|fix}"
        exit 1
        ;;
esac

exit 0
EOFSCRIPT
chmod +x /usr/local/bin/ezraxtl-agent

# ──────────────────────────────────────────────────────────────────────────────
# 11. Création d’un fichier de configuration par défaut (agent_config.yaml)
# ──────────────────────────────────────────────────────────────────────────────
if [ ! -f /opt/ezrax-agent/agent_config.yaml ]; then
    echo "[*] Création d'un fichier de configuration par défaut..."
    cat > /opt/ezrax-agent/agent_config.yaml << EOF
# Configuration par défaut de l'agent EZRAX IDS/IPS

central_server:
  host: "127.0.0.1"   # IP du serveur central
  port: 5000
  api_key: "changez_moi_en_production"  # Clé API du serveur central
  use_ssl: false
  check_interval: 30  # en secondes

scanners:
  enabled: true
  syn_flood:
    enabled: true
    threshold: 100
    time_window: 5
    interfaces: ["$ACTIVE_INTERFACE"]
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
  block_duration: 3600
  auto_block: true
  whitelist: ["127.0.0.1","::1"]

database:
  path: "/opt/ezrax-agent/storage/ezrax.db"
  retention_days: 30

reporting:
  enabled: true
  interval: 3600
  output_dir: "/opt/ezrax-agent/reports"

logging:
  level: "INFO"
  file: "/opt/ezrax-agent/logs/ezrax-agent.log"
  max_size: 10485760
  backup_count: 5
EOF

    chown ezrax:ezrax /opt/ezrax-agent/agent_config.yaml
    echo "[*] Fichier agent_config.yaml créé (veuillez modifier central_server.api_key après avoir configuré .env)."
fi

echo "[+] Installation terminée avec succès !"
echo "[+] L’agent EZRAX est maintenant configuré."
echo "[+] Interface réseau détectée : $ACTIVE_INTERFACE"
echo "[+] Pour débuter l’agent, exécutez : ezraxtl-agent start"
echo "[+] Veillez à éditer /etc/ezrax-agent/.env et /opt/ezrax-agent/agent_config.yaml"
echo "    afin de remplacer la valeur "changez_moi_en_production" par votre api-key."

