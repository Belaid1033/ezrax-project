#!/bin/bash

# Script d'installation ultra-simplifié pour le serveur central EZRAX
# À exécuter sur Ubuntu Desktop 24.10

set -e  # Arrêter l'exécution en cas d'erreur

echo "[*] Début de l'installation du serveur central EZRAX..."

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
apt install -y python3 python3-pip python3-venv python3-tk docker.io git sqlite3 jq curl

# Vérifier si Docker est installé correctement
echo "[*] Vérification de l'installation de Docker..."
if ! docker --version; then
  echo "[!] Erreur: Docker n'est pas correctement installé"
  exit 1
fi

# Ajouter l'utilisateur courant au groupe Docker
echo "[*] Ajout de l'utilisateur au groupe Docker..."
REAL_USER=$(logname || echo $SUDO_USER || echo $USER)
usermod -aG docker $REAL_USER

# Création du répertoire de l'application
echo "[*] Création du répertoire de l'application..."
mkdir -p /opt/ezrax-server
mkdir -p /opt/ezrax-server/logs
mkdir -p /opt/ezrax-server/grafana_data

# Copie des fichiers depuis le répertoire actuel
echo "[*] Utilisation des fichiers du répertoire courant..."
cp -r ./* /opt/ezrax-server/

# Création d'un environnement virtuel Python
echo "[*] Création d'un environnement virtuel Python..."
python3 -m venv /opt/ezrax-server/venv
source /opt/ezrax-server/venv/bin/activate

# Installation des dépendances Python
echo "[*] Installation des dépendances Python..."
pip install --upgrade pip
pip install flask werkzeug requests ttkthemes

# Création de la commande ezraxtl simplifiée
echo "[*] Création de la commande ezraxtl simplifiée..."
cat > /usr/local/bin/ezraxtl << 'EOF'
#!/bin/bash

# Commande simplifiée pour gérer EZRAX
EZRAX_DIR="/opt/ezrax-server"
LOGS_DIR="$EZRAX_DIR/logs"
PID_FILE="$LOGS_DIR/ezrax.pid"

start() {
    mkdir -p "$LOGS_DIR"
    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo "Le serveur est déjà en cours d'exécution."
        return
    fi
    
    echo "Démarrage du serveur EZRAX..."
    cd "$EZRAX_DIR"
    nohup $EZRAX_DIR/venv/bin/python $EZRAX_DIR/server.py > $LOGS_DIR/server.log 2>&1 &
    echo $! > "$PID_FILE"
    echo "Serveur démarré avec PID $(cat $PID_FILE)"
    
    
}

stop() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 $PID 2>/dev/null; then
            echo "Arrêt du serveur EZRAX (PID: $PID)..."
            kill $PID
            rm "$PID_FILE"
        else
            echo "Le serveur ne semble pas être en cours d'exécution"
            rm "$PID_FILE"
        fi
    else
        echo "Aucun PID trouvé, le serveur ne semble pas être en cours d'exécution"
    fi
    
    
}

status() {
    if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
        echo "Le serveur EZRAX est en cours d'exécution (PID: $(cat $PID_FILE))"
    else
        echo "Le serveur EZRAX n'est pas en cours d'exécution"
    fi
    
    
    echo ""
    echo "Ports en écoute:"
    netstat -tuln | grep -E ':(5000)' | sort
}

logs() {
    if [ "$1" = "server" ]; then
        tail -f "$LOGS_DIR/server.log"
    else
        echo "Usage: ezraxtl logs [server]"
    fi
}

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
    *)
        echo "Usage: ezraxtl {start|stop|restart|status|logs}"
        echo "  logs [server] - Affiche les logs du serveur"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/ezraxtl


# Configuration des permissions
echo "[*] Configuration des permissions..."
chown -R $REAL_USER:$REAL_USER /opt/ezrax-server
chmod -R 755 /opt/ezrax-server

echo "[+] Installation terminée avec succès!"
echo "[+] Utilisez les commandes suivantes pour gérer EZRAX:"
echo "    ezraxtl start      - Démarrer le serveur"
echo "    ezraxtl stop       - Arrêter le serveur"
echo "    ezraxtl restart    - Redémarrer le serveur"
echo "    ezraxtl status     - Vérifier le statut du serveur"
echo "    ezraxtl logs       - Afficher les logs"
echo ""
echo "[*] Pour démarrer le serveur maintenant, exécutez:"
echo "    ezraxtl start"
