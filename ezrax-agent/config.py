#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration de l'agent EZRAX IDS/IPS
"""

import os
import uuid
import yaml
import socket
import logging
import logging.handlers
from pathlib import Path
from dotenv import load_dotenv

# Chargement des variables d'environnement depuis .env s'il existe
load_dotenv()

# Répertoire de base de l'agent
BASE_DIR = Path(__file__).resolve().parent

# Identifiant unique de l'agent (généré au premier démarrage s'il n'existe pas)
AGENT_ID_FILE = os.path.join(BASE_DIR, ".agent_id")

def get_agent_id():
    """Récupère ou génère l'identifiant unique de l'agent"""
    if os.path.exists(AGENT_ID_FILE):
        with open(AGENT_ID_FILE, "r") as f:
            return f.read().strip()
    
    # Génère un nouvel ID unique
    agent_id = str(uuid.uuid4())
    with open(AGENT_ID_FILE, "w") as f:
        f.write(agent_id)
    
    return agent_id

# Informations sur l'agent
AGENT_ID = get_agent_id()
AGENT_HOSTNAME = socket.gethostname()

# Fichier de configuration YAML
CONFIG_FILE = os.environ.get("EZRAX_CONFIG", os.path.join(BASE_DIR, "agent_config.yaml"))

# Configuration par défaut
DEFAULT_CONFIG = {
    "central_server": {
        "host": os.environ.get("CENTRAL_SERVER_HOST", "192.168.0.139"),
        "port": int(os.environ.get("CENTRAL_SERVER_PORT", 5000)),
        "api_key": os.environ.get("CENTRAL_SERVER_API_KEY", "09eefb2d04794fc38d3ea1ca586291de"),
        "use_ssl": os.environ.get("CENTRAL_SERVER_USE_SSL", "True").lower() == "true",
        "check_interval": int(os.environ.get("CHECK_INTERVAL", 30)),  # Secondes
    },
    "scanners": {
        "enabled": os.environ.get("SCANNERS_ENABLED", "True").lower() == "true",
        "syn_flood": {
            "enabled": os.environ.get("SYN_FLOOD_ENABLED", "True").lower() == "true",
            "threshold": int(os.environ.get("SYN_FLOOD_THRESHOLD", 100)),
            "time_window": int(os.environ.get("SYN_FLOOD_WINDOW", 5)),  # Secondes
            "interfaces": os.environ.get("MONITOR_INTERFACES", "eth0").split(","),
        },
        "udp_flood": {
            "enabled": os.environ.get("UDP_FLOOD_ENABLED", "True").lower() == "true",
            "threshold": int(os.environ.get("UDP_FLOOD_THRESHOLD", 200)),
            "time_window": int(os.environ.get("UDP_FLOOD_WINDOW", 5)),  # Secondes
        },
        "port_scan": {
            "enabled": os.environ.get("PORT_SCAN_ENABLED", "True").lower() == "true",
            "threshold": int(os.environ.get("PORT_SCAN_THRESHOLD", 15)),
            "time_window": int(os.environ.get("PORT_SCAN_WINDOW", 10)),  # Secondes
        },
        "ping_flood": {
            "enabled": os.environ.get("PING_FLOOD_ENABLED", "True").lower() == "true",
            "threshold": int(os.environ.get("PING_FLOOD_THRESHOLD", 30)),
            "time_window": int(os.environ.get("PING_FLOOD_WINDOW", 5)),  # Secondes
        },
    },
    "ips": {
        "enabled": os.environ.get("IPS_ENABLED", "True").lower() == "true",
        "block_duration": int(os.environ.get("BLOCK_DURATION", 3600)),  # Secondes (1 heure par défaut)
        "auto_block": os.environ.get("AUTO_BLOCK", "True").lower() == "true",
        "whitelist": os.environ.get("IP_WHITELIST", "127.0.0.1,192.168.1.1").split(","),
    },
    "database": {
        "path": os.environ.get("DB_PATH", os.path.join(BASE_DIR, "storage", "ezrax.db")),
        "retention_days": int(os.environ.get("LOG_RETENTION_DAYS", 30)),
    },
    "reporting": {
        "enabled": os.environ.get("REPORTING_ENABLED", "True").lower() == "true",
        "interval": int(os.environ.get("REPORTING_INTERVAL", 3600)),  # Secondes (1 heure par défaut)
        "output_dir": os.environ.get("REPORT_OUTPUT_DIR", os.path.join(BASE_DIR, "reports")),
    },
    "logging": {
        "level": os.environ.get("LOG_LEVEL", "INFO"),
        "file": os.environ.get("LOG_FILE", os.path.join(BASE_DIR, "logs", "ezrax-agent.log")),
        "max_size": int(os.environ.get("LOG_MAX_SIZE", 1024 * 1024 * 10)),  # 10 MB
        "backup_count": int(os.environ.get("LOG_BACKUP_COUNT", 5)),
    }
}

def load_config():
    """Charge la configuration depuis le fichier YAML et fusionne avec les valeurs par défaut"""
    config = DEFAULT_CONFIG.copy()
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                yaml_config = yaml.safe_load(f) or {}
                
            # Mise à jour récursive de la configuration
            def update_dict(d, u):
                for k, v in u.items():
                    if isinstance(v, dict):
                        d[k] = update_dict(d.get(k, {}), v)
                    else:
                        d[k] = v
                return d
                
            config = update_dict(config, yaml_config)
        except Exception as e:
            logging.error(f"Erreur lors du chargement de la configuration: {e}")
    
    return config

# Configuration chargée
CONFIG = load_config()
CONFIG["AGENT_ID"] = AGENT_ID
CONFIG["AGENT_HOSTNAME"] = AGENT_HOSTNAME
# Configuration du logging
def setup_logging():
    """Configure le système de logging"""
    log_config = CONFIG["logging"]
    log_dir = os.path.dirname(log_config["file"])
    
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    logging.basicConfig(
        level=getattr(logging, log_config["level"]),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.handlers.RotatingFileHandler(
                log_config["file"],
                maxBytes=log_config["max_size"],
                backupCount=log_config["backup_count"]
            )
        ]
    )

# Création des répertoires nécessaires
def ensure_directories():
    """Crée les répertoires nécessaires au fonctionnement de l'agent"""
    dirs = [
        os.path.dirname(CONFIG["database"]["path"]),
        CONFIG["reporting"]["output_dir"],
        os.path.dirname(CONFIG["logging"]["file"])
    ]
    
    for directory in dirs:
        if not os.path.exists(directory):
            os.makedirs(directory)
