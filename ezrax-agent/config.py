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
import ipaddress
import secrets
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Union, Optional
from dotenv import load_dotenv

# Chargement des variables d'environnement depuis .env s'il existe
load_dotenv()

# Répertoire de base de l'agent
BASE_DIR = Path(__file__).resolve().parent

# Configuration du logging temporaire pour ce module
logger = logging.getLogger(__name__)

class ConfigValidator:
    """Validateur de configuration pour sécuriser les valeurs"""
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Valide une adresse IP"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    @staticmethod
    def validate_ip_list(ip_list: Union[str, List[str]]) -> List[str]:
        """Valide et nettoie une liste d'adresses IP"""
        if isinstance(ip_list, str):
            ip_list = [ip.strip() for ip in ip_list.split(",") if ip.strip()]
            
        validated_ips = []
        for ip in ip_list:
            if ConfigValidator.validate_ip_address(ip):
                validated_ips.append(ip)
            else:
                logger.warning(f"Adresse IP invalide ignorée dans la configuration: {ip}")
                
        return validated_ips
        
    @staticmethod
    def validate_port(port: Union[str, int], min_port: int = 1, max_port: int = 65535) -> int:
        """Valide un numéro de port"""
        try:
            port_num = int(port)
            if min_port <= port_num <= max_port:
                return port_num
            else:
                raise ValueError(f"Port hors limites: {port_num}")
        except (ValueError, TypeError) as e:
            logger.error(f"Port invalide: {port} - {e}")
            raise ValueError(f"Port invalide: {port}")
            
    @staticmethod
    def validate_positive_int(value: Union[str, int], min_value: int = 1) -> int:
        """Valide un entier positif"""
        try:
            int_value = int(value)
            if int_value >= min_value:
                return int_value
            else:
                raise ValueError(f"Valeur trop petite: {int_value} (min: {min_value})")
        except (ValueError, TypeError) as e:
            logger.error(f"Entier invalide: {value} - {e}")
            raise ValueError(f"Entier invalide: {value}")
            
    @staticmethod
    def validate_boolean(value: Union[str, bool]) -> bool:
        """Valide une valeur booléenne"""
        if isinstance(value, bool):
            return value
        elif isinstance(value, str):
            return value.lower() in ("true", "yes", "1", "on")
        else:
            return bool(value)
            
    @staticmethod
    def get_active_network_interface() -> str:
        """Détecte l'interface réseau active"""
        try:
            # Méthode 1: via route par défaut
            result = subprocess.run(
                ['ip', 'route', 'get', '8.8.8.8'], 
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                import re
                match = re.search(r'dev (\S+)', result.stdout)
                if match:
                    interface = match.group(1)
                    logger.info(f"Interface active détectée: {interface}")
                    return interface
        except:
            pass
            
        try:
            # Méthode 2: via les interfaces UP
            result = subprocess.run(
                ['ip', 'link', 'show'], 
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                import re
                interfaces = re.findall(r'\d+: (\w+).*state UP', result.stdout)
                # Filtrer les interfaces loopback
                non_lo_interfaces = [iface for iface in interfaces if not iface.startswith('lo')]
                if non_lo_interfaces:
                    interface = non_lo_interfaces[0]
                    logger.info(f"Interface UP détectée: {interface}")
                    return interface
        except:
            pass
            
        # Méthode 3: interfaces communes
        common_interfaces = ['enp0s3', 'enp0s8', 'ens33', 'ens18', 'eth0', 'wlan0']
        try:
            import psutil
            available_interfaces = list(psutil.net_if_addrs().keys())
            for iface in common_interfaces:
                if iface in available_interfaces:
                    logger.info(f"Interface commune trouvée: {iface}")
                    return iface
        except ImportError:
            pass
            
        logger.warning("Impossible de détecter l'interface réseau, utilisation d'enp0s3 par défaut")
        return "enp0s3"
            
    @staticmethod
    def validate_interfaces_list(interfaces: Union[str, List[str]]) -> List[str]:
        """Valide une liste d'interfaces réseau"""
        if isinstance(interfaces, str):
            interfaces = [iface.strip() for iface in interfaces.split(",") if iface.strip()]
            
        # Si la liste est vide ou contient seulement des interfaces par défaut, détecter automatiquement
        if not interfaces or (len(interfaces) == 1 and interfaces[0] in ['eth0', 'enp0s3']):
            active_interface = ConfigValidator.get_active_network_interface()
            return [active_interface]
            
        # Récupérer les interfaces disponibles
        try:
            import psutil
            available_interfaces = list(psutil.net_if_addrs().keys())
        except ImportError:
            logger.warning("psutil non disponible, validation des interfaces ignorée")
            return interfaces
            
        validated_interfaces = []
        for iface in interfaces:
            if iface in available_interfaces or iface == "any":
                validated_interfaces.append(iface)
            else:
                logger.warning(f"Interface réseau inexistante ignorée: {iface}")
                
        # Si aucune interface valide, utiliser l'interface active détectée
        if not validated_interfaces:
            active_interface = ConfigValidator.get_active_network_interface()
            validated_interfaces.append(active_interface)
                
        return validated_interfaces

class SecretManager:
    """Gestionnaire de secrets pour sécuriser les clés API"""
    
    @staticmethod
    def generate_api_key() -> str:
        """Génère une clé API sécurisée"""
        return secrets.token_urlsafe(32)
        
    @staticmethod
    def hash_secret(secret: str) -> str:
        """Hache un secret de manière sécurisée"""
        return hashlib.sha256(secret.encode()).hexdigest()
        
    @staticmethod
    def load_secret_from_env_or_generate(env_key: str, default_generator=None) -> str:
        """Charge un secret depuis les variables d'environnement ou le génère"""
        secret = os.environ.get(env_key)
        
        if secret:
            # Vérifier que le secret n'est pas celui par défaut (dangereux)
            dangerous_defaults = [
                "changez_moi_en_production",
                "09eefb2d04794fc38d3ea1ca586291de",
                "default_api_key",
                "test_key"
            ]
            
            if secret in dangerous_defaults:
                logger.error(f"Secret par défaut dangereux détecté pour {env_key}")
                if default_generator:
                    secret = default_generator()
                    logger.warning(f"Secret généré automatiquement pour {env_key}")
            
            return secret
            
        elif default_generator:
            return default_generator()
        else:
            return SecretManager.generate_api_key()

# Identifiant unique de l'agent (généré au premier démarrage s'il n'existe pas)
AGENT_ID_FILE = os.path.join(BASE_DIR, ".agent_id")

def get_agent_id() -> str:
    """Récupère ou génère l'identifiant unique de l'agent"""
    if os.path.exists(AGENT_ID_FILE):
        try:
            with open(AGENT_ID_FILE, "r") as f:
                agent_id = f.read().strip()
                # Valider que c'est un UUID valide
                uuid.UUID(agent_id)
                return agent_id
        except (ValueError, OSError) as e:
            logger.warning(f"ID d'agent invalide ou illisible: {e}, génération d'un nouveau")
    
    # Génère un nouvel ID unique
    agent_id = str(uuid.uuid4())
    try:
        with open(AGENT_ID_FILE, "w") as f:
            f.write(agent_id)
        # Sécuriser les permissions du fichier
        os.chmod(AGENT_ID_FILE, 0o600)
    except OSError as e:
        logger.error(f"Impossible de sauvegarder l'ID d'agent: {e}")
    
    return agent_id

# Informations sur l'agent
AGENT_ID = get_agent_id()
AGENT_HOSTNAME = socket.gethostname()

# Fichier de configuration YAML
CONFIG_FILE = os.environ.get("EZRAX_CONFIG", os.path.join(BASE_DIR, "agent_config.yaml"))

# Configuration par défaut avec validation
def get_default_config() -> Dict[str, Any]:
    """Retourne la configuration par défaut validée"""
    
    # NOUVEAU: Génération sécurisée des clés API
    default_api_key = SecretManager.load_secret_from_env_or_generate(
        "CENTRAL_SERVER_API_KEY",
        SecretManager.generate_api_key
    )
    
    config = {
        "central_server": {
            "host": os.environ.get("CENTRAL_SERVER_HOST", "127.0.0.1"),  # SÉCURISÉ: localhost par défaut
            "port": ConfigValidator.validate_port(
                os.environ.get("CENTRAL_SERVER_PORT", 5000)
            ),
            "api_key": default_api_key,  # SÉCURISÉ: Clé générée automatiquement
            "use_ssl": ConfigValidator.validate_boolean(
                os.environ.get("CENTRAL_SERVER_USE_SSL", "False")
            ),
            "check_interval": ConfigValidator.validate_positive_int(
                os.environ.get("CHECK_INTERVAL", 30), min_value=5
            ),
            "timeout": ConfigValidator.validate_positive_int(
                os.environ.get("CENTRAL_SERVER_TIMEOUT", 10), min_value=1
            ),
            "max_retries": ConfigValidator.validate_positive_int(
                os.environ.get("CENTRAL_SERVER_MAX_RETRIES", 3), min_value=1
            )
        },
        "scanners": {
            "enabled": ConfigValidator.validate_boolean(
                os.environ.get("SCANNERS_ENABLED", "True")
            ),
            "syn_flood": {
                "enabled": ConfigValidator.validate_boolean(
                    os.environ.get("SYN_FLOOD_ENABLED", "True")
                ),
                "threshold": ConfigValidator.validate_positive_int(
                    os.environ.get("SYN_FLOOD_THRESHOLD", 100), min_value=10
                ),
                "time_window": ConfigValidator.validate_positive_int(
                    os.environ.get("SYN_FLOOD_WINDOW", 5), min_value=1
                ),
                "interfaces": ConfigValidator.validate_interfaces_list(
                    os.environ.get("MONITOR_INTERFACES", "auto")
                ),
            },
            "udp_flood": {
                "enabled": ConfigValidator.validate_boolean(
                    os.environ.get("UDP_FLOOD_ENABLED", "True")
                ),
                "threshold": ConfigValidator.validate_positive_int(
                    os.environ.get("UDP_FLOOD_THRESHOLD", 200), min_value=20
                ),
                "time_window": ConfigValidator.validate_positive_int(
                    os.environ.get("UDP_FLOOD_WINDOW", 5), min_value=1
                ),
            },
            "port_scan": {
                "enabled": ConfigValidator.validate_boolean(
                    os.environ.get("PORT_SCAN_ENABLED", "True")
                ),
                "threshold": ConfigValidator.validate_positive_int(
                    os.environ.get("PORT_SCAN_THRESHOLD", 15), min_value=5
                ),
                "time_window": ConfigValidator.validate_positive_int(
                    os.environ.get("PORT_SCAN_WINDOW", 10), min_value=5
                ),
            },
            "ping_flood": {
                "enabled": ConfigValidator.validate_boolean(
                    os.environ.get("PING_FLOOD_ENABLED", "True")
                ),
                "threshold": ConfigValidator.validate_positive_int(
                    os.environ.get("PING_FLOOD_THRESHOLD", 30), min_value=10
                ),
                "time_window": ConfigValidator.validate_positive_int(
                    os.environ.get("PING_FLOOD_WINDOW", 5), min_value=1
                ),
            },
        },
        "ips": {
            "enabled": ConfigValidator.validate_boolean(
                os.environ.get("IPS_ENABLED", "True")
            ),
            "block_duration": ConfigValidator.validate_positive_int(
                os.environ.get("BLOCK_DURATION", 3600), min_value=60  # Min 1 minute
            ),
            "max_block_duration": ConfigValidator.validate_positive_int(
                os.environ.get("MAX_BLOCK_DURATION", 86400), min_value=3600  # Min 1 heure
            ),
            "max_blocked_ips": ConfigValidator.validate_positive_int(
                os.environ.get("MAX_BLOCKED_IPS", 10000), min_value=100
            ),
            "auto_block": ConfigValidator.validate_boolean(
                os.environ.get("AUTO_BLOCK", "True")
            ),
            "whitelist": ConfigValidator.validate_ip_list(
                os.environ.get("IP_WHITELIST", "127.0.0.1,::1")  # IPv4 et IPv6 localhost
            ),
        },
        "database": {
            "path": os.environ.get("DB_PATH", os.path.join(BASE_DIR, "storage", "ezrax.db")),
            "retention_days": ConfigValidator.validate_positive_int(
                os.environ.get("LOG_RETENTION_DAYS", 30), min_value=1
            ),
            "backup_enabled": ConfigValidator.validate_boolean(
                os.environ.get("DB_BACKUP_ENABLED", "True")
            ),
            "backup_interval": ConfigValidator.validate_positive_int(
                os.environ.get("DB_BACKUP_INTERVAL", 86400), min_value=3600  # Min 1 heure
            )
        },
        "reporting": {
            "enabled": ConfigValidator.validate_boolean(
                os.environ.get("REPORTING_ENABLED", "True")
            ),
            "interval": ConfigValidator.validate_positive_int(
                os.environ.get("REPORTING_INTERVAL", 3600), min_value=300  # Min 5 minutes
            ),
            "output_dir": os.environ.get("REPORT_OUTPUT_DIR", os.path.join(BASE_DIR, "reports")),
            "max_report_size": ConfigValidator.validate_positive_int(
                os.environ.get("MAX_REPORT_SIZE", 10485760), min_value=1048576  # Min 1MB
            )
        },
        "logging": {
            "level": os.environ.get("LOG_LEVEL", "INFO"),
            "file": os.environ.get("LOG_FILE", os.path.join(BASE_DIR, "logs", "ezrax-agent.log")),
            "max_size": ConfigValidator.validate_positive_int(
                os.environ.get("LOG_MAX_SIZE", 1024 * 1024 * 10), min_value=1024 * 1024  # Min 1MB
            ),
            "backup_count": ConfigValidator.validate_positive_int(
                os.environ.get("LOG_BACKUP_COUNT", 5), min_value=1
            ),
            "console_enabled": ConfigValidator.validate_boolean(
                os.environ.get("LOG_CONSOLE_ENABLED", "True")
            )
        }
    }
    
    return config

DEFAULT_CONFIG = get_default_config()

def validate_config_section(config: Dict[str, Any], section_name: str, 
                          expected_keys: List[str]) -> bool:
    """Valide qu'une section de configuration contient les clés attendues"""
    if section_name not in config:
        logger.error(f"Section de configuration manquante: {section_name}")
        return False
        
    section = config[section_name]
    missing_keys = [key for key in expected_keys if key not in section]
    
    if missing_keys:
        logger.error(f"Clés manquantes dans la section {section_name}: {missing_keys}")
        return False
        
    return True

def validate_full_config(config: Dict[str, Any]) -> bool:
    """Valide l'ensemble de la configuration"""
    required_sections = {
        "central_server": ["host", "port", "api_key"],
        "scanners": ["enabled"],
        "ips": ["enabled", "whitelist"],
        "database": ["path", "retention_days"],
        "logging": ["level", "file"]
    }
    
    for section_name, required_keys in required_sections.items():
        if not validate_config_section(config, section_name, required_keys):
            return False
            
    # Validation spécifique des valeurs
    try:
        # Vérifier que les répertoires nécessaires peuvent être créés
        for path_key in ["database.path", "reporting.output_dir", "logging.file"]:
            section, key = path_key.split(".")
            if section in config and key in config[section]:
                path = config[section][key]
                parent_dir = os.path.dirname(path)
                if not os.path.exists(parent_dir):
                    os.makedirs(parent_dir, exist_ok=True)
                    logger.info(f"Répertoire créé: {parent_dir}")
                    
        # Test de connectivité au serveur central (simplifié)
        if config["central_server"]["enabled"] if "enabled" in config["central_server"] else True:
            host = config["central_server"]["host"]
            port = config["central_server"]["port"]
            
            # Test de résolution DNS simple (sans timeout)
            try:
                socket.getaddrinfo(host, port)
                logger.info(f"Serveur central accessible: {host}:{port}")
            except (socket.gaierror, socket.timeout):
                logger.warning(f"Serveur central non accessible: {host}:{port}")
                
    except Exception as e:
        logger.error(f"Erreur lors de la validation de la configuration: {e}")
        return False
        
    return True

def load_config() -> Dict[str, Any]:
    """Charge la configuration depuis le fichier YAML et fusionne avec les valeurs par défaut"""
    config = DEFAULT_CONFIG.copy()
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
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
            logger.info(f"Configuration chargée depuis: {CONFIG_FILE}")
            
        except yaml.YAMLError as e:
            logger.error(f"Erreur YAML lors du chargement de la configuration: {e}")
            logger.warning("Utilisation de la configuration par défaut")
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la configuration: {e}")
            logger.warning("Utilisation de la configuration par défaut")
    else:
        logger.info(f"Fichier de configuration non trouvé: {CONFIG_FILE}")
        logger.info("Utilisation de la configuration par défaut")
    
    # Validation de la configuration finale
    if not validate_full_config(config):
        logger.error("Configuration invalide détectée")
        raise ValueError("Configuration invalide")
    
    return config

# Configuration chargée et validée
try:
    CONFIG = load_config()
    CONFIG["AGENT_ID"] = AGENT_ID
    CONFIG["AGENT_HOSTNAME"] = AGENT_HOSTNAME
    
    # NOUVEAU: Masquer les secrets dans les logs
    def mask_secrets_in_config(config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Masque les secrets dans la configuration pour les logs"""
        masked_config = config_dict.copy()
        
        # Masquer les clés sensibles
        sensitive_keys = ["api_key", "password", "token", "secret"]
        
        def mask_recursive(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if any(sensitive in key.lower() for sensitive in sensitive_keys):
                        obj[key] = "*" * 8
                    else:
                        mask_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    mask_recursive(item)
                    
        mask_recursive(masked_config)
        return masked_config
    
    # Log de la configuration (avec secrets masqués)
    masked_config = mask_secrets_in_config(CONFIG)
    logger.info(f"Configuration chargée et validée: {len(CONFIG)} sections")
    logger.debug(f"Configuration détaillée: {masked_config}")
    
except Exception as e:
    logger.critical(f"Impossible de charger la configuration: {e}")
    raise

# Configuration du logging sécurisée
def setup_logging():
    """Configure le système de logging de manière sécurisée"""
    log_config = CONFIG["logging"]
    log_dir = os.path.dirname(log_config["file"])
    
    # Créer le répertoire de logs avec permissions appropriées
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, mode=0o750)  # rwxr-x---
    
    # Configurer les handlers
    handlers = []
    
    # Handler fichier avec rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_config["file"],
        maxBytes=log_config["max_size"],
        backupCount=log_config["backup_count"],
        encoding="utf-8"
    )
    file_handler.setLevel(getattr(logging, log_config["level"]))
    handlers.append(file_handler)
    
    # Handler console (optionnel)
    if log_config.get("console_enabled", True):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, log_config["level"]))
        handlers.append(console_handler)
    
    # Configuration du logging
    logging.basicConfig(
        level=getattr(logging, log_config["level"]),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers
    )
    
    # Sécuriser les permissions du fichier de log
    try:
        os.chmod(log_config["file"], 0o640)  # rw-r-----
    except OSError:
        pass  # Ignorer les erreurs de permissions

# Création des répertoires nécessaires avec permissions sécurisées
def ensure_directories():
    """Crée les répertoires nécessaires au fonctionnement de l'agent"""
    dirs_to_create = [
        (os.path.dirname(CONFIG["database"]["path"]), 0o750),
        (CONFIG["reporting"]["output_dir"], 0o750),
        (os.path.dirname(CONFIG["logging"]["file"]), 0o750)
    ]
    
    for directory, mode in dirs_to_create:
        if directory and not os.path.exists(directory):
            try:
                os.makedirs(directory, mode=mode)
                logger.info(f"Répertoire créé: {directory}")
            except OSError as e:
                logger.error(f"Impossible de créer le répertoire {directory}: {e}")

def reload_config() -> bool:
    """Recharge la configuration à chaud"""
    try:
        global CONFIG
        new_config = load_config()
        new_config["AGENT_ID"] = AGENT_ID
        new_config["AGENT_HOSTNAME"] = AGENT_HOSTNAME
        
        CONFIG = new_config
        logger.info("Configuration rechargée avec succès")
        return True
        
    except Exception as e:
        logger.error(f"Erreur lors du rechargement de la configuration: {e}")
        return False

def save_config_template():
    """Sauvegarde un template de configuration pour référence"""
    template_path = os.path.join(BASE_DIR, "agent_config.template.yaml")
    
    try:
        # Obtenir l'interface active pour le template
        active_interface = ConfigValidator.get_active_network_interface()
        
        # Créer un template avec des valeurs par défaut et des commentaires
        template_content = f"""# Configuration EZRAX IDS/IPS Agent
# Ce fichier est un template - copiez-le vers agent_config.yaml pour personnaliser

central_server:
  host: "127.0.0.1"          # Adresse du serveur central
  port: 5000                 # Port du serveur central
  api_key: "CHANGE_ME"       # Clé API (générer avec: python -c "import secrets; print(secrets.token_urlsafe(32))")
  use_ssl: false             # Utiliser HTTPS
  check_interval: 30         # Intervalle de vérification (secondes)
  timeout: 10                # Timeout des requêtes
  max_retries: 3             # Nombre de tentatives

scanners:
  enabled: true
  
  syn_flood:
    enabled: true
    threshold: 100           # Nombre de paquets SYN pour déclencher l'alerte
    time_window: 5           # Fenêtre de temps (secondes)
    interfaces: ["{active_interface}"]     # Interface réseau détectée automatiquement
    
  udp_flood:
    enabled: true
    threshold: 200
    time_window: 5
    
  port_scan:
    enabled: true
    threshold: 15            # Nombre de ports pour déclencher l'alerte
    time_window: 10
    
  ping_flood:
    enabled: true
    threshold: 30
    time_window: 5

ips:
  enabled: true
  block_duration: 3600       # Durée de blocage par défaut (secondes)
  max_block_duration: 86400  # Durée maximum de blocage
  max_blocked_ips: 10000     # Nombre maximum d'IPs bloquées simultanément
  auto_block: true           # Blocage automatique des attaquants
  whitelist:                 # IPs à ne jamais bloquer
    - "127.0.0.1"
    - "::1"

database:
  path: "./storage/ezrax.db"
  retention_days: 30         # Durée de rétention des logs
  backup_enabled: true
  backup_interval: 86400     # Intervalle de backup (secondes)

reporting:
  enabled: true
  interval: 3600             # Intervalle de génération des rapports
  output_dir: "./reports"
  max_report_size: 10485760  # Taille maximum des rapports (bytes)

logging:
  level: "INFO"              # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: "./logs/ezrax-agent.log"
  max_size: 10485760         # Taille maximum du fichier de log
  backup_count: 5            # Nombre de fichiers de backup
  console_enabled: true      # Affichage sur la console
"""
        
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(template_content)
            
        logger.info(f"Template de configuration sauvegardé: {template_path}")
        
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde du template: {e}")

# Sauvegarder le template au premier démarrage
if not os.path.exists(os.path.join(BASE_DIR, "agent_config.template.yaml")):
    save_config_template()
