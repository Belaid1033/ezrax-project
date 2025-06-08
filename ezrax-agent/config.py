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
from dotenv import load_dotenv, find_dotenv
import sys

BASE_DIR = Path(__file__).resolve().parent

logger = logging.getLogger(__name__)

env_path_system = Path("/etc/ezrax-agent/.env")
initial_dot_env_loaded = False

if env_path_system.exists():
    if os.access(env_path_system, os.R_OK):
        if load_dotenv(dotenv_path=env_path_system, override=True):
            logger.info(f"Variables d'environnement chargées depuis {env_path_system}")
            initial_dot_env_loaded = True
        else:
            logger.warning(f"load_dotenv n'a rien chargé depuis {env_path_system} (fichier peut-être vide ou mal formaté).")
    else:
        logger.error(f"Permission de lecture REFUSÉE pour {env_path_system}. Vérifiez les permissions.")
else:
    logger.info(f"Fichier .env système non trouvé à {env_path_system}.")

if not initial_dot_env_loaded:
    local_env_path = find_dotenv(usecwd=True, raise_error_if_not_found=False)
    if local_env_path and Path(local_env_path).exists():
        if load_dotenv(dotenv_path=local_env_path, override=True):
            logger.info(f"Variables d'environnement chargées depuis le .env local/parent : {local_env_path}")
        else:
            logger.warning(f"load_dotenv n'a rien chargé depuis {local_env_path} (fichier peut-être vide ou mal formaté).")
    else:
        logger.info("Aucun fichier .env local ou parent trouvé par find_dotenv.")

class ConfigValidator:
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    @staticmethod
    def validate_ip_list(ip_list: Union[str, List[str]]) -> List[str]:
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
        if isinstance(value, bool):
            return value
        elif isinstance(value, str):
            return value.lower() in ("true", "yes", "1", "on")
        else:
            return bool(value)
            
    @staticmethod
    def get_active_network_interface() -> str:
        try:
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
            result = subprocess.run(
                ['ip', 'link', 'show'], 
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                import re
                interfaces = re.findall(r'\d+: (\w+).*state UP', result.stdout)
                non_lo_interfaces = [iface for iface in interfaces if not iface.startswith('lo')]
                if non_lo_interfaces:
                    interface = non_lo_interfaces[0]
                    logger.info(f"Interface UP détectée: {interface}")
                    return interface
        except:
            pass
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
        if isinstance(interfaces, str):
            interfaces = [iface.strip() for iface in interfaces.split(",") if iface.strip()]
        if not interfaces or (len(interfaces) == 1 and interfaces[0] in ['eth0', 'enp0s3', 'auto']):
            active_interface = ConfigValidator.get_active_network_interface()
            return [active_interface]
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
        if not validated_interfaces:
            active_interface = ConfigValidator.get_active_network_interface()
            validated_interfaces.append(active_interface)
        return validated_interfaces

class SecretManager:
    @staticmethod
    def generate_api_key() -> str:
        return secrets.token_urlsafe(32)
        
    @staticmethod
    def hash_secret(secret: str) -> str:
        return hashlib.sha256(secret.encode()).hexdigest()
        
    @staticmethod
    def load_secret_from_env_or_generate(env_key: str, default_generator=None) -> str:
        secret = os.environ.get(env_key)
        source_log_info = "non défini"
        
        if secret:
            source_log_info = f"variable d'environnement ({env_key})"
            dangerous_defaults = [
                "changez_moi_en_production",
                "default_api_key", "test_key"
            ]
            if secret in dangerous_defaults:
                logger.error(f"Secret par défaut dangereux détecté pour {env_key}")
                if default_generator:
                    secret = default_generator()
                    logger.warning(f"Secret généré automatiquement pour {env_key} car valeur par défaut dangereuse.")
                    source_log_info = f"généré automatiquement (valeur dangereuse pour {env_key})"
        elif default_generator:
            secret = default_generator()
            source_log_info = f"généré automatiquement (car {env_key} non trouvé)"
        else: # Devrait seulement arriver si default_generator est None et secret non trouvé
            secret = SecretManager.generate_api_key() # Fallback ultime
            source_log_info = f"généré par fallback ultime (car {env_key} non trouvé et pas de générateur par défaut)"

        logger.debug(f"Secret pour '{env_key}' obtenu depuis : {source_log_info}. Valeur (début): {str(secret)[:4]}...")
        return secret

AGENT_ID_FILE = os.path.join(BASE_DIR, ".agent_id")

def get_agent_id() -> str:
    if os.path.exists(AGENT_ID_FILE):
        try:
            with open(AGENT_ID_FILE, "r") as f:
                agent_id = f.read().strip()
                uuid.UUID(agent_id)
                return agent_id
        except (ValueError, OSError) as e:
            logger.warning(f"ID d'agent invalide ou illisible: {e}, génération d'un nouveau")
    agent_id = str(uuid.uuid4())
    try:
        with open(AGENT_ID_FILE, "w") as f:
            f.write(agent_id)
        os.chmod(AGENT_ID_FILE, 0o600)
    except OSError as e:
        logger.error(f"Impossible de sauvegarder l'ID d'agent: {e}")
    return agent_id

AGENT_ID = get_agent_id()
AGENT_HOSTNAME = socket.gethostname()

CONFIG_FILE = os.environ.get("EZRAX_CONFIG", os.path.join(BASE_DIR, "agent_config.yaml"))

def get_default_config() -> Dict[str, Any]:
    default_api_key = SecretManager.load_secret_from_env_or_generate(
        "CENTRAL_SERVER_API_KEY",
        SecretManager.generate_api_key
    )
    
    config = {
        "central_server": {
            "host": os.environ.get("CENTRAL_SERVER_HOST", "127.0.0.1"),
            "port": ConfigValidator.validate_port(os.environ.get("CENTRAL_SERVER_PORT", 5000)),
            "api_key": default_api_key,
            "use_ssl": ConfigValidator.validate_boolean(os.environ.get("CENTRAL_SERVER_USE_SSL", "False")),
            "check_interval": ConfigValidator.validate_positive_int(os.environ.get("CHECK_INTERVAL", 30), min_value=5),
            "timeout": ConfigValidator.validate_positive_int(os.environ.get("CENTRAL_SERVER_TIMEOUT", 10), min_value=1),
            "max_retries": ConfigValidator.validate_positive_int(os.environ.get("CENTRAL_SERVER_MAX_RETRIES", 3), min_value=1)
        },
        "scanners": {
            "enabled": ConfigValidator.validate_boolean(os.environ.get("SCANNERS_ENABLED", "True")),
            "syn_flood": {
                "enabled": ConfigValidator.validate_boolean(os.environ.get("SYN_FLOOD_ENABLED", "True")),
                "threshold": ConfigValidator.validate_positive_int(os.environ.get("SYN_FLOOD_THRESHOLD", 100), min_value=10),
                "time_window": ConfigValidator.validate_positive_int(os.environ.get("SYN_FLOOD_WINDOW", 5), min_value=1),
                "interfaces": ConfigValidator.validate_interfaces_list(os.environ.get("MONITOR_INTERFACES", "auto")),
            },
            "udp_flood": {
                "enabled": ConfigValidator.validate_boolean(os.environ.get("UDP_FLOOD_ENABLED", "True")),
                "threshold": ConfigValidator.validate_positive_int(os.environ.get("UDP_FLOOD_THRESHOLD", 200), min_value=20),
                "time_window": ConfigValidator.validate_positive_int(os.environ.get("UDP_FLOOD_WINDOW", 5), min_value=1),
            },
            "port_scan": {
                "enabled": ConfigValidator.validate_boolean(os.environ.get("PORT_SCAN_ENABLED", "True")),
                "threshold": ConfigValidator.validate_positive_int(os.environ.get("PORT_SCAN_THRESHOLD", 15), min_value=5),
                "time_window": ConfigValidator.validate_positive_int(os.environ.get("PORT_SCAN_WINDOW", 10), min_value=5),
            },
            "ping_flood": {
                "enabled": ConfigValidator.validate_boolean(os.environ.get("PING_FLOOD_ENABLED", "True")),
                "threshold": ConfigValidator.validate_positive_int(os.environ.get("PING_FLOOD_THRESHOLD", 30), min_value=10),
                "time_window": ConfigValidator.validate_positive_int(os.environ.get("PING_FLOOD_WINDOW", 5), min_value=1),
            },
        },
        "ips": {
            "enabled": ConfigValidator.validate_boolean(os.environ.get("IPS_ENABLED", "True")),
            "block_duration": ConfigValidator.validate_positive_int(os.environ.get("BLOCK_DURATION", 3600), min_value=60),
            "max_block_duration": ConfigValidator.validate_positive_int(os.environ.get("MAX_BLOCK_DURATION", 86400), min_value=3600),
            "max_blocked_ips": ConfigValidator.validate_positive_int(os.environ.get("MAX_BLOCKED_IPS", 10000), min_value=100),
            "auto_block": ConfigValidator.validate_boolean(os.environ.get("AUTO_BLOCK", "True")),
            "whitelist": ConfigValidator.validate_ip_list(os.environ.get("IP_WHITELIST", "127.0.0.1,::1")),
        },
        "database": {
            "path": os.environ.get("DB_PATH", os.path.join(BASE_DIR, "storage", "ezrax.db")),
            "retention_days": ConfigValidator.validate_positive_int(os.environ.get("LOG_RETENTION_DAYS", 30), min_value=1),
            "backup_enabled": ConfigValidator.validate_boolean(os.environ.get("DB_BACKUP_ENABLED", "True")),
            "backup_interval": ConfigValidator.validate_positive_int(os.environ.get("DB_BACKUP_INTERVAL", 86400), min_value=3600)
        },
        "reporting": {
            "enabled": ConfigValidator.validate_boolean(os.environ.get("REPORTING_ENABLED", "True")),
            "interval": ConfigValidator.validate_positive_int(os.environ.get("REPORTING_INTERVAL", 3600), min_value=300),
            "output_dir": os.environ.get("REPORT_OUTPUT_DIR", os.path.join(BASE_DIR, "reports")),
            "max_report_size": ConfigValidator.validate_positive_int(os.environ.get("MAX_REPORT_SIZE", 10485760), min_value=1048576)
        },
        "logging": {
            "level": os.environ.get("LOG_LEVEL", "INFO").upper(),
            "file": os.environ.get("LOG_FILE", os.path.join(BASE_DIR, "logs", "ezrax-agent.log")),
            "max_size": ConfigValidator.validate_positive_int(os.environ.get("LOG_MAX_SIZE", 1024 * 1024 * 10), min_value=1024 * 1024),
            "backup_count": ConfigValidator.validate_positive_int(os.environ.get("LOG_BACKUP_COUNT", 5), min_value=1),
            "console_enabled": ConfigValidator.validate_boolean(os.environ.get("LOG_CONSOLE_ENABLED", "True"))
        }
    }
    return config

DEFAULT_CONFIG = get_default_config()

def validate_config_section(config_dict: Dict[str, Any], section_name: str, expected_keys: List[str]) -> bool:
    if section_name not in config_dict:
        logger.error(f"Section de configuration manquante: {section_name}")
        return False
    section = config_dict[section_name]
    missing_keys = [key for key in expected_keys if key not in section]
    if missing_keys:
        logger.error(f"Clés manquantes dans la section {section_name}: {missing_keys}")
        return False
    return True

def validate_full_config(config_dict: Dict[str, Any]) -> bool:
    required_sections = {
        "central_server": ["host", "port", "api_key"],
        "scanners": ["enabled"],
        "ips": ["enabled", "whitelist"],
        "database": ["path", "retention_days"],
        "logging": ["level", "file"]
    }
    for section_name, required_keys in required_sections.items():
        if not validate_config_section(config_dict, section_name, required_keys):
            return False
    try:
        for path_key in ["database.path", "reporting.output_dir", "logging.file"]:
            parts = path_key.split(".")
            section, key = parts[0], parts[1]
            if section in config_dict and key in config_dict[section]:
                path_val = config_dict[section][key]
                parent_dir = Path(path_val).parent
                if not parent_dir.exists():
                    parent_dir.mkdir(parents=True, exist_ok=True)
                    logger.info(f"Répertoire créé: {parent_dir}")
        
        central_server_conf = config_dict.get("central_server", {})
        if central_server_conf.get("enabled", True): # Assume enabled if key missing
            host = central_server_conf.get("host")
            port = central_server_conf.get("port")
            if host and port:
                try:
                    socket.getaddrinfo(host, port)
                    logger.info(f"Serveur central accessible (DNS lookup): {host}:{port}")
                except (socket.gaierror, socket.timeout):
                    logger.warning(f"Serveur central non accessible (DNS lookup): {host}:{port}")
    except Exception as e:
        logger.error(f"Erreur lors de la validation étendue de la configuration: {e}")
        return False
    return True

def load_config() -> Dict[str, Any]:
    config_data = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                yaml_config = yaml.safe_load(f) or {}
            def update_dict(d, u):
                for k, v in u.items():
                    if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                        d[k] = update_dict(d[k], v)
                    else:
                        d[k] = v
                return d
            config_data = update_dict(config_data, yaml_config)
            logger.info(f"Configuration chargée depuis: {CONFIG_FILE}")
        except yaml.YAMLError as e:
            logger.error(f"Erreur YAML lors du chargement de {CONFIG_FILE}: {e}. Utilisation de la configuration par défaut.")
        except Exception as e:
            logger.error(f"Erreur lors du chargement de {CONFIG_FILE}: {e}. Utilisation de la configuration par défaut.")
    else:
        logger.info(f"Fichier de configuration non trouvé: {CONFIG_FILE}. Utilisation de la configuration par défaut.")
    
    if not validate_full_config(config_data):
        logger.critical("Configuration invalide détectée après chargement. Vérifiez les erreurs ci-dessus.")
        raise ValueError("Configuration invalide")
    
    return config_data

try:
    CONFIG = load_config()
    CONFIG["AGENT_ID"] = AGENT_ID
    CONFIG["AGENT_HOSTNAME"] = AGENT_HOSTNAME
    
    def mask_secrets_in_config(config_dict: Dict[str, Any]) -> Dict[str, Any]:
        import copy
        masked_config = copy.deepcopy(config_dict)
        sensitive_keys = ["api_key", "password", "token", "secret"]
        def mask_recursive(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if any(sensitive in key.lower() for sensitive in sensitive_keys) and isinstance(value, str):
                        obj[key] = (value[:2] + "*" * (len(value) - 4) + value[-2:]) if len(value) > 4 else "*" * len(value)
                    else:
                        mask_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    mask_recursive(item)
        mask_recursive(masked_config)
        return masked_config
    
    logger.info(f"Configuration chargée et validée: {len(CONFIG)} sections principales.")
    if logger.isEnabledFor(logging.DEBUG):
        masked_config_log = mask_secrets_in_config(CONFIG)
        logger.debug(f"Configuration détaillée (secrets masqués): {json.dumps(masked_config_log, indent=2, default=str)}")
    
except Exception as e:
    logger.critical(f"Impossible de charger ou valider la configuration: {e}")
    logger.critical(traceback.format_exc())
    raise

def setup_logging():
    log_config = CONFIG["logging"]
    log_dir = Path(log_config["file"]).parent
    
    if not log_dir.exists():
        log_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    
    log_level_name = log_config.get("level", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    # Supprimer les handlers existants du root logger pour éviter la duplication
    # si setup_logging est appelé plusieurs fois ou si basicConfig a été appelé avant.
    root_logger = logging.getLogger()
    if root_logger.hasHandlers():
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    handlers_list = []
    
    file_handler = logging.handlers.RotatingFileHandler(
        log_config["file"],
        maxBytes=log_config["max_size"],
        backupCount=log_config["backup_count"],
        encoding="utf-8"
    )
    file_handler.setLevel(log_level)
    formatter = logging.Formatter("%(asctime)s - %(name)s - [%(levelname)s] - %(message)s")
    file_handler.setFormatter(formatter)
    handlers_list.append(file_handler)
    
    if log_config.get("console_enabled", True):
        console_handler = logging.StreamHandler(sys.stdout) # Explicitement sys.stdout
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        handlers_list.append(console_handler)
    
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - [%(levelname)s] - %(message)s", # Format par défaut pour basicConfig
        handlers=handlers_list # Important: passer les handlers ici
    )
    
    # Mettre à jour le niveau du logger racine (celui configuré par basicConfig)
    logging.getLogger().setLevel(log_level)
    
    # Mettre à jour le niveau du logger de ce module (config.py) aussi
    logger.setLevel(log_level)

    try:
        if Path(log_config["file"]).exists():
             os.chmod(log_config["file"], 0o640)
    except OSError as e:
        logger.warning(f"Impossible de définir les permissions sur le fichier de log {log_config['file']}: {e}")

    logger.info(f"Système de logging configuré. Niveau: {log_level_name}, Fichier: {log_config['file']}")


def ensure_directories():
    dirs_to_create = [
        (Path(CONFIG["database"]["path"]).parent, 0o750),
        (Path(CONFIG["reporting"]["output_dir"]), 0o750),
        (Path(CONFIG["logging"]["file"]).parent, 0o750)
    ]
    for directory, mode in dirs_to_create:
        if directory and not directory.exists():
            try:
                directory.mkdir(mode=mode, parents=True, exist_ok=True)
                logger.info(f"Répertoire créé: {directory} avec mode {oct(mode)}")
            except OSError as e:
                logger.error(f"Impossible de créer le répertoire {directory}: {e}")

def reload_config() -> bool:
    global CONFIG
    try:
        new_config = load_config()
        new_config["AGENT_ID"] = AGENT_ID
        new_config["AGENT_HOSTNAME"] = AGENT_HOSTNAME
        CONFIG = new_config
        setup_logging() # Reconfigurer le logging avec la nouvelle config
        logger.info("Configuration et logging rechargés avec succès.")
        return True
    except Exception as e:
        logger.error(f"Erreur lors du rechargement de la configuration: {e}")
        return False

def save_config_template():
    template_path = BASE_DIR / "agent_config.template.yaml"
    try:
        active_interface = ConfigValidator.get_active_network_interface()
        template_content = f"""# Configuration EZRAX IDS/IPS Agent
# Ce fichier est un template - copiez-le vers agent_config.yaml pour personnaliser

central_server:
  host: "127.0.0.1"
  port: 5000
#  api_key: "DEFINIR_DANS_FICHIER_.ENV_COMME_CENTRAL_SERVER_API_KEY"
  use_ssl: false
  check_interval: 30
  timeout: 10
  max_retries: 3

scanners:
  enabled: true
  syn_flood:
    enabled: true
    threshold: 100
    time_window: 5
    interfaces: ["{active_interface}"]
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
  max_block_duration: 86400
  max_blocked_ips: 10000
  auto_block: true
  whitelist:
    - "127.0.0.1"
    - "::1"

database:
  path: "{BASE_DIR / 'storage' / 'ezrax.db'}"
  retention_days: 30
  backup_enabled: true
  backup_interval: 86400

reporting:
  enabled: true
  interval: 3600
  output_dir: "{BASE_DIR / 'reports'}"
  max_report_size: 10485760

logging:
  level: "INFO"
  file: "{BASE_DIR / 'logs' / 'ezrax-agent.log'}"
  max_size: 10485760
  backup_count: 5
  console_enabled: true
"""
        with open(template_path, "w", encoding="utf-8") as f:
            f.write(template_content)
        logger.info(f"Template de configuration sauvegardé: {template_path}")
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde du template: {e}")

if not (BASE_DIR / "agent_config.template.yaml").exists():
    save_config_template()


setup_logging()
