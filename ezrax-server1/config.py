#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuration sécurisée pour le serveur central EZRAX
"""

import os
import sys
import yaml
import uuid
import logging
import secrets
import ipaddress
from pathlib import Path
from typing import Dict, Any, List, Optional

# Configuration du logging pour ce module
logger = logging.getLogger(__name__)

class ServerConfigValidator:
    """Validateur de configuration pour le serveur"""
    
    @staticmethod
    def validate_port(port: int, min_port: int = 1024, max_port: int = 65535) -> bool:
        """Valide un port (éviter les ports privilégiés par défaut)"""
        return min_port <= port <= max_port
        
    @staticmethod
    def validate_host(host: str) -> bool:
        """Valide une adresse d'écoute"""
        if host in ["0.0.0.0", "127.0.0.1", "localhost"]:
            return True
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False
            
    @staticmethod
    def validate_api_key(api_key: str) -> bool:
        """Valide une clé API"""
        return (
            isinstance(api_key, str) and 
            len(api_key) >= 32 and
            api_key not in [
                "changez_moi_en_production",
                "default_api_key",
                "test_key",
                "api_key_here"
            ]
        )
        
    @staticmethod
    def validate_database_path(path: str) -> bool:
        """Valide un chemin de base de données"""
        try:
            db_path = Path(path)
            parent_dir = db_path.parent
            
            # Vérifier que le répertoire parent existe ou peut être créé
            if not parent_dir.exists():
                parent_dir.mkdir(parents=True, exist_ok=True)
                
            # Vérifier les permissions d'écriture
            return os.access(parent_dir, os.W_OK)
        except (OSError, PermissionError):
            return False

class ServerSecurityManager:
    """Gestionnaire de sécurité pour le serveur"""
    
    @staticmethod
    def generate_secure_api_key() -> str:
        """Génère une clé API sécurisée pour le serveur"""
        return secrets.token_urlsafe(32)
        
    @staticmethod
    def generate_server_secret() -> str:
        """Génère un secret serveur sécurisé"""
        return secrets.token_hex(32)
        
    @staticmethod
    def validate_security_config(config: Dict[str, Any]) -> List[str]:
        """Valide la configuration de sécurité et retourne les avertissements"""
        warnings = []
        
        # Vérifier la clé API
        api_key = config.get("api", {}).get("key", "")
        if not ServerConfigValidator.validate_api_key(api_key):
            warnings.append("Clé API faible ou par défaut détectée")
            
        # Vérifier l'adresse d'écoute
        host = config.get("api", {}).get("host", "0.0.0.0")
        if host == "0.0.0.0":
            warnings.append("Serveur configuré pour écouter sur toutes les interfaces (0.0.0.0)")
            
        # Vérifier le mode debug
        if config.get("debug", False):
            warnings.append("Mode debug activé en production")
            
        # Vérifier SSL
        if not config.get("api", {}).get("use_ssl", False):
            warnings.append("SSL/TLS désactivé")
            
        return warnings

def get_default_server_config() -> Dict[str, Any]:
    """Retourne la configuration par défaut sécurisée du serveur"""
    
    # Générer une clé API sécurisée si pas fournie par l'environnement
    api_key = os.environ.get("EZRAX_SERVER_API_KEY")
    if not api_key or not ServerConfigValidator.validate_api_key(api_key):
        api_key = ServerSecurityManager.generate_secure_api_key()
        logger.warning(f"Clé API générée automatiquement: {api_key[:8]}...{api_key[-8:]}")
    
    config = {
        "api": {
            "host": os.environ.get("EZRAX_SERVER_HOST", "127.0.0.1"),  # Sécurisé par défaut
            "port": int(os.environ.get("EZRAX_SERVER_PORT", 5000)),
            "key": api_key,
            "use_ssl": os.environ.get("EZRAX_USE_SSL", "false").lower() == "true",
            "ssl_cert": os.environ.get("EZRAX_SSL_CERT", ""),
            "ssl_key": os.environ.get("EZRAX_SSL_KEY", ""),
            "max_content_length": int(os.environ.get("EZRAX_MAX_CONTENT_LENGTH", 16777216)),  # 16MB
            "rate_limit": {
                "enabled": True,
                "requests_per_minute": int(os.environ.get("EZRAX_RATE_LIMIT", 120)),
                "burst_limit": int(os.environ.get("EZRAX_BURST_LIMIT", 200))
            }
        },
        
        "database": {
            "path": os.environ.get("EZRAX_DB_PATH", "./data/ezrax_server.db"),
            "pool_size": int(os.environ.get("EZRAX_DB_POOL_SIZE", 15)),
            "timeout": int(os.environ.get("EZRAX_DB_TIMEOUT", 30)),
            "retention_days": int(os.environ.get("EZRAX_RETENTION_DAYS", 90)),
            "backup": {
                "enabled": os.environ.get("EZRAX_BACKUP_ENABLED", "true").lower() == "true",
                "interval_hours": int(os.environ.get("EZRAX_BACKUP_INTERVAL", 24)),
                "max_backups": int(os.environ.get("EZRAX_MAX_BACKUPS", 7)),
                "backup_dir": os.environ.get("EZRAX_BACKUP_DIR", "./backups")
            }
        },
        
        "logging": {
            "level": os.environ.get("EZRAX_LOG_LEVEL", "INFO"),
            "file": os.environ.get("EZRAX_LOG_FILE", "./logs/ezrax_server.log"),
            "max_size": int(os.environ.get("EZRAX_LOG_MAX_SIZE", 52428800)),  # 50MB
            "backup_count": int(os.environ.get("EZRAX_LOG_BACKUP_COUNT", 10)),
            "console_enabled": os.environ.get("EZRAX_CONSOLE_LOG", "true").lower() == "true",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        },
        
        "agents": {
            "max_agents": int(os.environ.get("EZRAX_MAX_AGENTS", 1000)),
            "heartbeat_timeout": int(os.environ.get("EZRAX_HEARTBEAT_TIMEOUT", 300)),  # 5 minutes
            "offline_threshold": int(os.environ.get("EZRAX_OFFLINE_THRESHOLD", 600)),  # 10 minutes
            "max_sync_records": int(os.environ.get("EZRAX_MAX_SYNC_RECORDS", 1000)),
            "command_timeout": int(os.environ.get("EZRAX_COMMAND_TIMEOUT", 3600)),  # 1 heure
            "validation": {
                "strict_uuid": True,
                "validate_ip": True,
                "validate_hostname": True,
                "max_hostname_length": 255
            }
        },
        
        "security": {
            "api_key_rotation": {
                "enabled": False,  # Désactivé par défaut
                "interval_days": 30
            },
            "ip_whitelist": [],  # Vide = toutes IPs autorisées
            "max_login_attempts": 5,
            "lockout_duration": 900,  # 15 minutes
            "session_timeout": 3600,  # 1 heure
            "require_https": False,  # Désactivé par défaut pour dev
            "validate_user_agent": True
        },
        
        "performance": {
            "cache": {
                "enabled": True,
                "ttl_seconds": 300,  # 5 minutes
                "max_size": 1000
            },
            "monitoring": {
                "enabled": True,
                "metrics_retention_hours": 168,  # 7 jours
                "slow_query_threshold": 1.0,  # 1 seconde
                "memory_alert_threshold": 0.8  # 80%
            }
        },
        
        "grafana": {
            "enabled": os.environ.get("EZRAX_GRAFANA_ENABLED", "true").lower() == "true",
            "docker_image": "grafana/grafana-oss:10.1.4",
            "port": int(os.environ.get("EZRAX_GRAFANA_PORT", 3000)),
            "plugins": [
                "grafana-clock-panel",
                "grafana-simple-json-datasource"
            ],
            "auto_start": os.environ.get("EZRAX_GRAFANA_AUTO_START", "true").lower() == "true"
        },
        
        "alerts": {
            "enabled": os.environ.get("EZRAX_ALERTS_ENABLED", "true").lower() == "true",
            "email": {
                "enabled": False,
                "smtp_server": os.environ.get("EZRAX_SMTP_SERVER", ""),
                "smtp_port": int(os.environ.get("EZRAX_SMTP_PORT", 587)),
                "username": os.environ.get("EZRAX_SMTP_USER", ""),
                "password": os.environ.get("EZRAX_SMTP_PASS", ""),
                "from_address": os.environ.get("EZRAX_FROM_EMAIL", ""),
                "to_addresses": []
            },
            "thresholds": {
                "high_attack_rate": int(os.environ.get("EZRAX_ALERT_ATTACK_RATE", 100)),
                "agent_offline_count": int(os.environ.get("EZRAX_ALERT_OFFLINE_AGENTS", 5)),
                "disk_usage_percent": int(os.environ.get("EZRAX_ALERT_DISK_USAGE", 90)),
                "memory_usage_percent": int(os.environ.get("EZRAX_ALERT_MEMORY_USAGE", 90))
            }
        },
        
        "maintenance": {
            "auto_optimize": True,
            "optimize_interval_hours": 24,
            "auto_cleanup": True,
            "cleanup_interval_hours": 6,
            "vacuum_threshold_mb": 100
        },
        
        "debug": os.environ.get("EZRAX_DEBUG", "false").lower() == "true"
    }
    
    return config

def load_server_config(config_file: str = "server_config.yaml") -> Dict[str, Any]:
    """Charge la configuration du serveur depuis un fichier YAML"""
    
    # Configuration par défaut
    config = get_default_server_config()
    
    # Charger depuis le fichier s'il existe
    if os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                yaml_config = yaml.safe_load(f) or {}
                
            # Fusion récursive
            def merge_dicts(base: dict, update: dict) -> dict:
                for key, value in update.items():
                    if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                        merge_dicts(base[key], value)
                    else:
                        base[key] = value
                return base
                
            config = merge_dicts(config, yaml_config)
            logger.info(f"Configuration serveur chargée depuis: {config_file}")
            
        except yaml.YAMLError as e:
            logger.error(f"Erreur YAML dans {config_file}: {e}")
            logger.warning("Utilisation de la configuration par défaut")
        except Exception as e:
            logger.error(f"Erreur lecture {config_file}: {e}")
            logger.warning("Utilisation de la configuration par défaut")
    else:
        logger.info(f"Fichier {config_file} non trouvé, utilisation config par défaut")
    
    # Validation de la configuration
    if not validate_server_config(config):
        raise ValueError("Configuration serveur invalide")
    
    # Vérifications de sécurité
    security_warnings = ServerSecurityManager.validate_security_config(config)
    for warning in security_warnings:
        logger.warning(f"Sécurité: {warning}")
    
    return config

def validate_server_config(config: Dict[str, Any]) -> bool:
    """Valide la configuration complète du serveur"""
    
    try:
        # Validation API
        api_config = config.get("api", {})
        
        if not ServerConfigValidator.validate_host(api_config.get("host", "127.0.0.1")):
            logger.error("Adresse d'écoute invalide")
            return False
            
        if not ServerConfigValidator.validate_port(api_config.get("port", 5000)):
            logger.error("Port d'écoute invalide")
            return False
            
        if not ServerConfigValidator.validate_api_key(api_config.get("key", "")):
            logger.error("Clé API invalide ou faible")
            return False
        
        # Validation base de données
        db_config = config.get("database", {})
        db_path = db_config.get("path", "./data/ezrax_server.db")
        
        if not ServerConfigValidator.validate_database_path(db_path):
            logger.error(f"Chemin base de données invalide: {db_path}")
            return False
        
        # Validation logging
        log_config = config.get("logging", {})
        log_file = log_config.get("file", "./logs/ezrax_server.log")
        log_dir = os.path.dirname(log_file)
        
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
                logger.info(f"Répertoire de logs créé: {log_dir}")
            except OSError as e:
                logger.error(f"Impossible de créer le répertoire de logs: {e}")
                return False
        
        # Validation agents
        agents_config = config.get("agents", {})
        max_agents = agents_config.get("max_agents", 1000)
        
        if max_agents <= 0 or max_agents > 10000:
            logger.error("Nombre maximum d'agents invalide")
            return False
        
        # Validation Grafana
        grafana_config = config.get("grafana", {})
        grafana_port = grafana_config.get("port", 3000)
        
        if not ServerConfigValidator.validate_port(grafana_port, min_port=1024):
            logger.error("Port Grafana invalide")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Erreur lors de la validation de la configuration: {e}")
        return False

def save_server_config_template(output_file: str = "server_config.template.yaml"):
    """Sauvegarde un template de configuration serveur"""
    
    try:
        # Générer une clé API d'exemple
        example_api_key = ServerSecurityManager.generate_secure_api_key()
        
        template_content = f"""# Configuration du serveur central EZRAX IDS/IPS
# Ce fichier est un template - copiez-le vers server_config.yaml pour personnaliser

api:
  host: "127.0.0.1"              # Adresse d'écoute (127.0.0.1 = localhost uniquement)
  port: 5000                     # Port d'écoute
  key: "{example_api_key}"    # Clé API (CHANGEZ CETTE VALEUR!)
  use_ssl: false                 # Utiliser HTTPS
  ssl_cert: ""                   # Chemin vers le certificat SSL
  ssl_key: ""                    # Chemin vers la clé privée SSL
  max_content_length: 16777216   # Taille max des requêtes (16MB)
  
  rate_limit:
    enabled: true
    requests_per_minute: 120     # Limite de requêtes par minute par IP
    burst_limit: 200             # Limite de rafale

database:
  path: "./data/ezrax_server.db" # Chemin de la base de données
  pool_size: 15                  # Taille du pool de connexions
  timeout: 30                    # Timeout des requêtes (secondes)
  retention_days: 90             # Durée de rétention des données
  
  backup:
    enabled: true
    interval_hours: 24           # Intervalle de sauvegarde
    max_backups: 7               # Nombre de sauvegardes à conserver
    backup_dir: "./backups"      # Répertoire des sauvegardes

logging:
  level: "INFO"                  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: "./logs/ezrax_server.log"
  max_size: 52428800            # Taille max du fichier de log (50MB)
  backup_count: 10              # Nombre de fichiers de backup
  console_enabled: true         # Affichage console
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

agents:
  max_agents: 1000              # Nombre maximum d'agents
  heartbeat_timeout: 300        # Timeout heartbeat (secondes)
  offline_threshold: 600        # Seuil pour marquer un agent offline
  max_sync_records: 1000        # Nombre max d'enregistrements par sync
  command_timeout: 3600         # Timeout des commandes (secondes)
  
  validation:
    strict_uuid: true           # Validation stricte des UUID
    validate_ip: true           # Validation des adresses IP
    validate_hostname: true     # Validation des noms d'hôte
    max_hostname_length: 255    # Longueur max du hostname

security:
  api_key_rotation:
    enabled: false              # Rotation automatique des clés API
    interval_days: 30           # Intervalle de rotation
    
  ip_whitelist: []              # Liste des IPs autorisées (vide = toutes)
  max_login_attempts: 5         # Tentatives de connexion max
  lockout_duration: 900         # Durée de verrouillage (secondes)
  session_timeout: 3600         # Timeout de session
  require_https: false          # Forcer HTTPS
  validate_user_agent: true     # Valider User-Agent

performance:
  cache:
    enabled: true
    ttl_seconds: 300            # Durée de vie du cache
    max_size: 1000              # Taille max du cache
    
  monitoring:
    enabled: true
    metrics_retention_hours: 168  # Rétention des métriques (7 jours)
    slow_query_threshold: 1.0     # Seuil requête lente (secondes)
    memory_alert_threshold: 0.8   # Seuil alerte mémoire

grafana:
  enabled: true
  docker_image: "grafana/grafana-oss:10.1.4"
  port: 3000
  plugins:
    - "grafana-clock-panel"
    - "grafana-simple-json-datasource"
  auto_start: true              # Démarrage automatique

alerts:
  enabled: true
  
  email:
    enabled: false              # Alertes par email
    smtp_server: ""
    smtp_port: 587
    username: ""
    password: ""
    from_address: ""
    to_addresses: []
    
  thresholds:
    high_attack_rate: 100       # Seuil d'attaques/minute
    agent_offline_count: 5      # Nombre d'agents offline pour alerte
    disk_usage_percent: 90      # Seuil d'utilisation disque
    memory_usage_percent: 90    # Seuil d'utilisation mémoire

maintenance:
  auto_optimize: true           # Optimisation automatique
  optimize_interval_hours: 24   # Intervalle d'optimisation
  auto_cleanup: true            # Nettoyage automatique
  cleanup_interval_hours: 6     # Intervalle de nettoyage
  vacuum_threshold_mb: 100      # Seuil pour VACUUM

debug: false                    # Mode debug (à désactiver en production)
"""
        
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(template_content)
            
        logger.info(f"Template de configuration serveur sauvegardé: {output_file}")
        logger.warning(f"IMPORTANT: Changez la clé API dans le fichier de configuration!")
        
    except Exception as e:
        logger.error(f"Erreur sauvegarde template: {e}")

def setup_server_logging(config: Dict[str, Any]):
    """Configure le système de logging du serveur"""
    
    log_config = config.get("logging", {})
    
    # Créer le répertoire de logs
    log_file = log_config.get("file", "./logs/ezrax_server.log")
    log_dir = os.path.dirname(log_file)
    
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, mode=0o755)
    
    # Configuration des handlers
    handlers = []
    
    # Handler fichier avec rotation
    if log_file:
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=log_config.get("max_size", 52428800),
            backupCount=log_config.get("backup_count", 10),
            encoding="utf-8"
        )
        file_handler.setLevel(getattr(logging, log_config.get("level", "INFO")))
        handlers.append(file_handler)
    
    # Handler console
    if log_config.get("console_enabled", True):
        console_handler = logging.StreamHandler()
        console_handler.setLevel(getattr(logging, log_config.get("level", "INFO")))
        handlers.append(console_handler)
    
    # Configuration du logging
    logging.basicConfig(
        level=getattr(logging, log_config.get("level", "INFO")),
        format=log_config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"),
        handlers=handlers,
        force=True  # Forcer la reconfiguration
    )
    
    # Sécuriser les permissions du fichier de log
    if log_file and os.path.exists(log_file):
        try:
            os.chmod(log_file, 0o640)  # rw-r-----
        except OSError:
            pass

def get_server_info(config: Dict[str, Any]) -> Dict[str, Any]:
    """Retourne les informations du serveur (sans données sensibles)"""
    
    return {
        "version": "2.0.0",
        "api": {
            "host": config["api"]["host"],
            "port": config["api"]["port"],
            "ssl_enabled": config["api"]["use_ssl"],
            "rate_limiting": config["api"]["rate_limit"]["enabled"]
        },
        "database": {
            "retention_days": config["database"]["retention_days"],
            "backup_enabled": config["database"]["backup"]["enabled"]
        },
        "agents": {
            "max_agents": config["agents"]["max_agents"],
            "heartbeat_timeout": config["agents"]["heartbeat_timeout"]
        },
        "security": {
            "ip_whitelist_enabled": len(config["security"]["ip_whitelist"]) > 0,
            "https_required": config["security"]["require_https"]
        },
        "grafana": {
            "enabled": config["grafana"]["enabled"],
            "port": config["grafana"]["port"]
        },
        "alerts_enabled": config["alerts"]["enabled"],
        "debug_mode": config["debug"]
    }

# Configuration par défaut chargée
DEFAULT_SERVER_CONFIG = get_default_server_config()

def create_example_agent_config(server_config: Dict[str, Any], output_file: str = "agent_config.example.yaml"):
    """Crée un fichier de configuration d'exemple pour les agents"""
    
    try:
        server_host = server_config["api"]["host"]
        server_port = server_config["api"]["port"]
        api_key = server_config["api"]["key"]
        
        # Si le serveur écoute sur localhost, utiliser l'IP réelle pour les agents
        if server_host in ["127.0.0.1", "localhost"]:
            import socket
            try:
                # Obtenir l'IP locale
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                server_host = s.getsockname()[0]
                s.close()
            except:
                server_host = "192.168.1.100"  # Fallback
        
        agent_config_content = f"""# Configuration d'exemple pour les agents EZRAX
# Copiez ce fichier vers agent_config.yaml sur chaque agent

central_server:
  host: "{server_host}"          # Adresse IP du serveur central
  port: {server_port}                     # Port du serveur central
  api_key: "{api_key}"    # Clé API du serveur (DOIT CORRESPONDRE!)
  use_ssl: {str(server_config["api"]["use_ssl"]).lower()}                 # Utiliser HTTPS
  check_interval: 30             # Intervalle de synchronisation (secondes)
  timeout: 10                    # Timeout des requêtes
  max_retries: 3                 # Nombre de tentatives

scanners:
  enabled: true
  
  syn_flood:
    enabled: true
    threshold: 100               # Nombre de paquets SYN pour alerte
    time_window: 5               # Fenêtre de temps (secondes)
    interfaces: ["enp0s3"]       # Interfaces réseau à surveiller
    
  udp_flood:
    enabled: true
    threshold: 200
    time_window: 5
    
  port_scan:
    enabled: true
    threshold: 15                # Nombre de ports pour alerte
    time_window: 10
    
  ping_flood:
    enabled: true
    threshold: 30
    time_window: 5

ips:
  enabled: true
  block_duration: 3600           # Durée de blocage par défaut (secondes)
  max_block_duration: 86400      # Durée maximum de blocage
  max_blocked_ips: 10000         # Nombre maximum d'IPs bloquées
  auto_block: true               # Blocage automatique
  whitelist:                     # IPs à ne jamais bloquer
    - "127.0.0.1"
    - "::1"
    - "{server_host}"            # Serveur central

database:
  path: "./storage/ezrax.db"
  retention_days: 30             # Durée de rétention des logs
  backup_enabled: true
  backup_interval: 86400         # Intervalle de backup (secondes)

reporting:
  enabled: true
  interval: 3600                 # Intervalle de génération des rapports
  output_dir: "./reports"
  max_report_size: 10485760      # Taille maximum des rapports

logging:
  level: "INFO"                  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  file: "./logs/ezrax-agent.log"
  max_size: 10485760             # Taille maximum du fichier de log
  backup_count: 5                # Nombre de fichiers de backup
  console_enabled: true          # Affichage console
"""
        
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(agent_config_content)
            
        logger.info(f"Configuration d'exemple pour agents créée: {output_file}")
        logger.info(f"Serveur configuré sur: {server_host}:{server_port}")
        logger.info(f"Clé API: {api_key[:8]}...{api_key[-8:]}")
        
    except Exception as e:
        logger.error(f"Erreur création config agent: {e}")

# Variables globales pour l'export
__all__ = [
    'ServerConfigValidator',
    'ServerSecurityManager', 
    'get_default_server_config',
    'load_server_config',
    'validate_server_config',
    'save_server_config_template',
    'setup_server_logging',
    'get_server_info',
    'create_example_agent_config',
    'DEFAULT_SERVER_CONFIG'
]
