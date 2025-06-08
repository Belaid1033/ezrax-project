#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Point d'entrée principal du serveur central EZRAX v2.0 
"""

import os
import sys
import time
import signal
import logging
import argparse
import threading
import json
import secrets
from pathlib import Path
from typing import Dict, List, Any, Optional

# Configuration du logging précoce
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("ezrax_server.log")
    ]
)
logger = logging.getLogger(__name__)

# Importation des modules
from db_manager import ServerDatabaseManager
from server_api import EzraxServerAPI

# Import conditionnel de l'interface graphique
try:
    from gui_app import EzraxServerGUI
    GUI_AVAILABLE = True
except ImportError as e:
    logger.warning(f"Interface graphique non disponible: {e}")
    GUI_AVAILABLE = False

class EzraxServerConfig:
    """Gestionnaire de configuration du serveur avec validation"""
    
    def __init__(self, config_file="server_config.json"):
        self.config_file = config_file
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Charge la configuration depuis le fichier"""
        default_config = {
            "server": {
                "host": "0.0.0.0",
                "port": 5000,
                "debug": False,
                "max_content_length": 16777216,  # 16MB
                "request_timeout": 30
            },
            "database": {
                "path": "ezrax_server.db",
                "pool_size": 15,
                "backup_enabled": True,
                "backup_interval": 86400,
                "retention_days": 30
            },
            "security": {
                "api_key": None,  # Sera généré si absent
                "jwt_secret": None,  # Sera généré si absent
                "admin_api_enabled": True,
                "rate_limiting": {
                    "agents": {"max_requests": 1000, "window_seconds": 60},
                    "admin": {"max_requests": 200, "window_seconds": 60},
                    "public": {"max_requests": 50, "window_seconds": 60}
                }
            },
            "logging": {
                "level": "INFO",
                "file": "ezrax_server.log",
                "max_size": 10485760,  # 10MB
                "backup_count": 5,
                "console_enabled": True
            },
            "monitoring": {
                "metrics_enabled": True,
                "performance_alerts": True,
                "health_check_interval": 60
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    
                # Fusion des configs
                self._deep_update(default_config, file_config)
                logger.info(f"Configuration chargée depuis {self.config_file}")
                
            except Exception as e:
                logger.error(f"Erreur lors du chargement de la config: {e}")
                logger.info("Utilisation de la configuration par défaut")
                
        else:
            logger.info(f"Fichier de config non trouvé, création de {self.config_file}")
            self._save_config(default_config)
            
        # Générer les secrets manquants
        self._ensure_secrets(default_config)
        
        return default_config
        
    def _deep_update(self, base_dict: Dict, update_dict: Dict):
        """Met à jour récursivement un dictionnaire"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value
                
    def _ensure_secrets(self, config: Dict[str, Any]):
        """Génère les secrets manquants"""
        secrets_updated = False
        
        if not config["security"]["api_key"]:
            config["security"]["api_key"] = secrets.token_urlsafe(32)
            secrets_updated = True
            logger.info("Nouvelle clé API générée")
            
        if not config["security"]["jwt_secret"]:
            config["security"]["jwt_secret"] = secrets.token_urlsafe(32)
            secrets_updated = True
            logger.info("Nouveau secret JWT généré")
            
        if secrets_updated:
            self._save_config(config)
            
    def _save_config(self, config: Dict[str, Any]):
        """Sauvegarde la configuration"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
                
            logger.info(f"Configuration sauvegardée dans {self.config_file}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde de la config: {e}")
            
    def get(self, key_path: str, default=None):
        """Récupère une valeur de configuration avec chemin pointé"""
        keys = key_path.split('.')
        value = self.config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
                
        return value

class PerformanceMonitor:
    """Moniteur de performance du serveur"""
    
    def __init__(self, server_manager, check_interval=60):
        self.server_manager = server_manager
        self.check_interval = check_interval
        self.running = False
        self.thread = None
        self.alerts = []
        
    def start(self):
        """Démarre le monitoring"""
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Monitoring de performance démarré")
        
    def stop(self):
        """Arrête le monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
            
    def _monitor_loop(self):
        """Boucle de monitoring"""
        while self.running:
            try:
                self._check_performance()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Erreur dans le monitoring: {e}")
                time.sleep(30)
                
    def _check_performance(self):
        """Vérifie les performances et génère des alertes"""
        try:
            # Métriques de la base de données
            if hasattr(self.server_manager, 'db_manager'):
                db_metrics = self.server_manager.db_manager.get_performance_metrics()
                
                # Alertes DB
                if db_metrics['avg_query_time'] > 0.5:  # 500ms
                    self._add_alert("WARNING", f"Temps de requête DB élevé: {db_metrics['avg_query_time']*1000:.0f}ms")
                    
                if db_metrics['connection_pool']['active_connections'] >= db_metrics['connection_pool']['pool_size'] * 0.9:
                    self._add_alert("WARNING", "Pool de connexions DB près de la saturation")
                    
                cache_hit_rate = db_metrics['query_cache']['hit_rate']
                if cache_hit_rate < 0.7:  # Moins de 70%
                    self._add_alert("INFO", f"Taux de cache DB faible: {cache_hit_rate:.1%}")
                    
            # Métriques de l'API
            if hasattr(self.server_manager, 'api_server'):
                api_metrics = self.server_manager.api_server.get_api_metrics()
                
                # Alertes API
                api_stats = api_metrics['api_metrics']
                if api_stats['avg_response_time'] > 1.0:  # 1 seconde
                    self._add_alert("WARNING", f"Temps de réponse API élevé: {api_stats['avg_response_time']*1000:.0f}ms")
                    
                total_requests = max(api_stats['requests_total'], 1)
                error_rate = api_stats['requests_failed'] / total_requests
                if error_rate > 0.05:  # Plus de 5% d'erreurs
                    self._add_alert("ERROR", f"Taux d'erreur API élevé: {error_rate:.1%}")
                    
        except Exception as e:
            logger.error(f"Erreur lors de la vérification des performances: {e}")
            
    def _add_alert(self, level: str, message: str):
        """Ajoute une alerte"""
        alert = {
            "timestamp": time.time(),
            "level": level,
            "message": message
        }
        
        self.alerts.append(alert)
        
        # Limiter le nombre d'alertes
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-50:]
            
        # Logger l'alerte
        getattr(logger, level.lower())(f"Performance Alert: {message}")
        
    def get_alerts(self, since: Optional[float] = None) -> List[Dict[str, Any]]:
        """Récupère les alertes récentes"""
        if since is None:
            return self.alerts[-10:]  # 10 dernières
            
        return [alert for alert in self.alerts if alert['timestamp'] >= since]

class EzraxServerManager:
    """Gestionnaire principal du serveur EZRAX"""
    
    def __init__(self, config_file="server_config.json"):
        """Initialisation du gestionnaire de serveur"""
        # Configuration
        self.config_manager = EzraxServerConfig(config_file)
        self.config = self.config_manager.config
        
        # État du serveur
        self.running = False
        self.start_time = time.time()
        
        # Composants
        self.db_manager = None
        self.api_server = None
        self.gui_app = None
        self.performance_monitor = None
        
        # Configuration du logging avancé
        self._setup_logging()
        
        # Signaux de fermeture
        self._setup_signal_handlers()
        
        logger.info("=" * 60)
        logger.info("EZRAX Central Server v2.0 - Initialisation")
        logger.info("=" * 60)
        
    def _setup_logging(self):
        """Configure le système de logging avancé"""
        log_config = self.config["logging"]
        
        # Niveau de log
        log_level = getattr(logging, log_config["level"], logging.INFO)
        
        # Formateur
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        
        # Handler fichier avec rotation
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_config["file"],
            maxBytes=log_config["max_size"],
            backupCount=log_config["backup_count"]
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        
        # Configurer le logger racine
        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.addHandler(file_handler)
        
        # Handler console optionnel
        if log_config["console_enabled"]:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(log_level)
            console_handler.setFormatter(formatter)
            root_logger.addHandler(console_handler)
            
        root_logger.setLevel(log_level)
        
        logger.info(f"Logging configuré: niveau {log_config['level']}, fichier {log_config['file']}")
        
    def _setup_signal_handlers(self):
        """Configure les gestionnaires de signaux"""
        def signal_handler(sig, frame):
            signal_name = signal.Signals(sig).name
            logger.info(f"Signal {signal_name} reçu, arrêt gracieux...")
            self.stop()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        if hasattr(signal, 'SIGHUP'):
            def reload_handler(sig, frame):
                logger.info("Signal SIGHUP reçu, rechargement de la configuration...")
                self._reload_config()
                
            signal.signal(signal.SIGHUP, reload_handler)
            
    def _reload_config(self):
        """Recharge la configuration à chaud"""
        try:
            old_config = self.config.copy()
            self.config_manager = EzraxServerConfig(self.config_manager.config_file)
            self.config = self.config_manager.config
            
            # Reconfigurer le logging si nécessaire
            if old_config["logging"] != self.config["logging"]:
                self._setup_logging()
                
            logger.info("Configuration rechargée avec succès")
            
        except Exception as e:
            logger.error(f"Erreur lors du rechargement de la configuration: {e}")
            
    def initialize_components(self):
        """Initialise tous les composants du serveur"""
        try:
            # 1. Base de données
            logger.info("Initialisation de la base de données...")
            self.db_manager = ServerDatabaseManager(
                db_path=self.config["database"]["path"]
            )
            logger.info("✓ Base de données initialisée")
            
            # 2. Serveur API
            logger.info("Initialisation du serveur API...")
            self.api_server = EzraxServerAPI(
                db_manager=self.db_manager,
                host=self.config["server"]["host"],
                port=self.config["server"]["port"],
                api_key=self.config["security"]["api_key"],
                enable_admin_api=self.config["security"]["admin_api_enabled"],
                jwt_secret=self.config["security"]["jwt_secret"]
            )
            logger.info("✓ Serveur API initialisé")
            
            # 3. Monitoring de performance
            if self.config["monitoring"]["metrics_enabled"]:
                logger.info("Initialisation du monitoring de performance...")
                self.performance_monitor = PerformanceMonitor(
                    self, 
                    self.config["monitoring"]["health_check_interval"]
                )
                logger.info("✓ Monitoring de performance initialisé")
                
            logger.info("Tous les composants ont été initialisés avec succès")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation des composants: {e}")
            raise
            
    def start_console_mode(self):
        """Démarre le serveur en mode console"""
        logger.info("Démarrage en mode console")
        
        # Démarrer les composants
        self._start_components()
        
        # Afficher les informations de démarrage
        self._display_startup_info()
        
        # Boucle principale console
        self._console_main_loop()
        
    def start_gui_mode(self):
        """Démarre le serveur en mode interface graphique"""
        logger.info("Démarrage en mode interface graphique")
        
        if not GUI_AVAILABLE:
            logger.error("Interface graphique non disponible, passage en mode console")
            self.start_console_mode()
            return
        
        try:
            import tkinter as tk
            
            # Test de l'affichage X11
            try:
                root = tk.Tk()
                root.withdraw()  # Cacher temporairement
                root.destroy()
            except tk.TclError as e:
                if "couldn't connect to display" in str(e):
                    logger.error("Impossible de se connecter au serveur X11")
                    logger.info("Solutions possibles:")
                    logger.info("1. Exporter DISPLAY: export DISPLAY=:0")
                    logger.info("2. Utiliser SSH avec X11 forwarding: ssh -X user@host")
                    logger.info("3. Utiliser le mode console: ezraxtl start")
                    raise
                    
            # Créer la fenêtre principale
            root = tk.Tk()
            
            # Démarrer les composants en arrière-plan
            self._start_components_async()
            
            # Créer l'interface graphique
            if GUI_AVAILABLE:
                self.gui_app = EzraxServerGUI(root, self.db_manager, self.api_server)
            
            # Configurer la fermeture
            root.protocol("WM_DELETE_WINDOW", self._on_gui_closing)
            
            # Démarrer la boucle GUI
            root.mainloop()
            
        except ImportError:
            logger.error("Tkinter non disponible, passage en mode console")
            self.start_console_mode()
        except Exception as e:
            logger.error(f"Erreur lors du démarrage de l'interface graphique: {e}")
            logger.info("Passage en mode console...")
            self.start_console_mode()
            
    def _start_components(self):
        """Démarre tous les composants"""
        self.running = True
        
        try:
            # Démarrer le monitoring
            if self.performance_monitor:
                self.performance_monitor.start()
                
            # Afficher les informations importantes
            self._log_security_info()
            
            # Démarrer l'API dans le thread principal
            logger.info("Démarrage du serveur API...")
            self.api_server.start()
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage des composants: {e}")
            self.stop()
            raise
            
    def _start_components_async(self):
        """Démarre les composants en mode asynchrone pour la GUI"""
        self.running = True
        
        # Démarrer le monitoring
        if self.performance_monitor:
            self.performance_monitor.start()
            
        # Démarrer l'API dans un thread séparé
        api_thread = threading.Thread(
            target=self.api_server.start,
            name="APIServer",
            daemon=True
        )
        api_thread.start()
        
        # Afficher les informations de sécurité
        self._log_security_info()
        
        logger.info("Composants démarrés en mode asynchrone")
        
    def _log_security_info(self):
        """Affiche les informations de sécurité importantes"""
        logger.info("=" * 50)
        logger.info("INFORMATIONS DE SÉCURITÉ")
        logger.info("=" * 50)
        
        api_key = self.config["security"]["api_key"]
        logger.info(f"Clé API: {api_key[:8]}...{api_key[-4:]}")
        
        if self.config["security"]["admin_api_enabled"]:
            logger.warning("API d'administration ACTIVÉE")
            logger.warning("Assurez-vous de configurer des mots de passe forts pour les admins")
        else:
            logger.info("API d'administration DÉSACTIVÉE")
            
        logger.info(f"Serveur accessible sur: http://{self.config['server']['host']}:{self.config['server']['port']}")
        logger.info("=" * 50)
        
    def _display_startup_info(self):
        """Affiche les informations de démarrage"""
        print("\n" + "=" * 60)
        print("EZRAX Central Server v2.0 - DÉMARRÉ")
        print("=" * 60)
        print(f"Serveur API: http://{self.config['server']['host']}:{self.config['server']['port']}")
        print(f"Clé API: {self.config['security']['api_key'][:8]}...")
        print(f"Admin API: {'Activé' if self.config['security']['admin_api_enabled'] else 'Désactivé'}")
        print(f"Base de données: {self.config['database']['path']}")
        print(f"Logs: {self.config['logging']['file']}")
        print("=" * 60)
        print("Commandes disponibles:")
        print("  stats    - Afficher les statistiques")
        print("  agents   - Lister les agents connectés")
        print("  alerts   - Afficher les alertes")
        print("  reload   - Recharger la configuration")
        print("  quit     - Arrêter le serveur")
        print("=" * 60)
        
    def _console_main_loop(self):
        """Boucle principale en mode console"""
        try:
            while self.running:
                try:
                    command = input("\nezrax-server> ").strip().lower()
                    
                    if command in ['quit', 'exit', 'q']:
                        break
                    elif command == 'stats':
                        self._show_stats()
                    elif command == 'agents':
                        self._show_agents()
                    elif command == 'alerts':
                        self._show_alerts()
                    elif command == 'reload':
                        self._reload_config()
                    elif command == 'help':
                        self._show_help()
                    elif command == '':
                        continue
                    else:
                        print(f"Commande inconnue: {command}. Tapez 'help' pour l'aide.")
                        
                except KeyboardInterrupt:
                    print("\nUtilisez 'quit' pour arrêter le serveur proprement.")
                except EOFError:
                    break
                    
        except Exception as e:
            logger.error(f"Erreur dans la boucle console: {e}")
        finally:
            self.stop()
            
    def _show_stats(self):
        """Affiche les statistiques du serveur"""
        try:
            print("\nSTATISTIQUES DU SERVEUR")
            print("=" * 40)
            
            # Uptime
            uptime = time.time() - self.start_time
            uptime_str = self._format_duration(uptime)
            print(f"Uptime: {uptime_str}")
            
            # Stats globales
            if self.db_manager:
                global_stats = self.db_manager.get_global_stats()
                print(f"Agents: {global_stats['total_agents']} total, {global_stats['active_agents']} actifs")
                print(f"Attaques: {global_stats['total_attacks']} total")
                print(f"IPs bloquées: {global_stats['blocked_ips']}")
                
            # Stats API
            if self.api_server:
                api_metrics = self.api_server.get_api_metrics()
                api_stats = api_metrics['api_metrics']
                print(f"Requêtes API: {api_stats['requests_total']} total, {api_stats['requests_success']} réussies")
                print(f"Temps de réponse moyen: {api_stats['avg_response_time']*1000:.0f}ms")
                
            # Stats DB
            if self.db_manager:
                db_metrics = self.db_manager.get_performance_metrics()
                print(f"Requêtes DB: {db_metrics['queries_executed']}")
                print(f"Cache hit rate: {db_metrics['query_cache']['hit_rate']:.1%}")
                
        except Exception as e:
            print(f"Erreur lors de l'affichage des statistiques: {e}")
            
    def _show_agents(self):
        """Affiche la liste des agents"""
        try:
            print("\nAGENTS CONNECTÉS")
            print("=" * 40)
            
            if self.db_manager:
                agents = self.db_manager.get_agents()
                
                if not agents:
                    print("Aucun agent enregistré")
                    return
                    
                for agent in agents:
                    status_emoji = "🟢" if agent['status'] == 'online' else "🔴"
                    print(f"{status_emoji} {agent['hostname']} ({agent['ip_address']})")
                    print(f"   ID: {agent['agent_id']}")
                    
                    if agent['last_seen']:
                        last_seen = time.time() - agent['last_seen']
                        last_seen_str = self._format_duration(last_seen)
                        print(f"   Dernière activité: il y a {last_seen_str}")
                        
                    print()
                    
        except Exception as e:
            print(f"Erreur lors de l'affichage des agents: {e}")
            
    def _show_alerts(self):
        """Affiche les alertes récentes"""
        try:
            print("\nALERTES RÉCENTES")
            print("=" * 40)
            
            if self.performance_monitor:
                alerts = self.performance_monitor.get_alerts()
                
                if not alerts:
                    print("Aucune alerte récente")
                    return
                    
                for alert in alerts[-10:]:  # 10 dernières
                    level_emoji = {"INFO": "ℹ️", "WARNING": "⚠️", "ERROR": "❌"}.get(alert['level'], "📝")
                    alert_time = time.strftime('%H:%M:%S', time.localtime(alert['timestamp']))
                    print(f"{level_emoji} [{alert_time}] {alert['message']}")
                    
        except Exception as e:
            print(f"Erreur lors de l'affichage des alertes: {e}")
            
    def _show_help(self):
        """Affiche l'aide des commandes"""
        print("\nAIDE DES COMMANDES")
        print("=" * 40)
        print("stats    - Afficher les statistiques du serveur")
        print("agents   - Lister les agents connectés")
        print("alerts   - Afficher les alertes de performance")
        print("reload   - Recharger la configuration")
        print("help     - Afficher cette aide")
        print("quit     - Arrêter le serveur proprement")
        
    def _format_duration(self, seconds: float) -> str:
        """Formate une durée en chaîne lisible"""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.0f}m {seconds%60:.0f}s"
        elif seconds < 86400:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours:.0f}h {minutes:.0f}m"
        else:
            days = seconds // 86400
            hours = (seconds % 86400) // 3600
            return f"{days:.0f}j {hours:.0f}h"
            
    def _on_gui_closing(self):
        """Gère la fermeture de l'interface graphique"""
        if self.gui_app:
            self.gui_app.on_closing()
        self.stop()
        
    def stop(self):
        """Arrête proprement le serveur"""
        if not self.running:
            return
            
        logger.info("Arrêt du serveur EZRAX...")
        self.running = False
        
        # Arrêter les composants dans l'ordre inverse
        if self.performance_monitor:
            self.performance_monitor.stop()
            
        if self.api_server:
            self.api_server.stop()
            
        if self.db_manager:
            self.db_manager.close()
            
        logger.info("Serveur EZRAX arrêté proprement")
        
    def get_status(self) -> Dict[str, Any]:
        """Retourne le statut complet du serveur"""
        status = {
            "running": self.running,
            "start_time": self.start_time,
            "uptime": time.time() - self.start_time,
            "config": {
                "host": self.config["server"]["host"],
                "port": self.config["server"]["port"],
                "admin_api": self.config["security"]["admin_api_enabled"]
            },
            "components": {
                "database": self.db_manager is not None,
                "api_server": self.api_server is not None and self.api_server.is_running,
                "gui": self.gui_app is not None,
                "monitoring": self.performance_monitor is not None
            }
        }
        
        # Ajouter les métriques si disponibles
        if self.db_manager:
            status["database_metrics"] = self.db_manager.get_performance_metrics()
            
        if self.api_server:
            status["api_metrics"] = self.api_server.get_api_metrics()
            
        return status

def parse_arguments():
    """Parse les arguments de la ligne de commande"""
    parser = argparse.ArgumentParser(description="Serveur central EZRAX IDS/IPS v2.0")
    
    parser.add_argument(
        "--config",
        help="Fichier de configuration",
        default="server_config.json"
    )
    
    parser.add_argument(
        "--host",
        help="Adresse d'écoute de l'API",
        default=None
    )
    
    parser.add_argument(
        "--port",
        help="Port d'écoute de l'API",
        type=int,
        default=None
    )
    
    parser.add_argument(
        "--no-gui",
        help="Désactiver l'interface graphique",
        action="store_true"
    )
    
    parser.add_argument(
        "--debug",
        help="Activer le mode debug",
        action="store_true"
    )
    
    parser.add_argument(
        "--api-key",
        help="Clé API personnalisée",
        default=None
    )
    
    parser.add_argument(
        "--daemon",
        help="Lancer en mode daemon (console seulement)",
        action="store_true"
    )
    
    return parser.parse_args()

def main():
    """Point d'entrée principal"""
    try:
        # Parser les arguments
        args = parse_arguments()
        
        # Créer le gestionnaire de serveur
        server_manager = EzraxServerManager(args.config)
        
        # Surcharger la config avec les arguments
        if args.host:
            server_manager.config["server"]["host"] = args.host
        if args.port:
            server_manager.config["server"]["port"] = args.port
        if args.debug:
            server_manager.config["server"]["debug"] = True
            server_manager.config["logging"]["level"] = "DEBUG"
        if args.api_key:
            server_manager.config["security"]["api_key"] = args.api_key
            
        # Reconfigurer le logging si debug
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Mode debug activé")
            
        # Initialiser les composants
        server_manager.initialize_components()
        
        # Choisir le mode de démarrage
        if args.no_gui or args.daemon:
            # Mode console/daemon
            server_manager.start_console_mode()
        else:
            # Mode interface graphique (par défaut)
            server_manager.start_gui_mode()
            
    except KeyboardInterrupt:
        logger.info("Interruption clavier reçue")
    except Exception as e:
        logger.critical(f"Erreur critique: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
