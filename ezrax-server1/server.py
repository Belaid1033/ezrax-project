#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Point d'entrée principal du serveur central EZRAX
"""

import os
import sys
import time
import signal
import logging
import argparse
import subprocess
import webbrowser
import threading
import atexit
from typing import Dict, List, Any, Optional

# Ajouter le répertoire du serveur au PYTHONPATH
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Imports des modules (corrigés)
try:
    from config import (
        load_server_config, 
        setup_server_logging, 
        save_server_config_template,
        create_example_agent_config,
        get_server_info
    )
    from db_manager import ServerDatabaseManager
    from server_api import EzraxServerAPI
except ImportError as e:
    print(f"Erreur d'importation: {e}")
    print("Assurez-vous que tous les fichiers du serveur sont présents")
    sys.exit(1)

logger = logging.getLogger(__name__)

class EzraxServerManager:
    """Gestionnaire principal du serveur EZRAX amélioré"""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialisation du gestionnaire de serveur
        
        Args:
            config: Configuration du serveur
        """
        self.config = config
        self.running = False
        self.db_manager = None
        self.api_server = None
        self.grafana_container_id = None
        
        # Composants du serveur
        self.components = {}
        
        # Gestionnaires de signaux
        self.setup_signal_handlers()
        
        # Enregistrer le nettoyage à la sortie
        atexit.register(self.cleanup)
        
    def setup_signal_handlers(self):
        """Configure les gestionnaires de signaux"""
        def signal_handler(sig, frame):
            logger.info(f"Signal {sig} reçu, arrêt propre du serveur...")
            self.stop()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Sur Windows, gérer aussi SIGBREAK
        if hasattr(signal, 'SIGBREAK'):
            signal.signal(signal.SIGBREAK, signal_handler)
            
    def initialize_components(self):
        """Initialise tous les composants du serveur"""
        try:
            logger.info("=== Initialisation du serveur EZRAX ===")
            
            # 1. Base de données
            logger.info("Initialisation de la base de données...")
            self.db_manager = ServerDatabaseManager(self.config["database"]["path"])
            self.components["database"] = self.db_manager
            logger.info("✓ Base de données initialisée")
            
            # 2. API Server
            logger.info("Initialisation de l'API serveur...")
            self.api_server = EzraxServerAPI(
                self.db_manager,
                host=self.config["api"]["host"],
                port=self.config["api"]["port"],
                debug=self.config.get("debug", False)
            )
            self.components["api"] = self.api_server
            logger.info("✓ API serveur initialisée")
            
            # 3. Afficher les informations de connexion
            api_key = self.api_server.get_api_key()
            logger.info(f"Serveur configuré sur: {self.config['api']['host']}:{self.config['api']['port']}")
            logger.info(f"Clé API principale: {api_key}")
            
            # 4. Créer la configuration d'exemple pour les agents
            try:
                create_example_agent_config(self.config, "agent_config.example.yaml")
                logger.info("✓ Configuration d'exemple pour agents créée")
            except Exception as e:
                logger.warning(f"Impossible de créer la config agent: {e}")
            
            logger.info(f"Serveur initialisé avec {len(self.components)} composants")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation: {e}")
            return False
            
    def start(self):
        """Démarre le serveur complet"""
        if self.running:
            logger.warning("Le serveur est déjà en cours d'exécution")
            return
            
        try:
            # Initialiser les composants
            if not self.initialize_components():
                logger.error("Échec de l'initialisation des composants")
                return False
                
            self.running = True
            
            # Démarrer l'API serveur dans un thread séparé
            api_thread = threading.Thread(
                target=self.api_server.start,
                name="APIServerThread",
                daemon=True
            )
            api_thread.start()
            
            # Attendre un peu pour s'assurer que l'API a démarré
            time.sleep(2)
            
            if not self.api_server.is_running:
                logger.error("L'API serveur n'a pas pu démarrer")
                return False
                
            logger.info("=== Serveur EZRAX démarré avec succès ===")
            self.display_startup_info()
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage: {e}")
            self.running = False
            return False
            
    def display_startup_info(self):
        """Affiche les informations de démarrage"""
        try:
            info = get_server_info(self.config)
            
            print("\n" + "="*60)
            print("🛡️  SERVEUR EZRAX IDS/IPS DÉMARRÉ")
            print("="*60)
            print(f"Version: {info['version']}")
            print(f"API: http://{info['api']['host']}:{info['api']['port']}")
            print(f"SSL: {'Activé' if info['api']['ssl_enabled'] else 'Désactivé'}")
            print(f"Agents maximum: {info['agents']['max_agents']}")
            
            if info['grafana']['enabled']:
                print(f"Grafana: http://localhost:{info['grafana']['port']}")
                
            print(f"Mode debug: {'Activé' if info['debug_mode'] else 'Désactivé'}")
            print("\n📋 INFORMATIONS DE CONNEXION POUR LES AGENTS:")
            print(f"Host: {self.config['api']['host']}:{self.config['api']['port']}")
            print(f"Clé API: {self.api_server.get_api_key()}")
            print("\n📁 Fichiers générés:")
            print("- agent_config.example.yaml (configuration pour les agents)")
            print("- server_config.template.yaml (template de configuration)")
            print("\n🔧 Commandes utiles:")
            print("- Ctrl+C pour arrêter le serveur")
            print("- Consultez les logs dans ./logs/ezrax_server.log")
            print("="*60 + "\n")
            
        except Exception as e:
            logger.error(f"Erreur affichage infos: {e}")
            
    def start_grafana(self) -> bool:
        """Démarre Grafana dans un conteneur Docker"""
        if not self.config["grafana"]["enabled"]:
            logger.info("Grafana désactivé dans la configuration")
            return False
            
        try:
            logger.info("Démarrage de Grafana...")
            
            # Vérifier si Docker est disponible
            result = subprocess.run(
                ["docker", "--version"], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                logger.error("Docker n'est pas installé ou disponible")
                return False
                
            # Vérifier si le conteneur existe déjà
            result = subprocess.run(
                ["docker", "ps", "-a", "--filter", "name=ezrax-grafana", "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            container_exists = "ezrax-grafana" in result.stdout
            
            if container_exists:
                # Démarrer le conteneur existant
                logger.info("Démarrage du conteneur Grafana existant...")
                result = subprocess.run(
                    ["docker", "start", "ezrax-grafana"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0:
                    self.grafana_container_id = "ezrax-grafana"
                    logger.info("Grafana démarré avec succès")
                else:
                    logger.error(f"Erreur démarrage Grafana: {result.stderr}")
                    return False
            else:
                # Créer un nouveau conteneur
                logger.info("Création d'un nouveau conteneur Grafana...")
                
                # Créer le répertoire de données
                grafana_data_dir = os.path.join(BASE_DIR, "grafana_data")
                os.makedirs(grafana_data_dir, exist_ok=True)
                
                # Créer le conteneur
                grafana_port = self.config["grafana"]["port"]
                grafana_image = self.config["grafana"]["docker_image"]
                plugins = ",".join(self.config["grafana"]["plugins"])
                
                docker_cmd = [
                    "docker", "run", "-d",
                    "--name", "ezrax-grafana",
                    "-p", f"{grafana_port}:3000",
                    "-v", f"{grafana_data_dir}:/var/lib/grafana",
                    "-e", f"GF_INSTALL_PLUGINS={plugins}",
                    "-e", "GF_SECURITY_ADMIN_PASSWORD=ezrax123",
                    grafana_image
                ]
                
                result = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    self.grafana_container_id = result.stdout.strip()
                    logger.info("Conteneur Grafana créé avec succès")
                else:
                    logger.error(f"Erreur création Grafana: {result.stderr}")
                    return False
            
            # Attendre que Grafana soit prêt
            logger.info("Attente du démarrage de Grafana...")
            time.sleep(10)
            
            # Ouvrir Grafana dans le navigateur si demandé
            if self.config["grafana"].get("auto_start", True):
                try:
                    grafana_url = f"http://localhost:{self.config['grafana']['port']}"
                    webbrowser.open(grafana_url)
                    logger.info(f"Grafana ouvert dans le navigateur: {grafana_url}")
                except Exception as e:
                    logger.warning(f"Impossible d'ouvrir le navigateur: {e}")
            
            return True
            
        except subprocess.TimeoutExpired:
            logger.error("Timeout lors du démarrage de Grafana")
            return False
        except Exception as e:
            logger.error(f"Erreur lors du démarrage de Grafana: {e}")
            return False
            
    def stop_grafana(self):
        """Arrête le conteneur Grafana"""
        if not self.grafana_container_id:
            return
            
        try:
            logger.info("Arrêt de Grafana...")
            subprocess.run(
                ["docker", "stop", self.grafana_container_id],
                capture_output=True,
                timeout=30
            )
            logger.info("Grafana arrêté")
        except Exception as e:
            logger.warning(f"Erreur arrêt Grafana: {e}")
            
    def stop(self):
        """Arrête le serveur proprement"""
        if not self.running:
            return
            
        logger.info("=== Arrêt du serveur EZRAX ===")
        self.running = False
        
        # Arrêter l'API serveur
        if self.api_server:
            try:
                self.api_server.stop()
                logger.info("API serveur arrêtée")
            except Exception as e:
                logger.error(f"Erreur arrêt API: {e}")
        
        # Arrêter la base de données
        if self.db_manager:
            try:
                self.db_manager.close()
                logger.info("Base de données fermée")
            except Exception as e:
                logger.error(f"Erreur fermeture DB: {e}")
        
        # Arrêter Grafana
        self.stop_grafana()
        
        logger.info("Serveur arrêté proprement")
        
    def cleanup(self):
        """Nettoyage final à la sortie"""
        if self.running:
            self.stop()
            
    def get_status(self) -> Dict[str, Any]:
        """Retourne le statut du serveur"""
        status = {
            "running": self.running,
            "components": {},
            "api_server": {
                "running": self.api_server.is_running if self.api_server else False,
                "host": self.config["api"]["host"],
                "port": self.config["api"]["port"]
            }
        }
        
        if self.db_manager:
            try:
                status["database"] = self.db_manager.get_performance_metrics()
            except:
                status["database"] = {"status": "error"}
                
        if self.api_server:
            try:
                status["api_stats"] = self.api_server.get_server_stats()
            except:
                status["api_stats"] = {"status": "error"}
                
        return status

def run_grafana_only(config: Dict[str, Any]) -> bool:
    """Lance uniquement Grafana (mode standalone)"""
    server_manager = EzraxServerManager(config)
    return server_manager.start_grafana()

def parse_arguments():
    """Parse les arguments de la ligne de commande"""
    parser = argparse.ArgumentParser(
        description="Serveur central EZRAX IDS/IPS amélioré",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  %(prog)s                          # Démarrage normal
  %(prog)s --config custom.yaml     # Avec configuration personnalisée
  %(prog)s --grafana-only           # Lancer uniquement Grafana
  %(prog)s --create-template        # Créer template de configuration
  %(prog)s --debug                  # Mode debug
        """
    )
    
    parser.add_argument(
        "--config", "-c",
        help="Fichier de configuration YAML",
        default="server_config.yaml"
    )
    
    parser.add_argument(
        "--host",
        help="Adresse d'écoute de l'API (surcharge la config)",
        default=None
    )
    
    parser.add_argument(
        "--port", "-p",
        help="Port d'écoute de l'API (surcharge la config)",
        type=int,
        default=None
    )
    
    parser.add_argument(
        "--api-key",
        help="Clé API (surcharge la config)",
        default=None
    )
    
    parser.add_argument(
        "--grafana", "-g",
        help="Démarrer Grafana automatiquement",
        action="store_true"
    )
    
    parser.add_argument(
        "--grafana-only",
        help="Démarrer uniquement Grafana",
        action="store_true"
    )
    
    parser.add_argument(
        "--no-grafana",
        help="Ne pas démarrer Grafana",
        action="store_true"
    )
    
    parser.add_argument(
        "--create-template",
        help="Créer un template de configuration et quitter",
        action="store_true"
    )
    
    parser.add_argument(
        "--debug", "-d",
        help="Activer le mode debug",
        action="store_true"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        help="Mode verbeux",
        action="store_true"
    )
    
    parser.add_argument(
        "--log-level",
        help="Niveau de log",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default=None
    )
    
    return parser.parse_args()

def main():
    """Point d'entrée principal"""
    try:
        # Parser les arguments
        args = parse_arguments()
        
        # Créer template si demandé
        if args.create_template:
            save_server_config_template("server_config.template.yaml")
            print("Template de configuration créé: server_config.template.yaml")
            return 0
        
        # Charger la configuration
        try:
            config = load_server_config(args.config)
        except Exception as e:
            print(f"Erreur de configuration: {e}")
            print("Utilisez --create-template pour créer un template")
            return 1
        
        # Surcharger avec les arguments de ligne de commande
        if args.host:
            config["api"]["host"] = args.host
        if args.port:
            config["api"]["port"] = args.port
        if args.api_key:
            config["api"]["key"] = args.api_key
        if args.debug:
            config["debug"] = True
        if args.log_level:
            config["logging"]["level"] = args.log_level
        if args.verbose:
            config["logging"]["level"] = "DEBUG"
        if args.no_grafana:
            config["grafana"]["enabled"] = False
        elif args.grafana:
            config["grafana"]["enabled"] = True
        
        # Configurer le logging
        setup_server_logging(config)
        
        # Mode Grafana uniquement
        if args.grafana_only:
            logger.info("Démarrage de Grafana en mode standalone...")
            success = run_grafana_only(config)
            if success:
                print(f"Grafana démarré sur http://localhost:{config['grafana']['port']}")
                print("Appuyez sur Ctrl+C pour arrêter...")
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\nArrêt de Grafana...")
            return 0 if success else 1
        
        # Démarrage normal du serveur
        server_manager = EzraxServerManager(config)
        
        # Démarrer le serveur
        if not server_manager.start():
            logger.error("Échec du démarrage du serveur")
            return 1
        
        # Démarrer Grafana si configuré
        if config["grafana"]["enabled"]:
            server_manager.start_grafana()
        
        # Boucle principale
        try:
            logger.info("Serveur en fonctionnement. Appuyez sur Ctrl+C pour arrêter...")
            while server_manager.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Interruption clavier reçue")
        finally:
            server_manager.stop()
            
        return 0
        
    except Exception as e:
        logger.critical(f"Erreur critique: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
