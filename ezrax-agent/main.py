#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Point d'entrée principal de l'agent EZRAX IDS/IPS
"""

import os
import sys
import time
import signal
import logging
import argparse
from typing import List, Dict, Any

# Chemin absolu du répertoire de l'agent
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Importation des modules
from config import CONFIG, setup_logging, ensure_directories, AGENT_ID, AGENT_HOSTNAME
from storage import DatabaseManager, LogManager
from ips import IptablesManager
from scanners import initialize_scanners
from reporting import ReportGenerator
from communication import CentralClient

# Configuration du logging
setup_logging()
logger = logging.getLogger(__name__)

class EzraxAgent:
    """
    Classe principale de l'agent EZRAX IDS/IPS
    """
    
    def __init__(self):
        """Initialisation de l'agent"""
        self.config = CONFIG
        self.running = False
        self.scanners = []
        
        # S'assurer que les répertoires nécessaires existent
        ensure_directories()
        
        # Initialiser les composants
        try:
            # Base de données
            self.db_manager = DatabaseManager(self.config)
            
            # Enregistrer l'heure de démarrage
            self.db_manager.set_agent_state("start_time", time.time())
            
            # Gestionnaire IPS
            self.ips_manager = IptablesManager(self.config, self.db_manager)
            
            # Gestionnaire de logs
            self.log_manager = LogManager(self.config, self.db_manager)
            
            # Scanners
            self.scanners = initialize_scanners(self.config, self.db_manager, self.ips_manager)
            
            # Générateur de rapports
            self.report_generator = ReportGenerator(self.config, self.db_manager, self.log_manager)
            
            # Client de communication
            self.central_client = CentralClient(self.config, self.db_manager, self.ips_manager)
            
            logger.info(f"Agent EZRAX initialisé (ID: {AGENT_ID}, Hostname: {AGENT_HOSTNAME})")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation de l'agent: {e}")
            sys.exit(1)
            
    def start(self):
        """Démarre l'agent"""
        if self.running:
            logger.warning("L'agent est déjà en cours d'exécution")
            return
            
        try:
            logger.info("Démarrage de l'agent EZRAX...")
            
            # Configurer les gestionnaires de signaux
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            # Démarrer les scanners
            for scanner in self.scanners:
                scanner.start()
                
            logger.info(f"Agent démarré avec {len(self.scanners)} scanners actifs")
            
            # Enregistrer l'agent auprès du serveur central
            self.central_client.register_agent()
            
            # Générer un rapport initial
            if self.config["reporting"]["enabled"]:
                self.report_generator.generate_report()
                
            self.running = True
            
            # Boucle principale
            while self.running:
                try:
                    # Nettoyer les anciennes données
                    self.db_manager.cleanup_old_data()
                    
                    # Synchroniser avec le serveur central
                    self.central_client.send_heartbeat()
                    
                    # Pause
                    time.sleep(10)  # 10 secondes
                    
                except Exception as e:
                    logger.error(f"Erreur dans la boucle principale: {e}")
                    time.sleep(30)  # Pause plus longue en cas d'erreur
                    
        except Exception as e:
            logger.error(f"Erreur lors du démarrage de l'agent: {e}")
            self.stop()
            
    def stop(self):
        """Arrête l'agent"""
        if not self.running:
            return
            
        logger.info("Arrêt de l'agent EZRAX...")
        self.running = False
        
        # Arrêter les scanners
        for scanner in self.scanners:
            try:
                scanner.stop()
            except Exception as e:
                logger.error(f"Erreur lors de l'arrêt du scanner {scanner.name}: {e}")
                
        # Arrêter les autres composants
        try:
            if hasattr(self, "central_client"):
                self.central_client.shutdown()
                
            if hasattr(self, "report_generator"):
                self.report_generator.shutdown()
                
            if hasattr(self, "ips_manager"):
                self.ips_manager.shutdown()
                
            if hasattr(self, "db_manager"):
                self.db_manager.close()
                
        except Exception as e:
            logger.error(f"Erreur lors de l'arrêt des composants: {e}")
            
        logger.info("Agent EZRAX arrêté")
        
    def _signal_handler(self, sig, frame):
        """
        Gestionnaire de signaux
        
        Args:
            sig: Signal reçu
            frame: Frame d'exécution
        """
        logger.info(f"Signal reçu: {sig}")
        self.stop()
        sys.exit(0)
        
def parse_arguments():
    """
    Parse les arguments de la ligne de commande
    
    Returns:
        Arguments parsés
    """
    parser = argparse.ArgumentParser(description="Agent EZRAX IDS/IPS")
    
    parser.add_argument(
        "--config",
        help="Chemin vers le fichier de configuration",
        default=os.path.join(BASE_DIR, "agent_config.yaml")
    )
    
    parser.add_argument(
        "--no-ips",
        help="Désactiver la fonctionnalité IPS",
        action="store_true"
    )
    
    parser.add_argument(
        "--no-central",
        help="Désactiver la communication avec le serveur central",
        action="store_true"
    )
    
    parser.add_argument(
        "--debug",
        help="Activer le mode debug",
        action="store_true"
    )
    
    return parser.parse_args()
    
def main():
    """Point d'entrée principal"""
    # Parser les arguments
    args = parse_arguments()
    
    # Configuration du mode debug
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        
    # Modification de la configuration
    if args.no_ips:
        CONFIG["ips"]["enabled"] = False
        
    if args.no_central:
        CONFIG["central_server"]["enabled"] = False
        
    # Créer et démarrer l'agent
    agent = EzraxAgent()
    
    try:
        agent.start()
    except KeyboardInterrupt:
        logger.info("Interruption clavier reçue, arrêt de l'agent...")
    finally:
        agent.stop()
        
if __name__ == "__main__":
    main()
