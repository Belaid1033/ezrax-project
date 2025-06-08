#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Point d'entrée de l'agent EZRAX IDS/IPS
"""

import os
import sys
import time
import signal
import logging
import threading
import traceback


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)


from config import CONFIG, setup_logging, ensure_directories, AGENT_ID, AGENT_HOSTNAME
from storage import DatabaseManager, LogManager
from ips import IptablesManager
from scanners import initialize_scanners
from reporting import ReportGenerator
from communication import CentralClient


setup_logging()
logger = logging.getLogger(__name__)

class SimpleEzraxAgent:
    """Agent EZRAX simplifié avec initialisation séquentielle"""
    
    def __init__(self):
        self.config = CONFIG
        self.running = False
        self.components = {}
        
        # S'assurer que les répertoires nécessaires existent
        ensure_directories()
        
        logger.info(f"Démarrage de l'agent EZRAX v2.0 (ID: {AGENT_ID})")
        self._initialize_components()
        
    def _initialize_components(self):
        """Initialise les composants de manière séquentielle"""
        logger.info("Initialisation des composants...")
        
        try:
            # 1. Base de données
            logger.info("Initialisation de la base de données...")
            self.components["database"] = DatabaseManager(self.config)
            logger.info("✓ Base de données initialisée")
            
            # 2. Gestionnaire de logs
            logger.info("Initialisation du gestionnaire de logs...")
            self.components["log_manager"] = LogManager(self.config, self.components["database"])
            logger.info("✓ Gestionnaire de logs initialisé")
            
            # 3. Gestionnaire IPS
            logger.info("Initialisation du gestionnaire IPS...")
            self.components["ips_manager"] = IptablesManager(self.config, self.components["database"])
            logger.info("✓ Gestionnaire IPS initialisé")
            
            # 4. Scanners
            logger.info("Initialisation des scanners...")
            self.components["scanners"] = initialize_scanners(
                self.config, 
                self.components["database"], 
                self.components["ips_manager"]
            )
            logger.info(f"✓ {len(self.components['scanners'])} scanners initialisés")
            
            # 5. Générateur de rapports
            if self.config["reporting"]["enabled"]:
                logger.info("Initialisation du générateur de rapports...")
                self.components["report_generator"] = ReportGenerator(
                    self.config, 
                    self.components["database"], 
                    self.components["log_manager"]
                )
                logger.info("✓ Générateur de rapports initialisé")
            
            # 6. Client central
            logger.info("Initialisation du client central...")
            self.components["central_client"] = CentralClient(
                self.config, 
                self.components["database"], 
                self.components["ips_manager"]
            )
            logger.info("✓ Client central initialisé")
            
            logger.info(f"Initialisation terminée - {len(self.components)} composants chargés")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation: {e}")
            logger.error(traceback.format_exc())
            raise
            
    def start(self):
        """Démarre l'agent"""
        if self.running:
            return
            
        try:
            logger.info("=== Démarrage de l'agent EZRAX ===")
            
            # Configurer les gestionnaires de signaux
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            # Démarrer les scanners
            scanners_started = 0
            for scanner in self.components.get("scanners", []):
                try:
                    scanner.start()
                    scanners_started += 1
                    logger.info(f"Scanner {scanner.__class__.__name__} démarré")
                except Exception as e:
                    logger.error(f"Erreur lors du démarrage du scanner {scanner.__class__.__name__}: {e}")
                    
            logger.info(f"Agent démarré avec {scanners_started} scanners actifs")
            
            # Enregistrer l'agent auprès du serveur central
            if "central_client" in self.components:
                try:
                    self.components["central_client"].register_agent()
                    logger.info("Agent enregistré auprès du serveur central")
                except Exception as e:
                    logger.warning(f"Erreur lors de l'enregistrement central: {e}")
                    
            self.running = True
            
            # Boucle principale simple
            self._main_loop()
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage: {e}")
            self.stop()
            
    def _main_loop(self):
        """Boucle principale simplifiée"""
        logger.info("Boucle principale démarrée")
        
        while self.running:
            try:
                # Pause
                time.sleep(30)
                
                # Maintenance basique
                if "database" in self.components:
                    self.components["database"].cleanup_old_data()
                    
                # Heartbeat
                if "central_client" in self.components:
                    self.components["central_client"].send_heartbeat()
                    
            except Exception as e:
                logger.error(f"Erreur dans la boucle principale: {e}")
                time.sleep(10)
                
    def stop(self):
        """Arrête l'agent"""
        if not self.running:
            return
            
        logger.info("=== Arrêt de l'agent EZRAX ===")
        self.running = False
        
        # Arrêter les scanners
        for scanner in self.components.get("scanners", []):
            try:
                scanner.stop()
                logger.info(f"Scanner {scanner.__class__.__name__} arrêté")
            except Exception as e:
                logger.error(f"Erreur lors de l'arrêt du scanner: {e}")
                
        # Arrêter les autres composants
        for name in ["central_client", "report_generator", "ips_manager", "log_manager", "database"]:
            if name in self.components:
                try:
                    component = self.components[name]
                    if hasattr(component, 'shutdown'):
                        component.shutdown()
                    elif hasattr(component, 'close'):
                        component.close()
                    logger.info(f"Composant {name} arrêté")
                except Exception as e:
                    logger.error(f"Erreur lors de l'arrêt de {name}: {e}")
                    
    def _signal_handler(self, sig, frame):
        """Gestionnaire de signaux"""
        logger.info(f"Signal {sig} reçu, arrêt gracieux...")
        self.stop()
        sys.exit(0)

def main():
    """Point d'entrée principal"""
    try:
        agent = SimpleEzraxAgent()
        agent.start()
    except KeyboardInterrupt:
        logger.info("Interruption clavier reçue")
    except Exception as e:
        logger.critical(f"Erreur critique: {e}")
        logger.critical(traceback.format_exc())
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
