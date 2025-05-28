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
import tkinter as tk
from typing import List, Dict, Any

# Configuration du logging
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
from gui_app import EzraxServerGUI

def run_grafana_docker():
    """
    Démarre Grafana dans un conteneur Docker
    
    Returns:
        True si le démarrage a réussi, False sinon
    """
    try:
        # Vérifier si Docker est installé
        subprocess.run(["docker", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Vérifier si le conteneur Grafana existe déjà
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=ezrax-grafana", "--format", "{{.Names}}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        container_exists = "ezrax-grafana" in result.stdout.decode()
        
        if container_exists:
            # Démarrer le conteneur existant
            logger.info("Démarrage du conteneur Grafana existant...")
            subprocess.run(["docker", "start", "ezrax-grafana"], check=True)
        else:
            # Créer et démarrer un nouveau conteneur
            logger.info("Création d'un nouveau conteneur Grafana...")
            
            # Créer le répertoire pour les données Grafana
            os.makedirs("./grafana_data", exist_ok=True)
            
            # Créer le conteneur
            subprocess.run([
                "docker", "run", "-d",
                "--name", "ezrax-grafana",
                "-p", "3000:3000",
                "-v", f"{os.path.abspath('./grafana_data')}:/var/lib/grafana",
                "-e", "GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource",
                "grafana/grafana-oss:10.1.4"
            ], check=True)
            
        # Attendre que Grafana soit prêt
        logger.info("Attente du démarrage de Grafana...")
        time.sleep(5)
        
        # Ouvrir Grafana dans le navigateur
        webbrowser.open("http://localhost:3000")
        
        logger.info("Grafana démarré avec succès")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur lors du démarrage de Grafana: {e}")
        return False
    except Exception as e:
        logger.error(f"Erreur lors du démarrage de Grafana: {e}")
        return False
        
def parse_arguments():
    """
    Parse les arguments de la ligne de commande
    
    Returns:
        Arguments parsés
    """
    parser = argparse.ArgumentParser(description="Serveur central EZRAX IDS/IPS")
    
    parser.add_argument(
        "--host",
        help="Adresse d'écoute de l'API",
        default="0.0.0.0"
    )
    
    parser.add_argument(
        "--port",
        help="Port d'écoute de l'API",
        type=int,
        default=5000
    )
    
    parser.add_argument(
        "--db-path",
        help="Chemin de la base de données",
        default="ezrax_server.db"
    )
    
    parser.add_argument(
        "--api-key",
        help="Clé API pour l'authentification"
    )
    
    parser.add_argument(
        "--grafana",
        help="Démarrer Grafana dans Docker",
        action="store_true"
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
    
    return parser.parse_args()
    
def main():
    """Point d'entrée principal"""
    # Parser les arguments
    args = parse_arguments()
    
    # Configuration du mode debug
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        
    # Initialiser la base de données
    db_manager = ServerDatabaseManager(args.db_path)
    
    # Démarrer Grafana si demandé
    if args.grafana:
        run_grafana_docker()
        
    # Mode avec ou sans interface graphique
    if args.no_gui:
        # Mode sans interface graphique
        logger.info("Démarrage en mode console (sans GUI)")
        
        # Créer et démarrer l'API
        server_api = EzraxServerAPI(db_manager, args.host, args.port, args.api_key)
        
        # Configurer les gestionnaires de signaux
        def signal_handler(sig, frame):
            """Gestionnaire de signaux"""
            logger.info(f"Signal reçu: {sig}")
            server_api.stop()
            sys.exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Démarrer l'API
        try:
            server_api.start()
        except KeyboardInterrupt:
            logger.info("Interruption clavier reçue, arrêt du serveur...")
        finally:
            server_api.stop()
            
    else:
        # Mode avec interface graphique
        logger.info("Démarrage de l'interface graphique")
        
        # Créer la fenêtre principale
        root = tk.Tk()
        app = EzraxServerGUI(root)
        
        # Démarrer la boucle principale
        root.mainloop()
        
if __name__ == "__main__":
    main()
