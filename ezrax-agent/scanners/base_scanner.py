#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de base pour tous les scanners de l'agent EZRAX IDS/IPS
"""

import time
import logging
import threading
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class BaseScanner(ABC):
    """Classe de base abstraite pour tous les scanners"""
    
    def __init__(self, config: Dict[str, Any], db_manager: Any, ips_manager: Any):
        """
        Initialisation du scanner
        
        Args:
            config: Configuration du scanner
            db_manager: Gestionnaire de base de données
            ips_manager: Gestionnaire IPS
        """
        self.config = config
        self.db_manager = db_manager
        self.ips_manager = ips_manager
        self.active = False
        self.thread = None
        self.stop_event = threading.Event()
        self.name = self.__class__.__name__
        
    def start(self):
        """Démarre le scanner dans un thread séparé"""
        if self.active:
            logger.warning(f"Scanner {self.name} déjà actif")
            return
        
        logger.info(f"Démarrage du scanner {self.name}")
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name=f"Thread-{self.name}")
        self.thread.daemon = True
        self.thread.start()
        self.active = True
        
    def stop(self):
        """Arrête le scanner"""
        if not self.active:
            return
            
        logger.info(f"Arrêt du scanner {self.name}")
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5.0)
        self.active = False
        
    def _run(self):
        """Boucle principale du scanner"""
        try:
            self.setup()
            while not self.stop_event.is_set():
                try:
                    self.scan_cycle()
                    # Pause entre les cycles de scan (configurable)
                    self.stop_event.wait(1.0)  # Vérifie toutes les secondes
                except Exception as e:
                    logger.error(f"Erreur dans le cycle de scan de {self.name}: {e}")
                    # Pause plus longue en cas d'erreur
                    self.stop_event.wait(5.0)
        except Exception as e:
            logger.error(f"Erreur critique dans le scanner {self.name}: {e}")
        finally:
            self.cleanup()
            
    def setup(self):
        """Configuration initiale du scanner (peut être surchargée)"""
        pass
        
    def cleanup(self):
        """Nettoyage des ressources du scanner (peut être surchargée)"""
        pass
        
    def is_ip_whitelisted(self, ip: str) -> bool:
        """
        Vérifie si une adresse IP est dans la liste blanche
        
        Args:
            ip: Adresse IP à vérifier
            
        Returns:
            True si l'IP est dans la liste blanche, False sinon
        """
        return ip in self.config["ips"]["whitelist"]
        
    def log_attack(self, attack_type: str, source_ip: str, details: Dict[str, Any]):
        """
        Enregistre une attaque détectée
        
        Args:
            attack_type: Type d'attaque (SYN_FLOOD, UDP_FLOOD, etc.)
            source_ip: Adresse IP source de l'attaque
            details: Détails supplémentaires sur l'attaque
        """
        # Enregistrement dans la base de données
        self.db_manager.add_attack_log(
            attack_type=attack_type,
            source_ip=source_ip,
            scanner=self.name,
            details=details
        )
        
        # Si l'IPS est activé et que le blocage automatique est activé
        if (self.config["ips"]["enabled"] and 
            self.config["ips"]["auto_block"] and 
            not self.is_ip_whitelisted(source_ip)):
            self.ips_manager.block_ip(
                source_ip, 
                attack_type, 
                duration=self.config["ips"]["block_duration"]
            )
            
        logger.warning(
            f"Attaque {attack_type} détectée depuis {source_ip}: {details}"
        )
        
    @abstractmethod
    def scan_cycle(self):
        """Méthode à implémenter pour chaque scanner"""
        pass
