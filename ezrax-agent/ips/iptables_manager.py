#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gestionnaire IPS utilisant iptables pour bloquer les adresses IP malveillantes
"""

import os
import time
import logging
import threading
import subprocess
import re
from typing import Dict, List, Tuple, Any, Optional

logger = logging.getLogger(__name__)

class IptablesManager:
    """
    Gestionnaire IPS utilisant iptables pour bloquer les adresses IP malveillantes
    """
    
    def __init__(self, config, db_manager):
        """
        Initialisation du gestionnaire IPS
        
        Args:
            config: Configuration de l'agent
            db_manager: Gestionnaire de base de données
        """
        self.config = config
        self.db_manager = db_manager
        self.enabled = config["ips"]["enabled"]
        self.block_duration = config["ips"]["block_duration"]
        self.whitelist = set(config["ips"]["whitelist"])
        
        # Liste des IPs bloquées et leurs timestamps
        self.blocked_ips = {}  # {ip: (timestamp, reason)}
        self.lock = threading.Lock()
        
        # Nom de la chaîne iptables
        self.chain_name = "EZRAX_IPS"
        
        if self.enabled:
            # Initialiser iptables
            self._setup_iptables()
            
            # Démarrer le thread de nettoyage
            self.stop_event = threading.Event()
            self.cleanup_thread = threading.Thread(
                target=self._cleanup_thread, 
                name="IptablesCleanupThread"
            )
            self.cleanup_thread.daemon = True
            self.cleanup_thread.start()
            
    def _setup_iptables(self):
        """Configure la chaîne iptables personnalisée"""
        try:
            # Vérifier si la chaîne existe déjà
            check_cmd = ["sudo", "iptables", "-L", self.chain_name, "-n"]
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            
            # Si la chaîne n'existe pas, la créer
            if result.returncode != 0:
                # Créer la chaîne
                create_cmd = ["sudo", "iptables", "-N", self.chain_name]
                subprocess.run(create_cmd, check=True)
                
                # Ajouter la chaîne à INPUT
                insert_cmd = ["sudo", "iptables", "-I", "INPUT", "-j", self.chain_name]
                subprocess.run(insert_cmd, check=True)
                
                logger.info(f"Chaîne iptables {self.chain_name} créée et configurée")
            else:
                logger.info(f"Chaîne iptables {self.chain_name} déjà configurée")
                
            # Récupérer les règles existantes
            self._load_existing_rules()
            
        except Exception as e:
            logger.error(f"Erreur lors de la configuration d'iptables: {e}")
            self.enabled = False
            
    def _load_existing_rules(self):
        """Charge les règles iptables existantes dans la chaîne EZRAX_IPS"""
        try:
            # Récupérer les règles existantes
            list_cmd = ["sudo", "iptables", "-L", self.chain_name, "-n"]
            result = subprocess.run(list_cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Analyser la sortie pour extraire les IPs bloquées
                lines = result.stdout.strip().split('\n')
                
                # Skip header lines
                rules = lines[2:] if len(lines) > 2 else []
                
                current_time = time.time()
                
                for rule in rules:
                    # Parse the rule to get the IP
                    match = re.search(r"DROP\s+all\s+--\s+(\d+\.\d+\.\d+\.\d+)", rule)
                    if match:
                        ip = match.group(1)
                        # Ajouter à notre liste d'IPs bloquées avec un timestamp approximatif
                        # (considérant qu'elles ont été ajoutées récemment)
                        # Le reason est inconnu, donc on met "IMPORTED_RULE"
                        self.blocked_ips[ip] = (current_time, "IMPORTED_RULE")
                        
                logger.info(f"Chargement de {len(self.blocked_ips)} règles iptables existantes")
                
        except Exception as e:
            logger.error(f"Erreur lors du chargement des règles iptables: {e}")
            
    def block_ip(self, ip: str, reason: str, duration: Optional[int] = None):
        """
        Bloque une adresse IP avec iptables
        
        Args:
            ip: Adresse IP à bloquer
            reason: Raison du blocage
            duration: Durée du blocage en secondes (utilise la valeur par défaut si None)
        """
        if not self.enabled:
            logger.warning(f"IPS désactivé, impossible de bloquer {ip}")
            return False
            
        if ip in self.whitelist:
            logger.info(f"L'IP {ip} est dans la liste blanche, pas de blocage")
            return False
            
        # Vérifier si l'adresse IP est déjà bloquée
        with self.lock:
            if ip in self.blocked_ips:
                logger.info(f"L'IP {ip} est déjà bloquée")
                return True
                
            # Utiliser la durée par défaut si non spécifiée
            if duration is None:
                duration = self.block_duration
                
            try:
                # Ajouter la règle iptables
                block_cmd = [
                    "sudo", "iptables", "-I", self.chain_name, "-s", ip, "-j", "DROP"
                ]
                subprocess.run(block_cmd, check=True)
                
                # Enregistrer le timestamp et la raison
                timestamp = time.time()
                self.blocked_ips[ip] = (timestamp, reason)
                
                # Enregistrer dans la base de données
                self.db_manager.add_blocked_ip(
                    ip=ip,
                    reason=reason,
                    timestamp=timestamp,
                    duration=duration
                )
                
                logger.info(f"IP {ip} bloquée pour {duration} secondes. Raison: {reason}")
                return True
                
            except Exception as e:
                logger.error(f"Erreur lors du blocage de l'IP {ip}: {e}")
                return False
                
    def unblock_ip(self, ip: str):
        """
        Débloque une adresse IP
        
        Args:
            ip: Adresse IP à débloquer
            
        Returns:
            True si l'opération a réussi, False sinon
        """
        if not self.enabled:
            return False
            
        with self.lock:
            if ip not in self.blocked_ips:
                return False
                
            try:
                # Supprimer la règle iptables
                unblock_cmd = [
                    "sudo", "iptables", "-D", self.chain_name, "-s", ip, "-j", "DROP"
                ]
                subprocess.run(unblock_cmd, check=True)
                
                # Mettre à jour la base de données
                self.db_manager.update_block_end_time(ip)
                
                # Supprimer de la liste des IPs bloquées
                del self.blocked_ips[ip]
                
                logger.info(f"IP {ip} débloquée")
                return True
                
            except Exception as e:
                logger.error(f"Erreur lors du déblocage de l'IP {ip}: {e}")
                return False
                
    def _cleanup_thread(self):
        """Thread pour nettoyer les règles iptables expirées"""
        while not self.stop_event.is_set():
            try:
                self._cleanup_expired_rules()
            except Exception as e:
                logger.error(f"Erreur dans le thread de nettoyage: {e}")
                
            # Vérifier toutes les 10 secondes
            self.stop_event.wait(10)
            
    def _cleanup_expired_rules(self):
        """Supprime les règles iptables expirées"""
        current_time = time.time()
        
        with self.lock:
            # Liste des IPs à débloquer
            ips_to_unblock = []
            
            for ip, (timestamp, _) in self.blocked_ips.items():
                # Vérifier si la règle a expiré
                if current_time - timestamp >= self.block_duration:
                    ips_to_unblock.append(ip)
                    
            # Débloquer les IPs expirées
            for ip in ips_to_unblock:
                self.unblock_ip(ip)
                
    def update_whitelist(self, new_whitelist: List[str]):
        """
        Met à jour la liste blanche des IPs
        
        Args:
            new_whitelist: Nouvelle liste blanche
        """
        with self.lock:
            old_whitelist = self.whitelist
            self.whitelist = set(new_whitelist)
            
            # Débloquer les IPs qui sont maintenant dans la liste blanche
            for ip in self.whitelist:
                if ip in self.blocked_ips:
                    self.unblock_ip(ip)
                    
            logger.info(f"Liste blanche mise à jour: {len(self.whitelist)} entrées")
            
    def get_blocked_ips(self):
        """
        Renvoie la liste des IPs actuellement bloquées
        
        Returns:
            Liste des IPs bloquées avec leur timestamp et raison
        """
        with self.lock:
            return {ip: (timestamp, reason) for ip, (timestamp, reason) in self.blocked_ips.items()}
            
    def shutdown(self):
        """Arrête proprement le gestionnaire IPS"""
        if self.enabled:
            logger.info("Arrêt du gestionnaire IPS")
            self.stop_event.set()
            
            if self.cleanup_thread.is_alive():
                self.cleanup_thread.join(timeout=2.0)
