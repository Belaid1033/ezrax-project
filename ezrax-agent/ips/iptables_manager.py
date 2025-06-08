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
import ipaddress
import shutil
from typing import Dict, List, Tuple, Any, Optional

logger = logging.getLogger(__name__)

class IptablesManager:
    """
    Gestionnaire IPS utilisant iptables 
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
        

        self.max_blocked_ips = config["ips"].get("max_blocked_ips", 10000)
        self.max_block_duration = config["ips"].get("max_block_duration", 86400)  # 24h max
        
        # Liste des IPs bloquées et leurs timestamps
        self.blocked_ips = {}  # {ip: (timestamp, reason, duration)}
        self.lock = threading.Lock()
        

        self.chain_name = "EZRAX_IPS"
        

        self._validate_iptables_availability()
        

        self.block_operations = 0
        self.unblock_operations = 0
        self.failed_operations = 0
        
        if self.enabled:
            # Créer un backup des règles actuelles
            self._backup_current_rules()
            
            # Initialiser iptables
            self._setup_iptables()
            
            # Démarrer le thread de nettoyage optimisé
            self.stop_event = threading.Event()
            self.cleanup_thread = threading.Thread(
                target=self._cleanup_thread, 
                name="IptablesCleanupThread"
            )
            self.cleanup_thread.daemon = True
            self.cleanup_thread.start()
            
    def _validate_iptables_availability(self):
        """Valide que iptables est disponible et utilisable"""
        if not self.enabled:
            return
            
        # Vérifier si iptables est installé
        if not shutil.which("iptables"):
            logger.error("iptables n'est pas installé ou non trouvé dans PATH")
            self.enabled = False
            return
            
        try:
            # Test simple pour vérifier les permissions
            result = subprocess.run(
                ["sudo", "-n", "iptables", "--version"], 
                capture_output=True, 
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                logger.error("Permissions insuffisantes pour utiliser iptables")
                self.enabled = False
                return
                
            logger.info(f"iptables validé: {result.stdout.strip()}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la validation d'iptables: {e}")
            self.enabled = False
            
    def _backup_current_rules(self):
        """Crée un backup des règles iptables actuelles"""
        try:
            backup_dir = "/tmp/ezrax_iptables_backup"
            os.makedirs(backup_dir, exist_ok=True)
            
            timestamp = int(time.time())
            backup_file = f"{backup_dir}/iptables_backup_{timestamp}.rules"
            
            # Sauvegarder les règles
            with open(backup_file, 'w') as f:
                result = subprocess.run(
                    ["sudo", "iptables-save"], 
                    stdout=f, 
                    stderr=subprocess.PIPE,
                    timeout=10
                )
                
            if result.returncode == 0:
                logger.info(f"Backup des règles iptables créé: {backup_file}")
                # Garder seulement les 5 derniers backups
                self._cleanup_old_backups(backup_dir)
            else:
                logger.warning("Impossible de créer un backup des règles iptables")
                
        except Exception as e:
            logger.error(f"Erreur lors du backup des règles iptables: {e}")
            
    def _cleanup_old_backups(self, backup_dir: str):
        """Nettoie les anciens backups (garde les 5 plus récents)"""
        try:
            backups = []
            for filename in os.listdir(backup_dir):
                if filename.startswith("iptables_backup_") and filename.endswith(".rules"):
                    filepath = os.path.join(backup_dir, filename)
                    backups.append((os.path.getctime(filepath), filepath))
                    
            # Trier par date de création et supprimer les anciens
            backups.sort(reverse=True)
            for _, filepath in backups[5:]:  # Garder les 5 plus récents
                os.remove(filepath)
                logger.debug(f"Ancien backup supprimé: {filepath}")
                
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage des backups: {e}")
            
    def _setup_iptables(self):
        """Configure la chaîne iptables personnalisée avec validation"""
        try:
            # Vérifier si la chaîne existe déjà
            check_result = self._execute_iptables_command(
                ["iptables", "-L", self.chain_name, "-n"],
                timeout=10
            )
            
            # Si la chaîne n'existe pas, la créer
            if not check_result["success"]:
                # Créer la chaîne
                create_result = self._execute_iptables_command(
                    ["iptables", "-N", self.chain_name],
                    timeout=10
                )
                
                if not create_result["success"]:
                    logger.error(f"Impossible de créer la chaîne {self.chain_name}")
                    self.enabled = False
                    return
                    
                # Ajouter la chaîne à INPUT avec gestion d'erreur
                insert_result = self._execute_iptables_command(
                    ["iptables", "-I", "INPUT", "1", "-j", self.chain_name],
                    timeout=10
                )
                
                if not insert_result["success"]:
                    logger.error(f"Impossible d'insérer la chaîne {self.chain_name} dans INPUT")
                    # Tenter de supprimer la chaîne créée
                    self._execute_iptables_command(["iptables", "-X", self.chain_name])
                    self.enabled = False
                    return
                    
                logger.info(f"Chaîne iptables {self.chain_name} créée et configurée")
            else:
                logger.info(f"Chaîne iptables {self.chain_name} déjà configurée")
                
            # Récupérer les règles existantes
            self._load_existing_rules()
            
        except Exception as e:
            logger.error(f"Erreur lors de la configuration d'iptables: {e}")
            self.enabled = False
            
    def _execute_iptables_command(self, cmd: List[str], timeout: int = 5) -> Dict[str, Any]:
        """
        Exécute une commande iptables de manière sécurisée
        
        Args:
            cmd: Commande à exécuter (sans 'sudo')
            timeout: Timeout en secondes
            
        Returns:
            Dict avec success, stdout, stderr, returncode
        """
        try:
            # Validation basique des commandes
            if not cmd or cmd[0] != "iptables":
                return {"success": False, "error": "Commande invalide"}
                
            # Ajouter sudo au début
            full_cmd = ["sudo"] + cmd
            
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout lors de l'exécution de la commande iptables: {cmd}")
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            logger.error(f"Erreur lors de l'exécution de la commande iptables: {e}")
            return {"success": False, "error": str(e)}
            
    def _validate_ip_address(self, ip: str) -> bool:
        """
        Valide rigoureusement une adresse IP
        
        Args:
            ip: Adresse IP à valider
            
        Returns:
            True si l'IP est valide et sûre
        """
        try:
            # Validation de base
            ip_obj = ipaddress.ip_address(ip)
            
            # Rejeter les adresses privées/spéciales dangereuses
            if ip_obj.is_loopback:
                logger.warning(f"Tentative de blocage d'une adresse loopback: {ip}")
                return False
                
            if ip_obj.is_multicast:
                logger.warning(f"Tentative de blocage d'une adresse multicast: {ip}")
                return False
                
            if ip_obj.is_reserved:
                logger.warning(f"Tentative de blocage d'une adresse réservée: {ip}")
                return False
                
            # Vérifications supplémentaires pour IPv4
            if isinstance(ip_obj, ipaddress.IPv4Address):
                # Rejeter certaines plages dangereuses
                dangerous_ranges = [
                    "0.0.0.0/8",      # This network
                    "255.255.255.255/32"  # Broadcast
                ]
                
                for dangerous_range in dangerous_ranges:
                    if ip_obj in ipaddress.ip_network(dangerous_range):
                        logger.warning(f"Tentative de blocage d'une adresse dangereuse: {ip}")
                        return False
                        
            return True
            
        except ValueError as e:
            logger.error(f"Adresse IP invalide: {ip} - {e}")
            return False
        except Exception as e:
            logger.error(f"Erreur lors de la validation IP: {e}")
            return False
            
    def _sanitize_reason(self, reason: str) -> str:
        """Nettoie et valide la raison du blocage"""
        if not reason:
            return "UNKNOWN"
            
        # Nettoyer la chaîne et limiter la taille
        sanitized = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', str(reason))
        return sanitized[:50]  # Limiter à 50 caractères
        
    def _load_existing_rules(self):
        """Charge les règles iptables existantes dans la chaîne EZRAX_IPS"""
        try:
            # Récupérer les règles existantes
            list_result = self._execute_iptables_command(
                ["iptables", "-L", self.chain_name, "-n"],
                timeout=15
            )
            
            if not list_result["success"]:
                logger.error("Impossible de lister les règles existantes")
                return
                
            # Analyser la sortie pour extraire les IPs bloquées
            lines = list_result["stdout"].strip().split('\n')
            
            # Skip header lines
            rules = lines[2:] if len(lines) > 2 else []
            
            current_time = time.time()
            loaded_count = 0
            
            with self.lock:
                for rule in rules:
                    # Parse the rule to get the IP
                    match = re.search(r"DROP\s+all\s+--\s+(\d+\.\d+\.\d+\.\d+)", rule)
                    if match:
                        ip = match.group(1)
                        
                        # Valider l'IP avant de l'ajouter
                        if self._validate_ip_address(ip):
                            # Ajouter à notre liste d'IPs bloquées avec un timestamp approximatif
                            self.blocked_ips[ip] = (current_time, "IMPORTED_RULE", self.block_duration)
                            loaded_count += 1
                        else:
                            logger.warning(f"IP invalide trouvée dans les règles existantes: {ip}")
                            
            logger.info(f"Chargement de {loaded_count} règles iptables valides")
                
        except Exception as e:
            logger.error(f"Erreur lors du chargement des règles iptables: {e}")
            
    def block_ip(self, ip: str, reason: str, duration: Optional[int] = None) -> bool:
        """
        Bloque une adresse IP avec iptables 
        
        Args:
            ip: Adresse IP à bloquer
            reason: Raison du blocage
            duration: Durée du blocage en secondes
            
        Returns:
            True si le blocage a réussi, False sinon
        """
        if not self.enabled:
            logger.warning(f"IPS désactivé, impossible de bloquer {ip}")
            return False
            

        if not self._validate_ip_address(ip):
            logger.error(f"Adresse IP invalide ou dangereuse: {ip}")
            self.failed_operations += 1
            return False
            
        # Vérifier la whitelist
        if ip in self.whitelist:
            logger.info(f"L'IP {ip} est dans la liste blanche, pas de blocage")
            return False
            

        with self.lock:
            if len(self.blocked_ips) >= self.max_blocked_ips:
                logger.error(f"Limite d'IPs bloquées atteinte ({self.max_blocked_ips})")
                self.failed_operations += 1
                return False
                
            # Vérifier si l'adresse IP est déjà bloquée
            if ip in self.blocked_ips:
                logger.info(f"L'IP {ip} est déjà bloquée")
                return True
                
        # Utiliser la durée par défaut si non spécifiée
        if duration is None:
            duration = self.block_duration
            

        duration = min(duration, self.max_block_duration)
        
        # Nettoyer la raison
        clean_reason = self._sanitize_reason(reason)
        
        try:
            # Ajouter la règle iptables
            block_result = self._execute_iptables_command([
                "iptables", "-I", self.chain_name, "1", "-s", ip, "-j", "DROP"
            ])
            
            if not block_result["success"]:
                logger.error(f"Erreur lors du blocage de l'IP {ip}: {block_result.get('stderr', 'Erreur inconnue')}")
                self.failed_operations += 1
                return False
                
            # Enregistrer le timestamp et la raison
            timestamp = time.time()
            
            with self.lock:
                self.blocked_ips[ip] = (timestamp, clean_reason, duration)
                
            # Enregistrer dans la base de données
            self.db_manager.add_blocked_ip(
                ip=ip,
                reason=clean_reason,
                timestamp=timestamp,
                duration=duration
            )
            
            self.block_operations += 1
            logger.info(f"IP {ip} bloquée pour {duration} secondes. Raison: {clean_reason}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors du blocage de l'IP {ip}: {e}")
            self.failed_operations += 1
            return False
            
    def unblock_ip(self, ip: str) -> bool:
        """
        Débloque une adresse IP 
        
        Args:
            ip: Adresse IP à débloquer
            
        Returns:
            True si l'opération a réussi, False sinon
        """
        if not self.enabled:
            return False
            
        # Validation de l'IP
        if not self._validate_ip_address(ip):
            logger.error(f"Adresse IP invalide pour déblocage: {ip}")
            return False
            
        with self.lock:
            if ip not in self.blocked_ips:
                logger.debug(f"IP {ip} n'est pas dans la liste des IPs bloquées")
                return False
                
        try:
            # Supprimer la règle iptables
            unblock_result = self._execute_iptables_command([
                "iptables", "-D", self.chain_name, "-s", ip, "-j", "DROP"
            ])
            
            if not unblock_result["success"]:
                logger.error(f"Erreur lors du déblocage de l'IP {ip}: {unblock_result.get('stderr', 'Erreur inconnue')}")
                self.failed_operations += 1
                return False
                
            # Mettre à jour la base de données
            self.db_manager.update_block_end_time(ip)
            
            # Supprimer de la liste des IPs bloquées
            with self.lock:
                del self.blocked_ips[ip]
                
            self.unblock_operations += 1
            logger.info(f"IP {ip} débloquée")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors du déblocage de l'IP {ip}: {e}")
            self.failed_operations += 1
            return False
            
    def _cleanup_thread(self):
        """Thread pour nettoyer les règles iptables expirées - Version optimisée"""
        while not self.stop_event.is_set():
            try:
                self._cleanup_expired_rules()
            except Exception as e:
                logger.error(f"Erreur dans le thread de nettoyage: {e}")
                

            cleanup_interval = self._calculate_cleanup_interval()
            self.stop_event.wait(cleanup_interval)
            
    def _calculate_cleanup_interval(self) -> int:
        """Calcule l'intervalle de nettoyage optimal selon le nombre d'IPs bloquées"""
        with self.lock:
            blocked_count = len(self.blocked_ips)
            
        if blocked_count == 0:
            return 60  # 1 minute si aucune IP bloquée
        elif blocked_count < 100:
            return 30  # 30 secondes pour un petit nombre d'IPs
        else:
            return 10  # 10 secondes pour un grand nombre d'IPs
            
    def _cleanup_expired_rules(self):
        """Supprime les règles iptables expirées - Version optimisée"""
        current_time = time.time()
        
        with self.lock:
            # Liste des IPs à débloquer
            ips_to_unblock = []
            
            for ip, (timestamp, reason, duration) in self.blocked_ips.items():
                # Vérifier si la règle a expiré
                if current_time - timestamp >= duration:
                    ips_to_unblock.append(ip)
                    
        # Débloquer les IPs expirées (sans le lock pour éviter les deadlocks)
        for ip in ips_to_unblock:
            self.unblock_ip(ip)
            
        if ips_to_unblock:
            logger.info(f"Nettoyage automatique: {len(ips_to_unblock)} IPs débloquées")
            
    def update_whitelist(self, new_whitelist: List[str]):
        """
        Met à jour la liste blanche des IPs - Version validée
        
        Args:
            new_whitelist: Nouvelle liste blanche
        """
        validated_whitelist = set()
        
        # Valider chaque IP de la nouvelle whitelist
        for ip in new_whitelist:
            if self._validate_ip_address(ip):
                validated_whitelist.add(ip)
            else:
                logger.warning(f"IP invalide ignorée dans la whitelist: {ip}")
                
        with self.lock:
            old_whitelist = self.whitelist
            self.whitelist = validated_whitelist
            
            # Débloquer les IPs qui sont maintenant dans la liste blanche
            for ip in self.whitelist:
                if ip in self.blocked_ips:
                    # Débloquer sans le lock pour éviter les deadlocks
                    threading.Thread(target=self.unblock_ip, args=(ip,)).start()
                    
        logger.info(f"Liste blanche mise à jour: {len(validated_whitelist)} entrées valides")
        
    def get_blocked_ips(self) -> Dict[str, Tuple[float, str, int]]:
        """
        Renvoie la liste des IPs actuellement bloquées
        
        Returns:
            Dict des IPs bloquées avec leur timestamp, raison et durée
        """
        with self.lock:
            return self.blocked_ips.copy()
            
    def get_statistics(self) -> Dict[str, Any]:
        """Retourne les statistiques du gestionnaire IPS"""
        with self.lock:
            blocked_count = len(self.blocked_ips)
            
        return {
            "enabled": self.enabled,
            "blocked_ips_count": blocked_count,
            "max_blocked_ips": self.max_blocked_ips,
            "block_operations": self.block_operations,
            "unblock_operations": self.unblock_operations,
            "failed_operations": self.failed_operations,
            "whitelist_size": len(self.whitelist),
            "cleanup_interval": self._calculate_cleanup_interval()
        }
        
    def emergency_unblock_all(self) -> bool:
        """
        Fonction d'urgence pour débloquer toutes les IPs
        
        Returns:
            True si réussi, False sinon
        """
        if not self.enabled:
            return False
            
        logger.warning("URGENCE: Déblocage de toutes les IPs")
        
        try:
            # Vider complètement la chaîne EZRAX_IPS
            flush_result = self._execute_iptables_command([
                "iptables", "-F", self.chain_name
            ])
            
            if flush_result["success"]:
                with self.lock:
                    blocked_count = len(self.blocked_ips)
                    self.blocked_ips.clear()
                    
                logger.warning(f"URGENCE: {blocked_count} IPs débloquées")
                return True
            else:
                logger.error("URGENCE: Échec du flush de la chaîne iptables")
                return False
                
        except Exception as e:
            logger.error(f"URGENCE: Erreur lors du déblocage de toutes les IPs: {e}")
            return False
            
    def shutdown(self):
        """Arrête proprement le gestionnaire IPS"""
        if self.enabled:
            logger.info("Arrêt du gestionnaire IPS")
            self.stop_event.set()
            
            if hasattr(self, 'cleanup_thread') and self.cleanup_thread.is_alive():
                self.cleanup_thread.join(timeout=2.0)
                
            # Log des statistiques finales
            stats = self.get_statistics()
            logger.info(f"Statistiques finales IPS: {stats}")
