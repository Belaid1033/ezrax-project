#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Client de communication avec le serveur central pour l'agent EZRAX IDS/IPS
"""

import os
import time
import json
import logging
import threading
import requests
import schedule
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class CentralClient:
    """
    Client de communication avec le serveur central
    """
    
    def __init__(self, config, db_manager, ips_manager):
        """
        Initialisation du client
        
        Args:
            config: Configuration de l'agent
            db_manager: Gestionnaire de base de données
            ips_manager: Gestionnaire IPS
        """
        self.config = config
        self.db_manager = db_manager
        self.ips_manager = ips_manager
        self.central_config = config["central_server"]
        self.agent_id = config["AGENT_ID"]
        self.agent_hostname = config["AGENT_HOSTNAME"]
        
        # Configuration de l'API
        self.base_url = f"{'https' if self.central_config['use_ssl'] else 'http'}://{self.central_config['host']}:{self.central_config['port']}/api"
        self.api_key = self.central_config["api_key"]
        self.check_interval = self.central_config["check_interval"]
        
        # État du client
        self.connected = False
        self.last_connection = 0
        self.last_sync = 0
        
        # Thread de synchronisation périodique
        self.stop_event = threading.Event()
        self.scheduler_thread = None
        
        # Démarrer le planificateur
        self._start_scheduler()
        
    def _start_scheduler(self):
        """Démarre le planificateur pour la synchronisation périodique"""
        # Synchroniser toutes les X secondes
        schedule.every(self.check_interval).seconds.do(self.sync_with_central)
        
        # Démarrer le thread du planificateur
        self.scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            name="CentralSyncScheduler"
        )
        self.scheduler_thread.daemon = True
        self.scheduler_thread.start()
        logger.info(f"Planificateur de synchronisation démarré (intervalle: {self.check_interval} secondes)")
        
    def _scheduler_loop(self):
        """Boucle du planificateur"""
        while not self.stop_event.is_set():
            schedule.run_pending()
            self.stop_event.wait(1)  # Vérifier toutes les secondes
            
    def _get_headers(self):
        """
        Récupère les en-têtes HTTP pour les requêtes API
        
        Returns:
            Dictionnaire des en-têtes
        """
        return {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
            "X-Agent-ID": self.agent_id,
            "User-Agent": f"EZRAX-Agent/{self.agent_id}"
        }
        
    def register_agent(self):
        """
        Enregistre l'agent auprès du serveur central
        
        Returns:
            True si l'enregistrement a réussi, False sinon
        """
        try:
            url = f"{self.base_url}/agents/register"
            
            # Préparer les données d'enregistrement
            data = {
                "agent_id": self.agent_id,
                "hostname": self.agent_hostname,
                "ip_address": self._get_local_ip(),
                "os_info": self._get_os_info(),
                "version": "1.0.0",  # Version de l'agent
                "features": {
                    "scanners": {
                        "syn_flood": self.config["scanners"]["syn_flood"]["enabled"],
                        "udp_flood": self.config["scanners"]["udp_flood"]["enabled"],
                        "port_scan": self.config["scanners"]["port_scan"]["enabled"],
                        "ping_flood": self.config["scanners"]["ping_flood"]["enabled"]
                    },
                    "ips": self.config["ips"]["enabled"],
                    "reporting": self.config["reporting"]["enabled"]
                }
            }
            
            # Envoyer la requête
            response = requests.post(
                url,
                headers=self._get_headers(),
                json=data,
                timeout=10
            )
            
            # Traiter la réponse
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    self.connected = True
                    self.last_connection = time.time()
                    self.db_manager.set_agent_state("last_registration", self.last_connection)
                    logger.info(f"Agent enregistré avec succès auprès du serveur central")
                    return True
                else:
                    logger.error(f"Erreur lors de l'enregistrement: {result.get('message')}")
            else:
                logger.error(f"Échec de l'enregistrement: {response.status_code} - {response.text}")
                
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement de l'agent: {e}")
            self.connected = False
            return False
            
    def sync_with_central(self):
        """
        Synchronise les données avec le serveur central
        
        Returns:
            True si la synchronisation a réussi, False sinon
        """
        try:
            # Vérifier si l'agent est enregistré
            if not self.connected and time.time() - self.last_connection > 300:  # 5 minutes
                success = self.register_agent()
                if not success:
                    return False
                    
            # URL de synchronisation
            url = f"{self.base_url}/agents/{self.agent_id}/sync"
            
            # Récupérer les données non synchronisées
            attack_logs, blocked_ips = self.db_manager.get_unsynced_data(max_records=100)
            
            # Récupérer les statistiques de l'agent
            agent_stats = {
                "uptime": time.time() - self.db_manager.get_agent_state("start_time", time.time()),
                "attacks_detected": len(attack_logs),
                "ips_blocked": len(blocked_ips)
            }
            
            # Préparer les données à envoyer
            data = {
                "timestamp": time.time(),
                "agent_stats": agent_stats,
                "attack_logs": attack_logs,
                "blocked_ips": blocked_ips
            }
            
            # Envoyer la requête
            response = requests.post(
                url,
                headers=self._get_headers(),
                json=data,
                timeout=15
            )
            
            # Traiter la réponse
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    # Marquer les données comme synchronisées
                    attack_log_ids = [log["id"] for log in attack_logs]
                    blocked_ip_ids = [ip["id"] for ip in blocked_ips]
                    self.db_manager.mark_as_synced(attack_log_ids, blocked_ip_ids)
                    
                    # Mettre à jour la liste blanche
                    if "whitelist" in result:
                        self._update_whitelist(result["whitelist"])
                        
                    # Mettre à jour les commandes de l'agent
                    if "commands" in result:
                        self._process_commands(result["commands"])
                        
                    self.last_sync = time.time()
                    self.db_manager.set_agent_state("last_sync", self.last_sync)
                    logger.info(f"Synchronisation réussie: {len(attack_logs)} logs, {len(blocked_ips)} IPs")
                    return True
                else:
                    logger.error(f"Erreur lors de la synchronisation: {result.get('message')}")
            else:
                logger.error(f"Échec de la synchronisation: {response.status_code} - {response.text}")
                
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de la synchronisation avec le serveur central: {e}")
            self.connected = False
            return False
            
    def _update_whitelist(self, whitelist):
        """
        Met à jour la liste blanche locale
        
        Args:
            whitelist: Liste blanche reçue du serveur central
        """
        try:
            # Convertir la liste blanche en liste d'adresses IP
            ip_whitelist = [entry["ip"] for entry in whitelist]
            
            # Mettre à jour la liste blanche du gestionnaire IPS
            self.ips_manager.update_whitelist(ip_whitelist)
            
            # Mettre à jour la liste blanche dans la base de données
            self.db_manager.update_whitelist(whitelist)
            
            logger.info(f"Liste blanche mise à jour: {len(whitelist)} entrées")
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour de la liste blanche: {e}")
            
    def _process_commands(self, commands):
        """
        Traite les commandes reçues du serveur central
        
        Args:
            commands: Liste des commandes à exécuter
        """
        if not commands:
            return
            
        for cmd in commands:
            try:
                cmd_type = cmd.get("type")
                cmd_id = cmd.get("id")
                cmd_data = cmd.get("data", {})
                
                logger.info(f"Commande reçue: {cmd_type} (ID: {cmd_id})")
                
                if cmd_type == "restart":
                    # Redémarrage de l'agent (via systemd)
                    self._restart_agent()
                elif cmd_type == "update_config":
                    # Mise à jour de la configuration
                    self._update_config(cmd_data)
                elif cmd_type == "block_ip":
                    # Blocage manuel d'une IP
                    ip = cmd_data.get("ip")
                    reason = cmd_data.get("reason", "MANUAL_BLOCK")
                    duration = cmd_data.get("duration", self.config["ips"]["block_duration"])
                    
                    if ip:
                        self.ips_manager.block_ip(ip, reason, duration)
                elif cmd_type == "unblock_ip":
                    # Déblocage manuel d'une IP
                    ip = cmd_data.get("ip")
                    
                    if ip:
                        self.ips_manager.unblock_ip(ip)
                elif cmd_type == "generate_report":
                    # Génération d'un rapport
                    # Cette commande nécessite que le générateur de rapports soit passé au constructeur
                    pass
                else:
                    logger.warning(f"Commande non reconnue: {cmd_type}")
                    
                # Accuser réception de la commande
                self._acknowledge_command(cmd_id)
                
            except Exception as e:
                logger.error(f"Erreur lors du traitement de la commande {cmd.get('type')}: {e}")
                
    def _acknowledge_command(self, cmd_id):
        """
        Accuse réception d'une commande
        
        Args:
            cmd_id: Identifiant de la commande
        """
        try:
            url = f"{self.base_url}/agents/{self.agent_id}/commands/{cmd_id}/ack"
            
            # Envoyer l'accusé de réception
            response = requests.post(
                url,
                headers=self._get_headers(),
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info(f"Accusé de réception envoyé pour la commande {cmd_id}")
            else:
                logger.error(f"Échec de l'accusé de réception: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Erreur lors de l'accusé de réception: {e}")
            
    def _restart_agent(self):
        """Redémarre l'agent via systemd"""
        try:
            logger.info("Redémarrage de l'agent...")
            
            # Utiliser systemctl pour redémarrer le service
            # Cela fonctionne uniquement si l'agent est exécuté en tant que service systemd
            os.system("sudo systemctl restart ezrax-agent.service")
            
        except Exception as e:
            logger.error(f"Erreur lors du redémarrage de l'agent: {e}")
            
    def _update_config(self, new_config):
        """
        Met à jour la configuration de l'agent
        
        Args:
            new_config: Nouvelle configuration
        """
        try:
            # Enregistrer la nouvelle configuration
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent_config.yaml")
            
            with open(config_path, "w") as f:
                json.dump(new_config, f, indent=2)
                
            logger.info(f"Configuration mise à jour: {config_path}")
            
            # Redémarrer l'agent pour appliquer la nouvelle configuration
            self._restart_agent()
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour de la configuration: {e}")
            
    def send_heartbeat(self):
        """
        Envoie un heartbeat au serveur central
        
        Returns:
            True si le heartbeat a été envoyé avec succès, False sinon
        """
        try:
            url = f"{self.base_url}/agents/{self.agent_id}/heartbeat"
            
            # Préparer les données du heartbeat
            data = {
                "timestamp": time.time(),
                "status": "online",
                "ip_address": self._get_local_ip(),
                "uptime": time.time() - self.db_manager.get_agent_state("start_time", time.time())
            }
            
            # Envoyer la requête
            response = requests.post(
                url,
                headers=self._get_headers(),
                json=data,
                timeout=5
            )
            
            # Traiter la réponse
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    logger.debug("Heartbeat envoyé avec succès")
                    return True
                else:
                    logger.warning(f"Erreur lors de l'envoi du heartbeat: {result.get('message')}")
            else:
                logger.warning(f"Échec de l'envoi du heartbeat: {response.status_code} - {response.text}")
                
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi du heartbeat: {e}")
            return False
            
    def _get_local_ip(self):
        """
        Récupère l'adresse IP locale
        
        Returns:
            Adresse IP locale
        """
        try:
            # Méthode simple pour obtenir l'adresse IP
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
            
    def _get_os_info(self):
        """
        Récupère les informations sur le système d'exploitation
        
        Returns:
            Informations sur le système d'exploitation
        """
        try:
            import platform
            
            os_info = {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "arch": platform.machine(),
                "python": platform.python_version()
            }
            
            # Ajouter des informations spécifiques à Linux
            if os_info["system"] == "Linux":
                try:
                    # Distribution Linux
                    with open("/etc/os-release") as f:
                        os_release = {}
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            key, value = line.split("=", 1)
                            os_release[key] = value.strip('"')
                            
                    os_info["distro"] = os_release.get("PRETTY_NAME", "Unknown")
                except:
                    os_info["distro"] = "Unknown"
                    
            return os_info
        except:
            return {"system": "Unknown"}
            
    def shutdown(self):
        """Arrête proprement le client"""
        logger.info("Arrêt du client de communication")
        self.stop_event.set()
        
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            self.scheduler_thread.join(timeout=2.0)
            
        # Envoyer un heartbeat final pour indiquer que l'agent est offline
        try:
            url = f"{self.base_url}/agents/{self.agent_id}/heartbeat"
            
            data = {
                "timestamp": time.time(),
                "status": "offline",
                "ip_address": self._get_local_ip(),
                "uptime": time.time() - self.db_manager.get_agent_state("start_time", time.time())
            }
            
            requests.post(
                url,
                headers=self._get_headers(),
                json=data,
                timeout=5
            )
            
            logger.info("Heartbeat final envoyé (status: offline)")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi du heartbeat final: {e}")
