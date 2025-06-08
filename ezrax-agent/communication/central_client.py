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
import ssl
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta


try:
    from urllib3.util.retry import Retry
    from requests.adapters import HTTPAdapter
    URLLIB3_AVAILABLE = True
except ImportError:

    URLLIB3_AVAILABLE = False
    Retry = None
    HTTPAdapter = requests.adapters.HTTPAdapter

logger = logging.getLogger(__name__)

class ExponentialBackoff:
    """Gestionnaire de backoff exponentiel pour les reconnexions"""
    
    def __init__(self, base_delay: float = 1.0, max_delay: float = 300.0, 
                 multiplier: float = 2.0, jitter: bool = True):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.multiplier = multiplier
        self.jitter = jitter
        self.attempt = 0
        
    def get_delay(self) -> float:
        """Calcule le délai pour la prochaine tentative"""
        delay = min(self.base_delay * (self.multiplier ** self.attempt), self.max_delay)
        
        if self.jitter:
            import random
            delay *= (0.5 + random.random() * 0.5)  # Jitter de ±50%
            
        return delay
        
    def increment(self):
        """Incrémente le compteur de tentatives"""
        self.attempt += 1
        
    def reset(self):
        """Remet à zéro le compteur de tentatives"""
        self.attempt = 0

class SecureHTTPSession:
    """Session HTTP sécurisée avec retry automatique et pooling """
    
    def __init__(self, timeout: int = 10, max_retries: int = 3):
        self.session = requests.Session()
        self.timeout = timeout
        
        # Configuration des retry avec backoff 
        if URLLIB3_AVAILABLE and Retry is not None:
            retry_strategy = Retry(
                total=max_retries,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE"]
            )
            
            # Adapter avec retry
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        
        # Configuration SSL sécurisée
        self.session.verify = True
        
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Execute une requête avec gestion des erreurs"""
        kwargs.setdefault('timeout', self.timeout)
        return self.session.request(method, url, **kwargs)
        
    def close(self):
        """Ferme la session"""
        if self.session:
            self.session.close()

class ConnectionHealthMonitor:
    """Moniteur de santé de la connexion"""
    
    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.success_history = []
        self.response_times = []
        self.last_check = 0
        self.lock = threading.Lock()
        
    def record_success(self, response_time: float):
        """Enregistre un succès de connexion"""
        with self.lock:
            self.success_history.append((time.time(), True))
            self.response_times.append(response_time)
            self._cleanup_old_records()
            
    def record_failure(self):
        """Enregistre un échec de connexion"""
        with self.lock:
            self.success_history.append((time.time(), False))
            self._cleanup_old_records()
            
    def _cleanup_old_records(self):
        """Nettoie les anciens enregistrements"""
        cutoff_time = time.time() - 300  # 5 minutes
        self.success_history = [
            (timestamp, success) for timestamp, success in self.success_history
            if timestamp > cutoff_time
        ]
        self.response_times = self.response_times[-self.window_size:]
        
    def get_health_score(self) -> float:
        """Calcule un score de santé de 0.0 à 1.0"""
        with self.lock:
            if not self.success_history:
                return 0.0
                
            recent_successes = sum(1 for _, success in self.success_history if success)
            return recent_successes / len(self.success_history)
            
    def get_avg_response_time(self) -> float:
        """Retourne le temps de réponse moyen"""
        with self.lock:
            if not self.response_times:
                return 0.0
            return sum(self.response_times) / len(self.response_times)

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
        
        # SÉCURISÉ: Masquer la clé API dans les logs
        self._api_key = self.central_config["api_key"]
        if len(self._api_key) < 16:
            logger.warning("Clé API très courte détectée - sécurité faible")
            
        # Configuration de l'API avec validation
        self.base_url = self._build_base_url()
        self.check_interval = max(5, self.central_config.get("check_interval", 30))
        
        # Session HTTP sécurisée avec pooling
        self.http_session = SecureHTTPSession(
            timeout=self.central_config.get("timeout", 10),
            max_retries=self.central_config.get("max_retries", 3)
        )
        
        # État du client avec thread safety
        self.state_lock = threading.Lock()
        self.connected = False
        self.last_connection = 0
        self.last_sync = 0
        self.consecutive_failures = 0
        
        # Gestion robuste des erreurs
        self.backoff = ExponentialBackoff()
        self.health_monitor = ConnectionHealthMonitor()
        
        # Cache pour éviter les requêtes redondantes
        self.command_cache = {}
        self.whitelist_cache = {"data": [], "last_update": 0}
        
        # Thread de synchronisation
        self.stop_event = threading.Event()
        self.sync_thread = None
        self.heartbeat_thread = None
        
        # Métriques de performance
        self.metrics = {
            "requests_sent": 0,
            "requests_successful": 0,
            "requests_failed": 0,
            "data_uploaded_bytes": 0,
            "data_downloaded_bytes": 0,
            "avg_response_time": 0.0,
            "last_successful_sync": 0
        }
        
        # Démarrer les threads de communication
        self._start_communication_threads()
        
    def _build_base_url(self) -> str:
        """Construit l'URL de base de manière sécurisée"""
        use_ssl = self.central_config.get("use_ssl", False)
        host = self.central_config["host"]
        port = self.central_config["port"]
        
        # Validation de base
        if not host or not isinstance(port, int) or port <= 0:
            raise ValueError("Configuration serveur central invalide")
            
        scheme = "https" if use_ssl else "http"
        
        # Éviter les doubles slashes
        if host.endswith('/'):
            host = host.rstrip('/')
            
        return f"{scheme}://{host}:{port}/api"
        
    def _get_headers(self) -> Dict[str, str]:
        """
        Récupère les en-têtes HTTP sécurisés pour les requêtes API
        
        Returns:
            Dictionnaire des en-têtes
        """
        return {
            "Content-Type": "application/json",
            "X-API-Key": self._api_key,
            "X-Agent-ID": self.agent_id,
            "X-Agent-Version": "2.0.0",
            "User-Agent": f"EZRAX-Agent/{self.agent_id}",
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate"
        }
        
    def _start_communication_threads(self):
        """Démarre les threads de communication"""
        # Thread de synchronisation principale
        self.sync_thread = threading.Thread(
            target=self._sync_loop,
            name="CentralSyncThread"
        )
        self.sync_thread.daemon = True
        self.sync_thread.start()
        
        # Thread de heartbeat séparé (plus fréquent)
        self.heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name="HeartbeatThread"
        )
        self.heartbeat_thread.daemon = True
        self.heartbeat_thread.start()
        
        logger.info("Threads de communication démarrés")
        
    def _sync_loop(self):
        """Boucle principale de synchronisation"""
        while not self.stop_event.is_set():
            try:
                # Enregistrement initial si pas connecté
                if not self.connected:
                    self.register_agent()
                    
                # Synchronisation des données
                self.sync_with_central()
                
                # Calcul de l'intervalle adaptatif
                sleep_interval = self._calculate_sync_interval()
                self.stop_event.wait(sleep_interval)
                
            except Exception as e:
                logger.error(f"Erreur dans la boucle de synchronisation: {e}")
                # Backoff en cas d'erreur
                self.stop_event.wait(self.backoff.get_delay())
                self.backoff.increment()
                
    def _heartbeat_loop(self):
        """Boucle de heartbeat séparée"""
        while not self.stop_event.is_set():
            try:
                if self.connected:
                    self.send_heartbeat()
                    
                # Heartbeat plus fréquent que la sync
                heartbeat_interval = max(10, self.check_interval // 2)
                self.stop_event.wait(heartbeat_interval)
                
            except Exception as e:
                logger.error(f"Erreur dans la boucle de heartbeat: {e}")
                self.stop_event.wait(30)  # Attendre 30s en cas d'erreur
                
    def _calculate_sync_interval(self) -> int:
        """Calcule l'intervalle de sync adaptatif basé sur la santé de la connexion"""
        health_score = self.health_monitor.get_health_score()
        base_interval = self.check_interval
        
        if health_score > 0.8:
            return base_interval  # Connexion saine
        elif health_score > 0.5:
            return int(base_interval * 1.5)  # Connexion moyenne
        else:
            return int(base_interval * 2)  # Connexion faible
            
    def register_agent(self) -> bool:
        """
        Enregistre l'agent auprès du serveur central 
        
        Returns:
            True si l'enregistrement a réussi, False sinon
        """
        url = f"{self.base_url}/agents/register"
        
        try:
            # Préparer les données d'enregistrement avec validation
            data = {
                "agent_id": self.agent_id,
                "hostname": self.agent_hostname,
                "ip_address": self._get_local_ip(),
                "os_info": self._get_os_info(),
                "version": "2.0.0",
                "features": self._get_agent_features(),
                "timestamp": time.time()
            }
            
            # Validation des données avant envoi
            if not self._validate_registration_data(data):
                logger.error("Données d'enregistrement invalides")
                return False
            
            # Envoyer la requête avec métriques
            start_time = time.time()
            response = self.http_session.request(
                'POST', url,
                headers=self._get_headers(),
                json=data
            )
            response_time = time.time() - start_time
            
            # Mettre à jour les métriques
            self.metrics["requests_sent"] += 1
            self.metrics["data_uploaded_bytes"] += len(json.dumps(data).encode())
            
            # Traiter la réponse
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    with self.state_lock:
                        self.connected = True
                        self.last_connection = time.time()
                        self.consecutive_failures = 0
                        
                    self.backoff.reset()
                    self.health_monitor.record_success(response_time)
                    self.metrics["requests_successful"] += 1
                    self.metrics["last_successful_sync"] = time.time()
                    
                    # Sauvegarder l'état
                    self.db_manager.set_agent_state("last_registration", self.last_connection)
                    
                    logger.info("Agent enregistré avec succès auprès du serveur central")
                    return True
                else:
                    logger.error(f"Erreur lors de l'enregistrement: {result.get('message')}")
            else:
                logger.error(f"Échec de l'enregistrement: HTTP {response.status_code}")
                
        except requests.exceptions.Timeout:
            logger.warning("Timeout lors de l'enregistrement de l'agent")
        except requests.exceptions.ConnectionError:
            logger.warning("Erreur de connexion lors de l'enregistrement")
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur de requête lors de l'enregistrement: {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue lors de l'enregistrement: {e}")
            
        # Gestion des échecs
        with self.state_lock:
            self.connected = False
            self.consecutive_failures += 1
            
        self.health_monitor.record_failure()
        self.metrics["requests_failed"] += 1
        self.backoff.increment()
        
        return False
        
    def _validate_registration_data(self, data: Dict[str, Any]) -> bool:
        """Valide les données d'enregistrement"""
        required_fields = ["agent_id", "hostname", "ip_address"]
        
        for field in required_fields:
            if field not in data or not data[field]:
                logger.error(f"Champ requis manquant: {field}")
                return False
                
        # Validation UUID pour agent_id
        try:
            import uuid
            uuid.UUID(data["agent_id"])
        except ValueError:
            logger.error("Agent ID n'est pas un UUID valide")
            return False
            
        return True
        
    def sync_with_central(self) -> bool:
        """
        Synchronise les données avec le serveur central 
        
        Returns:
            True si la synchronisation a réussi, False sinon
        """
        if not self.connected:
            logger.debug("Agent non connecté, tentative de connexion...")
            return self.register_agent()
            
        url = f"{self.base_url}/agents/{self.agent_id}/sync"
        
        try:
            # Récupérer les données non synchronisées avec pagination
            max_records = 100
            attack_logs, blocked_ips = self.db_manager.get_unsynced_data(max_records=max_records)
            
            # Récupérer les statistiques de l'agent (en cache si possible)
            agent_stats = self._get_cached_agent_stats()
            
            # Préparer les données à envoyer
            data = {
                "timestamp": time.time(),
                "agent_stats": agent_stats,
                "attack_logs": attack_logs,
                "blocked_ips": blocked_ips,
                "health_metrics": {
                    "connection_health": self.health_monitor.get_health_score(),
                    "avg_response_time": self.health_monitor.get_avg_response_time(),
                    "consecutive_failures": self.consecutive_failures
                }
            }
            
            # Envoyer la requête avec métriques
            start_time = time.time()
            response = self.http_session.request(
                'POST', url,
                headers=self._get_headers(),
                json=data
            )
            response_time = time.time() - start_time
            
            # Mettre à jour les métriques
            self.metrics["requests_sent"] += 1
            data_size = len(json.dumps(data).encode())
            self.metrics["data_uploaded_bytes"] += data_size
            
            # Traiter la réponse
            if response.status_code == 200:
                result = response.json()
                response_size = len(response.content)
                self.metrics["data_downloaded_bytes"] += response_size
                
                if result.get("success"):
                    # Marquer les données comme synchronisées
                    if attack_logs or blocked_ips:
                        attack_log_ids = [log["id"] for log in attack_logs]
                        blocked_ip_ids = [ip["id"] for ip in blocked_ips]
                        self.db_manager.mark_as_synced(attack_log_ids, blocked_ip_ids)
                        
                    # Mettre à jour la liste blanche (avec cache)
                    if "whitelist" in result:
                        self._update_whitelist_cache(result["whitelist"])
                        
                    # Traiter les commandes de l'agent
                    if "commands" in result and result["commands"]:
                        self._process_commands(result["commands"])
                        
                    # Succès
                    with self.state_lock:
                        self.last_sync = time.time()
                        self.consecutive_failures = 0
                        
                    self.backoff.reset()
                    self.health_monitor.record_success(response_time)
                    self.metrics["requests_successful"] += 1
                    self.metrics["last_successful_sync"] = time.time()
                    
                    self.db_manager.set_agent_state("last_sync", self.last_sync)
                    
                    logger.debug(f"Synchronisation réussie: {len(attack_logs)} logs, {len(blocked_ips)} IPs")
                    return True
                else:
                    logger.error(f"Erreur lors de la synchronisation: {result.get('message')}")
            else:
                logger.error(f"Échec de la synchronisation: HTTP {response.status_code}")
                
        except requests.exceptions.Timeout:
            logger.warning("Timeout lors de la synchronisation")
        except requests.exceptions.ConnectionError:
            logger.warning("Erreur de connexion lors de la synchronisation")
        except requests.exceptions.RequestException as e:
            logger.error(f"Erreur de requête lors de la synchronisation: {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue lors de la synchronisation: {e}")
            
        # Gestion des échecs
        with self.state_lock:
            self.consecutive_failures += 1
            if self.consecutive_failures > 5:
                self.connected = False
                logger.warning(f"Connexion marquée comme déconnectée après {self.consecutive_failures} échecs")
                
        self.health_monitor.record_failure()
        self.metrics["requests_failed"] += 1
        self.backoff.increment()
        
        return False
        
    def _get_cached_agent_stats(self) -> Dict[str, Any]:
        """Récupère les statistiques de l'agent (avec cache)"""
        # Cache simple pour éviter les requêtes DB répétées
        cache_key = "agent_stats"
        current_time = time.time()
        
        if (cache_key in self.command_cache and 
            current_time - self.command_cache[cache_key]["timestamp"] < 60):
            return self.command_cache[cache_key]["data"]
            
        # Récupérer les nouvelles stats
        uptime = current_time - self.db_manager.get_agent_state("start_time", current_time)
        stats = {
            "uptime": uptime,
            "connected": self.connected,
            "last_sync": self.last_sync,
            "connection_health": self.health_monitor.get_health_score(),
            "requests_metrics": self.metrics.copy()
        }
        
        # Mettre en cache
        self.command_cache[cache_key] = {
            "data": stats,
            "timestamp": current_time
        }
        
        return stats
        
    def _update_whitelist_cache(self, whitelist: List[Dict[str, Any]]):
        """Met à jour le cache de la liste blanche"""
        try:
            # Vérifier si la whitelist a changé
            if (self.whitelist_cache["data"] != whitelist or
                time.time() - self.whitelist_cache["last_update"] > 300):  # 5 minutes
                
                # Convertir la liste blanche en liste d'adresses IP
                ip_whitelist = []
                for entry in whitelist:
                    if isinstance(entry, dict) and "ip" in entry:
                        ip = entry["ip"]
                    elif isinstance(entry, str):
                        ip = entry
                    else:
                        continue
                        
                    # Validation IP basique
                    try:
                        import ipaddress
                        ipaddress.ip_address(ip)
                        ip_whitelist.append(ip)
                    except ValueError:
                        logger.warning(f"IP invalide dans la whitelist: {ip}")
                        
                # Mettre à jour la liste blanche du gestionnaire IPS
                if ip_whitelist != [entry.get("ip", "") for entry in self.whitelist_cache["data"]]:
                    self.ips_manager.update_whitelist(ip_whitelist)
                    
                    # Mettre à jour la liste blanche dans la base de données
                    self.db_manager.update_whitelist(whitelist)
                    
                    # Mettre à jour le cache
                    self.whitelist_cache = {
                        "data": whitelist,
                        "last_update": time.time()
                    }
                    
                    logger.info(f"Liste blanche mise à jour: {len(ip_whitelist)} entrées")
                    
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour de la liste blanche: {e}")
            
    def _process_commands(self, commands: List[Dict[str, Any]]):
        """
        Traite les commandes reçues du serveur central 
        
        Args:
            commands: Liste des commandes à exécuter
        """
        if not commands:
            return
            
        for cmd in commands:
            try:
                cmd_type = cmd.get("type", "").lower()
                cmd_id = cmd.get("id")
                cmd_data = cmd.get("data", {})
                
                # Validation de base
                if not cmd_type or not cmd_id:
                    logger.warning(f"Commande invalide reçue: {cmd}")
                    continue
                    
                logger.info(f"Traitement de la commande: {cmd_type} (ID: {cmd_id})")
                
                # Traitement sécurisé des commandes
                success = False
                
                if cmd_type == "block_ip":
                    success = self._handle_block_ip_command(cmd_data)
                elif cmd_type == "unblock_ip":
                    success = self._handle_unblock_ip_command(cmd_data)
                elif cmd_type == "get_status":
                    success = True  # Commande passive
                else:
                    logger.warning(f"Type de commande non reconnu: {cmd_type}")
                    continue
                    
                # Accuser réception de la commande
                self._acknowledge_command(cmd_id, success)
                
            except Exception as e:
                logger.error(f"Erreur lors du traitement de la commande {cmd.get('type')}: {e}")
                if cmd.get("id"):
                    self._acknowledge_command(cmd["id"], False)
                    
    def _handle_block_ip_command(self, cmd_data: Dict[str, Any]) -> bool:
        """Traite une commande de blocage d'IP"""
        ip = cmd_data.get("ip")
        reason = cmd_data.get("reason", "MANUAL_BLOCK")
        duration = cmd_data.get("duration", self.config["ips"]["block_duration"])
        
        if not ip:
            logger.error("Commande block_ip sans adresse IP")
            return False
            
        # Validation de l'IP
        try:
            import ipaddress
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error(f"Adresse IP invalide dans la commande: {ip}")
            return False
            
        # Valider la durée
        try:
            duration = int(duration)
            if duration <= 0 or duration > 86400:  # Max 24h
                logger.error(f"Durée de blocage invalide: {duration}")
                return False
        except (ValueError, TypeError):
            logger.error(f"Durée de blocage non numérique: {duration}")
            return False
            
        # Exécuter le blocage
        return self.ips_manager.block_ip(ip, reason, duration)
        
    def _handle_unblock_ip_command(self, cmd_data: Dict[str, Any]) -> bool:
        """Traite une commande de déblocage d'IP"""
        ip = cmd_data.get("ip")
        
        if not ip:
            logger.error("Commande unblock_ip sans adresse IP")
            return False
            
        # Validation de l'IP
        try:
            import ipaddress
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error(f"Adresse IP invalide dans la commande: {ip}")
            return False
            
        # Exécuter le déblocage
        return self.ips_manager.unblock_ip(ip)
            
    def _acknowledge_command(self, cmd_id: int, success: bool = True):
        """
        Accuse réception d'une commande de manière asynchrone
        
        Args:
            cmd_id: Identifiant de la commande
            success: Succès de l'exécution
        """
        def _send_ack():
            try:
                url = f"{self.base_url}/agents/{self.agent_id}/commands/{cmd_id}/ack"
                
                data = {"success": success, "timestamp": time.time()}
                
                response = self.http_session.request(
                    'POST', url,
                    headers=self._get_headers(),
                    json=data
                )
                
                if response.status_code == 200:
                    logger.debug(f"Accusé de réception envoyé pour la commande {cmd_id}")
                else:
                    logger.error(f"Échec de l'accusé de réception: HTTP {response.status_code}")
                    
            except Exception as e:
                logger.error(f"Erreur lors de l'accusé de réception: {e}")
                
        # Envoyer l'ACK dans un thread séparé pour ne pas bloquer
        threading.Thread(target=_send_ack, daemon=True).start()
        
    def send_heartbeat(self) -> bool:
        """
        Envoie un heartbeat au serveur central 
        
        Returns:
            True si le heartbeat a été envoyé avec succès, False sinon
        """
        if not self.connected:
            return False
            
        url = f"{self.base_url}/agents/{self.agent_id}/heartbeat"
        
        try:
            # Préparer les données du heartbeat (léger)
            data = {
                "timestamp": time.time(),
                "status": "online",
                "ip_address": self._get_local_ip(),
                "uptime": time.time() - self.db_manager.get_agent_state("start_time", time.time()),
                "health_score": self.health_monitor.get_health_score()
            }
            
            # Envoyer avec timeout court
            start_time = time.time()
            response = self.http_session.request(
                'POST', url,
                headers=self._get_headers(),
                json=data
            )
            response_time = time.time() - start_time
            
            # Traiter la réponse
            if response.status_code == 200:
                result = response.json()
                if result.get("success"):
                    self.health_monitor.record_success(response_time)
                    logger.debug("Heartbeat envoyé avec succès")
                    return True
                else:
                    logger.warning(f"Erreur dans la réponse heartbeat: {result.get('message')}")
            else:
                logger.warning(f"Échec de l'envoi du heartbeat: HTTP {response.status_code}")
                
        except requests.exceptions.Timeout:
            logger.debug("Timeout du heartbeat (normal)")
        except requests.exceptions.RequestException as e:
            logger.debug(f"Erreur de requête heartbeat: {e}")
        except Exception as e:
            logger.error(f"Erreur inattendue lors du heartbeat: {e}")
            
        self.health_monitor.record_failure()
        return False
        
    def _get_local_ip(self) -> str:
        """
        Récupère l'adresse IP locale de manière robuste
        
        Returns:
            Adresse IP locale
        """
        try:
            # Méthode la plus fiable
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            try:
                # Fallback 1
                return socket.gethostbyname(socket.gethostname())
            except:
                # Fallback 2
                return "127.0.0.1"
                
    def _get_os_info(self) -> Dict[str, str]:
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
                "python": platform.python_version(),
                "hostname": platform.node()
            }
            
            # Ajouter des informations spécifiques à Linux
            if os_info["system"] == "Linux":
                try:
                    with open("/etc/os-release") as f:
                        os_release = {}
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            if "=" in line:
                                key, value = line.split("=", 1)
                                os_release[key] = value.strip('"')
                                
                    os_info["distro"] = os_release.get("PRETTY_NAME", "Unknown")
                except:
                    os_info["distro"] = "Unknown"
                    
            return os_info
        except:
            return {"system": "Unknown"}
            
    def _get_agent_features(self) -> Dict[str, Any]:
        """Récupère les fonctionnalités de l'agent"""
        return {
            "scanners": {
                "syn_flood": self.config["scanners"]["syn_flood"]["enabled"],
                "udp_flood": self.config["scanners"]["udp_flood"]["enabled"],
                "port_scan": self.config["scanners"]["port_scan"]["enabled"],
                "ping_flood": self.config["scanners"]["ping_flood"]["enabled"]
            },
            "ips": self.config["ips"]["enabled"],
            "reporting": self.config["reporting"]["enabled"],
            "version": "2.0.0",
            "capabilities": [
                "real_time_blocking",
                "adaptive_scanning",
                "health_monitoring",
                "secure_communication"
            ]
        }
        
    def get_connection_status(self) -> Dict[str, Any]:
        """Retourne le statut de la connexion"""
        with self.state_lock:
            return {
                "connected": self.connected,
                "last_connection": self.last_connection,
                "last_sync": self.last_sync,
                "consecutive_failures": self.consecutive_failures,
                "health_score": self.health_monitor.get_health_score(),
                "avg_response_time": self.health_monitor.get_avg_response_time(),
                "metrics": self.metrics.copy(),
                "backoff_delay": self.backoff.get_delay()
            }
            
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Retourne les métriques de performance détaillées"""
        status = self.get_connection_status()
        
        # Ajouter des métriques calculées
        total_requests = self.metrics["requests_sent"]
        if total_requests > 0:
            success_rate = self.metrics["requests_successful"] / total_requests
            failure_rate = self.metrics["requests_failed"] / total_requests
        else:
            success_rate = failure_rate = 0.0
            
        status.update({
            "success_rate": success_rate,
            "failure_rate": failure_rate,
            "data_transfer": {
                "uploaded_mb": self.metrics["data_uploaded_bytes"] / (1024 * 1024),
                "downloaded_mb": self.metrics["data_downloaded_bytes"] / (1024 * 1024)
            }
        })
        
        return status
        
    def force_reconnect(self):
        """Force une reconnexion au serveur central"""
        logger.info("Reconnexion forcée au serveur central")
        with self.state_lock:
            self.connected = False
            self.consecutive_failures = 0
        self.backoff.reset()
        
    def shutdown(self):
        """Arrête proprement le client"""
        logger.info("Arrêt du client de communication")
        
        # Signaler l'arrêt
        self.stop_event.set()
        
        # Envoyer un heartbeat final
        try:
            if self.connected:
                url = f"{self.base_url}/agents/{self.agent_id}/heartbeat"
                data = {
                    "timestamp": time.time(),
                    "status": "offline",
                    "ip_address": self._get_local_ip(),
                    "shutdown_reason": "normal"
                }
                
                self.http_session.request(
                    'POST', url,
                    headers=self._get_headers(),
                    json=data
                )
                logger.info("Heartbeat final envoyé (status: offline)")
                
        except Exception as e:
            logger.debug(f"Erreur lors de l'envoi du heartbeat final: {e}")
            
        # Attendre l'arrêt des threads
        for thread in [self.sync_thread, self.heartbeat_thread]:
            if thread and thread.is_alive():
                thread.join(timeout=2.0)
                
        # Fermer la session HTTP
        if self.http_session:
            self.http_session.close()
            
        # Log des métriques finales
        metrics = self.get_performance_metrics()
        logger.info(f"Métriques finales de communication: {metrics}")
