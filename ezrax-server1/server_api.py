#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API REST Flask améliorée pour le serveur central EZRAX
Version 2.0 - Mise à jour avec sécurité et performances optimisées
"""

import os
import time
import json
import logging
import threading
import uuid
import ipaddress
import hashlib
import secrets
import re
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, Response, abort, g
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.serving import make_server
from functools import wraps

logger = logging.getLogger(__name__)

class APIKeyManager:
    """Gestionnaire sécurisé des clés API avec rotation"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.api_keys = {}  # Cache des clés API valides {id: {key, expires_at}}
        self.key_usages = {}  # Compteur d'utilisation des clés {key: count}
        self.lock = threading.RLock()
        
        # Chargement initial
        self.load_api_keys()
        
    def load_api_keys(self):
        """Charge les clés API depuis la base de données"""
        try:
            with self.lock:
                # Clé principale
                master_key = self.db_manager.get_config("api_key")
                if master_key:
                    self.api_keys["master"] = {
                        "key": master_key,
                        "expires_at": None,  # Pas d'expiration pour la clé principale
                        "description": "Clé API principale"
                    }
                    logger.info("Clé API principale chargée depuis la base de données")
                else:
                    # Générer une nouvelle clé maître sécurisée
                    master_key = self.generate_secure_api_key()
                    self.db_manager.set_config("api_key", master_key)
                    self.api_keys["master"] = {
                        "key": master_key,
                        "expires_at": None,
                        "description": "Clé API principale générée automatiquement"
                    }
                    logger.info(f"Nouvelle clé API principale générée: {master_key[:8]}...{master_key[-8:]}")
                
                # Clés temporaires/secondaires
                temp_keys = self.db_manager.get_config("temp_api_keys", [])
                if isinstance(temp_keys, list):
                    for key_info in temp_keys:
                        if isinstance(key_info, dict) and "id" in key_info and "key" in key_info:
                            self.api_keys[key_info["id"]] = {
                                "key": key_info["key"],
                                "expires_at": key_info.get("expires_at"),
                                "description": key_info.get("description", "Clé temporaire")
                            }
                
        except Exception as e:
            logger.error(f"Erreur lors du chargement des clés API: {e}")
            
    def generate_secure_api_key(self) -> str:
        """Génère une clé API sécurisée"""
        # Utiliser secrets pour une génération cryptographiquement sûre
        return secrets.token_urlsafe(48)  # 64 caractères en base64
        
    def validate_api_key(self, api_key: str) -> bool:
        """Valide une clé API de manière sécurisée avec protection timing"""
        if not api_key or len(api_key) < 32:
            return False
        
        current_time = time.time()
        valid_key_found = False
        
        with self.lock:
            # Vérification avec protection contre les attaques de timing
            for key_id, key_info in list(self.api_keys.items()):
                # Vérifier l'expiration
                if key_info.get("expires_at") and key_info["expires_at"] < current_time:
                    # Supprimer les clés expirées
                    del self.api_keys[key_id]
                    continue
                
                # Comparaison sécurisée contre les attaques de timing
                if secrets.compare_digest(api_key, key_info["key"]):
                    valid_key_found = True
                    # Mettre à jour les statistiques d'utilisation
                    self.key_usages[key_id] = self.key_usages.get(key_id, 0) + 1
                    break
        
        return valid_key_found
        
    def get_master_key(self) -> str:
        """Retourne la clé API principale"""
        with self.lock:
            master_info = self.api_keys.get("master", {})
            return master_info.get("key", "")
            
    def create_temporary_key(self, description: str, expires_in: int = 86400) -> Dict[str, Any]:
        """Crée une clé API temporaire avec expiration"""
        with self.lock:
            key_id = f"temp_{uuid.uuid4()}"
            key = self.generate_secure_api_key()
            expires_at = time.time() + expires_in if expires_in > 0 else None
            
            key_info = {
                "id": key_id,
                "key": key,
                "expires_at": expires_at,
                "description": description,
                "created_at": time.time()
            }
            
            self.api_keys[key_id] = key_info
            
            # Enregistrer dans la base de données
            temp_keys = self.db_manager.get_config("temp_api_keys", [])
            temp_keys.append(key_info.copy())
            self.db_manager.set_config("temp_api_keys", temp_keys)
            
            logger.info(f"Clé API temporaire créée: {key_id}")
            
            # Retourner les informations (sans la clé complète pour les logs)
            safe_info = key_info.copy()
            safe_info["key"] = f"{key[:8]}...{key[-8:]}"
            return safe_info
            
    def revoke_key(self, key_id: str) -> bool:
        """Révoque une clé API"""
        with self.lock:
            if key_id not in self.api_keys or key_id == "master":
                return False
                
            # Supprimer la clé du cache
            del self.api_keys[key_id]
            
            # Supprimer de la base de données
            temp_keys = self.db_manager.get_config("temp_api_keys", [])
            temp_keys = [k for k in temp_keys if k.get("id") != key_id]
            self.db_manager.set_config("temp_api_keys", temp_keys)
            
            logger.info(f"Clé API révoquée: {key_id}")
            return True
            
    def rotate_master_key(self) -> Dict[str, str]:
        """Rotation de la clé API principale (pratique de sécurité avancée)"""
        with self.lock:
            # Sauvegarder l'ancienne clé
            old_key = self.get_master_key()
            
            # Générer une nouvelle clé
            new_key = self.generate_secure_api_key()
            
            # Mettre à jour la base de données
            self.db_manager.set_config("api_key", new_key)
            self.db_manager.set_config("previous_api_key", old_key)
            
            # Mettre à jour le cache
            self.api_keys["master"] = {
                "key": new_key,
                "expires_at": None,
                "description": "Clé API principale"
            }
            
            # Garder l'ancienne clé valide temporairement pour la transition
            self.api_keys["previous_master"] = {
                "key": old_key,
                "expires_at": time.time() + 3600,  # Valide 1 heure
                "description": "Ancienne clé principale (transition)"
            }
            
            logger.warning("Rotation de la clé API principale effectuée")
            
            return {
                "new_key": f"{new_key[:8]}...{new_key[-8:]}",
                "old_key": f"{old_key[:8]}...{old_key[-8:]}",
                "transition_period": "1 heure"
            }
            
    def get_key_usage_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques d'utilisation des clés"""
        with self.lock:
            stats = {}
            for key_id, count in self.key_usages.items():
                key_info = self.api_keys.get(key_id, {})
                if key_info:
                    stats[key_id] = {
                        "usage_count": count,
                        "description": key_info.get("description", ""),
                        "expires_at": key_info.get("expires_at")
                    }
            return stats


class RequestValidator:
    """Validateur avancé des requêtes avec cache et protection"""
    
    def __init__(self):
        # Cache pour les validations récurrentes
        self.validation_cache = {}
        self.cache_lock = threading.RLock()
        self.cache_size = 1000
        self.cache_ttl = 300  # 5 minutes
        
    def _get_cache(self, cache_type: str, key: str) -> Optional[bool]:
        """Récupère une validation du cache"""
        with self.cache_lock:
            cache_key = f"{cache_type}:{key}"
            if cache_key in self.validation_cache:
                entry = self.validation_cache[cache_key]
                if time.time() < entry["expires_at"]:
                    return entry["result"]
                else:
                    del self.validation_cache[cache_key]
            return None
            
    def _set_cache(self, cache_type: str, key: str, result: bool):
        """Stocke une validation dans le cache"""
        with self.cache_lock:
            # Nettoyer le cache si trop grand
            if len(self.validation_cache) >= self.cache_size:
                # Supprimer les entrées expirées
                current_time = time.time()
                expired_keys = [
                    k for k, v in self.validation_cache.items()
                    if v["expires_at"] < current_time
                ]
                for k in expired_keys:
                    del self.validation_cache[k]
                    
                # Si toujours trop grand, supprimer les plus anciennes entrées
                if len(self.validation_cache) >= self.cache_size:
                    sorted_entries = sorted(
                        self.validation_cache.items(),
                        key=lambda x: x[1]["expires_at"]
                    )
                    # Supprimer 20% des entrées
                    to_remove = int(len(sorted_entries) * 0.2)
                    for k, _ in sorted_entries[:to_remove]:
                        del self.validation_cache[k]
            
            cache_key = f"{cache_type}:{key}"
            self.validation_cache[cache_key] = {
                "result": result,
                "expires_at": time.time() + self.cache_ttl
            }
    
    def validate_uuid(self, value: str) -> bool:
        """Valide un UUID avec cache"""
        if not value:
            return False
            
        # Vérifier le cache
        cached_result = self._get_cache("uuid", value)
        if cached_result is not None:
            return cached_result
            
        try:
            # Validation stricte
            uuid_obj = uuid.UUID(value)
            result = str(uuid_obj) == value.lower()
            
            # Mettre en cache
            self._set_cache("uuid", value, result)
            return result
        except (ValueError, TypeError, AttributeError):
            self._set_cache("uuid", value, False)
            return False
            
    def validate_ip_address(self, ip: str) -> bool:
        """Valide une adresse IP avec cache"""
        if not ip:
            return False
            
        # Vérifier le cache
        cached_result = self._get_cache("ip", ip)
        if cached_result is not None:
            return cached_result
            
        try:
            # Validation avec ipaddress
            ipaddress.ip_address(ip)
            self._set_cache("ip", ip, True)
            return True
        except (ValueError, TypeError):
            self._set_cache("ip", ip, False)
            return False
            
    def validate_hostname(self, hostname: str) -> bool:
        """Valide un nom d'hôte"""
        if not hostname or len(hostname) > 255:
            return False
            
        # Vérifier le cache
        cached_result = self._get_cache("hostname", hostname)
        if cached_result is not None:
            return cached_result
            
        # Validation selon RFC 1123
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        result = bool(re.match(pattern, hostname))
        
        self._set_cache("hostname", hostname, result)
        return result
            
    def validate_version(self, version: str) -> bool:
        """Valide un numéro de version"""
        if not version:
            return False
            
        # Validation de format standard x.y.z
        pattern = r'^\d+\.\d+(\.\d+)?(-[a-zA-Z0-9\.]+)?$'
        return bool(re.match(pattern, version))
        
    def sanitize_json_data(self, data: Any, max_depth: int = 10) -> Any:
        """Nettoie et valide les données JSON de manière récursive avec limite de profondeur"""
        if max_depth <= 0:
            return None
            
        if isinstance(data, dict):
            return {
                str(k)[:100]: self.sanitize_json_data(v, max_depth - 1)
                for k, v in data.items()
                if k is not None and v is not None
            }
        elif isinstance(data, list):
            return [
                self.sanitize_json_data(item, max_depth - 1)
                for item in data[:1000]  # Limiter à 1000 éléments
            ]
        elif isinstance(data, str):
            return data[:10000]  # Limiter la taille des chaînes
        elif isinstance(data, (int, float, bool, type(None))):
            return data
        else:
            return str(data)[:1000]  # Convertir autres types en chaîne limitée
            
    def validate_request_size(self, content_length: int, max_size: int = 16777216) -> bool:
        """Valide la taille d'une requête"""
        return content_length is not None and content_length <= max_size
        
    def validate_agent_data(self, data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Valide les données d'un agent complet"""
        if not isinstance(data, dict):
            return False, "Les données ne sont pas un objet JSON"
            
        # Validation des champs requis
        required_fields = ["agent_id", "hostname", "ip_address"]
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        
        if missing_fields:
            return False, f"Champs requis manquants: {', '.join(missing_fields)}"
            
        # Validation des types de champs
        if not self.validate_uuid(data["agent_id"]):
            return False, "agent_id doit être un UUID valide"
            
        if not self.validate_ip_address(data["ip_address"]):
            return False, "ip_address doit être une adresse IP valide"
            
        if not self.validate_hostname(data["hostname"]):
            return False, "hostname contient des caractères invalides"
            
        # Validation de la version si fournie
        if "version" in data and data["version"] and not self.validate_version(data["version"]):
            return False, "Format de version invalide (attendu: x.y.z)"
            
        return True, None


class RateLimiter:
    """Limiteur de taux de requêtes par IP avec adaptabilité et burst"""
    
    def __init__(self, requests_per_minute: int = 60, burst_size: int = 120):
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.request_counts = {}  # {ip: {minute_window: count}}
        self.blacklist = {}  # {ip: expiry_time}
        self.whitelist = set()  # IPs sans limites
        self.lock = threading.RLock()
        
        # Paramètres adaptatifs
        self.adaptive_limits = {}  # {ip: custom_limit}
        
    def is_allowed(self, client_ip: str, endpoint: Optional[str] = None) -> bool:
        """Vérifie si l'IP peut faire une requête"""
        with self.lock:
            # Vérifier la whitelist
            if client_ip in self.whitelist:
                return True
                
            # Vérifier la blacklist
            if client_ip in self.blacklist:
                if time.time() < self.blacklist[client_ip]:
                    return False
                else:
                    # Expirée, supprimer
                    del self.blacklist[client_ip]
            
            current_time = time.time()
            minute_window = int(current_time // 60)
            
            # Initialiser le compteur pour cette IP si nécessaire
            if client_ip not in self.request_counts:
                self.request_counts[client_ip] = {}
                
            # Récupérer le compteur pour cette fenêtre de temps
            ip_counts = self.request_counts[client_ip]
            current_count = ip_counts.get(minute_window, 0)
            
            # Déterminer la limite applicable
            limit = self.adaptive_limits.get(client_ip, self.requests_per_minute)
            
            # Vérifier la limite normale
            if current_count < limit:
                ip_counts[minute_window] = current_count + 1
                return True
                
            # Vérifier la limite de burst (rafale)
            if endpoint and (endpoint.startswith("/api/agents/") or endpoint == "/api/health"):
                # Permettre des burst pour les endpoints critiques
                total_recent = sum(
                    count for window, count in ip_counts.items()
                    if minute_window - 1 <= window <= minute_window
                )
                
                if total_recent < self.burst_size:
                    ip_counts[minute_window] = current_count + 1
                    return True
            
            # Nettoyer les anciennes entrées
            self._cleanup_old_entries(client_ip, minute_window)
            
            return False
            
    def _cleanup_old_entries(self, client_ip: str, current_minute: int):
        """Nettoie les entrées expirées pour une IP"""
        if client_ip in self.request_counts:
            # Garder seulement les 5 dernières minutes
            ip_counts = self.request_counts[client_ip]
            
            expired_windows = [
                window for window in ip_counts.keys()
                if window < current_minute - 5
            ]
            
            for window in expired_windows:
                del ip_counts[window]
                
            # Supprimer l'entrée si vide
            if not ip_counts:
                del self.request_counts[client_ip]
                
    def blacklist_ip(self, client_ip: str, duration: int = 300):
        """Ajoute une IP à la blacklist temporairement"""
        with self.lock:
            self.blacklist[client_ip] = time.time() + duration
            
    def whitelist_ip(self, client_ip: str):
        """Ajoute une IP à la whitelist"""
        with self.lock:
            self.whitelist.add(client_ip)
            
    def remove_from_whitelist(self, client_ip: str):
        """Retire une IP de la whitelist"""
        with self.lock:
            self.whitelist.discard(client_ip)
            
    def set_custom_limit(self, client_ip: str, limit: int):
        """Définit une limite personnalisée pour une IP"""
        with self.lock:
            if limit <= 0:
                # Supprimer la limite personnalisée
                if client_ip in self.adaptive_limits:
                    del self.adaptive_limits[client_ip]
            else:
                self.adaptive_limits[client_ip] = limit
                
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du rate limiter"""
        with self.lock:
            stats = {
                "active_ips": len(self.request_counts),
                "blacklisted_ips": len(self.blacklist),
                "whitelisted_ips": len(self.whitelist),
                "custom_limits": len(self.adaptive_limits),
                "top_requesters": []
            }
            
            # Calculer le total par IP pour la dernière minute
            current_minute = int(time.time() // 60)
            ip_totals = {}
            
            for ip, counts in self.request_counts.items():
                recent_count = sum(
                    count for window, count in counts.items()
                    if window >= current_minute - 1
                )
                ip_totals[ip] = recent_count
                
            # Top 10 IPs par nombre de requêtes
            top_ips = sorted(
                ip_totals.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            stats["top_requesters"] = [
                {"ip": ip, "requests": count} for ip, count in top_ips
            ]
            
            return stats


class HealthMonitor:
    """Moniteur de santé avancé du serveur avec métriques détaillées"""
    
    def __init__(self):
        self.start_time = time.time()
        self.request_count = 0
        self.error_count = 0
        self.endpoint_stats = {}  # {endpoint: {count, errors, response_times}}
        self.last_error = None
        self.slow_responses = []  # Liste des réponses lentes (>1s)
        self.memory_usage = []  # Historique d'utilisation mémoire
        self.lock = threading.RLock()
        
        # Démarrer le thread de surveillance
        self.stop_event = threading.Event()
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="HealthMonitorThread"
        )
        self.monitor_thread.start()
        
    def record_request(self, endpoint: str, status_code: int, response_time: float):
        """Enregistre une requête avec métriques détaillées"""
        with self.lock:
            self.request_count += 1
            
            # Statistiques par endpoint
            if endpoint not in self.endpoint_stats:
                self.endpoint_stats[endpoint] = {
                    "count": 0,
                    "errors": 0,
                    "total_response_time": 0,
                    "avg_response_time": 0,
                    "max_response_time": 0
                }
                
            stats = self.endpoint_stats[endpoint]
            stats["count"] += 1
            
            if status_code >= 400:
                stats["errors"] += 1
                self.error_count += 1
                
            stats["total_response_time"] += response_time
            stats["avg_response_time"] = stats["total_response_time"] / stats["count"]
            stats["max_response_time"] = max(stats["max_response_time"], response_time)
            
            # Enregistrer les réponses lentes
            if response_time > 1.0:
                self.slow_responses.append({
                    "endpoint": endpoint,
                    "response_time": response_time,
                    "timestamp": time.time(),
                    "status_code": status_code
                })
                
                # Garder seulement les 100 dernières réponses lentes
                if len(self.slow_responses) > 100:
                    self.slow_responses.pop(0)
            
    def record_error(self, endpoint: str, error: str, status_code: int = 500):
        """Enregistre une erreur"""
        with self.lock:
            self.error_count += 1
            
            # Statistiques par endpoint
            if endpoint in self.endpoint_stats:
                self.endpoint_stats[endpoint]["errors"] += 1
                
            self.last_error = {
                "endpoint": endpoint,
                "message": error,
                "status_code": status_code,
                "timestamp": time.time()
            }
            
    def _monitor_loop(self):
        """Boucle de surveillance automatique"""
        while not self.stop_event.is_set():
            try:
                # Surveiller l'utilisation mémoire
                memory_usage = self._get_memory_usage()
                
                with self.lock:
                    self.memory_usage.append({
                        "usage": memory_usage,
                        "timestamp": time.time()
                    })
                    
                    # Garder seulement les 60 dernières mesures
                    if len(self.memory_usage) > 60:
                        self.memory_usage.pop(0)
                
                # Pause
                time.sleep(60)  # Mesure toutes les minutes
                
            except Exception as e:
                logger.error(f"Erreur surveillance santé: {e}")
                time.sleep(300)  # Pause plus longue en cas d'erreur
                
    def _get_memory_usage(self) -> float:
        """Récupère l'utilisation mémoire du processus"""
        try:
            import psutil
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()
            return memory_info.rss / (1024 * 1024)  # En MB
        except ImportError:
            # psutil non disponible
            return 0.0
        except Exception:
            return 0.0
            
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de santé complètes"""
        with self.lock:
            uptime = time.time() - self.start_time
            
            # Calculer le taux d'erreur global
            error_rate = self.error_count / max(1, self.request_count)
            
            # Déterminer le statut global
            status = "healthy"
            if error_rate > 0.1:
                status = "degraded"
            elif error_rate > 0.05:
                status = "warning"
                
            # Statistiques des endpoints
            endpoint_metrics = []
            for endpoint, stats in self.endpoint_stats.items():
                endpoint_error_rate = stats["errors"] / max(1, stats["count"])
                endpoint_metrics.append({
                    "endpoint": endpoint,
                    "requests": stats["count"],
                    "errors": stats["errors"],
                    "error_rate": endpoint_error_rate,
                    "avg_response_time": stats["avg_response_time"],
                    "max_response_time": stats["max_response_time"]
                })
                
            # Trier par nombre de requêtes
            endpoint_metrics.sort(key=lambda x: x["requests"], reverse=True)
            
            # Statistiques mémoire
            memory_stats = {
                "current_mb": self.memory_usage[-1]["usage"] if self.memory_usage else 0,
                "peak_mb": max([m["usage"] for m in self.memory_usage]) if self.memory_usage else 0,
                "samples": len(self.memory_usage)
            }
            
            return {
                "status": status,
                "uptime_seconds": uptime,
                "uptime_formatted": self._format_uptime(uptime),
                "total_requests": self.request_count,
                "total_errors": self.error_count,
                "error_rate": error_rate,
                "last_error": self.last_error,
                "endpoints": endpoint_metrics[:10],  # Top 10
                "slow_responses": len(self.slow_responses),
                "memory": memory_stats
            }
            
    def _format_uptime(self, seconds: float) -> str:
        """Formate la durée de fonctionnement"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m {secs}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"
            
    def stop(self):
        """Arrête le moniteur"""
        self.stop_event.set()
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2.0)


class EzraxServerAPI:
    """
    API REST Flask améliorée pour le serveur central EZRAX
    Version 2.0 avec sécurité renforcée et performances optimisées
    """
    
    def __init__(self, db_manager, host="0.0.0.0", port=5000, debug=False):
        """
        Initialisation de l'API améliorée
        
        Args:
            db_manager: Gestionnaire de base de données
            host: Adresse d'écoute
            port: Port d'écoute
            debug: Mode debug
        """
        self.db_manager = db_manager
        self.host = host
        self.port = port
        self.debug = debug
        
        # Composants de sécurité et performance
        self.api_key_manager = APIKeyManager(db_manager)
        self.rate_limiter = RateLimiter(requests_per_minute=120, burst_size=240)
        self.request_validator = RequestValidator()
        self.health_monitor = HealthMonitor()
        
        # Créer l'application Flask avec configuration sécurisée
        self.app = Flask(__name__)
        
        # Support des proxys pour obtenir l'IP réelle du client
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_for=1, x_proto=1)
        
        # Configuration Flask
        self.app.config.update({
            'SECRET_KEY': secrets.token_hex(32),
            'JSON_SORT_KEYS': False,
            'JSONIFY_PRETTYPRINT_REGULAR': debug,
            'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB max
            'JSON_AS_ASCII': False,
            'PROPAGATE_EXCEPTIONS': False
        })
        
        # Configurer les routes
        self._setup_routes()
        
        # Serveur HTTP
        self.server = None
        self.is_running = False
        
        logger.info(f"API serveur initialisée - Clé principale: {self.api_key_manager.get_master_key()[:8]}...{self.api_key_manager.get_master_key()[-8:]}")
        
    def _setup_routes(self):
        """Configure les routes de l'API avec middleware de sécurité"""
        
        # Middleware global de sécurité
        @self.app.before_request
        def security_middleware():
            """Middleware de sécurité global avec mesures avancées"""
            try:
                # Enregistrer l'heure de début pour calculer le temps de réponse
                g.request_start_time = time.time()
                
                # Récupérer l'IP du client (avec support proxy)
                client_ip = request.remote_addr
                if 'X-Forwarded-For' in request.headers:
                    forwarded_ip = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
                    if self.request_validator.validate_ip_address(forwarded_ip):
                        client_ip = forwarded_ip
                
                g.client_ip = client_ip
                
                # Vérifier la taille de la requête
                content_length = request.content_length
                if content_length and not self.request_validator.validate_request_size(content_length):
                    return jsonify({
                        "success": False, 
                        "message": "Taille de requête excessive"
                    }), 413
                
                # Vérifier le rate limiting
                if not self.rate_limiter.is_allowed(client_ip, request.path):
                    self.health_monitor.record_error(
                        request.path, 
                        f"Rate limit dépassé pour {client_ip}"
                    )
                    return jsonify({
                        "success": False, 
                        "message": "Trop de requêtes, veuillez patienter",
                        "retry_after": 60
                    }), 429
                
                # Routes publiques (pas d'auth requise)
                public_routes = ['/api/health', '/api/info']
                if request.path in public_routes:
                    return None
                    
                # Vérifier la clé API pour les autres routes
                api_key = request.headers.get('X-API-Key')
                if not api_key:
                    self.health_monitor.record_error(
                        request.path, 
                        "Clé API manquante"
                    )
                    return jsonify({
                        "success": False, 
                        "message": "Clé API manquante dans l'en-tête X-API-Key"
                    }), 401
                    
                if not self.api_key_manager.validate_api_key(api_key):
                    self.health_monitor.record_error(
                        request.path, 
                        "Clé API invalide"
                    )
                    return jsonify({
                        "success": False, 
                        "message": "Clé API invalide"
                    }), 401
                    
            except Exception as e:
                logger.error(f"Erreur middleware: {e}")
                self.health_monitor.record_error(
                    request.path if hasattr(request, 'path') else 'unknown',
                    str(e)
                )
                return jsonify({
                    "success": False, 
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
        
        # Middleware après requête
        @self.app.after_request
        def after_request_middleware(response):
            """Middleware après requête pour logging et métriques"""
            try:
                if hasattr(g, 'request_start_time'):
                    response_time = time.time() - g.request_start_time
                    
                    # Enregistrer les métriques
                    self.health_monitor.record_request(
                        request.path,
                        response.status_code,
                        response_time
                    )
                    
                    # Ajouter des en-têtes de performance
                    response.headers['X-Response-Time'] = f"{response_time:.6f}"
                    
                # Ajouter des en-têtes de sécurité
                response.headers['X-Content-Type-Options'] = 'nosniff'
                response.headers['X-Frame-Options'] = 'DENY'
                response.headers['X-XSS-Protection'] = '1; mode=block'
                
                return response
            except Exception as e:
                logger.error(f"Erreur middleware après requête: {e}")
                return response
        
        # Routes publiques
        
        @self.app.route('/api/health', methods=['GET'])
        def health():
            """Route de santé détaillée"""
            try:
                stats = self.health_monitor.get_stats()
                
                # Version simplifiée pour les clients
                health_info = {
                    "status": stats["status"],
                    "uptime": stats["uptime_formatted"],
                    "version": "2.0.0",
                    "timestamp": time.time()
                }
                
                # Version détaillée avec paramètre
                if request.args.get('detailed') == 'true':
                    health_info["server"] = stats
                    health_info["rate_limiter"] = self.rate_limiter.get_stats()
                
                return jsonify(health_info)
            except Exception as e:
                logger.error(f"Erreur route /health: {e}")
                return jsonify({"status": "error", "message": str(e)}), 500
                
        @self.app.route('/api/info', methods=['GET'])
        def server_info():
            """Informations sur le serveur (sans données sensibles)"""
            return jsonify({
                "name": "EZRAX Central Server",
                "version": "2.0.0",
                "api_version": "v1",
                "features": [
                    "agent_management",
                    "real_time_sync",
                    "attack_logging",
                    "ip_blocking",
                    "reporting",
                    "grafana_integration"
                ],
                "timestamp": time.time()
            })
        
        # Routes pour les agents (avec authentification)
        
        @self.app.route('/api/agents/register', methods=['POST'])
        def register_agent():
            """
            Enregistre un agent avec validation complète
            """
            try:
                data = request.get_json()
                if not data:
                    return jsonify({
                        "success": False,
                        "message": "Données JSON manquantes"
                    }), 400
                
                # Nettoyer et valider les données
                data = self.request_validator.sanitize_json_data(data)
                
                # Validation complète
                is_valid, error_message = self.request_validator.validate_agent_data(data)
                if not is_valid:
                    return jsonify({
                        "success": False,
                        "message": error_message
                    }), 400
                
                # Enregistrer l'agent
                success = self.db_manager.register_agent(data)
                
                if success:
                    # Ajouter l'IP de l'agent aux IPs à limite élevée
                    if hasattr(g, 'client_ip'):
                        self.rate_limiter.set_custom_limit(g.client_ip, 240)  # Double de la limite normale
                    
                    logger.info(f"Agent enregistré: {data['agent_id']} ({data['hostname']}) depuis {data['ip_address']}")
                    return jsonify({
                        "success": True,
                        "message": "Agent enregistré avec succès",
                        "agent_id": data["agent_id"],
                        "timestamp": time.time(),
                        "server_version": "2.0.0"
                    })
                else:
                    self.health_monitor.record_error(
                        request.path,
                        "Échec enregistrement agent"
                    )
                    return jsonify({
                        "success": False,
                        "message": "Erreur lors de l'enregistrement de l'agent"
                    }), 500
                    
            except Exception as e:
                logger.error(f"Erreur enregistrement agent: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
                
        @self.app.route('/api/agents/<agent_id>/heartbeat', methods=['POST'])
        def agent_heartbeat(agent_id):
            """
            Reçoit un heartbeat d'un agent avec validation UUID
            """
            try:
                # Valider l'UUID de l'agent
                if not self.request_validator.validate_uuid(agent_id):
                    return jsonify({
                        "success": False,
                        "message": "agent_id doit être un UUID valide"
                    }), 400
                
                data = request.get_json() or {}
                data = self.request_validator.sanitize_json_data(data)
                
                # Validation de l'adresse IP si fournie
                if "ip_address" in data and data["ip_address"]:
                    if not self.request_validator.validate_ip_address(data["ip_address"]):
                        return jsonify({
                            "success": False,
                            "message": "ip_address invalide dans le heartbeat"
                        }), 400
                
                # Mettre à jour le statut de l'agent
                success = self.db_manager.update_agent_status(
                    agent_id,
                    data.get("status", "online"),
                    data.get("ip_address")
                )
                
                if success:
                    # Heartbeat rapide
                    return jsonify({
                        "success": True,
                        "timestamp": time.time(),
                        "server_status": "healthy"
                    })
                else:
                    return jsonify({
                        "success": False,
                        "message": "Agent non trouvé ou erreur de mise à jour"
                    }), 404
                    
            except Exception as e:
                logger.error(f"Erreur heartbeat agent {agent_id}: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
                
        @self.app.route('/api/agents/<agent_id>/sync', methods=['POST'])
        def agent_sync(agent_id):
            """
            Synchronise les données avec un agent - Version optimisée
            """
            try:
                # Valider l'UUID de l'agent
                if not self.request_validator.validate_uuid(agent_id):
                    return jsonify({
                        "success": False,
                        "message": "agent_id doit être un UUID valide"
                    }), 400
                
                data = request.get_json() or {}
                data = self.request_validator.sanitize_json_data(data)
                
                # Mettre à jour le statut de l'agent
                self.db_manager.update_agent_status(agent_id, "online")
                
                # Traiter les logs d'attaques avec validation
                attack_logs_added = 0
                if "attack_logs" in data and isinstance(data["attack_logs"], list):
                    valid_logs = []
                    for log in data["attack_logs"][:1000]:  # Limiter à 1000 logs par sync
                        if self._validate_attack_log(log):
                            valid_logs.append(log)
                        else:
                            logger.warning(f"Log d'attaque invalide ignoré: {log}")
                    
                    if valid_logs:
                        attack_logs_added = self.db_manager.add_attack_logs(valid_logs)
                
                # Traiter les IPs bloquées avec validation
                blocked_ips_added = 0
                if "blocked_ips" in data and isinstance(data["blocked_ips"], list):
                    valid_blocks = []
                    for block in data["blocked_ips"][:1000]:  # Limiter à 1000 blocs par sync
                        if self._validate_blocked_ip(block):
                            valid_blocks.append(block)
                        else:
                            logger.warning(f"IP bloquée invalide ignorée: {block}")
                    
                    if valid_blocks:
                        blocked_ips_added = self.db_manager.add_blocked_ips(valid_blocks)
                
                # Récupérer la liste blanche
                whitelist = self.db_manager.get_whitelist()
                
                # Récupérer les commandes en attente
                commands = self.db_manager.get_pending_commands(agent_id)
                
                # Réponse avec statistiques
                response = {
                    "success": True,
                    "sync_stats": {
                        "attack_logs_processed": attack_logs_added,
                        "blocked_ips_processed": blocked_ips_added,
                        "commands_pending": len(commands)
                    },
                    "whitelist": whitelist,
                    "commands": commands,
                    "timestamp": time.time()
                }
                
                logger.debug(f"Sync réussie pour {agent_id}: {attack_logs_added} logs, {blocked_ips_added} IPs bloquées")
                return jsonify(response)
                
            except Exception as e:
                logger.error(f"Erreur sync agent {agent_id}: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
        
        @self.app.route('/api/agents/<agent_id>/commands/<int:command_id>/ack', methods=['POST'])
        def command_acknowledgment(agent_id, command_id):
            """
            Accusé de réception d'une commande avec validation
            """
            try:
                # Valider l'UUID de l'agent
                if not self.request_validator.validate_uuid(agent_id):
                    return jsonify({
                        "success": False,
                        "message": "agent_id doit être un UUID valide"
                    }), 400
                
                data = request.get_json() or {}
                success = data.get("success", True)
                
                # Mettre à jour le statut de la commande
                update_success = self.db_manager.update_command_status(
                    command_id, 
                    "executed" if success else "failed",
                    data.get("result")
                )
                
                if update_success:
                    return jsonify({
                        "success": True,
                        "timestamp": time.time()
                    })
                else:
                    return jsonify({
                        "success": False,
                        "message": "Commande non trouvée"
                    }), 404
                    
            except Exception as e:
                logger.error(f"Erreur ACK commande {command_id}: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
        
        # Nouvelles routes de gestion des agents
        
        @self.app.route('/api/agents', methods=['GET'])
        def list_agents():
            """Liste tous les agents avec filtres"""
            try:
                # Paramètres de filtrage
                status = request.args.get('status')
                hostname = request.args.get('hostname')
                since = request.args.get('since')
                
                # Convertir since en timestamp si fourni
                since_ts = None
                if since:
                    try:
                        since_ts = float(since)
                    except ValueError:
                        # Ignorer si invalide
                        pass
                
                # Récupérer les agents
                agents = self.db_manager.get_agents(
                    include_offline=status != "online"
                )
                
                # Filtrer les résultats
                if hostname:
                    agents = [a for a in agents if hostname.lower() in a.get("hostname", "").lower()]
                
                if since_ts:
                    agents = [a for a in agents if a.get("last_seen", 0) >= since_ts]
                
                return jsonify({
                    "success": True,
                    "agents": agents,
                    "count": len(agents),
                    "timestamp": time.time()
                })
                
            except Exception as e:
                logger.error(f"Erreur liste agents: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
        
        @self.app.route('/api/agents/<agent_id>', methods=['GET'])
        def get_agent_details(agent_id):
            """Récupère les détails d'un agent spécifique"""
            try:
                # Valider l'UUID de l'agent
                if not self.request_validator.validate_uuid(agent_id):
                    return jsonify({
                        "success": False,
                        "message": "agent_id doit être un UUID valide"
                    }), 400
                
                # Récupérer les détails de l'agent
                agents = self.db_manager.get_agents()
                agent = next((a for a in agents if a["agent_id"] == agent_id), None)
                
                if not agent:
                    return jsonify({
                        "success": False,
                        "message": "Agent non trouvé"
                    }), 404
                
                # Récupérer les statistiques de l'agent
                stats = self.db_manager.get_agent_stats(agent_id)
                
                return jsonify({
                    "success": True,
                    "agent": agent,
                    "stats": stats,
                    "timestamp": time.time()
                })
                
            except Exception as e:
                logger.error(f"Erreur détails agent {agent_id}: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
        
        @self.app.route('/api/agents/<agent_id>/command', methods=['POST'])
        def send_command(agent_id):
            """Envoie une commande à un agent"""
            try:
                # Valider l'UUID de l'agent
                if not self.request_validator.validate_uuid(agent_id):
                    return jsonify({
                        "success": False,
                        "message": "agent_id doit être un UUID valide"
                    }), 400
                
                data = request.get_json()
                if not data or "type" not in data:
                    return jsonify({
                        "success": False,
                        "message": "Données JSON invalides ou type de commande manquant"
                    }), 400
                
                # Nettoyer et valider les données
                data = self.request_validator.sanitize_json_data(data)
                
                # Validation du type de commande
                valid_command_types = ["restart", "block_ip", "unblock_ip", "generate_report", "update_config"]
                if data["type"] not in valid_command_types:
                    return jsonify({
                        "success": False,
                        "message": f"Type de commande invalide. Types valides: {', '.join(valid_command_types)}"
                    }), 400
                
                # Validation des données de commande spécifiques
                if data["type"] == "block_ip" or data["type"] == "unblock_ip":
                    if "data" not in data or not isinstance(data["data"], dict) or "ip" not in data["data"]:
                        return jsonify({
                            "success": False,
                            "message": "Données de commande invalides pour block_ip/unblock_ip. Champ 'ip' requis."
                        }), 400
                    
                    if not self.request_validator.validate_ip_address(data["data"]["ip"]):
                        return jsonify({
                            "success": False,
                            "message": "Adresse IP invalide dans les données de commande"
                        }), 400
                
                # Récupérer les paramètres optionnels
                priority = int(data.get("priority", 1))
                expires_in = int(data.get("expires_in", 3600))
                
                # Limites de sécurité
                priority = max(1, min(priority, 10))  # Entre 1 et 10
                expires_in = max(60, min(expires_in, 86400))  # Entre 1 minute et 24 heures
                
                # Envoyer la commande
                command_id = self.db_manager.add_command(
                    agent_id,
                    data["type"],
                    data.get("data"),
                    priority,
                    expires_in
                )
                
                if command_id:
                    return jsonify({
                        "success": True,
                        "command_id": command_id,
                        "message": f"Commande {data['type']} envoyée à l'agent",
                        "timestamp": time.time()
                    })
                else:
                    return jsonify({
                        "success": False,
                        "message": "Erreur lors de l'envoi de la commande"
                    }), 500
                    
            except Exception as e:
                logger.error(f"Erreur envoi commande à {agent_id}: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
        
        # Routes Grafana (conservées et sécurisées)
        
        @self.app.route('/api/grafana/agents', methods=['GET'])
        def grafana_agents():
            """Agents pour Grafana avec cache"""
            try:
                agents = self.db_manager.get_agents()
                grafana_agents = []
                
                for agent in agents:
                    grafana_agents.append({
                        "agent_id": agent["agent_id"],
                        "hostname": agent["hostname"],
                        "status": agent["status"],
                        "ip_address": agent["ip_address"],
                        "last_seen": agent["last_seen"],
                        "version": agent.get("version", "unknown")
                    })
                    
                return jsonify(grafana_agents)
                
            except Exception as e:
                logger.error(f"Erreur Grafana agents: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({"error": str(e)}), 500
                
        @self.app.route('/api/grafana/attacks', methods=['GET'])
        def grafana_attacks():
            """Attaques pour Grafana avec filtres"""
            try:
                # Paramètres de filtrage
                hours = request.args.get('hours', '24')
                attack_type = request.args.get('attack_type')
                
                try:
                    hours = int(hours)
                except ValueError:
                    hours = 24
                    
                since = time.time() - (hours * 3600)
                
                # Récupérer les attaques
                attacks = self.db_manager.get_attack_logs(
                    limit=1000,
                    since=since,
                    attack_type=attack_type
                )
                
                # Simplifier pour Grafana
                grafana_attacks = []
                for attack in attacks:
                    grafana_attacks.append({
                        "timestamp": attack["timestamp"],
                        "attack_type": attack["attack_type"],
                        "source_ip": attack["source_ip"],
                        "agent_id": attack.get("agent_id", ""),
                        "severity": attack.get("severity", "MEDIUM")
                    })
                    
                return jsonify(grafana_attacks)
                
            except Exception as e:
                logger.error(f"Erreur Grafana attacks: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({"error": str(e)}), 500
                
        @self.app.route('/api/grafana/blocked_ips', methods=['GET'])
        def grafana_blocked_ips():
            """IPs bloquées pour Grafana"""
            try:
                # Récupérer les IPs bloquées
                blocked_ips = self.db_manager.get_blocked_ips(include_expired=False)
                
                # Simplifier pour Grafana
                grafana_blocked = []
                for block in blocked_ips:
                    grafana_blocked.append({
                        "ip": block["ip"],
                        "timestamp": block["timestamp"],
                        "reason": block["reason"],
                        "agent_id": block.get("agent_id", "")
                    })
                    
                return jsonify(grafana_blocked)
                
            except Exception as e:
                logger.error(f"Erreur Grafana blocked_ips: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({"error": str(e)}), 500
                
        @self.app.route('/api/grafana/stats', methods=['GET'])
        def grafana_stats():
            """Statistiques globales pour Grafana"""
            try:
                stats = self.db_manager.get_global_stats()
                return jsonify(stats)
                
            except Exception as e:
                logger.error(f"Erreur Grafana stats: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({"error": str(e)}), 500
        
        # Nouvelles routes d'administration
        
        @self.app.route('/api/admin/apikeys', methods=['GET'])
        def list_api_keys():
            """Liste les clés API (sans les valeurs complètes)"""
            try:
                # Statistiques d'utilisation
                usage_stats = self.api_key_manager.get_key_usage_stats()
                
                # Liste des clés (masquées)
                keys = []
                for key_id, info in self.api_key_manager.api_keys.items():
                    key_value = info["key"]
                    masked_key = f"{key_value[:8]}...{key_value[-8:]}"
                    
                    keys.append({
                        "id": key_id,
                        "key": masked_key,
                        "description": info.get("description", ""),
                        "expires_at": info.get("expires_at"),
                        "usage": usage_stats.get(key_id, {}).get("usage_count", 0)
                    })
                    
                return jsonify({
                    "success": True,
                    "keys": keys,
                    "timestamp": time.time()
                })
                
            except Exception as e:
                logger.error(f"Erreur liste clés API: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
                
        @self.app.route('/api/admin/apikeys/create', methods=['POST'])
        def create_api_key():
            """Crée une nouvelle clé API temporaire"""
            try:
                data = request.get_json() or {}
                
                description = data.get("description", "Clé temporaire")
                expires_in = data.get("expires_in", 86400)  # 24h par défaut
                
                # Valider
                if not isinstance(description, str) or len(description) > 200:
                    return jsonify({
                        "success": False,
                        "message": "Description invalide"
                    }), 400
                    
                try:
                    expires_in = int(expires_in)
                    expires_in = max(300, min(expires_in, 2592000))  # Entre 5 minutes et 30 jours
                except (ValueError, TypeError):
                    return jsonify({
                        "success": False,
                        "message": "Durée d'expiration invalide"
                    }), 400
                    
                # Créer la clé
                key_info = self.api_key_manager.create_temporary_key(description, expires_in)
                
                return jsonify({
                    "success": True,
                    "key": key_info,
                    "message": "Clé API créée avec succès",
                    "timestamp": time.time()
                })
                
            except Exception as e:
                logger.error(f"Erreur création clé API: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
                
        @self.app.route('/api/admin/apikeys/<key_id>/revoke', methods=['POST'])
        def revoke_api_key(key_id):
            """Révoque une clé API"""
            try:
                if key_id == "master":
                    return jsonify({
                        "success": False,
                        "message": "Impossible de révoquer la clé principale"
                    }), 400
                    
                success = self.api_key_manager.revoke_key(key_id)
                
                if success:
                    return jsonify({
                        "success": True,
                        "message": "Clé API révoquée avec succès",
                        "timestamp": time.time()
                    })
                else:
                    return jsonify({
                        "success": False,
                        "message": "Clé API non trouvée ou déjà révoquée"
                    }), 404
                    
            except Exception as e:
                logger.error(f"Erreur révocation clé API: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
                
        @self.app.route('/api/admin/rotate-master-key', methods=['POST'])
        def rotate_master_key():
            """Rotation de la clé API principale"""
            try:
                result = self.api_key_manager.rotate_master_key()
                
                return jsonify({
                    "success": True,
                    "message": "Rotation de la clé API principale effectuée",
                    "rotation_info": result,
                    "timestamp": time.time()
                })
                
            except Exception as e:
                logger.error(f"Erreur rotation clé principale: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
                
        @self.app.route('/api/admin/server-info', methods=['GET'])
        def admin_server_info():
            """Informations détaillées sur le serveur pour administration"""
            try:
                # Informations de base
                info = {
                    "version": "2.0.0",
                    "uptime": self.health_monitor.get_stats()["uptime_formatted"],
                    "timestamp": time.time()
                }
                
                # Statistiques
                info["health"] = self.health_monitor.get_stats()
                info["rate_limiter"] = self.rate_limiter.get_stats()
                
                # Informations DB
                try:
                    info["database"] = self.db_manager.get_performance_metrics()
                except:
                    info["database"] = {"status": "error"}
                
                return jsonify({
                    "success": True,
                    "server_info": info
                })
                
            except Exception as e:
                logger.error(f"Erreur info serveur admin: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
                
        @self.app.route('/api/admin/performance', methods=['GET'])
        def server_performance():
            """Métriques de performance du serveur"""
            try:
                # Métriques de l'API
                api_metrics = {
                    "requests": self.health_monitor.request_count,
                    "errors": self.health_monitor.error_count,
                    "endpoints": self.health_monitor.endpoint_stats
                }
                
                # Métriques DB
                db_metrics = self.db_manager.get_performance_metrics()
                
                # Métriques système
                system_metrics = self._get_system_metrics()
                
                return jsonify({
                    "success": True,
                    "api": api_metrics,
                    "database": db_metrics,
                    "system": system_metrics,
                    "timestamp": time.time()
                })
                
            except Exception as e:
                logger.error(f"Erreur métriques performance: {e}")
                self.health_monitor.record_error(request.path, f"Erreur: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur",
                    "error": str(e) if self.debug else None
                }), 500
        
        # Gestionnaire d'erreurs global
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({
                "success": False,
                "message": "Endpoint non trouvé"
            }), 404
            
        @self.app.errorhandler(405)
        def method_not_allowed(error):
            return jsonify({
                "success": False,
                "message": "Méthode HTTP non autorisée"
            }), 405
            
        @self.app.errorhandler(413)
        def payload_too_large(error):
            return jsonify({
                "success": False,
                "message": "Données trop volumineuses"
            }), 413
            
        @self.app.errorhandler(500)
        def internal_error(error):
            logger.error(f"Erreur interne: {error}")
            self.health_monitor.record_error(
                request.path if hasattr(request, 'path') else 'unknown',
                "Erreur interne 500"
            )
            return jsonify({
                "success": False,
                "message": "Erreur interne du serveur",
                "error": str(error) if self.debug else None
            }), 500
    
    def _validate_attack_log(self, log: Dict[str, Any]) -> bool:
        """Valide un log d'attaque"""
        required_fields = ["agent_id", "timestamp", "attack_type", "source_ip", "scanner"]
        
        # Vérifier les champs requis
        if not all(field in log for field in required_fields):
            return False
            
        # Valider l'agent_id
        if not self.request_validator.validate_uuid(log["agent_id"]):
            return False
            
        # Valider l'IP source
        if not self.request_validator.validate_ip_address(log["source_ip"]):
            return False
            
        # Valider le timestamp
        try:
            timestamp = float(log["timestamp"])
            if timestamp <= 0 or timestamp > time.time() + 3600:  # Pas plus d'1h dans le futur
                return False
        except (ValueError, TypeError):
            return False
            
        # Valider le type d'attaque
        valid_attack_types = ["SYN_FLOOD", "UDP_FLOOD", "PORT_SCAN", "PING_FLOOD"]
        if log["attack_type"] not in valid_attack_types:
            return False
            
        return True
    
    def _validate_blocked_ip(self, block: Dict[str, Any]) -> bool:
        """Valide une entrée d'IP bloquée"""
        required_fields = ["agent_id", "ip", "timestamp", "reason", "duration"]
        
        # Vérifier les champs requis
        if not all(field in block for field in required_fields):
            return False
            
        # Valider l'agent_id
        if not self.request_validator.validate_uuid(block["agent_id"]):
            return False
            
        # Valider l'IP
        if not self.request_validator.validate_ip_address(block["ip"]):
            return False
            
        # Valider le timestamp
        try:
            timestamp = float(block["timestamp"])
            if timestamp <= 0 or timestamp > time.time() + 3600:
                return False
        except (ValueError, TypeError):
            return False
            
        # Valider la durée
        try:
            duration = int(block["duration"])
            if duration <= 0 or duration > 86400:  # Max 24h
                return False
        except (ValueError, TypeError):
            return False
            
        return True
    
    def _get_system_metrics(self) -> Dict[str, Any]:
        """Récupère les métriques système"""
        metrics = {
            "cpu_usage": 0.0,
            "memory_usage_mb": 0.0,
            "disk_usage_percent": 0.0,
            "process_threads": 0
        }
        
        try:
            import psutil
            process = psutil.Process(os.getpid())
            
            # Utilisation CPU
            metrics["cpu_usage"] = process.cpu_percent(interval=0.1)
            
            # Utilisation mémoire
            memory_info = process.memory_info()
            metrics["memory_usage_mb"] = memory_info.rss / (1024 * 1024)
            
            # Utilisation disque
            if os.path.exists(self.db_manager.db_path):
                disk = psutil.disk_usage(os.path.dirname(self.db_manager.db_path))
                metrics["disk_usage_percent"] = disk.percent
                
            # Threads
            metrics["process_threads"] = len(process.threads())
            
        except ImportError:
            # psutil non disponible
            pass
        except Exception as e:
            logger.error(f"Erreur récupération métriques système: {e}")
            
        return metrics
    
    def start(self):
        """Démarre le serveur API avec gestion d'erreurs"""
        if self.is_running:
            logger.warning("Le serveur API est déjà en cours d'exécution")
            return
            
        try:
            logger.info(f"Démarrage du serveur API sécurisé sur {self.host}:{self.port}")
            logger.info(f"Clé API principale: {self.api_key_manager.get_master_key()}")
            
            # Créer le serveur HTTP
            self.server = make_server(self.host, self.port, self.app)
            self.is_running = True
            
            # Démarrer le serveur
            self.server.serve_forever()
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du serveur API: {e}")
            self.health_monitor.record_error("startup", f"Erreur démarrage: {str(e)}")
            self.is_running = False
            
    def stop(self):
        """Arrête le serveur API proprement"""
        if not self.is_running or not self.server:
            return
            
        try:
            logger.info("Arrêt du serveur API")
            
            # Log des statistiques finales
            stats = self.health_monitor.get_stats()
            logger.info(f"Statistiques finales du serveur: {stats}")
            
            # Arrêter le moniteur de santé
            self.health_monitor.stop()
            
            # Arrêter le serveur
            self.server.shutdown()
            self.is_running = False
            
        except Exception as e:
            logger.error(f"Erreur lors de l'arrêt du serveur API: {e}")
            
    def get_api_key(self) -> str:
        """Retourne la clé API principale pour configuration"""
        return self.api_key_manager.get_master_key()
        
    def get_server_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques complètes du serveur"""
        return {
            "api": self.health_monitor.get_stats(),
            "security": {
                "rate_limiter_active": True,
                "api_key_validation_active": True,
                "request_validation_active": True,
                "rate_limiter_stats": self.rate_limiter.get_stats()
            },
            "database": self.db_manager.get_performance_metrics() if hasattr(self.db_manager, 'get_performance_metrics') else {}
        }
