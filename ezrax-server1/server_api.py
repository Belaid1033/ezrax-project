#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API REST Flask améliorée pour le serveur central EZRAX
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
from typing import Dict, List, Any, Optional, Tuple
from flask import Flask, request, jsonify, Response
from werkzeug.serving import make_server
from functools import wraps
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class APIKeyManager:
    """Gestionnaire sécurisé des clés API"""
    
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.api_keys = {}  # Cache des clés API valides
        self.load_api_keys()
        
    def load_api_keys(self):
        """Charge les clés API depuis la base de données"""
        try:
            stored_key = self.db_manager.get_config("api_key")
            if stored_key:
                self.api_keys["master"] = stored_key
                logger.info("Clé API principale chargée depuis la base de données")
            else:
                # Générer une nouvelle clé maître sécurisée
                master_key = self.generate_secure_api_key()
                self.db_manager.set_config("api_key", master_key)
                self.api_keys["master"] = master_key
                logger.info(f"Nouvelle clé API principale générée: {master_key[:8]}...{master_key[-8:]}")
                
        except Exception as e:
            logger.error(f"Erreur lors du chargement des clés API: {e}")
            
    def generate_secure_api_key(self) -> str:
        """Génère une clé API sécurisée"""
        return secrets.token_urlsafe(32)
        
    def validate_api_key(self, api_key: str) -> bool:
        """Valide une clé API de manière sécurisée"""
        if not api_key or len(api_key) < 16:
            return False
            
        # Vérification avec protection contre les attaques de timing
        import hmac
        for key_name, valid_key in self.api_keys.items():
            if hmac.compare_digest(api_key, valid_key):
                return True
        return False
        
    def get_master_key(self) -> str:
        """Retourne la clé API principale"""
        return self.api_keys.get("master", "")

class RequestValidator:
    """Validateur avancé des requêtes"""
    
    @staticmethod
    def validate_uuid(value: str) -> bool:
        """Valide un UUID"""
        try:
            uuid.UUID(value)
            return True
        except (ValueError, TypeError):
            return False
            
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Valide une adresse IP"""
        try:
            ipaddress.ip_address(ip)
            return True
        except (ValueError, TypeError):
            return False
            
    @staticmethod
    def validate_hostname(hostname: str) -> bool:
        """Valide un nom d'hôte"""
        if not hostname or len(hostname) > 255:
            return False
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        return bool(re.match(pattern, hostname))
        
    @staticmethod
    def validate_version(version: str) -> bool:
        """Valide un numéro de version"""
        if not version:
            return False
        import re
        pattern = r'^\d+\.\d+(\.\d+)?$'
        return bool(re.match(pattern, version))
        
    @staticmethod
    def sanitize_json_data(data: Any, max_depth: int = 10) -> Any:
        """Nettoie et valide les données JSON de manière récursive"""
        if max_depth <= 0:
            return None
            
        if isinstance(data, dict):
            return {
                str(k)[:100]: RequestValidator.sanitize_json_data(v, max_depth - 1)
                for k, v in data.items()
                if k is not None and v is not None
            }
        elif isinstance(data, list):
            return [
                RequestValidator.sanitize_json_data(item, max_depth - 1)
                for item in data[:1000]  # Limiter à 1000 éléments
            ]
        elif isinstance(data, str):
            return data[:10000]  # Limiter la taille des chaînes
        elif isinstance(data, (int, float, bool)):
            return data
        else:
            return str(data)[:1000]

class RateLimiter:
    """Limiteur de taux de requêtes par IP"""
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.request_counts = {}
        self.lock = threading.Lock()
        
    def is_allowed(self, client_ip: str) -> bool:
        """Vérifie si l'IP peut faire une requête"""
        current_time = time.time()
        minute_window = int(current_time // 60)
        
        with self.lock:
            # Nettoyer les anciennes entrées
            self._cleanup_old_entries(minute_window)
            
            # Vérifier la limite pour cette IP
            key = f"{client_ip}:{minute_window}"
            current_count = self.request_counts.get(key, 0)
            
            if current_count >= self.requests_per_minute:
                return False
                
            # Incrémenter le compteur
            self.request_counts[key] = current_count + 1
            return True
            
    def _cleanup_old_entries(self, current_minute: int):
        """Nettoie les entrées expirées"""
        expired_keys = [
            key for key in self.request_counts.keys()
            if int(key.split(':')[1]) < current_minute - 2
        ]
        for key in expired_keys:
            del self.request_counts[key]

class HealthMonitor:
    """Moniteur de santé du serveur"""
    
    def __init__(self):
        self.start_time = time.time()
        self.request_count = 0
        self.error_count = 0
        self.last_error = None
        self.lock = threading.Lock()
        
    def record_request(self):
        """Enregistre une requête"""
        with self.lock:
            self.request_count += 1
            
    def record_error(self, error: str):
        """Enregistre une erreur"""
        with self.lock:
            self.error_count += 1
            self.last_error = {
                "message": error,
                "timestamp": time.time()
            }
            
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de santé"""
        with self.lock:
            uptime = time.time() - self.start_time
            return {
                "uptime_seconds": uptime,
                "uptime_formatted": self._format_uptime(uptime),
                "total_requests": self.request_count,
                "total_errors": self.error_count,
                "error_rate": self.error_count / max(1, self.request_count),
                "last_error": self.last_error,
                "status": "healthy" if self.error_count < 10 else "degraded"
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

class EzraxServerAPI:
    """
    API REST Flask améliorée pour le serveur central EZRAX
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
        
        # Composants de sécurité
        self.api_key_manager = APIKeyManager(db_manager)
        self.rate_limiter = RateLimiter(requests_per_minute=120)
        self.health_monitor = HealthMonitor()
        
        # Créer l'application Flask avec configuration sécurisée
        self.app = Flask(__name__)
        self.app.config.update({
            'SECRET_KEY': secrets.token_hex(32),
            'JSON_SORT_KEYS': False,
            'JSONIFY_PRETTYPRINT_REGULAR': debug,
            'MAX_CONTENT_LENGTH': 16 * 1024 * 1024,  # 16MB max
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
            """Middleware de sécurité global"""
            try:
                # Enregistrer la requête
                self.health_monitor.record_request()
                
                # Vérifier le rate limiting
                client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                if not self.rate_limiter.is_allowed(client_ip):
                    return jsonify({
                        "success": False, 
                        "message": "Trop de requêtes, veuillez patienter"
                    }), 429
                
                # Routes publiques (pas d'auth requise)
                public_routes = ['/api/health', '/api/info']
                if request.path in public_routes:
                    return None
                    
                # Vérifier la clé API pour les autres routes
                api_key = request.headers.get('X-API-Key')
                if not api_key:
                    return jsonify({
                        "success": False, 
                        "message": "Clé API manquante dans l'en-tête X-API-Key"
                    }), 401
                    
                if not self.api_key_manager.validate_api_key(api_key):
                    self.health_monitor.record_error("Clé API invalide")
                    return jsonify({
                        "success": False, 
                        "message": "Clé API invalide"
                    }), 401
                    
            except Exception as e:
                logger.error(f"Erreur dans le middleware de sécurité: {e}")
                self.health_monitor.record_error(str(e))
                return jsonify({
                    "success": False, 
                    "message": "Erreur interne du serveur"
                }), 500
                
        # Routes publiques
        
        @self.app.route('/api/health', methods=['GET'])
        def health():
            """Route de santé détaillée"""
            try:
                stats = self.health_monitor.get_stats()
                return jsonify({
                    "status": "ok",
                    "timestamp": time.time(),
                    "server": stats
                })
            except Exception as e:
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
                data = RequestValidator.sanitize_json_data(data)
                
                # Validation des champs requis
                required_fields = ["agent_id", "hostname", "ip_address"]
                missing_fields = [field for field in required_fields if field not in data or not data[field]]
                
                if missing_fields:
                    return jsonify({
                        "success": False,
                        "message": f"Champs manquants: {', '.join(missing_fields)}"
                    }), 400
                
                # Validations spécifiques
                if not RequestValidator.validate_uuid(data["agent_id"]):
                    return jsonify({
                        "success": False,
                        "message": "agent_id doit être un UUID valide"
                    }), 400
                    
                if not RequestValidator.validate_ip_address(data["ip_address"]):
                    return jsonify({
                        "success": False,
                        "message": "ip_address doit être une adresse IP valide"
                    }), 400
                    
                if not RequestValidator.validate_hostname(data["hostname"]):
                    return jsonify({
                        "success": False,
                        "message": "hostname contient des caractères invalides"
                    }), 400
                
                # Validation de la version si fournie
                if "version" in data and data["version"]:
                    if not RequestValidator.validate_version(data["version"]):
                        return jsonify({
                            "success": False,
                            "message": "Format de version invalide (attendu: x.y.z)"
                        }), 400
                
                # Enregistrer l'agent
                success = self.db_manager.register_agent(data)
                
                if success:
                    logger.info(f"Agent enregistré: {data['agent_id']} ({data['hostname']}) depuis {data['ip_address']}")
                    return jsonify({
                        "success": True,
                        "message": "Agent enregistré avec succès",
                        "agent_id": data["agent_id"],
                        "timestamp": time.time()
                    })
                else:
                    self.health_monitor.record_error("Échec enregistrement agent")
                    return jsonify({
                        "success": False,
                        "message": "Erreur lors de l'enregistrement de l'agent"
                    }), 500
                    
            except Exception as e:
                logger.error(f"Erreur lors de l'enregistrement de l'agent: {e}")
                self.health_monitor.record_error(f"Erreur enregistrement: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur"
                }), 500
                
        @self.app.route('/api/agents/<agent_id>/heartbeat', methods=['POST'])
        def agent_heartbeat(agent_id):
            """
            Reçoit un heartbeat d'un agent avec validation UUID
            """
            try:
                # Valider l'UUID de l'agent
                if not RequestValidator.validate_uuid(agent_id):
                    return jsonify({
                        "success": False,
                        "message": "agent_id doit être un UUID valide"
                    }), 400
                
                data = request.get_json() or {}
                data = RequestValidator.sanitize_json_data(data)
                
                # Validation de l'adresse IP si fournie
                if "ip_address" in data and data["ip_address"]:
                    if not RequestValidator.validate_ip_address(data["ip_address"]):
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
                logger.error(f"Erreur lors du heartbeat de l'agent {agent_id}: {e}")
                self.health_monitor.record_error(f"Erreur heartbeat: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur"
                }), 500
                
        @self.app.route('/api/agents/<agent_id>/sync', methods=['POST'])
        def agent_sync(agent_id):
            """
            Synchronise les données avec un agent - Version sécurisée
            """
            try:
                # Valider l'UUID de l'agent
                if not RequestValidator.validate_uuid(agent_id):
                    return jsonify({
                        "success": False,
                        "message": "agent_id doit être un UUID valide"
                    }), 400
                
                data = request.get_json() or {}
                data = RequestValidator.sanitize_json_data(data)
                
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
                logger.error(f"Erreur lors de la synchronisation avec {agent_id}: {e}")
                self.health_monitor.record_error(f"Erreur sync: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur"
                }), 500
        
        @self.app.route('/api/agents/<agent_id>/commands/<int:command_id>/ack', methods=['POST'])
        def command_acknowledgment(agent_id, command_id):
            """
            Accusé de réception d'une commande avec validation
            """
            try:
                # Valider l'UUID de l'agent
                if not RequestValidator.validate_uuid(agent_id):
                    return jsonify({
                        "success": False,
                        "message": "agent_id doit être un UUID valide"
                    }), 400
                
                data = request.get_json() or {}
                success = data.get("success", True)
                
                # Mettre à jour le statut de la commande
                update_success = self.db_manager.update_command_status(
                    command_id, 
                    "executed" if success else "failed"
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
                logger.error(f"Erreur lors de l'accusé de réception: {e}")
                self.health_monitor.record_error(f"Erreur ACK: {str(e)}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur"
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
                return jsonify({"error": str(e)}), 500
        
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
            self.health_monitor.record_error("Erreur interne 500")
            return jsonify({
                "success": False,
                "message": "Erreur interne du serveur"
            }), 500
    
    def _validate_attack_log(self, log: Dict[str, Any]) -> bool:
        """Valide un log d'attaque"""
        required_fields = ["agent_id", "timestamp", "attack_type", "source_ip", "scanner"]
        
        # Vérifier les champs requis
        if not all(field in log for field in required_fields):
            return False
            
        # Valider l'agent_id
        if not RequestValidator.validate_uuid(log["agent_id"]):
            return False
            
        # Valider l'IP source
        if not RequestValidator.validate_ip_address(log["source_ip"]):
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
        if not RequestValidator.validate_uuid(block["agent_id"]):
            return False
            
        # Valider l'IP
        if not RequestValidator.validate_ip_address(block["ip"]):
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
            self.health_monitor.record_error(f"Erreur démarrage: {str(e)}")
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
                "request_validation_active": True
            },
            "database": self.db_manager.get_performance_metrics() if hasattr(self.db_manager, 'get_performance_metrics') else {}
        }
