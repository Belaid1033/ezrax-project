#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API REST Flask optimisée pour le serveur central EZRAX avec sécurité renforcée
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
from typing import Dict, List, Any, Optional
from functools import wraps
from collections import defaultdict, deque
from flask import Flask, request, jsonify, Response, session
from werkzeug.serving import make_server
from werkzeug.middleware.proxy_fix import ProxyFix
import jwt

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiter pour protéger l'API"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(lambda: deque(maxlen=max_requests))
        self.lock = threading.Lock()
        
    def is_allowed(self, client_id: str) -> bool:
        """Vérifie si une requête est autorisée"""
        current_time = time.time()
        cutoff_time = current_time - self.window_seconds
        
        with self.lock:
            # Nettoyer les anciennes requêtes
            client_requests = self.requests[client_id]
            while client_requests and client_requests[0] <= cutoff_time:
                client_requests.popleft()
                
            # Vérifier la limite
            if len(client_requests) >= self.max_requests:
                return False
                
            # Ajouter la nouvelle requête
            client_requests.append(current_time)
            return True
            
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du rate limiter"""
        with self.lock:
            active_clients = len([
                client_id for client_id, requests in self.requests.items()
                if requests
            ])
            
            total_requests = sum(len(requests) for requests in self.requests.values())
            
            return {
                "active_clients": active_clients,
                "total_requests_tracked": total_requests,
                "max_requests_per_window": self.max_requests,
                "window_seconds": self.window_seconds
            }

class SecurityValidator:
    """Validateur de sécurité pour les données d'entrée"""
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Valide une adresse IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Rejeter les adresses dangereuses
            if ip_obj.is_loopback and ip != "127.0.0.1":
                return False
            if ip_obj.is_multicast or ip_obj.is_reserved:
                return False
                
            return True
        except ValueError:
            return False
            
    @staticmethod
    def validate_agent_id(agent_id: str) -> bool:
        """Valide un identifiant d'agent"""
        try:
            uuid.UUID(agent_id)
            return True
        except ValueError:
            return False
            
    @staticmethod
    def sanitize_string(value: str, max_length: int = 255) -> str:
        """Nettoie et valide une chaîne de caractères"""
        if not isinstance(value, str):
            return ""
            
        # Supprimer les caractères dangereux
        import re
        sanitized = re.sub(r'[<>"\'\x00-\x1f\x7f-\x9f]', '', value)
        
        # Limiter la longueur
        return sanitized[:max_length]
        
    @staticmethod
    def validate_json_data(data: Any, max_size: int = 1024 * 1024) -> bool:
        """Valide des données JSON"""
        try:
            json_str = json.dumps(data)
            return len(json_str.encode()) <= max_size
        except (TypeError, ValueError):
            return False

class EzraxServerAPI:
    """
    API REST Flask optimisée pour le serveur central EZRAX
    """
    
    def __init__(self, db_manager, host="0.0.0.0", port=5000, api_key=None, 
                 enable_admin_api=True, jwt_secret=None):
        """
        Initialisation de l'API optimisée
        """
        self.db_manager = db_manager
        self.host = host
        self.port = port
        self.api_key = api_key or self._load_or_generate_api_key()
        self.enable_admin_api = enable_admin_api
        self.jwt_secret = jwt_secret or secrets.token_urlsafe(32)
        
        # Créer l'application Flask avec sécurité renforcée
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = secrets.token_urlsafe(32)
        self.app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
        
        # Middleware de sécurité
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_for=1, x_proto=1)
        
        # Rate limiters
        self.agent_rate_limiter = RateLimiter(max_requests=1000, window_seconds=60)
        self.admin_rate_limiter = RateLimiter(max_requests=200, window_seconds=60)
        self.public_rate_limiter = RateLimiter(max_requests=50, window_seconds=60)
        
        # Métriques de performance
        self.api_metrics = {
            "requests_total": 0,
            "requests_success": 0,
            "requests_failed": 0,
            "requests_rate_limited": 0,
            "avg_response_time": 0.0,
            "active_agents": set(),
            "admin_logins": 0,
            "last_reset": time.time()
        }
        self.metrics_lock = threading.Lock()
        
        # Configurer les routes
        self._setup_routes()
        
        # Serveur HTTP
        self.server = None
        self.is_running = False
        
    def _load_or_generate_api_key(self):
        """Charge ou génère une clé API sécurisée"""
        api_key = self.db_manager.get_config("api_key")
        
        if api_key:
            # Vérifier que ce n'est pas une clé par défaut dangereuse
            dangerous_keys = [
                "changez_moi_en_production",
                "default_api_key",
                "test_key",
                "09eefb2d04794fc38d3ea1ca586291de"
            ]
            
            if api_key in dangerous_keys:
                logger.error("Clé API dangereuse détectée, génération d'une nouvelle")
                api_key = secrets.token_urlsafe(32)
                self.db_manager.set_config("api_key", api_key)
                logger.warning(f"Nouvelle clé API générée: {api_key}")
            
            return api_key
            
        # Générer une nouvelle clé API
        api_key = secrets.token_urlsafe(32)
        self.db_manager.set_config("api_key", api_key)
        logger.info(f"Nouvelle clé API générée: {api_key}")
        return api_key
        
    def _get_client_identifier(self) -> str:
        """Récupère un identifiant unique pour le client"""
        # Utiliser X-Forwarded-For si disponible, sinon l'IP directe
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        if client_ip and ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
            
        # Ajouter l'agent ID si disponible pour les agents
        agent_id = request.headers.get('X-Agent-ID', '')
        if agent_id:
            return f"{client_ip}:{agent_id}"
        
        return client_ip or "unknown"
        
    def _update_metrics(self, success: bool, response_time: float):
        """Met à jour les métriques de l'API"""
        with self.metrics_lock:
            self.api_metrics["requests_total"] += 1
            
            if success:
                self.api_metrics["requests_success"] += 1
            else:
                self.api_metrics["requests_failed"] += 1
                
            # Moyenne mobile du temps de réponse
            if self.api_metrics["avg_response_time"] == 0:
                self.api_metrics["avg_response_time"] = response_time
            else:
                alpha = 0.1
                self.api_metrics["avg_response_time"] = (
                    alpha * response_time + 
                    (1 - alpha) * self.api_metrics["avg_response_time"]
                )
                
            # Tracking des agents actifs
            agent_id = request.headers.get('X-Agent-ID')
            if agent_id:
                self.api_metrics["active_agents"].add(agent_id)
                
    def _require_rate_limit(self, rate_limiter: RateLimiter):
        """Décorateur pour le rate limiting"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                client_id = self._get_client_identifier()
                
                if not rate_limiter.is_allowed(client_id):
                    with self.metrics_lock:
                        self.api_metrics["requests_rate_limited"] += 1
                    
                    logger.warning(f"Rate limit dépassé pour {client_id}")
                    return jsonify({
                        "success": False,
                        "message": "Rate limit dépassé",
                        "retry_after": rate_limiter.window_seconds
                    }), 429
                    
                return f(*args, **kwargs)
            return decorated_function
        return decorator
        
    def _require_api_key(self):
        """Décorateur pour vérifier la clé API"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                api_key = request.headers.get('X-API-Key')
                
                if not api_key or api_key != self.api_key:
                    logger.warning(f"Tentative d'accès avec clé API invalide depuis {self._get_client_identifier()}")
                    return jsonify({
                        "success": False,
                        "message": "Clé API invalide"
                    }), 401
                    
                return f(*args, **kwargs)
            return decorated_function
        return decorator
        
    def _require_admin_auth(self):
        """Décorateur pour vérifier l'authentification admin"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Vérifier le token JWT
                auth_header = request.headers.get('Authorization')
                if not auth_header or not auth_header.startswith('Bearer '):
                    return jsonify({
                        "success": False,
                        "message": "Token d'authentification requis"
                    }), 401
                    
                token = auth_header[7:]  # Supprimer "Bearer "
                
                try:
                    payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
                    session_id = payload.get('session_id')
                    
                    if not session_id:
                        raise jwt.InvalidTokenError("Session ID manquant")
                        
                    # Valider la session
                    session_data = self.db_manager.admin_manager.validate_session(session_id)
                    if not session_data:
                        raise jwt.InvalidTokenError("Session expirée")
                        
                    # Ajouter les données de session à la requête
                    request.admin_session = session_data
                    
                except jwt.InvalidTokenError as e:
                    logger.warning(f"Token admin invalide: {e}")
                    return jsonify({
                        "success": False,
                        "message": "Token invalide ou expiré"
                    }), 401
                    
                return f(*args, **kwargs)
            return decorated_function
        return decorator
        
    def _setup_routes(self):
        """Configure toutes les routes de l'API"""
        
        # Middleware pour mesurer les performances
        @self.app.before_request
        def before_request():
            request.start_time = time.time()
            
        @self.app.after_request
        def after_request(response):
            response_time = time.time() - request.start_time
            success = response.status_code < 400
            self._update_metrics(success, response_time)
            
            # Headers de sécurité
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            
            return response
            
        # Route de santé publique
        @self.app.route('/api/health', methods=['GET'])
        @self._require_rate_limit(self.public_rate_limiter)
        def health():
            """Route de santé publique"""
            return jsonify({
                "status": "ok",
                "timestamp": time.time(),
                "version": "2.0.0"
            })
            
        # Route de métriques publiques
        @self.app.route('/api/metrics', methods=['GET'])
        @self._require_rate_limit(self.public_rate_limiter)
        def metrics():
            """Route de métriques publiques"""
            with self.metrics_lock:
                public_metrics = {
                    "requests_total": self.api_metrics["requests_total"],
                    "active_agents_count": len(self.api_metrics["active_agents"]),
                    "uptime": time.time() - self.api_metrics["last_reset"],
                    "avg_response_time": self.api_metrics["avg_response_time"]
                }
                
            return jsonify(public_metrics)
            
        # --- Routes pour les agents ---
        
        @self.app.route('/api/agents/register', methods=['POST'])
        @self._require_rate_limit(self.agent_rate_limiter)
        @self._require_api_key()
        def register_agent():
            """Enregistre un agent avec validation renforcée"""
            try:
                data = request.json
                
                if not data:
                    return jsonify({
                        "success": False,
                        "message": "Données JSON requises"
                    }), 400
                    
                # Validation des champs requis
                required_fields = ["agent_id", "hostname", "ip_address"]
                for field in required_fields:
                    if field not in data or not data[field]:
                        return jsonify({
                            "success": False,
                            "message": f"Champ requis manquant: {field}"
                        }), 400
                        
                # Validation de sécurité
                if not SecurityValidator.validate_agent_id(data["agent_id"]):
                    return jsonify({
                        "success": False,
                        "message": "ID d'agent invalide"
                    }), 400
                    
                if not SecurityValidator.validate_ip_address(data["ip_address"]):
                    return jsonify({
                        "success": False,
                        "message": "Adresse IP invalide"
                    }), 400
                    
                # Nettoyer les données
                data["hostname"] = SecurityValidator.sanitize_string(data["hostname"], 100)
                
                if "os_info" in data and not SecurityValidator.validate_json_data(data["os_info"]):
                    data["os_info"] = {}
                    
                if "features" in data and not SecurityValidator.validate_json_data(data["features"]):
                    data["features"] = {}
                    
                # Enregistrer l'agent
                success = self.db_manager.register_agent(data)
                
                if success:
                    return jsonify({
                        "success": True,
                        "message": "Agent enregistré avec succès"
                    })
                else:
                    return jsonify({
                        "success": False,
                        "message": "Erreur lors de l'enregistrement de l'agent"
                    }), 500
                    
            except Exception as e:
                logger.error(f"Erreur lors de l'enregistrement de l'agent: {e}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur"
                }), 500
                
        @self.app.route('/api/agents/<agent_id>/heartbeat', methods=['POST'])
        @self._require_rate_limit(self.agent_rate_limiter)
        @self._require_api_key()
        def agent_heartbeat(agent_id):
            """Reçoit un heartbeat d'un agent avec validation"""
            try:
                if not SecurityValidator.validate_agent_id(agent_id):
                    return jsonify({
                        "success": False,
                        "message": "ID d'agent invalide"
                    }), 400
                    
                data = request.json or {}
                
                # Extraire et valider les données
                status = data.get("status", "online")
                ip_address = data.get("ip_address")
                health_score = data.get("health_score")
                
                if ip_address and not SecurityValidator.validate_ip_address(ip_address):
                    ip_address = None
                    
                if health_score is not None:
                    try:
                        health_score = float(health_score)
                        health_score = max(0.0, min(1.0, health_score))  # Clamper entre 0 et 1
                    except (ValueError, TypeError):
                        health_score = None
                        
                # Mettre à jour le statut de l'agent
                success = self.db_manager.update_agent_status(
                    agent_id, status, ip_address, health_score
                )
                
                if success:
                    return jsonify({"success": True})
                else:
                    return jsonify({
                        "success": False,
                        "message": "Erreur lors de la mise à jour du statut"
                    }), 500
                    
            except Exception as e:
                logger.error(f"Erreur lors du traitement du heartbeat: {e}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur"
                }), 500
                
        @self.app.route('/api/agents/<agent_id>/sync', methods=['POST'])
        @self._require_rate_limit(self.agent_rate_limiter)
        @self._require_api_key()
        def agent_sync(agent_id):
            """Synchronise les données avec un agent"""
            try:
                if not SecurityValidator.validate_agent_id(agent_id):
                    return jsonify({
                        "success": False,
                        "message": "ID d'agent invalide"
                    }), 400
                    
                data = request.json or {}
                
                # Mettre à jour le statut de l'agent
                health_metrics = data.get("health_metrics", {})
                health_score = health_metrics.get("connection_health")
                
                self.db_manager.update_agent_status(
                    agent_id, "online", 
                    health_score=health_score
                )
                
                # Traiter les logs d'attaques avec validation
                attack_logs = data.get("attack_logs", [])
                if attack_logs:
                    # Valider et nettoyer les logs
                    valid_logs = []
                    for log in attack_logs[:1000]:  # Limiter à 1000 logs par sync
                        if (isinstance(log, dict) and 
                            all(key in log for key in ["timestamp", "attack_type", "source_ip", "scanner"])):
                            
                            # Ajouter l'agent_id
                            log["agent_id"] = agent_id
                            
                            # Valider l'IP source
                            if SecurityValidator.validate_ip_address(log["source_ip"]):
                                valid_logs.append(log)
                                
                    if valid_logs:
                        self.db_manager.add_attack_logs(valid_logs)
                        
                # Traiter les IPs bloquées avec validation
                blocked_ips = data.get("blocked_ips", [])
                if blocked_ips:
                    valid_blocks = []
                    for block in blocked_ips[:500]:  # Limiter à 500 blocages par sync
                        if (isinstance(block, dict) and 
                            all(key in block for key in ["ip", "timestamp", "reason", "duration"])):
                            
                            # Ajouter l'agent_id
                            block["agent_id"] = agent_id
                            
                            # Valider l'IP
                            if SecurityValidator.validate_ip_address(block["ip"]):
                                valid_blocks.append(block)
                                
                    if valid_blocks:
                        self.db_manager.add_blocked_ips(valid_blocks)
                        
                # Récupérer la liste blanche
                whitelist = self.db_manager.get_whitelist()
                
                # Récupérer les commandes en attente
                commands = self.db_manager.get_pending_commands(agent_id)
                
                return jsonify({
                    "success": True,
                    "whitelist": whitelist,
                    "commands": commands
                })
                
            except Exception as e:
                logger.error(f"Erreur lors de la synchronisation: {e}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur"
                }), 500
                
        @self.app.route('/api/agents/<agent_id>/commands/<int:command_id>/ack', methods=['POST'])
        @self._require_rate_limit(self.agent_rate_limiter)
        @self._require_api_key()
        def command_acknowledgment(agent_id, command_id):
            """Accusé de réception d'une commande"""
            try:
                if not SecurityValidator.validate_agent_id(agent_id):
                    return jsonify({
                        "success": False,
                        "message": "ID d'agent invalide"
                    }), 400
                    
                data = request.json or {}
                success = data.get("success", True)
                
                # Mettre à jour le statut de la commande
                status = "executed" if success else "failed"
                update_success = self.db_manager.update_command_status(command_id, status)
                
                if update_success:
                    return jsonify({"success": True})
                else:
                    return jsonify({
                        "success": False,
                        "message": "Erreur lors de la mise à jour du statut de la commande"
                    }), 500
                    
            except Exception as e:
                logger.error(f"Erreur lors de l'accusé de réception: {e}")
                return jsonify({
                    "success": False,
                    "message": "Erreur interne du serveur"
                }), 500
                
        # --- Routes d'administration ---
        
        if self.enable_admin_api:
            
            @self.app.route('/api/admin/login', methods=['POST'])
            @self._require_rate_limit(self.admin_rate_limiter)
            def admin_login():
                """Connexion administrateur"""
                try:
                    data = request.json
                    
                    if not data:
                        return jsonify({
                            "success": False,
                            "message": "Données JSON requises"
                        }), 400
                        
                    username = data.get("username", "").strip()
                    password = data.get("password", "")
                    
                    if not username or not password:
                        return jsonify({
                            "success": False,
                            "message": "Nom d'utilisateur et mot de passe requis"
                        }), 400
                        
                    # Nettoyer le nom d'utilisateur
                    username = SecurityValidator.sanitize_string(username, 50)
                    
                    # Authentifier
                    session_id = self.db_manager.admin_manager.authenticate_admin(username, password)
                    
                    if session_id:
                        # Créer un token JWT
                        payload = {
                            'session_id': session_id,
                            'username': username,
                            'iat': time.time(),
                            'exp': time.time() + 3600  # 1 heure
                        }
                        
                        token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
                        
                        with self.metrics_lock:
                            self.api_metrics["admin_logins"] += 1
                            
                        return jsonify({
                            "success": True,
                            "token": token,
                            "expires_in": 3600
                        })
                    else:
                        return jsonify({
                            "success": False,
                            "message": "Nom d'utilisateur ou mot de passe invalide"
                        }), 401
                        
                except Exception as e:
                    logger.error(f"Erreur lors de la connexion admin: {e}")
                    return jsonify({
                        "success": False,
                        "message": "Erreur interne du serveur"
                    }), 500
                    
            @self.app.route('/api/admin/logout', methods=['POST'])
            @self._require_admin_auth()
            def admin_logout():
                """Déconnexion administrateur"""
                try:
                    auth_header = request.headers.get('Authorization')
                    token = auth_header[7:]  # Supprimer "Bearer "
                    
                    payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
                    session_id = payload.get('session_id')
                    
                    if session_id:
                        self.db_manager.admin_manager.logout_admin(session_id)
                        
                    return jsonify({"success": True})
                    
                except Exception as e:
                    logger.error(f"Erreur lors de la déconnexion admin: {e}")
                    return jsonify({
                        "success": False,
                        "message": "Erreur interne du serveur"
                    }), 500
                    
            @self.app.route('/api/admin/agents', methods=['GET'])
            @self._require_rate_limit(self.admin_rate_limiter)
            @self._require_admin_auth()
            def admin_get_agents():
                """Récupère la liste des agents pour l'admin"""
                try:
                    include_offline = request.args.get('include_offline', 'true').lower() == 'true'
                    agents = self.db_manager.get_agents(include_offline=include_offline)
                    
                    return jsonify({
                        "success": True,
                        "agents": agents
                    })
                    
                except Exception as e:
                    logger.error(f"Erreur récupération agents admin: {e}")
                    return jsonify({
                        "success": False,
                        "message": "Erreur interne du serveur"
                    }), 500
                    
            @self.app.route('/api/admin/attacks', methods=['GET'])
            @self._require_rate_limit(self.admin_rate_limiter)
            @self._require_admin_auth()
            def admin_get_attacks():
                """Récupère les logs d'attaques pour l'admin"""
                try:
                    limit = min(int(request.args.get('limit', 100)), 1000)
                    offset = int(request.args.get('offset', 0))
                    since = request.args.get('since', type=float)
                    agent_id = request.args.get('agent_id')
                    attack_type = request.args.get('attack_type')
                    source_ip = request.args.get('source_ip')
                    
                    # Valider l'agent_id si fourni
                    if agent_id and not SecurityValidator.validate_agent_id(agent_id):
                        return jsonify({
                            "success": False,
                            "message": "ID d'agent invalide"
                        }), 400
                        
                    # Valider l'IP source si fournie
                    if source_ip and not SecurityValidator.validate_ip_address(source_ip):
                        return jsonify({
                            "success": False,
                            "message": "Adresse IP invalide"
                        }), 400
                        
                    logs = self.db_manager.get_attack_logs(
                        limit=limit,
                        offset=offset,
                        since=since,
                        attack_type=attack_type,
                        agent_id=agent_id,
                        source_ip=source_ip
                    )
                    
                    return jsonify({
                        "success": True,
                        "attacks": logs
                    })
                    
                except Exception as e:
                    logger.error(f"Erreur récupération attaques admin: {e}")
                    return jsonify({
                        "success": False,
                        "message": "Erreur interne du serveur"
                    }), 500
                    
            @self.app.route('/api/admin/blocked_ips', methods=['GET'])
            @self._require_rate_limit(self.admin_rate_limiter)
            @self._require_admin_auth()
            def admin_get_blocked_ips():
                """Récupère les IPs bloquées pour l'admin"""
                try:
                    include_expired = request.args.get('include_expired', 'false').lower() == 'true'
                    agent_id = request.args.get('agent_id')
                    
                    if agent_id and not SecurityValidator.validate_agent_id(agent_id):
                        return jsonify({
                            "success": False,
                            "message": "ID d'agent invalide"
                        }), 400
                        
                    blocked_ips = self.db_manager.get_blocked_ips(
                        include_expired=include_expired,
                        agent_id=agent_id
                    )
                    
                    return jsonify({
                        "success": True,
                        "blocked_ips": blocked_ips
                    })
                    
                except Exception as e:
                    logger.error(f"Erreur récupération IPs bloquées admin: {e}")
                    return jsonify({
                        "success": False,
                        "message": "Erreur interne du serveur"
                    }), 500
                    
            @self.app.route('/api/admin/stats', methods=['GET'])
            @self._require_rate_limit(self.admin_rate_limiter)
            @self._require_admin_auth()
            def admin_get_stats():
                """Récupère les statistiques pour l'admin"""
                try:
                    agent_id = request.args.get('agent_id')
                    
                    if agent_id:
                        if not SecurityValidator.validate_agent_id(agent_id):
                            return jsonify({
                                "success": False,
                                "message": "ID d'agent invalide"
                            }), 400
                        stats = self.db_manager.get_agent_stats(agent_id)
                    else:
                        stats = self.db_manager.get_global_stats()
                        
                    # Ajouter les métriques de l'API
                    with self.metrics_lock:
                        api_stats = self.api_metrics.copy()
                        api_stats["active_agents"] = list(api_stats["active_agents"])
                        
                    stats["api_metrics"] = api_stats
                    
                    return jsonify({
                        "success": True,
                        "stats": stats
                    })
                    
                except Exception as e:
                    logger.error(f"Erreur récupération statistiques admin: {e}")
                    return jsonify({
                        "success": False,
                        "message": "Erreur interne du serveur"
                    }), 500
                    
            @self.app.route('/api/admin/commands', methods=['POST'])
            @self._require_rate_limit(self.admin_rate_limiter)
            @self._require_admin_auth()
            def admin_send_command():
                """Envoie une commande à un agent"""
                try:
                    data = request.json
                    
                    if not data:
                        return jsonify({
                            "success": False,
                            "message": "Données JSON requises"
                        }), 400
                        
                    agent_id = data.get("agent_id")
                    command_type = data.get("command_type")
                    command_data = data.get("command_data", {})
                    priority = data.get("priority", 1)
                    
                    if not agent_id or not command_type:
                        return jsonify({
                            "success": False,
                            "message": "agent_id et command_type requis"
                        }), 400
                        
                    if not SecurityValidator.validate_agent_id(agent_id):
                        return jsonify({
                            "success": False,
                            "message": "ID d'agent invalide"
                        }), 400
                        
                    # Valider le type de commande
                    allowed_commands = ["block_ip", "unblock_ip", "restart", "generate_report", "update_config"]
                    if command_type not in allowed_commands:
                        return jsonify({
                            "success": False,
                            "message": f"Type de commande non autorisé: {command_type}"
                        }), 400
                        
                    # Valider les données de la commande
                    if not SecurityValidator.validate_json_data(command_data):
                        return jsonify({
                            "success": False,
                            "message": "Données de commande trop volumineuses"
                        }), 400
                        
                    # Validation spécifique pour les commandes d'IP
                    if command_type in ["block_ip", "unblock_ip"]:
                        ip = command_data.get("ip")
                        if not ip or not SecurityValidator.validate_ip_address(ip):
                            return jsonify({
                                "success": False,
                                "message": "Adresse IP invalide dans la commande"
                            }), 400
                            
                    # Ajouter la commande
                    created_by = request.admin_session.get("username", "unknown")
                    command_id = self.db_manager.add_command(
                        agent_id, command_type, command_data, created_by, priority
                    )
                    
                    if command_id:
                        return jsonify({
                            "success": True,
                            "command_id": command_id
                        })
                    else:
                        return jsonify({
                            "success": False,
                            "message": "Erreur lors de la création de la commande"
                        }), 500
                        
                except Exception as e:
                    logger.error(f"Erreur envoi commande admin: {e}")
                    return jsonify({
                        "success": False,
                        "message": "Erreur interne du serveur"
                    }), 500
                    
            @self.app.route('/api/admin/whitelist', methods=['GET'])
            @self._require_rate_limit(self.admin_rate_limiter)
            @self._require_admin_auth()
            def admin_get_whitelist():
                """Récupère la liste blanche"""
                try:
                    whitelist = self.db_manager.get_whitelist()
                    return jsonify({
                        "success": True,
                        "whitelist": whitelist
                    })
                    
                except Exception as e:
                    logger.error(f"Erreur récupération liste blanche admin: {e}")
                    return jsonify({
                        "success": False,
                        "message": "Erreur interne du serveur"
                    }), 500
                    
            @self.app.route('/api/admin/whitelist', methods=['POST'])
            @self._require_rate_limit(self.admin_rate_limiter)
            @self._require_admin_auth()
            def admin_add_whitelist():
                """Ajoute une entrée à la liste blanche"""
                try:
                    data = request.json
                    
                    if not data:
                        return jsonify({
                            "success": False,
                            "message": "Données JSON requises"
                        }), 400
                        
                    ip = data.get("ip")
                    description = data.get("description", "")
                    
                    if not ip:
                        return jsonify({
                            "success": False,
                            "message": "Adresse IP requise"
                        }), 400
                        
                    if not SecurityValidator.validate_ip_address(ip):
                        return jsonify({
                            "success": False,
                            "message": "Adresse IP invalide"
                        }), 400
                        
                    # Nettoyer la description
                    description = SecurityValidator.sanitize_string(description, 255)
                    
                    # Ajouter à la liste blanche
                    added_by = request.admin_session.get("username", "unknown")
                    success = self.db_manager.add_whitelist_entry(
                        ip, "manual", description, added_by
                    )
                    
                    if success:
                        return jsonify({"success": True})
                    else:
                        return jsonify({
                            "success": False,
                            "message": "Erreur lors de l'ajout à la liste blanche"
                        }), 500
                        
                except Exception as e:
                    logger.error(f"Erreur ajout liste blanche admin: {e}")
                    return jsonify({
                        "success": False,
                        "message": "Erreur interne du serveur"
                    }), 500
                    
            @self.app.route('/api/admin/whitelist/<ip>', methods=['DELETE'])
            @self._require_rate_limit(self.admin_rate_limiter)
            @self._require_admin_auth()
            def admin_remove_whitelist(ip):
                """Supprime une entrée de la liste blanche"""
                try:
                    if not SecurityValidator.validate_ip_address(ip):
                        return jsonify({
                            "success": False,
                            "message": "Adresse IP invalide"
                        }), 400
                        
                    success = self.db_manager.remove_whitelist_entry(ip)
                    
                    if success:
                        return jsonify({"success": True})
                    else:
                        return jsonify({
                            "success": False,
                            "message": "Erreur lors de la suppression de la liste blanche"
                        }), 500
                        
                except Exception as e:
                    logger.error(f"Erreur suppression liste blanche admin: {e}")
                    return jsonify({
                        "success": False,
                        "message": "Erreur interne du serveur"
                    }), 500
                    
        # Route pour les informations du serveur (publique mais limitée)
        @self.app.route('/api/server/info', methods=['GET'])
        @self._require_rate_limit(self.public_rate_limiter)
        def server_info():
            """Informations publiques du serveur"""
            return jsonify({
                "name": "EZRAX Central Server",
                "version": "2.0.0",
                "api_version": "2.0",
                "admin_api_enabled": self.enable_admin_api,
                "rate_limits": {
                    "agents": self.agent_rate_limiter.get_stats(),
                    "admin": self.admin_rate_limiter.get_stats(),
                    "public": self.public_rate_limiter.get_stats()
                }
            })
            
    def get_api_metrics(self) -> Dict[str, Any]:
        """Retourne les métriques complètes de l'API"""
        with self.metrics_lock:
            metrics = self.api_metrics.copy()
            metrics["active_agents"] = list(metrics["active_agents"])
            
        return {
            "api_metrics": metrics,
            "rate_limiters": {
                "agents": self.agent_rate_limiter.get_stats(),
                "admin": self.admin_rate_limiter.get_stats(),
                "public": self.public_rate_limiter.get_stats()
            }
        }
        
    def start(self):
        """Démarre le serveur API"""
        if self.is_running:
            logger.warning("Le serveur API est déjà en cours d'exécution")
            return
            
        try:
            logger.info(f"Démarrage du serveur API optimisé sur {self.host}:{self.port}")
            
            # Créer le serveur HTTP
            self.server = make_server(self.host, self.port, self.app, threaded=True)
            self.is_running = True
            
            # Log des informations de sécurité
            logger.info(f"API Key: {self.api_key[:8]}...")
            logger.info(f"Admin API: {'Activé' if self.enable_admin_api else 'Désactivé'}")
            
            # Démarrer le serveur
            self.server.serve_forever()
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du serveur API: {e}")
            self.is_running = False
            
    def stop(self):
        """Arrête le serveur API"""
        if not self.is_running or not self.server:
            return
            
        try:
            logger.info("Arrêt du serveur API")
            
            # Log des métriques finales
            final_metrics = self.get_api_metrics()
            logger.info(f"Métriques finales API: {final_metrics}")
            
            self.server.shutdown()
            self.is_running = False
            
        except Exception as e:
            logger.error(f"Erreur lors de l'arrêt du serveur API: {e}")
