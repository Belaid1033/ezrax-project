#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API REST sécurisée pour le serveur central EZRAX v2.0
"""

import os
import sys
import time
import json
import logging
import threading
import traceback
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from functools import wraps
from collections import defaultdict, deque

try:
    from flask import Flask, request, jsonify, abort, make_response, g
    from werkzeug.serving import make_server, WSGIRequestHandler
    from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, TooManyRequests
    import jwt
except ImportError as e:
    print(f"Dépendances manquantes: {e}")
    print("Installez avec: pip install flask pyjwt")
    sys.exit(1)

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiter avancé avec fenêtre glissante"""
    
    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = defaultdict(lambda: deque())
        self.lock = threading.Lock()
        
    def is_allowed(self, client_id: str) -> bool:
        """Vérifie si la requête est autorisée"""
        current_time = time.time()
        cutoff_time = current_time - self.window_seconds
        
        with self.lock:
            # Nettoyer les anciennes requêtes
            client_requests = self.requests[client_id]
            while client_requests and client_requests[0] < cutoff_time:
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
            active_clients = len([client for client, reqs in self.requests.items() if reqs])
            total_requests = sum(len(reqs) for reqs in self.requests.values())
            
            return {
                "active_clients": active_clients,
                "total_requests_tracked": total_requests,
                "max_requests_per_window": self.max_requests,
                "window_seconds": self.window_seconds
            }

class APIMetrics:
    """Collecteur de métriques API"""
    
    def __init__(self):
        self.start_time = time.time()
        self.requests_total = 0
        self.requests_success = 0
        self.requests_failed = 0
        self.requests_rate_limited = 0
        self.response_times = deque(maxlen=1000)
        self.active_agents = set()
        self.admin_logins = 0
        self.lock = threading.Lock()
        
    def record_request(self, success: bool, response_time: float, rate_limited: bool = False):
        """Enregistre une requête"""
        with self.lock:
            self.requests_total += 1
            if rate_limited:
                self.requests_rate_limited += 1
            elif success:
                self.requests_success += 1
            else:
                self.requests_failed += 1
                
            self.response_times.append(response_time)
            
    def record_agent_activity(self, agent_id: str):
        """Enregistre l'activité d'un agent"""
        with self.lock:
            self.active_agents.add(agent_id)
            
    def record_admin_login(self):
        """Enregistre une connexion admin"""
        with self.lock:
            self.admin_logins += 1
            
    def get_metrics(self) -> Dict[str, Any]:
        """Retourne les métriques"""
        with self.lock:
            avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0
            
            return {
                "uptime": time.time() - self.start_time,
                "requests_total": self.requests_total,
                "requests_success": self.requests_success,
                "requests_failed": self.requests_failed,
                "requests_rate_limited": self.requests_rate_limited,
                "avg_response_time": avg_response_time,
                "active_agents": list(self.active_agents),
                "admin_logins": self.admin_logins
            }

class QuietWSGIRequestHandler(WSGIRequestHandler):
    """Handler WSGI silencieux pour réduire les logs verbeux"""
    
    def log_request(self, code='-', size='-'):
        # Ne loguer que les erreurs
        if isinstance(code, int) and code >= 400:
            super().log_request(code, size)

class EzraxServerAPI:
    """
    API REST sécurisée pour le serveur central EZRAX
    """
    
    def __init__(self, db_manager, host="0.0.0.0", port=5000, api_key=None, 
                 enable_admin_api=True, jwt_secret=None):
        """
        Initialisation de l'API
        """
        self.db_manager = db_manager
        self.host = host
        self.port = port
        self.api_key = api_key or secrets.token_urlsafe(32)
        self.jwt_secret = jwt_secret or secrets.token_urlsafe(32)
        self.enable_admin_api = enable_admin_api
        
        # État du serveur
        self.is_running = False
        self.server = None
        self.server_thread = None
        
        # Métriques et rate limiting
        self.metrics = APIMetrics()
        self.rate_limiters = {
            "agents": RateLimiter(1000, 60),      # 1000 req/min pour agents
            "admin": RateLimiter(200, 60),        # 200 req/min pour admin
            "public": RateLimiter(50, 60)         # 50 req/min pour public
        }
        
        # Créer l'application Flask
        self.app = self._create_app()
        
        logger.info(f"API EZRAX initialisée sur {host}:{port}")
        
    def _create_app(self) -> Flask:
        """Crée l'application Flask avec toutes les routes"""
        app = Flask(__name__)
        app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
        
        # Configuration JSON
        app.json.ensure_ascii = False
        app.json.sort_keys = False
        
        # Middleware de métriques
        @app.before_request
        def before_request():
            g.start_time = time.time()
            
        @app.after_request
        def after_request(response):
            # Enregistrer les métriques
            response_time = time.time() - g.start_time
            success = 200 <= response.status_code < 400
            rate_limited = response.status_code == 429
            
            self.metrics.record_request(success, response_time, rate_limited)
            
            # Headers CORS sécurisés
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, X-API-Key, Authorization'
            
            return response
            
        # Gestionnaire d'erreurs global
        @app.errorhandler(Exception)
        def handle_exception(e):
            logger.error(f"Erreur API non gérée: {e}")
            logger.error(traceback.format_exc())
            
            if isinstance(e, (BadRequest, Unauthorized, Forbidden, NotFound, TooManyRequests)):
                return jsonify({"success": False, "error": str(e)}), e.code
                
            return jsonify({
                "success": False, 
                "error": "Erreur interne du serveur"
            }), 500
            
        # Routes API principales
        self._register_agent_routes(app)
        if self.enable_admin_api:
            self._register_admin_routes(app)
        self._register_public_routes(app)
        
        return app
        
    def _register_agent_routes(self, app):
        """Enregistre les routes pour les agents"""
        
        @app.route('/api/agents/register', methods=['POST'])
        @self._require_api_key
        @self._rate_limit("agents")
        def register_agent():
            """Enregistre un agent"""
            try:
                data = request.get_json()
                if not data:
                    abort(400, "Données JSON requises")
                    
                # Validation des données requises
                required_fields = ["agent_id", "hostname", "ip_address"]
                for field in required_fields:
                    if field not in data or not data[field]:
                        abort(400, f"Champ requis manquant: {field}")
                        
                # Validation UUID pour agent_id
                try:
                    import uuid
                    uuid.UUID(data["agent_id"])
                except ValueError:
                    abort(400, "agent_id doit être un UUID valide")
                    
                # Enregistrer l'agent
                success = self.db_manager.register_agent(data)
                
                if success:
                    self.metrics.record_agent_activity(data["agent_id"])
                    
                    # Récupérer les commandes en attente
                    pending_commands = self.db_manager.get_pending_commands(data["agent_id"])
                    
                    return jsonify({
                        "success": True,
                        "message": "Agent enregistré avec succès",
                        "commands": pending_commands,
                        "server_time": time.time()
                    })
                else:
                    abort(500, "Erreur lors de l'enregistrement de l'agent")
                    
            except Exception as e:
                logger.error(f"Erreur enregistrement agent: {e}")
                abort(500, "Erreur interne")
                
        @app.route('/api/agents/<agent_id>/sync', methods=['POST'])
        @self._require_api_key
        @self._rate_limit("agents")
        def sync_agent(agent_id):
            """Synchronise les données d'un agent"""
            try:
                data = request.get_json() or {}
                
                # Mettre à jour le statut de l'agent
                agent_stats = data.get("agent_stats", {})
                health_metrics = data.get("health_metrics", {})
                health_score = health_metrics.get("connection_health", 1.0)
                
                self.db_manager.update_agent_status(
                    agent_id, 
                    "online", 
                    request.remote_addr,
                    health_score
                )
                
                # Traiter les logs d'attaques
                attack_logs = data.get("attack_logs", [])
                if attack_logs:
                    count = self.db_manager.add_attack_logs(attack_logs)
                    logger.info(f"Agent {agent_id}: {count} logs d'attaques synchronisés")
                    
                # Traiter les IPs bloquées
                blocked_ips = data.get("blocked_ips", [])
                if blocked_ips:
                    count = self.db_manager.add_blocked_ips(blocked_ips)
                    logger.info(f"Agent {agent_id}: {count} IPs bloquées synchronisées")
                    
                self.metrics.record_agent_activity(agent_id)
                
                # Récupérer les commandes en attente
                pending_commands = self.db_manager.get_pending_commands(agent_id)
                
                # Récupérer la liste blanche mise à jour
                whitelist = self.db_manager.get_whitelist()
                
                return jsonify({
                    "success": True,
                    "commands": pending_commands,
                    "whitelist": whitelist,
                    "server_time": time.time()
                })
                
            except Exception as e:
                logger.error(f"Erreur synchronisation agent {agent_id}: {e}")
                abort(500, "Erreur lors de la synchronisation")
                
        @app.route('/api/agents/<agent_id>/heartbeat', methods=['POST'])
        @self._require_api_key
        @self._rate_limit("agents")
        def agent_heartbeat(agent_id):
            """Heartbeat d'un agent"""
            try:
                data = request.get_json() or {}
                
                status = data.get("status", "online")
                health_score = data.get("health_score", 1.0)
                
                # Mettre à jour le statut
                self.db_manager.update_agent_status(
                    agent_id, 
                    status, 
                    request.remote_addr,
                    health_score
                )
                
                self.metrics.record_agent_activity(agent_id)
                
                return jsonify({
                    "success": True,
                    "server_time": time.time()
                })
                
            except Exception as e:
                logger.error(f"Erreur heartbeat agent {agent_id}: {e}")
                abort(500, "Erreur lors du heartbeat")
                
        @app.route('/api/agents/<agent_id>/commands/<int:command_id>/ack', methods=['POST'])
        @self._require_api_key
        @self._rate_limit("agents")
        def acknowledge_command(agent_id, command_id):
            """Accusé de réception d'une commande"""
            try:
                data = request.get_json() or {}
                success = data.get("success", True)
                
                status = "executed" if success else "failed"
                self.db_manager.update_command_status(command_id, status)
                
                return jsonify({"success": True})
                
            except Exception as e:
                logger.error(f"Erreur ACK commande {command_id}: {e}")
                abort(500, "Erreur lors de l'accusé de réception")
                
    def _register_admin_routes(self, app):
        """Enregistre les routes d'administration"""
        
        @app.route('/api/admin/login', methods=['POST'])
        @self._rate_limit("admin")
        def admin_login():
            """Connexion administrateur"""
            try:
                data = request.get_json()
                if not data:
                    abort(400, "Données JSON requises")
                    
                username = data.get("username")
                password = data.get("password")
                
                if not username or not password:
                    abort(400, "Nom d'utilisateur et mot de passe requis")
                    
                # Authentifier l'administrateur
                session_id = self.db_manager.admin_manager.authenticate_admin(username, password)
                
                if session_id:
                    # Générer un token JWT
                    payload = {
                        "session_id": session_id,
                        "username": username,
                        "exp": datetime.utcnow() + timedelta(hours=8),
                        "iat": datetime.utcnow()
                    }
                    
                    token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")
                    
                    self.metrics.record_admin_login()
                    
                    return jsonify({
                        "success": True,
                        "token": token,
                        "expires_in": 28800  # 8 heures
                    })
                else:
                    abort(401, "Nom d'utilisateur ou mot de passe incorrect")
                    
            except Exception as e:
                logger.error(f"Erreur connexion admin: {e}")
                abort(500, "Erreur lors de la connexion")
                
        @app.route('/api/admin/dashboard', methods=['GET'])
        @self._require_admin_auth
        @self._rate_limit("admin")
        def admin_dashboard():
            """Tableau de bord administrateur"""
            try:
                # Statistiques globales
                global_stats = self.db_manager.get_global_stats()
                
                # Métriques API
                api_metrics = self.metrics.get_metrics()
                
                # Performance de la base de données
                db_metrics = self.db_manager.get_performance_metrics()
                
                return jsonify({
                    "success": True,
                    "data": {
                        "global_stats": global_stats,
                        "api_metrics": api_metrics,
                        "db_performance": db_metrics,
                        "server_info": {
                            "version": "2.0.0",
                            "host": self.host,
                            "port": self.port,
                            "uptime": time.time() - self.metrics.start_time
                        }
                    }
                })
                
            except Exception as e:
                logger.error(f"Erreur dashboard admin: {e}")
                abort(500, "Erreur lors du chargement du dashboard")
                
        @app.route('/api/admin/agents', methods=['GET'])
        @self._require_admin_auth
        @self._rate_limit("admin")
        def admin_list_agents():
            """Liste des agents pour l'admin"""
            try:
                include_offline = request.args.get('include_offline', 'true').lower() == 'true'
                agents = self.db_manager.get_agents(include_offline=include_offline)
                
                return jsonify({
                    "success": True,
                    "data": agents
                })
                
            except Exception as e:
                logger.error(f"Erreur liste agents admin: {e}")
                abort(500, "Erreur lors du chargement des agents")
                
        @app.route('/api/admin/attacks', methods=['GET'])
        @self._require_admin_auth
        @self._rate_limit("admin")
        def admin_list_attacks():
            """Liste des attaques pour l'admin"""
            try:
                limit = min(int(request.args.get('limit', 100)), 1000)
                offset = int(request.args.get('offset', 0))
                
                # Filtres optionnels
                since = request.args.get('since')
                if since:
                    since = float(since)
                    
                attack_type = request.args.get('attack_type')
                agent_id = request.args.get('agent_id')
                source_ip = request.args.get('source_ip')
                
                attacks = self.db_manager.get_attack_logs(
                    limit=limit,
                    offset=offset,
                    since=since,
                    attack_type=attack_type,
                    agent_id=agent_id,
                    source_ip=source_ip
                )
                
                return jsonify({
                    "success": True,
                    "data": attacks,
                    "pagination": {
                        "limit": limit,
                        "offset": offset,
                        "count": len(attacks)
                    }
                })
                
            except Exception as e:
                logger.error(f"Erreur liste attaques admin: {e}")
                abort(500, "Erreur lors du chargement des attaques")
                
        @app.route('/api/admin/commands', methods=['POST'])
        @self._require_admin_auth
        @self._rate_limit("admin")
        def admin_send_command():
            """Envoie une commande via l'admin"""
            try:
                data = request.get_json()
                if not data:
                    abort(400, "Données JSON requises")
                    
                agent_id = data.get("agent_id")
                command_type = data.get("command_type")
                command_data = data.get("command_data")
                priority = data.get("priority", 1)
                
                if not agent_id or not command_type:
                    abort(400, "agent_id et command_type requis")
                    
                # Obtenir l'utilisateur depuis le token
                username = g.get("admin_username", "admin")
                
                command_id = self.db_manager.add_command(
                    agent_id, command_type, command_data, username, priority
                )
                
                if command_id:
                    return jsonify({
                        "success": True,
                        "command_id": command_id,
                        "message": "Commande envoyée avec succès"
                    })
                else:
                    abort(500, "Erreur lors de l'envoi de la commande")
                    
            except Exception as e:
                logger.error(f"Erreur envoi commande admin: {e}")
                abort(500, "Erreur lors de l'envoi de la commande")
                
    def _register_public_routes(self, app):
        """Enregistre les routes publiques"""
        
        @app.route('/', methods=['GET'])
        def root():
            """Page d'accueil de l'API"""
            return jsonify({
                "service": "EZRAX Central Server API",
                "version": "2.0.0",
                "status": "online",
                "endpoints": {
                    "agents": "/api/agents/",
                    "admin": "/api/admin/" if self.enable_admin_api else None,
                    "health": "/api/health",
                    "metrics": "/api/metrics"
                }
            })
            
        @app.route('/api/health', methods=['GET'])
        @self._rate_limit("public")
        def health_check():
            """Vérification de santé"""
            try:
                # Test basique de la base de données
                agents_count = len(self.db_manager.get_agents())
                
                return jsonify({
                    "success": True,
                    "status": "healthy",
                    "timestamp": time.time(),
                    "agents_connected": agents_count,
                    "uptime": time.time() - self.metrics.start_time
                })
                
            except Exception as e:
                logger.error(f"Erreur health check: {e}")
                return jsonify({
                    "success": False,
                    "status": "unhealthy",
                    "error": str(e)
                }), 500
                
        @app.route('/api/metrics', methods=['GET'])
        @self._rate_limit("public")
        def public_metrics():
            """Métriques publiques"""
            try:
                metrics = self.metrics.get_metrics()
                
                # Métriques publiques seulement
                public_metrics = {
                    "uptime": metrics["uptime"],
                    "requests_total": metrics["requests_total"],
                    "avg_response_time": metrics["avg_response_time"],
                    "active_agents_count": len(metrics["active_agents"])
                }
                
                return jsonify({
                    "success": True,
                    "data": public_metrics
                })
                
            except Exception as e:
                logger.error(f"Erreur métriques publiques: {e}")
                abort(500, "Erreur lors du chargement des métriques")
                
    def _require_api_key(self, f):
        """Décorateur pour vérifier la clé API"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            api_key = request.headers.get('X-API-Key')
            
            if not api_key:
                logger.warning(f"Tentative d'accès sans clé API depuis {request.remote_addr}")
                abort(401, "Clé API requise")
                
            # Comparaison sécurisée des clés
            if not secrets.compare_digest(api_key, self.api_key):
                logger.warning(f"Tentative d'accès avec clé API invalide depuis {request.remote_addr}:{api_key}")
                abort(401, "Clé API invalide")
                
            return f(*args, **kwargs)
        return decorated_function
        
    def _require_admin_auth(self, f):
        """Décorateur pour vérifier l'authentification admin"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            
            if not auth_header or not auth_header.startswith('Bearer '):
                abort(401, "Token d'authentification requis")
                
            token = auth_header.split(' ')[1]
            
            try:
                payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
                session_id = payload.get("session_id")
                username = payload.get("username")
                
                # Valider la session
                session = self.db_manager.admin_manager.validate_session(session_id)
                if not session:
                    abort(401, "Session expirée")
                    
                # Stocker les infos dans g
                g.admin_session_id = session_id
                g.admin_username = username
                
            except jwt.ExpiredSignatureError:
                abort(401, "Token expiré")
            except jwt.InvalidTokenError:
                abort(401, "Token invalide")
                
            return f(*args, **kwargs)
        return decorated_function
        
    def _rate_limit(self, limiter_type):
        """Décorateur pour le rate limiting"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if limiter_type in self.rate_limiters:
                    limiter = self.rate_limiters[limiter_type]
                    client_id = request.remote_addr
                    
                    if not limiter.is_allowed(client_id):
                        abort(429, "Trop de requêtes")
                        
                return f(*args, **kwargs)
            return decorated_function
        return decorator
        
    def start(self):
        """Démarre le serveur API"""
        if self.is_running:
            logger.warning("Le serveur API est déjà en cours d'exécution")
            return
            
        try:
            self.server = make_server(
                self.host, 
                self.port, 
                self.app,
                request_handler=QuietWSGIRequestHandler,
                threaded=True
            )
            
            self.is_running = True
            
            logger.info(f"Serveur API EZRAX démarré sur http://{self.host}:{self.port}")
            logger.info(f"API Key: {self.api_key[:8]}...{self.api_key[-4:]}")
            
            # Démarrer le serveur (bloquant)
            self.server.serve_forever()
            
        except OSError as e:
            if e.errno == 98:  # Address already in use
                logger.error(f"Port {self.port} déjà utilisé")
            else:
                logger.error(f"Erreur lors du démarrage du serveur API: {e}")
            self.is_running = False
            raise
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du serveur API: {e}")
            self.is_running = False
            raise
            
    def start_async(self):
        """Démarre le serveur API en mode asynchrone"""
        if self.is_running:
            return
            
        self.server_thread = threading.Thread(target=self.start, daemon=True)
        self.server_thread.start()
        
        # Attendre que le serveur soit prêt
        max_wait = 10
        for _ in range(max_wait * 10):
            if self.is_running:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Le serveur n'a pas pu démarrer dans le délai imparti")
            
    def stop(self):
        """Arrête le serveur API"""
        if not self.is_running:
            return
            
        logger.info("Arrêt du serveur API...")
        
        if self.server:
            self.server.shutdown()
            
        self.is_running = False
        
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=5)
            
        logger.info("Serveur API arrêté")
        
    def get_api_metrics(self) -> Dict[str, Any]:
        """Retourne les métriques complètes de l'API"""
        return {
            "api_metrics": self.metrics.get_metrics(),
            "rate_limiters": {
                name: limiter.get_stats() 
                for name, limiter in self.rate_limiters.items()
            },
            "server_info": {
                "host": self.host,
                "port": self.port,
                "is_running": self.is_running,
                "admin_api_enabled": self.enable_admin_api
            }
        }

def main():
    """Point d'entrée principal pour les tests"""
    from db_manager import ServerDatabaseManager
    
    # Configuration de test
    db_manager = ServerDatabaseManager("test_server.db")
    api = EzraxServerAPI(db_manager)
    
    try:
        api.start()
    except KeyboardInterrupt:
        api.stop()

if __name__ == "__main__":
    main()
