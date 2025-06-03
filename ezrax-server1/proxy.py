#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Proxy optimisé pour l'API Grafana du serveur EZRAX
Version 2.0 - Sécurité renforcée et performances améliorées
"""

import os
import json
import time
import logging
import threading
import ipaddress
import requests
import hashlib
from datetime import datetime, timedelta
from urllib.parse import urljoin
from typing import Dict, List, Any, Optional, Union

from flask import Flask, request, Response, jsonify, g
from werkzeug.middleware.proxy_fix import ProxyFix

# Configuration du logging avec rotation
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler(
            "ezrax_proxy.log",
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5
        )
    ]
)
logger = logging.getLogger(__name__)

class RequestCache:
    """Cache des requêtes pour optimiser les performances"""
    
    def __init__(self, max_size=100, ttl=60):
        """
        Initialise le cache
        
        Args:
            max_size: Taille maximale du cache
            ttl: Durée de vie des entrées en secondes
        """
        self.cache = {}
        self.cache_times = {}
        self.ttl = ttl
        self.max_size = max_size
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        
    def get(self, key: str) -> Optional[Any]:
        """Récupère une valeur du cache si elle est toujours valide"""
        with self.lock:
            if key in self.cache:
                timestamp = self.cache_times.get(key, 0)
                if time.time() - timestamp <= self.ttl:
                    self.hits += 1
                    return self.cache[key]
                else:
                    # Expiré, supprimer
                    del self.cache[key]
                    del self.cache_times[key]
            
            self.misses += 1
            return None
            
    def set(self, key: str, value: Any):
        """Stocke une valeur dans le cache"""
        with self.lock:
            # Nettoyer le cache si nécessaire
            if len(self.cache) >= self.max_size:
                self._clean_cache()
                
            self.cache[key] = value
            self.cache_times[key] = time.time()
            
    def _clean_cache(self):
        """Nettoie le cache en supprimant les entrées les plus anciennes"""
        # Supprimer d'abord les entrées expirées
        current_time = time.time()
        expired_keys = [
            k for k, timestamp in self.cache_times.items()
            if current_time - timestamp > self.ttl
        ]
        
        for key in expired_keys:
            del self.cache[key]
            del self.cache_times[key]
            
        # Si toujours trop grand, supprimer les plus anciennes
        if len(self.cache) >= self.max_size:
            # Trier par ancienneté
            sorted_keys = sorted(
                self.cache_times.items(),
                key=lambda x: x[1]
            )
            
            # Supprimer 25% des entrées les plus anciennes
            keys_to_remove = sorted_keys[:max(1, len(sorted_keys) // 4)]
            for key, _ in keys_to_remove:
                del self.cache[key]
                del self.cache_times[key]
                
    def clear(self):
        """Vide le cache"""
        with self.lock:
            self.cache.clear()
            self.cache_times.clear()
            
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du cache"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests) if total_requests > 0 else 0
            
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "ttl": self.ttl,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": hit_rate
            }

class SecurityManager:
    """Gestionnaire de sécurité pour le proxy"""
    
    def __init__(self, api_key: str):
        """
        Initialise le gestionnaire de sécurité
        
        Args:
            api_key: Clé API pour l'authentification
        """
        self.api_key = api_key
        self.whitelist = set()  # IPs autorisées (vide = toutes)
        self.blacklist = {}  # {ip: expiry}
        self.rate_limits = {}  # {ip: {window: count}}
        self.requests_per_minute = 120
        self.lock = threading.RLock()
        
    def is_allowed(self, client_ip: str) -> bool:
        """Vérifie si une IP est autorisée"""
        with self.lock:
            # Vérifier la blacklist
            if client_ip in self.blacklist:
                if time.time() < self.blacklist[client_ip]:
                    return False
                else:
                    # Expirée, supprimer
                    del self.blacklist[client_ip]
            
            # Vérifier la whitelist (si non vide)
            if self.whitelist and client_ip not in self.whitelist:
                return False
                
            # Vérifier le rate limiting
            minute_window = int(time.time() // 60)
            
            if client_ip not in self.rate_limits:
                self.rate_limits[client_ip] = {}
                
            ip_counts = self.rate_limits[client_ip]
            current_count = ip_counts.get(minute_window, 0)
            
            if current_count >= self.requests_per_minute:
                return False
                
            # Incrémenter le compteur
            ip_counts[minute_window] = current_count + 1
            
            # Nettoyer les anciennes fenêtres
            self._cleanup_old_windows(client_ip, minute_window)
            
            return True
            
    def _cleanup_old_windows(self, client_ip: str, current_window: int):
        """Nettoie les anciennes fenêtres de temps"""
        if client_ip in self.rate_limits:
            ip_counts = self.rate_limits[client_ip]
            
            # Supprimer les fenêtres plus anciennes que 5 minutes
            old_windows = [w for w in ip_counts.keys() if w < current_window - 5]
            for window in old_windows:
                del ip_counts[window]
                
            # Supprimer l'entrée si vide
            if not ip_counts:
                del self.rate_limits[client_ip]
                
    def blacklist_ip(self, client_ip: str, duration: int = 300):
        """Ajoute une IP à la blacklist temporairement"""
        with self.lock:
            self.blacklist[client_ip] = time.time() + duration
            
    def whitelist_ip(self, client_ip: str):
        """Ajoute une IP à la whitelist"""
        with self.lock:
            self.whitelist.add(client_ip)
            
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de sécurité"""
        with self.lock:
            return {
                "whitelist_size": len(self.whitelist),
                "blacklist_size": len(self.blacklist),
                "rate_limited_ips": len(self.rate_limits),
                "requests_per_minute": self.requests_per_minute
            }

class GrafanaProxy:
    """Proxy optimisé pour Grafana"""
    
    def __init__(self, server_url: str, api_key: str, debug: bool = False):
        """
        Initialise le proxy Grafana
        
        Args:
            server_url: URL du serveur EZRAX
            api_key: Clé API pour l'authentification
            debug: Mode debug
        """
        self.server_url = server_url.rstrip('/')
        self.api_key = api_key
        self.debug = debug
        
        # Composants de sécurité et performance
        self.cache = RequestCache(max_size=200, ttl=60)
        self.security = SecurityManager(api_key)
        
        # Session HTTP pour la réutilisation des connexions
        self.session = requests.Session()
        
        # Adapter avec retry automatique
        retry_adapter = requests.adapters.HTTPAdapter(
            max_retries=3,
            pool_connections=10,
            pool_maxsize=20
        )
        self.session.mount('http://', retry_adapter)
        self.session.mount('https://', retry_adapter)
        
        # Métriques de performance
        self.metrics = {
            "requests_total": 0,
            "requests_success": 0,
            "requests_error": 0,
            "avg_response_time": 0.0,
            "data_bytes_transferred": 0
        }
        self.metrics_lock = threading.RLock()
        
        # Créer l'application Flask
        self.app = Flask(__name__)
        
        # Support des proxys pour obtenir l'IP réelle du client
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_for=1)
        
        # Configuration Flask
        self.app.config.update({
            'SECRET_KEY': os.urandom(24).hex(),
            'JSON_SORT_KEYS': False,
            'JSONIFY_PRETTYPRINT_REGULAR': debug,
            'MAX_CONTENT_LENGTH': 5 * 1024 * 1024,  # 5 MB max
            'JSON_AS_ASCII': False
        })
        
        # Configurer les routes
        self._setup_routes()
        
    def _setup_routes(self):
        """Configure les routes du proxy"""
        
        # Middleware pour les métriques et la sécurité
        @self.app.before_request
        def before_request_middleware():
            """Middleware avant requête"""
            try:
                # Enregistrer l'heure de début pour le calcul du temps de réponse
                g.request_start_time = time.time()
                
                # Récupérer l'IP du client (avec support proxy)
                client_ip = request.remote_addr
                if 'X-Forwarded-For' in request.headers:
                    forwarded_ip = request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
                    try:
                        ipaddress.ip_address(forwarded_ip)
                        client_ip = forwarded_ip
                    except (ValueError, TypeError):
                        pass
                        
                g.client_ip = client_ip
                
                # Vérifier la sécurité
                if not self.security.is_allowed(client_ip):
                    return jsonify({
                        "status": "error",
                        "message": "Trop de requêtes ou accès non autorisé"
                    }), 429
                
            except Exception as e:
                logger.error(f"Erreur middleware: {e}")
                return jsonify({"status": "error", "message": str(e)}), 500
                
        @self.app.after_request
        def after_request_middleware(response):
            """Middleware après requête pour métriques"""
            try:
                if hasattr(g, 'request_start_time'):
                    response_time = time.time() - g.request_start_time
                    
                    # Mettre à jour les métriques
                    with self.metrics_lock:
                        self.metrics["requests_total"] += 1
                        
                        if 200 <= response.status_code < 400:
                            self.metrics["requests_success"] += 1
                        else:
                            self.metrics["requests_error"] += 1
                            
                        # Moyenne mobile du temps de réponse
                        alpha = 0.1  # Facteur de lissage
                        if self.metrics["avg_response_time"] == 0:
                            self.metrics["avg_response_time"] = response_time
                        else:
                            self.metrics["avg_response_time"] = (
                                alpha * response_time + 
                                (1 - alpha) * self.metrics["avg_response_time"]
                            )
                            
                        # Taille des données
                        if hasattr(response, 'data'):
                            self.metrics["data_bytes_transferred"] += len(response.data)
                    
                    # Ajouter des en-têtes de performance
                    response.headers['X-Response-Time'] = f"{response_time:.6f}"
                
                # Ajouter des en-têtes de sécurité
                response.headers['X-Content-Type-Options'] = 'nosniff'
                response.headers['X-Frame-Options'] = 'DENY'
                
                return response
            except Exception as e:
                logger.error(f"Erreur middleware après requête: {e}")
                return response
        
        # Route d'accueil
        @self.app.route('/', methods=['GET'])
        def home():
            """Page d'accueil pour vérifier que le proxy fonctionne"""
            stats = self.get_metrics()
            
            return jsonify({
                "status": "ok",
                "message": "EZRAX Grafana Proxy est opérationnel",
                "version": "2.0.0",
                "timestamp": time.time(),
                "metrics": {
                    "uptime": stats["uptime_formatted"],
                    "requests": stats["requests_total"],
                    "cache_hit_rate": f"{stats['cache_hit_rate']:.2%}"
                },
                "available_routes": self._get_grafana_routes()
            })
            
        # Routes Grafana SimpleJSON
        
        @self.app.route('/search', methods=['POST'])
        def search():
            """Endpoint requis par Grafana SimpleJSON pour lister les métriques disponibles"""
            logger.info("Requête Grafana search reçue")
            return jsonify(self._get_grafana_routes())
            
        @self.app.route('/query', methods=['POST'])
        def query():
            """
            Endpoint principal pour les requêtes Grafana - Version optimisée
            """
            try:
                logger.info(f"Requête Grafana query reçue")
                
                data = request.get_json()
                if not data or 'targets' not in data:
                    logger.error("Format de requête invalide")
                    return jsonify([])
                    
                results = []
                
                # Générer un cache key basé sur la requête
                cache_key = self._generate_cache_key(data)
                cached_result = self.cache.get(cache_key)
                
                if cached_result is not None:
                    logger.info("Résultat récupéré du cache")
                    return jsonify(cached_result)
                
                # Traiter chaque cible demandée
                for target in data['targets']:
                    if 'target' not in target:
                        continue
                        
                    route = target['target']
                    
                    if route not in self._get_grafana_routes():
                        logger.warning(f"Route inconnue demandée: {route}")
                        continue
                        
                    # Faire la requête au serveur EZRAX avec les bons paramètres
                    grafana_data = self._fetch_grafana_data(route, data)
                    
                    if grafana_data:
                        route_results = self._format_grafana_results(route, grafana_data, data)
                        results.extend(route_results)
                
                # Mettre en cache si non vide
                if results:
                    self.cache.set(cache_key, results)
                
                logger.info(f"Renvoi de {len(results)} résultats à Grafana")
                return jsonify(results)
                
            except Exception as e:
                logger.error(f"Erreur traitement requête Grafana: {e}")
                return jsonify([])
                
        # Route de proxy générique
        
        @self.app.route('/<path:path>', methods=['GET', 'POST'])
        def proxy(path):
            """Proxy pour toutes les autres requêtes vers le serveur EZRAX"""
            try:
                logger.info(f"Proxying request to {path}")
                
                # Construire l'URL
                url = f"{self.server_url}/api/grafana/{path}"
                
                # Préparer les en-têtes
                headers = {
                    'X-API-Key': self.api_key,
                    'Content-Type': 'application/json'
                }
                
                # Ajouter les en-têtes de la requête originale (sauf sensibles)
                for header, value in request.headers.items():
                    if header.lower() not in ['host', 'content-length', 'connection', 'x-api-key']:
                        headers[header] = value
                
                # Envoyer la requête au serveur
                start_time = time.time()
                
                if request.method == 'GET':
                    resp = self.session.get(
                        url,
                        headers=headers,
                        params=request.args,
                        timeout=10
                    )
                else:  # POST
                    resp = self.session.post(
                        url,
                        headers=headers,
                        params=request.args,
                        json=request.get_json(silent=True),
                        timeout=10
                    )
                
                response_time = time.time() - start_time
                logger.info(f"Réponse de {url}: {resp.status_code} en {response_time:.3f}s")
                
                # Mettre à jour les métriques
                with self.metrics_lock:
                    self.metrics["data_bytes_transferred"] += len(resp.content)
                
                # Créer la réponse
                return Response(
                    resp.content,
                    status=resp.status_code,
                    content_type=resp.headers.get('content-type', 'application/json')
                )
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Erreur requête HTTP: {e}")
                return jsonify({"error": str(e)}), 502
            except Exception as e:
                logger.error(f"Erreur proxy: {e}")
                return jsonify({"error": str(e)}), 500
                
        # Routes de monitoring du proxy
        
        @self.app.route('/proxy/metrics', methods=['GET'])
        def proxy_metrics():
            """Retourne les métriques du proxy"""
            return jsonify(self.get_metrics())
            
        @self.app.route('/proxy/cache/clear', methods=['POST'])
        def clear_cache():
            """Vide le cache du proxy"""
            self.cache.clear()
            return jsonify({
                "status": "ok",
                "message": "Cache vidé",
                "timestamp": time.time()
            })
            
        # Gestionnaires d'erreurs
        
        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({
                "status": "error",
                "message": "Endpoint non trouvé"
            }), 404
            
        @self.app.errorhandler(500)
        def server_error(error):
            return jsonify({
                "status": "error",
                "message": "Erreur interne du serveur",
                "error": str(error) if self.debug else None
            }), 500
    
    def _get_grafana_routes(self) -> List[str]:
        """Retourne la liste des routes Grafana disponibles"""
        return [
            "agents",
            "attacks",
            "blocked_ips",
            "stats",
            "agent_uptime",
            "attack_types",
            "blocked_reasons"
        ]
        
    def _generate_cache_key(self, data: Dict[str, Any]) -> str:
        """Génère une clé de cache basée sur la requête"""
        # Extraire les éléments importants
        targets = [t.get('target') for t in data.get('targets', [])]
        range_from = data.get('range', {}).get('from', '')
        range_to = data.get('range', {}).get('to', '')
        
        # Créer une chaîne à hacher
        key_str = f"{','.join(targets)}|{range_from}|{range_to}"
        
        # Générer un hash MD5
        return hashlib.md5(key_str.encode()).hexdigest()
        
    def _fetch_grafana_data(self, route: str, grafana_query: Dict[str, Any]) -> Any:
        """
        Récupère les données Grafana du serveur EZRAX
        
        Args:
            route: Route Grafana à interroger
            grafana_query: Requête Grafana originale
            
        Returns:
            Données récupérées ou None en cas d'erreur
        """
        try:
            # Construire l'URL
            url = f"{self.server_url}/api/grafana/{route}"
            
            # Préparer les paramètres de requête
            params = {}
            
            # Convertir les timestamps Grafana en paramètres
            if 'range' in grafana_query:
                range_data = grafana_query['range']
                
                # Calculer le nombre d'heures
                try:
                    from_time = self._parse_grafana_time(range_data.get('from', ''))
                    to_time = self._parse_grafana_time(range_data.get('to', ''))
                    
                    if from_time and to_time:
                        hours = max(1, int((to_time - from_time).total_seconds() / 3600))
                        params['hours'] = str(hours)
                except:
                    # Fallback à 24h par défaut
                    params['hours'] = '24'
            
            # Faire la requête
            headers = {
                'X-API-Key': self.api_key,
                'Content-Type': 'application/json'
            }
            
            response = self.session.get(
                url,
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Erreur API Grafana {route}: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Erreur récupération données Grafana {route}: {e}")
            return None
            
    def _parse_grafana_time(self, time_str: str) -> Optional[datetime]:
        """
        Parse une chaîne de temps Grafana
        
        Args:
            time_str: Chaîne de temps Grafana (ex: "2020-01-01T00:00:00.000Z")
            
        Returns:
            Objet datetime ou None en cas d'erreur
        """
        try:
            # Format ISO
            if 'T' in time_str and ('Z' in time_str or '+' in time_str):
                return datetime.fromisoformat(time_str.replace('Z', '+00:00'))
            
            # Format epoch (ms)
            if time_str.isdigit():
                timestamp = int(time_str) / 1000  # ms -> s
                return datetime.fromtimestamp(timestamp)
            
            # Format relatif (now-1h, etc.)
            if time_str.startswith('now'):
                now = datetime.now()
                
                if time_str == 'now':
                    return now
                    
                # now-1h, now-2d, etc.
                if '-' in time_str:
                    parts = time_str.split('-')
                    if len(parts) != 2:
                        return now
                        
                    value = parts[1]
                    
                    # Extraire le nombre et l'unité
                    import re
                    match = re.match(r'(\d+)([smhdw])', value)
                    if not match:
                        return now
                        
                    amount = int(match.group(1))
                    unit = match.group(2)
                    
                    # Convertir en timedelta
                    if unit == 's':
                        return now - timedelta(seconds=amount)
                    elif unit == 'm':
                        return now - timedelta(minutes=amount)
                    elif unit == 'h':
                        return now - timedelta(hours=amount)
                    elif unit == 'd':
                        return now - timedelta(days=amount)
                    elif unit == 'w':
                        return now - timedelta(weeks=amount)
            
            return None
            
        except Exception as e:
            logger.error(f"Erreur parsing time Grafana {time_str}: {e}")
            return None
            
    def _format_grafana_results(self, route: str, data: Any, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Formate les données pour Grafana SimpleJSON
        
        Args:
            route: Route Grafana
            data: Données récupérées
            query: Requête Grafana originale
            
        Returns:
            Liste de résultats formatés
        """
        results = []
        
        try:
            # Format de la réponse dépend du type de route
            if route == "agents":
                results = self._format_agents_data(data, query)
            elif route == "attacks":
                results = self._format_attacks_data(data, query)
            elif route == "blocked_ips":
                results = self._format_blocked_ips_data(data, query)
            elif route == "stats":
                results = self._format_stats_data(data, query)
            elif route == "attack_types":
                results = self._format_attack_types_data(data, query)
            else:
                # Format générique
                results.append({
                    "target": route,
                    "datapoints": [[len(data) if isinstance(data, list) else 1, int(time.time() * 1000)]],
                    "type": "table",
                    "columns": [{"text": "value", "type": "number"}],
                    "rows": [[len(data) if isinstance(data, list) else 1]]
                })
                
        except Exception as e:
            logger.error(f"Erreur formatage résultats Grafana {route}: {e}")
            
        return results
        
    def _format_agents_data(self, data: List[Dict[str, Any]], query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Formate les données d'agents pour Grafana"""
        results = []
        
        try:
            # Tableaux pour la vue générale
            if isinstance(data, list):
                # Tableau avec tous les agents
                results.append({
                    "type": "table",
                    "columns": [
                        {"text": "Hostname", "type": "string"},
                        {"text": "Status", "type": "string"},
                        {"text": "IP", "type": "string"},
                        {"text": "Last Seen", "type": "time"},
                        {"text": "Version", "type": "string"}
                    ],
                    "rows": [
                        [
                            agent.get("hostname", ""),
                            agent.get("status", ""),
                            agent.get("ip_address", ""),
                            agent.get("last_seen", 0) * 1000,  # Convert to ms
                            agent.get("version", "")
                        ]
                        for agent in data
                    ]
                })
                
                # Séries pour les statuts
                statuses = {"online": 0, "offline": 0}
                for agent in data:
                    status = agent.get("status", "unknown")
                    statuses[status] = statuses.get(status, 0) + 1
                    
                # Ajouter une série pour chaque statut
                timestamp = int(time.time() * 1000)
                for status, count in statuses.items():
                    results.append({
                        "target": f"agents_{status}",
                        "datapoints": [[count, timestamp]]
                    })
                
                # Total des agents
                results.append({
                    "target": "agents_total",
                    "datapoints": [[len(data), timestamp]]
                })
                
        except Exception as e:
            logger.error(f"Erreur formatage agents: {e}")
            
        return results
        
    def _format_attacks_data(self, data: List[Dict[str, Any]], query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Formate les données d'attaques pour Grafana"""
        results = []
        
        try:
            # Tableau d'attaques
            if isinstance(data, list):
                # Tableau
                results.append({
                    "type": "table",
                    "columns": [
                        {"text": "Time", "type": "time"},
                        {"text": "Attack Type", "type": "string"},
                        {"text": "Source IP", "type": "string"},
                        {"text": "Severity", "type": "string"}
                    ],
                    "rows": [
                        [
                            attack.get("timestamp", 0) * 1000,  # Convert to ms
                            attack.get("attack_type", ""),
                            attack.get("source_ip", ""),
                            attack.get("severity", "MEDIUM")
                        ]
                        for attack in data
                    ]
                })
                
                # Séries par type d'attaque
                attack_types = {}
                for attack in data:
                    attack_type = attack.get("attack_type", "UNKNOWN")
                    attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                    
                # Ajouter une série pour chaque type d'attaque
                timestamp = int(time.time() * 1000)
                for attack_type, count in attack_types.items():
                    results.append({
                        "target": f"attacks_{attack_type}",
                        "datapoints": [[count, timestamp]]
                    })
                    
                # Série pour le total
                results.append({
                    "target": "attacks_total",
                    "datapoints": [[len(data), timestamp]]
                })
                
                # Séries par sévérité
                severities = {}
                for attack in data:
                    severity = attack.get("severity", "MEDIUM")
                    severities[severity] = severities.get(severity, 0) + 1
                    
                for severity, count in severities.items():
                    results.append({
                        "target": f"attacks_severity_{severity}",
                        "datapoints": [[count, timestamp]]
                    })
                
        except Exception as e:
            logger.error(f"Erreur formatage attacks: {e}")
            
        return results
        
    def _format_blocked_ips_data(self, data: List[Dict[str, Any]], query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Formate les données d'IPs bloquées pour Grafana"""
        results = []
        
        try:
            # Tableau d'IPs bloquées
            if isinstance(data, list):
                # Tableau
                results.append({
                    "type": "table",
                    "columns": [
                        {"text": "IP", "type": "string"},
                        {"text": "Blocked At", "type": "time"},
                        {"text": "Reason", "type": "string"},
                        {"text": "Duration", "type": "number"}
                    ],
                    "rows": [
                        [
                            block.get("ip", ""),
                            block.get("timestamp", 0) * 1000,  # Convert to ms
                            block.get("reason", ""),
                            block.get("duration", 0) / 3600  # Convert to hours
                        ]
                        for block in data
                    ]
                })
                
                # Séries par raison
                reasons = {}
                for block in data:
                    reason = block.get("reason", "UNKNOWN")
                    reasons[reason] = reasons.get(reason, 0) + 1
                    
                # Ajouter une série pour chaque raison
                timestamp = int(time.time() * 1000)
                for reason, count in reasons.items():
                    results.append({
                        "target": f"blocked_{reason}",
                        "datapoints": [[count, timestamp]]
                    })
                    
                # Série pour le total
                results.append({
                    "target": "blocked_total",
                    "datapoints": [[len(data), timestamp]]
                })
                
        except Exception as e:
            logger.error(f"Erreur formatage blocked_ips: {e}")
            
        return results
        
    def _format_stats_data(self, data: Dict[str, Any], query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Formate les données de statistiques pour Grafana"""
        results = []
        
        try:
            if isinstance(data, dict):
                # Série temporelle pour chaque métrique principale
                timestamp = int(time.time() * 1000)
                
                for metric, value in data.items():
                    if isinstance(value, (int, float)):
                        results.append({
                            "target": f"stats_{metric}",
                            "datapoints": [[value, timestamp]]
                        })
                    elif isinstance(value, dict):
                        # Traiter les sous-métriques
                        for sub_metric, sub_value in value.items():
                            if isinstance(sub_value, (int, float)):
                                results.append({
                                    "target": f"stats_{metric}_{sub_metric}",
                                    "datapoints": [[sub_value, timestamp]]
                                })
                
        except Exception as e:
            logger.error(f"Erreur formatage stats: {e}")
            
        return results
        
    def _format_attack_types_data(self, data: Dict[str, Any], query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Formate les données de types d'attaque pour Grafana"""
        results = []
        
        try:
            if isinstance(data, dict) and "attacks_by_type" in data:
                attack_types = data["attacks_by_type"]
                
                # Série pour chaque type d'attaque
                timestamp = int(time.time() * 1000)
                
                for attack_type, count in attack_types.items():
                    results.append({
                        "target": f"attack_type_{attack_type}",
                        "datapoints": [[count, timestamp]]
                    })
                
        except Exception as e:
            logger.error(f"Erreur formatage attack_types: {e}")
            
        return results
        
    def get_metrics(self) -> Dict[str, Any]:
        """Retourne les métriques complètes du proxy"""
        with self.metrics_lock:
            metrics = self.metrics.copy()
            
        # Ajouter les statistiques du cache
        cache_stats = self.cache.get_stats()
        metrics["cache"] = cache_stats
        metrics["cache_hit_rate"] = cache_stats["hit_rate"]
        
        # Ajouter les statistiques de sécurité
        metrics["security"] = self.security.get_stats()
        
        # Statistiques supplémentaires
        metrics["uptime"] = time.time() - self._get_start_time()
        metrics["uptime_formatted"] = self._format_uptime(metrics["uptime"])
        
        return metrics
        
    def _get_start_time(self) -> float:
        """Retourne l'heure de démarrage du proxy"""
        return getattr(self, "start_time", time.time())
        
    def _format_uptime(self, seconds: float) -> str:
        """Formate la durée d'uptime"""
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
            
    def run(self, host='0.0.0.0', port=5002, debug=False):
        """Démarre le serveur proxy"""
        # Enregistrer l'heure de démarrage
        self.start_time = time.time()
        logger.info(f"Démarrage du proxy Grafana EZRAX sur {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)


def main():
    """Point d'entrée principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Proxy Grafana pour EZRAX")
    parser.add_argument("--host", default="0.0.0.0", help="Adresse d'écoute (défaut: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5002, help="Port d'écoute (défaut: 5002)")
    parser.add_argument("--server", default="http://localhost:5000", help="URL du serveur EZRAX (défaut: http://localhost:5000)")
    parser.add_argument("--api-key", required=True, help="Clé API pour l'authentification")
    parser.add_argument("--debug", action="store_true", help="Activer le mode debug")
    
    args = parser.parse_args()
    
    # Créer et démarrer le proxy
    proxy = GrafanaProxy(args.server, args.api_key, args.debug)
    proxy.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
