#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
API REST Flask pour le serveur central EZRAX
"""

import os
import time
import json
import logging
import threading
import uuid
from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify, Response
from werkzeug.serving import make_server

logger = logging.getLogger(__name__)

class EzraxServerAPI:
    """
    API REST Flask pour le serveur central EZRAX
    """
    
    def __init__(self, db_manager, host="0.0.0.0", port=5000, api_key=None):
        """
        Initialisation de l'API
        
        Args:
            db_manager: Gestionnaire de base de données
            host: Adresse d'écoute
            port: Port d'écoute
            api_key: Clé API pour l'authentification
        """
        self.db_manager = db_manager
        self.host = host
        self.port = port
        self.api_key = api_key or self._load_or_generate_api_key()
        
        # Créer l'application Flask
        self.app = Flask(__name__)
        
        # Configurer les routes
        self._setup_routes()
        
        # Serveur HTTP
        self.server = None
        self.is_running = False
        
    def _load_or_generate_api_key(self):
        """
        Charge ou génère une clé API
        
        Returns:
            Clé API
        """
        # Essayer de charger la clé API depuis la base de données
        api_key = self.db_manager.get_config("api_key")
        
        if api_key:
            return api_key
            
        # Générer une nouvelle clé API
        api_key = str(uuid.uuid4())
        
        # Enregistrer la clé API dans la base de données
        self.db_manager.set_config("api_key", api_key)
        
        logger.info(f"Nouvelle clé API générée: {api_key}")
        return api_key
        
    def _setup_routes(self):
        """Configure les routes de l'API"""
        # Middleware pour l'authentification
        @self.app.before_request
        def auth_middleware():
            """Middleware d'authentification"""
            # Ignorer l'authentification pour certaines routes
            if request.path == '/api/health':
                return None
                
            # Vérifier la clé API
            api_key = request.headers.get('X-API-Key')
            
            if not api_key or api_key != self.api_key:
                return jsonify({"success": False, "message": "Clé API invalide"}), 401
                
        # Route de santé
        @self.app.route('/api/health', methods=['GET'])
        def health():
            """Route de santé"""
            return jsonify({
                "status": "ok",
                "timestamp": time.time()
            })
            
        # Routes pour les agents
        
        @self.app.route('/api/agents/register', methods=['POST'])
        def register_agent():
            """
            Enregistre un agent
            
            Exemple de requête:
            {
                "agent_id": "550e8400-e29b-41d4-a716-446655440000",
                "hostname": "ubuntu-vm-1",
                "ip_address": "192.168.1.100",
                "os_info": {...},
                "version": "1.0.0",
                "features": {...}
            }
            
            Exemple de réponse:
            {
                "success": true,
                "message": "Agent enregistré avec succès"
            }
            """
            try:
                data = request.json
                
                # Vérifier les données requises
                if not all(key in data for key in ["agent_id", "hostname", "ip_address"]):
                    return jsonify({
                        "success": False,
                        "message": "Données incomplètes"
                    }), 400
                    
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
                    "message": f"Erreur: {str(e)}"
                }), 500
                
        @self.app.route('/api/agents/<agent_id>/heartbeat', methods=['POST'])
        def agent_heartbeat(agent_id):
            """
            Reçoit un heartbeat d'un agent
            
            Exemple de requête:
            {
                "timestamp": 1621234567.89,
                "status": "online",
                "ip_address": "192.168.1.100",
                "uptime": 3600
            }
            
            Exemple de réponse:
            {
                "success": true
            }
            """
            try:
                data = request.json
                
                # Mettre à jour le statut de l'agent
                success = self.db_manager.update_agent_status(
                    agent_id,
                    data.get("status", "online"),
                    data.get("ip_address")
                )
                
                if success:
                    return jsonify({"success": True})
                else:
                    return jsonify({
                        "success": False,
                        "message": "Erreur lors de la mise à jour du statut de l'agent"
                    }), 500
                    
            except Exception as e:
                logger.error(f"Erreur lors du traitement du heartbeat: {e}")
                return jsonify({
                    "success": False,
                    "message": f"Erreur: {str(e)}"
                }), 500
                
        @self.app.route('/api/agents/<agent_id>/sync', methods=['POST'])
        def agent_sync(agent_id):
            """
            Synchronise les données avec un agent
            
            Exemple de requête:
            {
                "timestamp": 1621234567.89,
                "agent_stats": {...},
                "attack_logs": [...],
                "blocked_ips": [...]
            }
            
            Exemple de réponse:
            {
                "success": true,
                "whitelist": [...],
                "commands": [...]
            }
            """
            try:
                data = request.json
                
                # Mettre à jour le statut de l'agent
                self.db_manager.update_agent_status(agent_id, "online")
                
                # Traiter les logs d'attaques
                if "attack_logs" in data and data["attack_logs"]:
                    self.db_manager.add_attack_logs(data["attack_logs"])
                    
                # Traiter les IPs bloquées
                if "blocked_ips" in data and data["blocked_ips"]:
                    self.db_manager.add_blocked_ips(data["blocked_ips"])
                    
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
                    "message": f"Erreur: {str(e)}"
                }), 500
                
        @self.app.route('/api/agents/<agent_id>/commands/<int:command_id>/ack', methods=['POST'])
        def command_acknowledgment(agent_id, command_id):
            """
            Accusé de réception d'une commande
            
            Exemple de réponse:
            {
                "success": true
            }
            """
            try:
                # Mettre à jour le statut de la commande
                success = self.db_manager.update_command_status(command_id, "executed")
                
                if success:
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
                    "message": f"Erreur: {str(e)}"
                }), 500
                
        # Routes pour Grafana
        
        @self.app.route('/api/grafana/agents', methods=['GET'])
        def grafana_agents():
            """
            Récupère la liste des agents pour Grafana
            
            Exemple de réponse:
            [
                {
                    "agent_id": "550e8400-e29b-41d4-a716-446655440000",
                    "hostname": "ubuntu-vm-1",
                    "status": "online",
                    "ip_address": "192.168.1.100",
                    "last_seen": 1621234567.89
                },
                ...
            ]
            """
            try:
                # Récupérer les agents
                agents = self.db_manager.get_agents()
                
                # Filtrer les champs pour Grafana
                grafana_agents = []
                for agent in agents:
                    grafana_agents.append({
                        "agent_id": agent["agent_id"],
                        "hostname": agent["hostname"],
                        "status": agent["status"],
                        "ip_address": agent["ip_address"],
                        "last_seen": agent["last_seen"]
                    })
                    
                return jsonify(grafana_agents)
                
            except Exception as e:
                logger.error(f"Erreur lors de la récupération des agents pour Grafana: {e}")
                return jsonify({
                    "success": False,
                    "message": f"Erreur: {str(e)}"
                }), 500
                
        @self.app.route('/api/grafana/attacks', methods=['GET'])
        def grafana_attacks():
            """
            Récupère les logs d'attaques pour Grafana
            
            Paramètres:
            - limit: Nombre maximum de logs à récupérer
            - since: Timestamp à partir duquel récupérer les logs
            - agent_id: Filtrer par agent
            - attack_type: Filtrer par type d'attaque
            
            Exemple de réponse:
            [
                {
                    "id": 1,
                    "timestamp": 1621234567.89,
                    "attack_type": "SYN_FLOOD",
                    "source_ip": "192.168.1.100",
                    "agent_id": "550e8400-e29b-41d4-a716-446655440000",
                    "hostname": "ubuntu-vm-1"
                },
                ...
            ]
            """
            try:
                # Récupérer les paramètres
                limit = request.args.get('limit', 1000, type=int)
                since = request.args.get('since', type=float)
                agent_id = request.args.get('agent_id')
                attack_type = request.args.get('attack_type')
                
                # Récupérer les logs d'attaques
                logs = self.db_manager.get_attack_logs(
                    limit=limit,
                    since=since,
                    agent_id=agent_id,
                    attack_type=attack_type
                )
                
                # Ajouter les noms des agents
                agents = {agent["agent_id"]: agent for agent in self.db_manager.get_agents()}
                
                for log in logs:
                    if log["agent_id"] in agents:
                        log["hostname"] = agents[log["agent_id"]]["hostname"]
                    else:
                        log["hostname"] = "Inconnu"
                        
                return jsonify(logs)
                
            except Exception as e:
                logger.error(f"Erreur lors de la récupération des logs d'attaques pour Grafana: {e}")
                return jsonify({
                    "success": False,
                    "message": f"Erreur: {str(e)}"
                }), 500
                
        @self.app.route('/api/grafana/blocked_ips', methods=['GET'])
        def grafana_blocked_ips():
            """
            Récupère les IPs bloquées pour Grafana
            
            Paramètres:
            - include_expired: Inclure les IPs dont le blocage a expiré
            - agent_id: Filtrer par agent
            
            Exemple de réponse:
            [
                {
                    "id": 1,
                    "agent_id": "550e8400-e29b-41d4-a716-446655440000",
                    "hostname": "ubuntu-vm-1",
                    "ip": "192.168.1.100",
                    "timestamp": 1621234567.89,
                    "reason": "SYN_FLOOD",
                    "duration": 3600
                },
                ...
            ]
            """
            try:
                # Récupérer les paramètres
                include_expired = request.args.get('include_expired', 'false').lower() == 'true'
                agent_id = request.args.get('agent_id')
                
                # Récupérer les IPs bloquées
                blocked_ips = self.db_manager.get_blocked_ips(
                    include_expired=include_expired,
                    agent_id=agent_id
                )
                
                # Ajouter les noms des agents
                agents = {agent["agent_id"]: agent for agent in self.db_manager.get_agents()}
                
                for block in blocked_ips:
                    if block["agent_id"] in agents:
                        block["hostname"] = agents[block["agent_id"]]["hostname"]
                    else:
                        block["hostname"] = "Inconnu"
                        
                return jsonify(blocked_ips)
                
            except Exception as e:
                logger.error(f"Erreur lors de la récupération des IPs bloquées pour Grafana: {e}")
                return jsonify({
                    "success": False,
                    "message": f"Erreur: {str(e)}"
                }), 500
                
        @self.app.route('/api/grafana/stats', methods=['GET'])
        def grafana_stats():
            """
            Récupère les statistiques pour Grafana
            
            Paramètres:
            - agent_id: Filtrer par agent
            
            Exemple de réponse:
            {
                "total_agents": 10,
                "active_agents": 5,
                "total_attacks": 100,
                "blocked_ips": 20,
                "attacks_by_type": {
                    "SYN_FLOOD": 50,
                    "UDP_FLOOD": 30,
                    "PORT_SCAN": 15,
                    "PING_FLOOD": 5
                },
                "top_attackers": [
                    {"ip": "192.168.1.100", "count": 50},
                    ...
                ]
            }
            """
            try:
                # Récupérer les paramètres
                agent_id = request.args.get('agent_id')
                
                # Récupérer les statistiques
                if agent_id:
                    stats = self.db_manager.get_agent_stats(agent_id)
                else:
                    stats = self.db_manager.get_global_stats()
                    
                return jsonify(stats)
                
            except Exception as e:
                logger.error(f"Erreur lors de la récupération des statistiques pour Grafana: {e}")
                return jsonify({
                    "success": False,
                    "message": f"Erreur: {str(e)}"
                }), 500
                
    def start(self):
        """Démarre le serveur API"""
        if self.is_running:
            logger.warning("Le serveur API est déjà en cours d'exécution")
            return
            
        try:
            logger.info(f"Démarrage du serveur API sur {self.host}:{self.port}")
            
            # Créer le serveur HTTP
            self.server = make_server(self.host, self.port, self.app)
            self.is_running = True
            
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
            self.server.shutdown()
            self.is_running = False
            
        except Exception as e:
            logger.error(f"Erreur lors de l'arrêt du serveur API: {e}")
