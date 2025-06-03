#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gestionnaire de base de données SQLite pour le serveur central EZRAX
"""

import os
import time
import json
import uuid
import logging
import sqlite3
import threading
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class ServerDatabaseManager:
    """
    Gestionnaire de base de données SQLite pour le serveur central EZRAX
    """
    
    def __init__(self, db_path="ezrax_server.db"):
        """
        Initialisation du gestionnaire de base de données
        
        Args:
            db_path: Chemin de la base de données SQLite
        """
        self.db_path = db_path
        self.lock = threading.Lock()
        
        # Initialiser la base de données
        self._init_database()
        
    def _init_database(self):
        """Initialise la base de données SQLite avec les tables nécessaires"""
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Table des agents
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                ip_address TEXT,
                status TEXT DEFAULT 'offline',
                registered_at REAL,
                last_seen REAL,
                os_info TEXT,
                version TEXT,
                features TEXT
            )
            ''')
            
            # Table des logs d'attaques
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                attack_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                scanner TEXT NOT NULL,
                details TEXT NOT NULL,
                processed INTEGER DEFAULT 0,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
            ''')
            
            # Table des IPs bloquées
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                ip TEXT NOT NULL,
                timestamp REAL NOT NULL,
                end_time REAL,
                reason TEXT NOT NULL,
                duration INTEGER NOT NULL,
                processed INTEGER DEFAULT 0,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
            ''')
            
            # Table des commandes
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                command_type TEXT NOT NULL,
                command_data TEXT,
                status TEXT DEFAULT 'pending',
                created_at REAL NOT NULL,
                executed_at REAL,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
            ''')
            
            # Table de la liste blanche
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                added_at REAL NOT NULL,
                source TEXT NOT NULL,
                description TEXT
            )
            ''')
            
            # Table de configuration du serveur
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
            ''')
            
            # Indices pour améliorer les performances
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_logs_agent_id ON attack_logs(agent_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_logs_source_ip ON attack_logs(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_logs_attack_type ON attack_logs(attack_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ips_agent_id ON blocked_ips(agent_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_commands_agent_id ON commands(agent_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_commands_status ON commands(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist(ip)')
            
            conn.commit()
            
        logger.info(f"Base de données initialisée: {self.db_path}")
        
    # --- Gestion des agents ---
    
    def register_agent(self, agent_data):
        """
        Enregistre un agent dans la base de données
        
        Args:
            agent_data: Données de l'agent
            
        Returns:
            True si l'enregistrement a réussi, False sinon
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Vérifier si l'agent existe déjà
                cursor.execute('SELECT agent_id FROM agents WHERE agent_id = ?', (agent_data["agent_id"],))
                existing = cursor.fetchone()
                
                current_time = time.time()
                
                if existing:
                    # Mettre à jour l'agent existant
                    cursor.execute(
                        '''
                        UPDATE agents
                        SET hostname = ?, ip_address = ?, status = 'online', last_seen = ?,
                            os_info = ?, version = ?, features = ?
                        WHERE agent_id = ?
                        ''',
                        (
                            agent_data["hostname"],
                            agent_data["ip_address"],
                            current_time,
                            json.dumps(agent_data.get("os_info", {})),
                            agent_data.get("version", ""),
                            json.dumps(agent_data.get("features", {})),
                            agent_data["agent_id"]
                        )
                    )
                else:
                    # Créer un nouvel agent
                    cursor.execute(
                        '''
                        INSERT INTO agents
                        (agent_id, hostname, ip_address, status, registered_at, last_seen, os_info, version, features)
                        VALUES (?, ?, ?, 'online', ?, ?, ?, ?, ?)
                        ''',
                        (
                            agent_data["agent_id"],
                            agent_data["hostname"],
                            agent_data["ip_address"],
                            current_time,
                            current_time,
                            json.dumps(agent_data.get("os_info", {})),
                            agent_data.get("version", ""),
                            json.dumps(agent_data.get("features", {}))
                        )
                    )
                    
                conn.commit()
                
                logger.info(f"Agent enregistré: {agent_data['agent_id']} ({agent_data['hostname']})")
                return True
                
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement de l'agent: {e}")
            return False
            
    def update_agent_status(self, agent_id, status="online", ip_address=None):
        """
        Met à jour le statut d'un agent
        
        Args:
            agent_id: Identifiant de l'agent
            status: Nouveau statut (online/offline)
            ip_address: Adresse IP de l'agent (optionnel)
            
        Returns:
            True si la mise à jour a réussi, False sinon
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Vérifier si l'agent existe
                cursor.execute('SELECT agent_id FROM agents WHERE agent_id = ?', (agent_id,))
                existing = cursor.fetchone()
                
                if not existing:
                    logger.warning(f"Tentative de mise à jour d'un agent inexistant: {agent_id}")
                    return False
                    
                current_time = time.time()
                
                # Mettre à jour le statut
                if ip_address:
                    cursor.execute(
                        '''
                        UPDATE agents
                        SET status = ?, last_seen = ?, ip_address = ?
                        WHERE agent_id = ?
                        ''',
                        (status, current_time, ip_address, agent_id)
                    )
                else:
                    cursor.execute(
                        '''
                        UPDATE agents
                        SET status = ?, last_seen = ?
                        WHERE agent_id = ?
                        ''',
                        (status, current_time, agent_id)
                    )
                    
                conn.commit()
                
                logger.debug(f"Statut de l'agent mis à jour: {agent_id} ({status})")
                return True
                
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour du statut de l'agent: {e}")
            return False
            
    def get_agents(self, include_offline=True):
        """
        Récupère la liste des agents
        
        Args:
            include_offline: Inclure les agents hors ligne
            
        Returns:
            Liste des agents
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = 'SELECT * FROM agents'
                if not include_offline:
                    query += " WHERE status = 'online'"
                query += ' ORDER BY last_seen DESC'
                
                cursor.execute(query)
                
                agents = []
                for row in cursor.fetchall():
                    agent = dict(row)
                    
                    # Convertir les champs JSON
                    for field in ["os_info", "features"]:
                        if agent[field]:
                            try:
                                agent[field] = json.loads(agent[field])
                            except:
                                agent[field] = {}
                                
                    agents.append(agent)
                    
                return agents
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des agents: {e}")
            return []
            
    def get_agent(self, agent_id):
        """
        Récupère les informations d'un agent
        
        Args:
            agent_id: Identifiant de l'agent
            
        Returns:
            Informations de l'agent ou None
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM agents WHERE agent_id = ?', (agent_id,))
                row = cursor.fetchone()
                
                if row:
                    agent = dict(row)
                    
                    # Convertir les champs JSON
                    for field in ["os_info", "features"]:
                        if agent[field]:
                            try:
                                agent[field] = json.loads(agent[field])
                            except:
                                agent[field] = {}
                                
                    return agent
                    
                return None
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'agent: {e}")
            return None
            
    # --- Gestion des logs d'attaques ---
    
    def add_attack_logs(self, logs):
        """
        Ajoute des logs d'attaques à la base de données
        
        Args:
            logs: Liste des logs d'attaques
            
        Returns:
            Nombre de logs ajoutés
        """
        if not logs:
            return 0
            
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                count = 0
                for log in logs:
                    # Vérifier les champs requis
                    if not all(key in log for key in ["agent_id", "timestamp", "attack_type", "source_ip", "scanner"]):
                        logger.warning(f"Log d'attaque incomplet: {log}")
                        continue
                        
                    # Convertir les détails en JSON
                    details = log.get("details", {})
                    if not isinstance(details, str):
                        details = json.dumps(details)
                        
                    # Ajouter le log
                    cursor.execute(
                        '''
                        INSERT INTO attack_logs
                        (agent_id, timestamp, attack_type, source_ip, scanner, details)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ''',
                        (
                            log["agent_id"],
                            log["timestamp"],
                            log["attack_type"],
                            log["source_ip"],
                            log["scanner"],
                            details
                        )
                    )
                    count += 1
                    
                conn.commit()
                
                logger.info(f"{count} logs d'attaques ajoutés")
                return count
                
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout des logs d'attaques: {e}")
            return 0
            
    def get_attack_logs(self, limit=100, offset=0, since=None, attack_type=None, agent_id=None, source_ip=None):
        """
        Récupère les logs d'attaques
        
        Args:
            limit: Nombre maximum de logs à récupérer
            offset: Décalage pour la pagination
            since: Timestamp à partir duquel récupérer les logs
            attack_type: Filtrer par type d'attaque
            agent_id: Filtrer par agent
            source_ip: Filtrer par IP source
            
        Returns:
            Liste des logs d'attaques
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = 'SELECT * FROM attack_logs'
                params = []
                
                # Ajouter les filtres
                filters = []
                
                if since is not None:
                    filters.append('timestamp >= ?')
                    params.append(since)
                    
                if attack_type is not None:
                    filters.append('attack_type = ?')
                    params.append(attack_type)
                    
                if agent_id is not None:
                    filters.append('agent_id = ?')
                    params.append(agent_id)
                    
                if source_ip is not None:
                    filters.append('source_ip = ?')
                    params.append(source_ip)
                    
                if filters:
                    query += ' WHERE ' + ' AND '.join(filters)
                    
                query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
                params.extend([limit, offset])
                
                cursor.execute(query, params)
                
                logs = []
                for row in cursor.fetchall():
                    log = dict(row)
                    
                    # Convertir les détails
                    if log["details"]:
                        try:
                            log["details"] = json.loads(log["details"])
                        except:
                            pass
                            
                    logs.append(log)
                    
                return logs
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des logs d'attaques: {e}")
            return []
            
    # --- Gestion des IPs bloquées ---
    
    def add_blocked_ips(self, blocked_ips):
        """
        Ajoute des IPs bloquées à la base de données
        
        Args:
            blocked_ips: Liste des IPs bloquées
            
        Returns:
            Nombre d'IPs ajoutées
        """
        if not blocked_ips:
            return 0
            
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                count = 0
                for block in blocked_ips:
                    # Vérifier les champs requis
                    if not all(key in block for key in ["agent_id", "ip", "timestamp", "reason", "duration"]):
                        logger.warning(f"Entrée d'IP bloquée incomplète: {block}")
                        continue
                        
                    # Ajouter l'IP bloquée
                    cursor.execute(
                        '''
                        INSERT INTO blocked_ips
                        (agent_id, ip, timestamp, end_time, reason, duration)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ''',
                        (
                            block["agent_id"],
                            block["ip"],
                            block["timestamp"],
                            block.get("end_time"),
                            block["reason"],
                            block["duration"]
                        )
                    )
                    count += 1
                    
                conn.commit()
                
                logger.info(f"{count} IPs bloquées ajoutées")
                return count
                
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout des IPs bloquées: {e}")
            return 0
            
    def get_blocked_ips(self, include_expired=False, agent_id=None):
        """
        Récupère la liste des IPs bloquées
        
        Args:
            include_expired: Inclure les IPs dont le blocage a expiré
            agent_id: Filtrer par agent
            
        Returns:
            Liste des IPs bloquées
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = 'SELECT * FROM blocked_ips'
                params = []
                
                # Ajouter les filtres
                filters = []
                
                if not include_expired:
                    filters.append('end_time IS NULL')
                    
                if agent_id is not None:
                    filters.append('agent_id = ?')
                    params.append(agent_id)
                    
                if filters:
                    query += ' WHERE ' + ' AND '.join(filters)
                    
                query += ' ORDER BY timestamp DESC'
                
                cursor.execute(query, params)
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des IPs bloquées: {e}")
            return []
            
    # --- Gestion des commandes ---
    
    def add_command(self, agent_id, command_type, command_data=None):
        """
        Ajoute une commande à la file d'attente
        
        Args:
            agent_id: Identifiant de l'agent
            command_type: Type de commande
            command_data: Données de la commande
            
        Returns:
            ID de la commande ou None
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Convertir les données en JSON
                if command_data is not None and not isinstance(command_data, str):
                    command_data = json.dumps(command_data)
                    
                current_time = time.time()
                
                # Ajouter la commande
                cursor.execute(
                    '''
                    INSERT INTO commands
                    (agent_id, command_type, command_data, status, created_at)
                    VALUES (?, ?, ?, 'pending', ?)
                    ''',
                    (agent_id, command_type, command_data, current_time)
                )
                
                command_id = cursor.lastrowid
                conn.commit()
                
                logger.info(f"Commande ajoutée: {command_id} ({command_type}) pour l'agent {agent_id}")
                return command_id
                
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout de la commande: {e}")
            return None
            
    def get_pending_commands(self, agent_id):
        """
        Récupère les commandes en attente pour un agent
        
        Args:
            agent_id: Identifiant de l'agent
            
        Returns:
            Liste des commandes en attente
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute(
                    '''
                    SELECT * FROM commands
                    WHERE agent_id = ? AND status = 'pending'
                    ORDER BY created_at
                    ''',
                    (agent_id,)
                )
                
                commands = []
                for row in cursor.fetchall():
                    command = dict(row)
                    
                    # Convertir les données
                    if command["command_data"]:
                        try:
                            command["command_data"] = json.loads(command["command_data"])
                        except:
                            pass
                            
                    commands.append(command)
                    
                return commands
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des commandes en attente: {e}")
            return []
            
    def update_command_status(self, command_id, status):
        """
        Met à jour le statut d'une commande
        
        Args:
            command_id: Identifiant de la commande
            status: Nouveau statut
            
        Returns:
            True si la mise à jour a réussi, False sinon
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                current_time = time.time()
                
                cursor.execute(
                    '''
                    UPDATE commands
                    SET status = ?, executed_at = ?
                    WHERE id = ?
                    ''',
                    (status, current_time if status == 'executed' else None, command_id)
                )
                
                conn.commit()
                
                logger.info(f"Statut de la commande mis à jour: {command_id} ({status})")
                return True
                
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour du statut de la commande: {e}")
            return False
            
    # --- Gestion de la liste blanche ---
    
    def add_whitelist_entry(self, ip, source, description=None):
        """
        Ajoute une entrée à la liste blanche
        
        Args:
            ip: Adresse IP
            source: Source de l'entrée
            description: Description
            
        Returns:
            True si l'ajout a réussi, False sinon
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                current_time = time.time()
                
                # Vérifier si l'IP existe déjà
                cursor.execute('SELECT ip FROM whitelist WHERE ip = ?', (ip,))
                existing = cursor.fetchone()
                
                if existing:
                    # Mettre à jour l'entrée existante
                    cursor.execute(
                        '''
                        UPDATE whitelist
                        SET source = ?, description = ?, added_at = ?
                        WHERE ip = ?
                        ''',
                        (source, description, current_time, ip)
                    )
                else:
                    # Ajouter une nouvelle entrée
                    cursor.execute(
                        '''
                        INSERT INTO whitelist
                        (ip, added_at, source, description)
                        VALUES (?, ?, ?, ?)
                        ''',
                        (ip, current_time, source, description)
                    )
                    
                conn.commit()
                
                logger.info(f"Entrée ajoutée à la liste blanche: {ip} ({source})")
                return True
                
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout à la liste blanche: {e}")
            return False
            
    def remove_whitelist_entry(self, ip):
        """
        Supprime une entrée de la liste blanche
        
        Args:
            ip: Adresse IP
            
        Returns:
            True si la suppression a réussi, False sinon
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('DELETE FROM whitelist WHERE ip = ?', (ip,))
                conn.commit()
                
                logger.info(f"Entrée supprimée de la liste blanche: {ip}")
                return True
                
        except Exception as e:
            logger.error(f"Erreur lors de la suppression de la liste blanche: {e}")
            return False
            
    def get_whitelist(self):
        """
        Récupère la liste blanche
        
        Returns:
            Liste des entrées de la liste blanche
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM whitelist ORDER BY added_at DESC')
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de la liste blanche: {e}")
            return []
            
    # --- Statistiques ---
    
    def get_global_stats(self):
        """
        Récupère les statistiques globales
        
        Returns:
            Dictionnaire des statistiques
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                stats = {
                    "total_agents": 0,
                    "active_agents": 0,
                    "total_attacks": 0,
                    "blocked_ips": 0,
                    "attacks_by_type": {},
                    "attacks_by_day": {},
                    "top_attackers": []
                }
                
                # Nombre total d'agents
                cursor.execute('SELECT COUNT(*) FROM agents')
                stats["total_agents"] = cursor.fetchone()[0]
                
                # Nombre d'agents actifs
                cursor.execute('SELECT COUNT(*) FROM agents WHERE status = "online"')
                stats["active_agents"] = cursor.fetchone()[0]
                
                # Nombre total d'attaques
                cursor.execute('SELECT COUNT(*) FROM attack_logs')
                stats["total_attacks"] = cursor.fetchone()[0]
                
                # Nombre d'IPs bloquées
                cursor.execute('SELECT COUNT(*) FROM blocked_ips WHERE end_time IS NULL')
                stats["blocked_ips"] = cursor.fetchone()[0]
                
                # Attaques par type
                cursor.execute(
                    '''
                    SELECT attack_type, COUNT(*) AS count
                    FROM attack_logs
                    GROUP BY attack_type
                    ORDER BY count DESC
                    '''
                )
                stats["attacks_by_type"] = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Top des attaquants
                cursor.execute(
                    '''
                    SELECT source_ip, COUNT(*) AS count
                    FROM attack_logs
                    GROUP BY source_ip
                    ORDER BY count DESC
                    LIMIT 10
                    '''
                )
                stats["top_attackers"] = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
                
                return stats
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des statistiques globales: {e}")
            return {
                "total_agents": 0,
                "active_agents": 0,
                "total_attacks": 0,
                "blocked_ips": 0,
                "attacks_by_type": {},
                "top_attackers": []
            }
            
    def get_agent_stats(self, agent_id):
        """
        Récupère les statistiques d'un agent
        
        Args:
            agent_id: Identifiant de l'agent
            
        Returns:
            Dictionnaire des statistiques de l'agent
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                stats = {
                    "total_attacks": 0,
                    "blocked_ips": 0,
                    "attacks_by_type": {},
                    "attacks_by_day": {}
                }
                
                # Nombre total d'attaques
                cursor.execute('SELECT COUNT(*) FROM attack_logs WHERE agent_id = ?', (agent_id,))
                stats["total_attacks"] = cursor.fetchone()[0]
                
                # Nombre d'IPs bloquées
                cursor.execute('SELECT COUNT(*) FROM blocked_ips WHERE agent_id = ? AND end_time IS NULL', (agent_id,))
                stats["blocked_ips"] = cursor.fetchone()[0]
                
                # Attaques par type
                cursor.execute(
                    '''
                    SELECT attack_type, COUNT(*) AS count
                    FROM attack_logs
                    WHERE agent_id = ?
                    GROUP BY attack_type
                    ORDER BY count DESC
                    ''',
                    (agent_id,)
                )
                stats["attacks_by_type"] = {row[0]: row[1] for row in cursor.fetchall()}
                
                return stats
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des statistiques de l'agent: {e}")
            return {
                "total_attacks": 0,
                "blocked_ips": 0,
                "attacks_by_type": {},
                "attacks_by_day": {}
            }
            
    # --- Configuration du serveur ---
    
    def set_config(self, key, value):
        """
        Définit une valeur de configuration
        
        Args:
            key: Clé de configuration
            value: Valeur de configuration
            
        Returns:
            True si la mise à jour a réussi, False sinon
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Convertir la valeur en JSON si nécessaire
                if not isinstance(value, str):
                    value = json.dumps(value)
                    
                current_time = time.time()
                
                cursor.execute(
                    '''
                    INSERT OR REPLACE INTO server_config
                    (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ''',
                    (key, value, current_time)
                )
                
                conn.commit()
                
                logger.debug(f"Configuration mise à jour: {key}")
                return True
                
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour de la configuration: {e}")
            return False
            
    def get_config(self, key, default=None):
        """
        Récupère une valeur de configuration
        
        Args:
            key: Clé de configuration
            default: Valeur par défaut
            
        Returns:
            Valeur de configuration ou valeur par défaut
        """
        try:
            with self.lock, sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT value FROM server_config WHERE key = ?', (key,))
                row = cursor.fetchone()
                
                if row:
                    value = row[0]
                    
                    # Essayer de convertir la valeur depuis JSON
                    try:
                        return json.loads(value)
                    except:
                        return value
                        
                return default
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de la configuration: {e}")
            return default
            
    def close(self):
        """Ferme proprement la base de données"""
        logger.info("Fermeture de la base de données")
