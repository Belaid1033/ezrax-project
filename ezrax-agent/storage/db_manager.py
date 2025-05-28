#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gestionnaire de base de données SQLite pour l'agent EZRAX IDS/IPS
"""

import os
import json
import time
import logging
import sqlite3
import threading
from typing import Dict, List, Tuple, Any, Optional

logger = logging.getLogger(__name__)

class DatabaseManager:
    """
    Gestionnaire de base de données SQLite pour l'agent EZRAX IDS/IPS
    """
    
    def __init__(self, config):
        """
        Initialisation du gestionnaire de base de données
        
        Args:
            config: Configuration de l'agent
        """
        self.config = config
        self.db_path = config["database"]["path"]
        self.retention_days = config["database"]["retention_days"]
        self.agent_id = config["AGENT_ID"]
        self.lock = threading.Lock()
        
        # Créer le répertoire de la base de données s'il n'existe pas
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Initialiser la base de données
        self._init_database()
        
    def _init_database(self):
        """Initialise la base de données SQLite avec les tables nécessaires"""
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Table des logs d'attaques
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                attack_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                scanner TEXT NOT NULL,
                details TEXT NOT NULL,
                synced INTEGER DEFAULT 0
            )
            ''')
            
            # Table des IPs bloquées
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp REAL NOT NULL,
                end_time REAL,
                reason TEXT NOT NULL,
                duration INTEGER NOT NULL,
                synced INTEGER DEFAULT 0
            )
            ''')
            
            # Table de configuration/état de l'agent
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS agent_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
            ''')
            
            # Table pour les listes blanches
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                added_at REAL NOT NULL,
                source TEXT NOT NULL,
                description TEXT
            )
            ''')
            
            # Indices pour améliorer les performances
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_logs_source_ip ON attack_logs(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_attack_logs_synced ON attack_logs(synced)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist(ip)')
            
            conn.commit()
            
        logger.info(f"Base de données initialisée: {self.db_path}")
        
    def add_attack_log(self, attack_type: str, source_ip: str, scanner: str, details: Dict[str, Any]):
        """
        Ajoute un log d'attaque à la base de données
        
        Args:
            attack_type: Type d'attaque
            source_ip: Adresse IP source
            scanner: Nom du scanner qui a détecté l'attaque
            details: Détails de l'attaque
        """
        timestamp = time.time()
        details_json = json.dumps(details)
        
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT INTO attack_logs (timestamp, attack_type, source_ip, scanner, details)
                VALUES (?, ?, ?, ?, ?)
                ''',
                (timestamp, attack_type, source_ip, scanner, details_json)
            )
            conn.commit()
            
    def add_blocked_ip(self, ip: str, reason: str, timestamp: float, duration: int):
        """
        Ajoute une IP bloquée à la base de données
        
        Args:
            ip: Adresse IP bloquée
            reason: Raison du blocage
            timestamp: Timestamp du blocage
            duration: Durée du blocage en secondes
        """
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Vérifier si l'IP est déjà bloquée
            cursor.execute('SELECT id FROM blocked_ips WHERE ip = ? AND end_time IS NULL', (ip,))
            existing = cursor.fetchone()
            
            if existing:
                # Mettre à jour l'entrée existante
                cursor.execute(
                    '''
                    UPDATE blocked_ips 
                    SET timestamp = ?, reason = ?, duration = ?, synced = 0
                    WHERE id = ?
                    ''',
                    (timestamp, reason, duration, existing[0])
                )
            else:
                # Créer une nouvelle entrée
                cursor.execute(
                    '''
                    INSERT INTO blocked_ips (ip, timestamp, reason, duration)
                    VALUES (?, ?, ?, ?)
                    ''',
                    (ip, timestamp, reason, duration)
                )
                
            conn.commit()
            
    def update_block_end_time(self, ip: str):
        """
        Met à jour le temps de fin de blocage d'une IP
        
        Args:
            ip: Adresse IP débloquée
        """
        end_time = time.time()
        
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                UPDATE blocked_ips 
                SET end_time = ?, synced = 0
                WHERE ip = ? AND end_time IS NULL
                ''',
                (end_time, ip)
            )
            conn.commit()
            
    def get_attack_logs(self, limit: int = 100, offset: int = 0, since: Optional[float] = None):
        """
        Récupère les logs d'attaques
        
        Args:
            limit: Nombre maximum de logs à récupérer
            offset: Décalage pour la pagination
            since: Timestamp à partir duquel récupérer les logs
            
        Returns:
            Liste des logs d'attaques
        """
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = '''
            SELECT id, timestamp, attack_type, source_ip, scanner, details
            FROM attack_logs
            '''
            params = []
            
            if since is not None:
                query += ' WHERE timestamp >= ?'
                params.append(since)
                
            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            result = []
            for row in rows:
                log = dict(row)
                log['details'] = json.loads(log['details'])
                result.append(log)
                
            return result
            
    def get_blocked_ips(self, include_expired: bool = False):
        """
        Récupère la liste des IPs bloquées
        
        Args:
            include_expired: Inclure les IPs dont le blocage a expiré
            
        Returns:
            Liste des IPs bloquées
        """
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query = '''
            SELECT ip, timestamp, end_time, reason, duration
            FROM blocked_ips
            '''
            
            if not include_expired:
                query += ' WHERE end_time IS NULL'
                
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]
            
    def get_unsynced_data(self, max_records: int = 100):
        """
        Récupère les données non synchronisées avec le serveur central
        
        Args:
            max_records: Nombre maximum d'enregistrements à récupérer
            
        Returns:
            Tuple contenant les logs d'attaques et les IPs bloquées non synchronisés
        """
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Récupérer les logs d'attaques non synchronisés
            attack_logs_cursor = conn.cursor()
            attack_logs_cursor.execute(
                '''
                SELECT id, timestamp, attack_type, source_ip, scanner, details
                FROM attack_logs
                WHERE synced = 0
                ORDER BY timestamp
                LIMIT ?
                ''',
                (max_records,)
            )
            attack_logs = []
            for row in attack_logs_cursor.fetchall():
                log = dict(row)
                log['details'] = json.loads(log['details'])
                log['agent_id'] = self.agent_id
                attack_logs.append(log)
                
            # Récupérer les IPs bloquées non synchronisées
            blocked_ips_cursor = conn.cursor()
            blocked_ips_cursor.execute(
                '''
                SELECT id, ip, timestamp, end_time, reason, duration
                FROM blocked_ips
                WHERE synced = 0
                ORDER BY timestamp
                LIMIT ?
                ''',
                (max_records,)
            )
            blocked_ips = []
            for row in blocked_ips_cursor.fetchall():
                blocked_ip = dict(row)
                blocked_ip['agent_id'] = self.agent_id
                blocked_ips.append(blocked_ip)
                
            return (attack_logs, blocked_ips)
            
    def mark_as_synced(self, attack_log_ids: List[int], blocked_ip_ids: List[int]):
        """
        Marque les données comme synchronisées avec le serveur central
        
        Args:
            attack_log_ids: Liste des IDs de logs d'attaques à marquer
            blocked_ip_ids: Liste des IDs d'IPs bloquées à marquer
        """
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Marquer les logs d'attaques
            if attack_log_ids:
                placeholders = ','.join('?' for _ in attack_log_ids)
                cursor.execute(
                    f'UPDATE attack_logs SET synced = 1 WHERE id IN ({placeholders})',
                    attack_log_ids
                )
                
            # Marquer les IPs bloquées
            if blocked_ip_ids:
                placeholders = ','.join('?' for _ in blocked_ip_ids)
                cursor.execute(
                    f'UPDATE blocked_ips SET synced = 1 WHERE id IN ({placeholders})',
                    blocked_ip_ids
                )
                
            conn.commit()
            
    def cleanup_old_data(self):
        """Supprime les anciennes données selon la politique de rétention"""
        cutoff_time = time.time() - (self.retention_days * 24 * 3600)
        
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Supprimer les logs d'attaques
            cursor.execute(
                'DELETE FROM attack_logs WHERE timestamp < ?',
                (cutoff_time,)
            )
            attack_logs_deleted = cursor.rowcount
            
            # Supprimer les IPs bloquées expirées
            cursor.execute(
                'DELETE FROM blocked_ips WHERE end_time IS NOT NULL AND end_time < ?',
                (cutoff_time,)
            )
            blocked_ips_deleted = cursor.rowcount
            
            conn.commit()
            
        logger.info(
            f"Nettoyage des données: {attack_logs_deleted} logs d'attaques et "
            f"{blocked_ips_deleted} IPs bloquées supprimés"
        )
        
    def update_whitelist(self, whitelist: List[Dict[str, Any]]):
        """
        Met à jour la liste blanche des IPs
        
        Args:
            whitelist: Liste des IPs à ajouter à la liste blanche
        """
        current_time = time.time()
        
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Vider la liste blanche
            cursor.execute('DELETE FROM whitelist')
            
            # Ajouter les nouvelles entrées
            for entry in whitelist:
                cursor.execute(
                    '''
                    INSERT INTO whitelist (ip, added_at, source, description)
                    VALUES (?, ?, ?, ?)
                    ''',
                    (
                        entry['ip'],
                        entry.get('added_at', current_time),
                        entry.get('source', 'central_server'),
                        entry.get('description', '')
                    )
                )
                
            conn.commit()
            
        logger.info(f"Liste blanche mise à jour: {len(whitelist)} entrées")
        
    def get_whitelist(self):
        """
        Récupère la liste blanche des IPs
        
        Returns:
            Liste des IPs dans la liste blanche
        """
        with self.lock, sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT ip, added_at, source, description FROM whitelist')
            return [dict(row) for row in cursor.fetchall()]
            
    def set_agent_state(self, key: str, value: Any):
        """
        Définit une valeur dans l'état de l'agent
        
        Args:
            key: Clé de l'état
            value: Valeur à stocker
        """
        json_value = json.dumps(value)
        current_time = time.time()
        
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                '''
                INSERT OR REPLACE INTO agent_state (key, value, updated_at)
                VALUES (?, ?, ?)
                ''',
                (key, json_value, current_time)
            )
            conn.commit()
            
    def get_agent_state(self, key: str, default: Any = None):
        """
        Récupère une valeur de l'état de l'agent
        
        Args:
            key: Clé de l'état
            default: Valeur par défaut si la clé n'existe pas
            
        Returns:
            Valeur stockée ou valeur par défaut
        """
        with self.lock, sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT value FROM agent_state WHERE key = ?', (key,))
            row = cursor.fetchone()
            
            if row:
                try:
                    return json.loads(row[0])
                except:
                    return row[0]
            else:
                return default
                
    def close(self):
        """Ferme proprement la base de données"""
        logger.info("Fermeture de la base de données")
