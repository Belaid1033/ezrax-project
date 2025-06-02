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
import hashlib
from typing import Dict, List, Tuple, Any, Optional, Union
from contextlib import contextmanager
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import queue

logger = logging.getLogger(__name__)

class ConnectionPool:
    """Pool de connexions SQLite optimisé pour le serveur"""
    
    def __init__(self, db_path: str, pool_size: int = 10, timeout: float = 30.0):
        self.db_path = db_path
        self.pool_size = pool_size
        self.timeout = timeout
        self.pool = queue.Queue(maxsize=pool_size)
        self.active_connections = set()
        self.lock = threading.Lock()
        self.total_connections = 0
        
        # Pré-créer les connexions
        for _ in range(pool_size):
            conn = self._create_connection()
            if conn:
                self.pool.put(conn)
                
    def _create_connection(self) -> Optional[sqlite3.Connection]:
        """Crée une nouvelle connexion optimisée pour le serveur"""
        try:
            conn = sqlite3.connect(
                self.db_path,
                timeout=self.timeout,
                check_same_thread=False,
                isolation_level=None  # Mode autocommit
            )
            
            # Optimisations SQLite pour serveur
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL") 
            conn.execute("PRAGMA cache_size=20000")  # Cache plus important pour serveur
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA mmap_size=536870912")  # 512MB memory mapping
            conn.execute("PRAGMA page_size=4096")
            conn.execute("PRAGMA optimize")
            
            conn.row_factory = sqlite3.Row
            
            with self.lock:
                self.total_connections += 1
                
            logger.debug(f"Connexion serveur SQLite créée (total: {self.total_connections})")
            return conn
            
        except Exception as e:
            logger.error(f"Erreur création connexion serveur SQLite: {e}")
            return None
            
    @contextmanager
    def get_connection(self):
        """Context manager pour récupérer une connexion du pool"""
        conn = None
        try:
            try:
                conn = self.pool.get(timeout=self.timeout)
            except queue.Empty:
                logger.warning("Pool serveur épuisé, création connexion temporaire")
                conn = self._create_connection()
                if not conn:
                    raise RuntimeError("Impossible de créer une connexion serveur")
                    
            with self.lock:
                self.active_connections.add(id(conn))
            yield conn
            
        except Exception as e:
            logger.error(f"Erreur avec connexion serveur: {e}")
            if conn:
                try:
                    conn.close()
                except:
                    pass
                conn = None
            raise
        finally:
            if conn:
                try:
                    with self.lock:
                        self.active_connections.discard(id(conn))
                    
                    if self.pool.qsize() < self.pool_size:
                        self.pool.put(conn)
                    else:
                        conn.close()
                except:
                    pass
                    
    def close_all(self):
        """Ferme toutes les connexions du pool"""
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                conn.close()
            except:
                pass
                
        with self.lock:
            self.active_connections.clear()
                
        logger.info(f"Pool serveur fermé ({self.total_connections} connexions)")

class ServerDatabaseManager:
    """
    Gestionnaire de base de données SQLite amélioré pour le serveur central EZRAX
    """
    
    def __init__(self, db_path="ezrax_server.db"):
        """
        Initialisation du gestionnaire de base de données serveur
        
        Args:
            db_path: Chemin de la base de données SQLite
        """
        self.db_path = db_path
        
        # Pool de connexions pour serveur (plus important)
        self.connection_pool = ConnectionPool(self.db_path, pool_size=15)
        
        # Locks granulaires par table
        self.table_locks = {
            "agents": threading.RLock(),
            "attack_logs": threading.RLock(),
            "blocked_ips": threading.RLock(),
            "commands": threading.RLock(),
            "whitelist": threading.RLock(),
            "server_config": threading.RLock()
        }
        
        # Thread pool pour opérations asynchrones
        self.executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="ServerDB-Worker")
        
        # Métriques de performance serveur
        self.metrics = {
            "queries_executed": 0,
            "agents_registered": 0,
            "attacks_processed": 0,
            "commands_sent": 0,
            "avg_query_time": 0.0,
            "slow_queries": 0,
            "errors": 0,
            "last_maintenance": 0,
            "cache_hits": 0,
            "cache_misses": 0
        }
        
        # Cache pour les requêtes fréquentes
        self.cache = {}
        self.cache_ttl = {}
        self.cache_lock = threading.RLock()
        
        # Créer le répertoire s'il n'existe pas
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Initialiser la base de données
        self._init_database()
        
        # Démarrer la maintenance automatique
        self._start_maintenance_thread()
        
    def _init_database(self):
        """Initialise la base de données SQLite avec les tables optimisées"""
        with self.connection_pool.get_connection() as conn:
            cursor = conn.cursor()
            
            # Table des agents avec champs étendus
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
                features TEXT,
                last_sync REAL DEFAULT 0,
                total_attacks INTEGER DEFAULT 0,
                total_blocks INTEGER DEFAULT 0,
                performance_metrics TEXT,
                connection_quality REAL DEFAULT 1.0
            )
            ''')
            
            # Table des logs d'attaques avec validation
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
                severity TEXT DEFAULT 'MEDIUM',
                hash TEXT UNIQUE,
                received_at REAL DEFAULT (julianday('now') - 2440587.5)*86400.0,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
            ''')
            
            # Table des IPs bloquées avec validation
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
                is_active INTEGER DEFAULT 1,
                received_at REAL DEFAULT (julianday('now') - 2440587.5)*86400.0,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id),
                UNIQUE(agent_id, ip, timestamp)
            )
            ''')
            
            # Table des commandes avec statut étendu
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                command_type TEXT NOT NULL,
                command_data TEXT,
                status TEXT DEFAULT 'pending',
                priority INTEGER DEFAULT 1,
                created_at REAL NOT NULL,
                executed_at REAL,
                expires_at REAL,
                retry_count INTEGER DEFAULT 0,
                result TEXT,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
            ''')
            
            # Table de la liste blanche avec gestion avancée
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                added_at REAL NOT NULL,
                source TEXT NOT NULL,
                description TEXT,
                is_active INTEGER DEFAULT 1,
                added_by TEXT,
                expires_at REAL,
                last_verified REAL
            )
            ''')
            
            # Table de configuration du serveur
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL,
                config_type TEXT DEFAULT 'string',
                description TEXT
            )
            ''')
            
            # Table de statistiques agrégées
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics_summary (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                period_start REAL NOT NULL,
                period_end REAL NOT NULL,
                total_attacks INTEGER DEFAULT 0,
                unique_attackers INTEGER DEFAULT 0,
                total_blocks INTEGER DEFAULT 0,
                active_agents INTEGER DEFAULT 0,
                attack_types TEXT,
                top_attackers TEXT,
                computed_at REAL DEFAULT (julianday('now') - 2440587.5)*86400.0
            )
            ''')
            
            # Indices optimisés pour serveur
            indices = [
                # Agents
                'CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)',
                'CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen)',
                'CREATE INDEX IF NOT EXISTS idx_agents_version ON agents(version)',
                
                # Attack logs - indices composites pour performance
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_agent_time ON attack_logs(agent_id, timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_type_time ON attack_logs(attack_type, timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_source_time ON attack_logs(source_ip, timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_severity ON attack_logs(severity)',
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_processed ON attack_logs(processed)',
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_received ON attack_logs(received_at)',
                
                # Blocked IPs
                'CREATE INDEX IF NOT EXISTS idx_blocked_ips_agent_ip ON blocked_ips(agent_id, ip)',
                'CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips(is_active, end_time)',
                'CREATE INDEX IF NOT EXISTS idx_blocked_ips_timestamp ON blocked_ips(timestamp)',
                
                # Commands
                'CREATE INDEX IF NOT EXISTS idx_commands_agent_status ON commands(agent_id, status)',
                'CREATE INDEX IF NOT EXISTS idx_commands_status_priority ON commands(status, priority)',
                'CREATE INDEX IF NOT EXISTS idx_commands_expires ON commands(expires_at)',
                
                # Whitelist
                'CREATE INDEX IF NOT EXISTS idx_whitelist_active ON whitelist(is_active)',
                'CREATE INDEX IF NOT EXISTS idx_whitelist_expires ON whitelist(expires_at)',
                
                # Statistics
                'CREATE INDEX IF NOT EXISTS idx_stats_period ON statistics_summary(period_start, period_end)'
            ]
            
            for index_sql in indices:
                cursor.execute(index_sql)
                
            conn.commit()
            
        logger.info(f"Base de données serveur initialisée: {self.db_path}")
        
    def _start_maintenance_thread(self):
        """Démarre le thread de maintenance automatique"""
        def maintenance_loop():
            while True:
                try:
                    time.sleep(600)  # Toutes les 10 minutes pour serveur
                    self._perform_maintenance()
                except Exception as e:
                    logger.error(f"Erreur maintenance serveur: {e}")
                    
        maintenance_thread = threading.Thread(
            target=maintenance_loop,
            daemon=True,
            name="ServerDB-Maintenance"
        )
        maintenance_thread.start()
        
    def _perform_maintenance(self):
        """Effectue la maintenance automatique optimisée pour serveur"""
        current_time = time.time()
        
        if current_time - self.metrics["last_maintenance"] < 300:
            return
            
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Nettoyer les commandes expirées
                cursor.execute('DELETE FROM commands WHERE expires_at < ?', (current_time,))
                
                # Nettoyer les entrées whitelist expirées
                cursor.execute('UPDATE whitelist SET is_active = 0 WHERE expires_at < ?', (current_time,))
                
                # Mettre à jour les statuts des agents (offline si pas vu depuis 5 min)
                offline_threshold = current_time - 300
                cursor.execute(
                    'UPDATE agents SET status = "offline" WHERE last_seen < ? AND status = "online"',
                    (offline_threshold,)
                )
                
                # Optimiser périodiquement
                cursor.execute('PRAGMA optimize')
                
                # Calculer des statistiques agrégées si nécessaire
                self._compute_statistics_summary(cursor, current_time)
                
                conn.commit()
                
            # Nettoyer le cache
            self._cleanup_cache()
            
            self.metrics["last_maintenance"] = current_time
            logger.debug("Maintenance serveur effectuée")
            
        except Exception as e:
            logger.error(f"Erreur maintenance serveur: {e}")
            
    def _compute_statistics_summary(self, cursor, current_time):
        """Calcule et stocke des statistiques agrégées"""
        try:
            # Période de la dernière heure
            hour_start = current_time - 3600
            
            # Vérifier si on a déjà des stats pour cette période
            cursor.execute(
                'SELECT id FROM statistics_summary WHERE period_start >= ? AND period_end <= ?',
                (hour_start, current_time)
            )
            if cursor.fetchone():
                return  # Déjà calculé
                
            # Calculer les statistiques
            cursor.execute(
                'SELECT COUNT(*) FROM attack_logs WHERE timestamp >= ?',
                (hour_start,)
            )
            total_attacks = cursor.fetchone()[0]
            
            cursor.execute(
                'SELECT COUNT(DISTINCT source_ip) FROM attack_logs WHERE timestamp >= ?',
                (hour_start,)
            )
            unique_attackers = cursor.fetchone()[0]
            
            cursor.execute(
                'SELECT COUNT(*) FROM blocked_ips WHERE timestamp >= ?',
                (hour_start,)
            )
            total_blocks = cursor.fetchone()[0]
            
            cursor.execute(
                'SELECT COUNT(*) FROM agents WHERE status = "online"'
            )
            active_agents = cursor.fetchone()[0]
            
            # Types d'attaques
            cursor.execute(
                '''SELECT attack_type, COUNT(*) 
                   FROM attack_logs 
                   WHERE timestamp >= ? 
                   GROUP BY attack_type''',
                (hour_start,)
            )
            attack_types = dict(cursor.fetchall())
            
            # Top attaquants
            cursor.execute(
                '''SELECT source_ip, COUNT(*) as count
                   FROM attack_logs 
                   WHERE timestamp >= ? 
                   GROUP BY source_ip 
                   ORDER BY count DESC 
                   LIMIT 10''',
                (hour_start,)
            )
            top_attackers = dict(cursor.fetchall())
            
            # Stocker le résumé
            cursor.execute(
                '''INSERT INTO statistics_summary 
                   (period_start, period_end, total_attacks, unique_attackers, 
                    total_blocks, active_agents, attack_types, top_attackers, computed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (hour_start, current_time, total_attacks, unique_attackers,
                 total_blocks, active_agents, json.dumps(attack_types),
                 json.dumps(top_attackers), current_time)
            )
            
        except Exception as e:
            logger.error(f"Erreur calcul statistiques: {e}")
            
    def _cleanup_cache(self):
        """Nettoie le cache expiré"""
        current_time = time.time()
        with self.cache_lock:
            expired_keys = [
                key for key, expiry in self.cache_ttl.items()
                if expiry < current_time
            ]
            for key in expired_keys:
                self.cache.pop(key, None)
                self.cache_ttl.pop(key, None)
                
    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Récupère une valeur du cache"""
        with self.cache_lock:
            if key in self.cache and key in self.cache_ttl:
                if self.cache_ttl[key] > time.time():
                    self.metrics["cache_hits"] += 1
                    return self.cache[key]
                else:
                    # Expiré
                    self.cache.pop(key, None)
                    self.cache_ttl.pop(key, None)
            
            self.metrics["cache_misses"] += 1
            return None
            
    def _set_cache(self, key: str, value: Any, ttl: int = 60):
        """Stocke une valeur dans le cache"""
        with self.cache_lock:
            self.cache[key] = value
            self.cache_ttl[key] = time.time() + ttl
            
    def _update_query_metrics(self, query_time: float):
        """Met à jour les métriques de performance"""
        self.metrics["queries_executed"] += 1
        
        if self.metrics["avg_query_time"] == 0:
            self.metrics["avg_query_time"] = query_time
        else:
            alpha = 0.1
            self.metrics["avg_query_time"] = (
                alpha * query_time + 
                (1 - alpha) * self.metrics["avg_query_time"]
            )
            
        if query_time > 1.0:
            self.metrics["slow_queries"] += 1
            logger.warning(f"Requête serveur lente: {query_time:.2f}s")
            
    def register_agent(self, agent_data: Dict[str, Any]) -> bool:
        """
        Enregistre un agent avec validation complète
        """
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Construire la requête avec filtres
                query = 'SELECT * FROM attack_logs'
                params = []
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
                    
                    # Convertir les détails JSON
                    if log["details"]:
                        try:
                            log["details"] = json.loads(log["details"])
                        except:
                            log["details"] = {}
                            
                    logs.append(log)
                
                # Cache pour les petites requêtes
                if limit <= 500 and offset == 0:
                    self._set_cache(cache_key, logs, 30)
                    
                self._update_query_metrics(time.time() - start_time)
                return logs
                
        except Exception as e:
            logger.error(f"Erreur récupération logs d'attaques: {e}")
            self.metrics["errors"] += 1
            return []
            
    def get_blocked_ips(self, include_expired: bool = False, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Récupère la liste des IPs bloquées avec cache"""
        cache_key = f"blocked_ips:{include_expired}:{agent_id}"
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result
            
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = 'SELECT * FROM blocked_ips'
                params = []
                filters = []
                
                if not include_expired:
                    filters.append('is_active = 1 AND (end_time IS NULL OR end_time > ?)')
                    params.append(time.time())
                    
                if agent_id is not None:
                    filters.append('agent_id = ?')
                    params.append(agent_id)
                    
                if filters:
                    query += ' WHERE ' + ' AND '.join(filters)
                    
                query += ' ORDER BY timestamp DESC'
                
                cursor.execute(query, params)
                result = [dict(row) for row in cursor.fetchall()]
                
                # Cache pour 60 secondes
                self._set_cache(cache_key, result, 60)
                self._update_query_metrics(time.time() - start_time)
                return result
                
        except Exception as e:
            logger.error(f"Erreur récupération IPs bloquées: {e}")
            self.metrics["errors"] += 1
            return []
            
    def add_command(self, agent_id: str, command_type: str, command_data: Optional[Dict[str, Any]] = None,
                   priority: int = 1, expires_in: int = 3600) -> Optional[int]:
        """Ajoute une commande avec expiration et priorité"""
        start_time = time.time()
        
        try:
            with self.table_locks["commands"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    current_time = time.time()
                    expires_at = current_time + expires_in
                    
                    # Convertir les données en JSON
                    if command_data is not None and not isinstance(command_data, str):
                        command_data = json.dumps(command_data)
                        
                    cursor.execute(
                        '''INSERT INTO commands
                           (agent_id, command_type, command_data, status, priority, 
                            created_at, expires_at)
                           VALUES (?, ?, ?, 'pending', ?, ?, ?)''',
                        (agent_id, command_type, command_data, priority, current_time, expires_at)
                    )
                    
                    command_id = cursor.lastrowid
                    conn.commit()
                    
                    self.metrics["commands_sent"] += 1
                    self._update_query_metrics(time.time() - start_time)
                    
                    logger.info(f"Commande ajoutée: {command_id} ({command_type}) pour {agent_id}")
                    return command_id
                    
        except Exception as e:
            logger.error(f"Erreur ajout commande: {e}")
            self.metrics["errors"] += 1
            return None
            
    def get_pending_commands(self, agent_id: str) -> List[Dict[str, Any]]:
        """Récupère les commandes en attente pour un agent"""
        cache_key = f"commands:{agent_id}"
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result
            
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                current_time = time.time()
                
                cursor.execute(
                    '''SELECT * FROM commands
                       WHERE agent_id = ? AND status = 'pending' 
                       AND (expires_at IS NULL OR expires_at > ?)
                       ORDER BY priority DESC, created_at ASC''',
                    (agent_id, current_time)
                )
                
                commands = []
                for row in cursor.fetchall():
                    command = dict(row)
                    
                    # Convertir les données JSON
                    if command["command_data"]:
                        try:
                            command["command_data"] = json.loads(command["command_data"])
                        except:
                            pass
                            
                    commands.append(command)
                
                # Cache court pour éviter les requêtes répétées
                self._set_cache(cache_key, commands, 10)
                self._update_query_metrics(time.time() - start_time)
                return commands
                
        except Exception as e:
            logger.error(f"Erreur récupération commandes: {e}")
            self.metrics["errors"] += 1
            return []
            
    def update_command_status(self, command_id: int, status: str, result: Optional[str] = None) -> bool:
        """Met à jour le statut d'une commande"""
        start_time = time.time()
        
        try:
            with self.table_locks["commands"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    current_time = time.time()
                    
                    cursor.execute(
                        '''UPDATE commands
                           SET status = ?, executed_at = ?, result = ?
                           WHERE id = ?''',
                        (status, current_time if status in ['executed', 'failed'] else None,
                         result, command_id)
                    )
                    
                    success = cursor.rowcount > 0
                    conn.commit()
                    
                    if success:
                        # Invalider le cache des commandes
                        with self.cache_lock:
                            expired_keys = [k for k in self.cache.keys() if k.startswith("commands:")]
                            for k in expired_keys:
                                self.cache.pop(k, None)
                                self.cache_ttl.pop(k, None)
                    
                    self._update_query_metrics(time.time() - start_time)
                    return success
                    
        except Exception as e:
            logger.error(f"Erreur mise à jour commande: {e}")
            self.metrics["errors"] += 1
            return False
            
    def get_whitelist(self) -> List[Dict[str, Any]]:
        """Récupère la liste blanche avec cache"""
        cache_key = "whitelist:active"
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result
            
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                current_time = time.time()
                
                cursor.execute(
                    '''SELECT ip, added_at, source, description FROM whitelist 
                       WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > ?)
                       ORDER BY added_at DESC''',
                    (current_time,)
                )
                
                result = [dict(row) for row in cursor.fetchall()]
                
                # Cache pour 5 minutes
                self._set_cache(cache_key, result, 300)
                self._update_query_metrics(time.time() - start_time)
                return result
                
        except Exception as e:
            logger.error(f"Erreur récupération whitelist: {e}")
            self.metrics["errors"] += 1
            return []
            
    def add_whitelist_entry(self, ip: str, source: str, description: Optional[str] = None,
                           added_by: Optional[str] = None, expires_in: Optional[int] = None) -> bool:
        """Ajoute une entrée à la liste blanche avec expiration optionnelle"""
        start_time = time.time()
        
        try:
            with self.table_locks["whitelist"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    current_time = time.time()
                    expires_at = None
                    if expires_in:
                        expires_at = current_time + expires_in
                    
                    cursor.execute(
                        '''INSERT OR REPLACE INTO whitelist
                           (ip, added_at, source, description, is_active, added_by, expires_at, last_verified)
                           VALUES (?, ?, ?, ?, 1, ?, ?, ?)''',
                        (ip, current_time, source, description, added_by, expires_at, current_time)
                    )
                    
                    conn.commit()
                    
                    # Invalider le cache
                    with self.cache_lock:
                        self.cache.pop("whitelist:active", None)
                        self.cache_ttl.pop("whitelist:active", None)
                    
                    self._update_query_metrics(time.time() - start_time)
                    logger.info(f"Entrée whitelist ajoutée: {ip} ({source})")
                    return True
                    
        except Exception as e:
            logger.error(f"Erreur ajout whitelist: {e}")
            self.metrics["errors"] += 1
            return False
            
    def remove_whitelist_entry(self, ip: str) -> bool:
        """Supprime une entrée de la liste blanche"""
        start_time = time.time()
        
        try:
            with self.table_locks["whitelist"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('UPDATE whitelist SET is_active = 0 WHERE ip = ?', (ip,))
                    success = cursor.rowcount > 0
                    conn.commit()
                    
                    if success:
                        # Invalider le cache
                        with self.cache_lock:
                            self.cache.pop("whitelist:active", None)
                            self.cache_ttl.pop("whitelist:active", None)
                    
                    self._update_query_metrics(time.time() - start_time)
                    logger.info(f"Entrée whitelist supprimée: {ip}")
                    return success
                    
        except Exception as e:
            logger.error(f"Erreur suppression whitelist: {e}")
            self.metrics["errors"] += 1
            return False
            
    def get_global_stats(self) -> Dict[str, Any]:
        """Récupère les statistiques globales optimisées"""
        cache_key = "global_stats"
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result
            
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {
                    "total_agents": 0,
                    "active_agents": 0,
                    "total_attacks": 0,
                    "attacks_last_24h": 0,
                    "blocked_ips": 0,
                    "attacks_by_type": {},
                    "top_attackers": [],
                    "agent_versions": {},
                    "system_health": "healthy"
                }
                
                # Statistiques des agents
                cursor.execute('SELECT COUNT(*) FROM agents')
                stats["total_agents"] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM agents WHERE status = "online"')
                stats["active_agents"] = cursor.fetchone()[0]
                
                # Statistiques des attaques
                cursor.execute('SELECT COUNT(*) FROM attack_logs')
                stats["total_attacks"] = cursor.fetchone()[0]
                
                # Attaques dernières 24h
                since_24h = time.time() - 86400
                cursor.execute('SELECT COUNT(*) FROM attack_logs WHERE timestamp >= ?', (since_24h,))
                stats["attacks_last_24h"] = cursor.fetchone()[0]
                
                # IPs bloquées actives
                cursor.execute(
                    'SELECT COUNT(*) FROM blocked_ips WHERE is_active = 1 AND (end_time IS NULL OR end_time > ?)',
                    (time.time(),)
                )
                stats["blocked_ips"] = cursor.fetchone()[0]
                
                # Types d'attaques (dernières 24h)
                cursor.execute(
                    '''SELECT attack_type, COUNT(*) as count
                       FROM attack_logs 
                       WHERE timestamp >= ?
                       GROUP BY attack_type
                       ORDER BY count DESC''',
                    (since_24h,)
                )
                stats["attacks_by_type"] = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Top attaquants (dernières 24h)
                cursor.execute(
                    '''SELECT source_ip, COUNT(*) as count
                       FROM attack_logs 
                       WHERE timestamp >= ?
                       GROUP BY source_ip
                       ORDER BY count DESC
                       LIMIT 10''',
                    (since_24h,)
                )
                stats["top_attackers"] = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
                
                # Versions des agents
                cursor.execute(
                    '''SELECT version, COUNT(*) as count
                       FROM agents 
                       WHERE version IS NOT NULL AND version != ""
                       GROUP BY version'''
                )
                stats["agent_versions"] = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Santé du système
                error_rate = self.metrics["errors"] / max(1, self.metrics["queries_executed"])
                if error_rate > 0.1:
                    stats["system_health"] = "degraded"
                elif error_rate > 0.05:
                    stats["system_health"] = "warning"
                
                # Cache pour 60 secondes
                self._set_cache(cache_key, stats, 60)
                self._update_query_metrics(time.time() - start_time)
                return stats
                
        except Exception as e:
            logger.error(f"Erreur récupération statistiques globales: {e}")
            self.metrics["errors"] += 1
            return {
                "total_agents": 0,
                "active_agents": 0,
                "total_attacks": 0,
                "attacks_last_24h": 0,
                "blocked_ips": 0,
                "attacks_by_type": {},
                "top_attackers": [],
                "agent_versions": {},
                "system_health": "error"
            }
            
    def get_agent_stats(self, agent_id: str) -> Dict[str, Any]:
        """Récupère les statistiques d'un agent spécifique"""
        cache_key = f"agent_stats:{agent_id}"
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result
            
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {
                    "total_attacks": 0,
                    "attacks_last_24h": 0,
                    "blocked_ips": 0,
                    "attacks_by_type": {},
                    "last_seen": None,
                    "status": "unknown"
                }
                
                # Vérifier que l'agent existe
                cursor.execute('SELECT status, last_seen FROM agents WHERE agent_id = ?', (agent_id,))
                agent_info = cursor.fetchone()
                if not agent_info:
                    return stats
                    
                stats["status"] = agent_info[0]
                stats["last_seen"] = agent_info[1]
                
                # Statistiques des attaques
                cursor.execute('SELECT COUNT(*) FROM attack_logs WHERE agent_id = ?', (agent_id,))
                stats["total_attacks"] = cursor.fetchone()[0]
                
                # Attaques dernières 24h
                since_24h = time.time() - 86400
                cursor.execute(
                    'SELECT COUNT(*) FROM attack_logs WHERE agent_id = ? AND timestamp >= ?',
                    (agent_id, since_24h)
                )
                stats["attacks_last_24h"] = cursor.fetchone()[0]
                
                # IPs bloquées
                cursor.execute(
                    '''SELECT COUNT(*) FROM blocked_ips 
                       WHERE agent_id = ? AND is_active = 1 
                       AND (end_time IS NULL OR end_time > ?)''',
                    (agent_id, time.time())
                )
                stats["blocked_ips"] = cursor.fetchone()[0]
                
                # Types d'attaques
                cursor.execute(
                    '''SELECT attack_type, COUNT(*) as count
                       FROM attack_logs
                       WHERE agent_id = ?
                       GROUP BY attack_type
                       ORDER BY count DESC''',
                    (agent_id,)
                )
                stats["attacks_by_type"] = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Cache pour 30 secondes
                self._set_cache(cache_key, stats, 30)
                self._update_query_metrics(time.time() - start_time)
                return stats
                
        except Exception as e:
            logger.error(f"Erreur récupération statistiques agent: {e}")
            self.metrics["errors"] += 1
            return stats
            
    def set_config(self, key: str, value: Any, description: Optional[str] = None) -> bool:
        """Définit une valeur de configuration"""
        start_time = time.time()
        
        try:
            with self.table_locks["server_config"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Convertir la valeur
                    if isinstance(value, (dict, list)):
                        config_type = "json"
                        value_str = json.dumps(value)
                    elif isinstance(value, bool):
                        config_type = "boolean"
                        value_str = str(value)
                    elif isinstance(value, (int, float)):
                        config_type = "number"
                        value_str = str(value)
                    else:
                        config_type = "string"
                        value_str = str(value)
                    
                    current_time = time.time()
                    
                    cursor.execute(
                        '''INSERT OR REPLACE INTO server_config
                           (key, value, updated_at, config_type, description)
                           VALUES (?, ?, ?, ?, ?)''',
                        (key, value_str, current_time, config_type, description)
                    )
                    
                    conn.commit()
                    
                    # Invalider le cache de config
                    with self.cache_lock:
                        self.cache.pop(f"config:{key}", None)
                        self.cache_ttl.pop(f"config:{key}", None)
                    
                    self._update_query_metrics(time.time() - start_time)
                    logger.debug(f"Configuration mise à jour: {key}")
                    return True
                    
        except Exception as e:
            logger.error(f"Erreur mise à jour configuration: {e}")
            self.metrics["errors"] += 1
            return False
            
    def get_config(self, key: str, default: Any = None) -> Any:
        """Récupère une valeur de configuration"""
        cache_key = f"config:{key}"
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result
            
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT value, config_type FROM server_config WHERE key = ?', (key,))
                row = cursor.fetchone()
                
                if row:
                    value_str, config_type = row
                    
                    # Convertir selon le type
                    if config_type == "json":
                        try:
                            result = json.loads(value_str)
                        except:
                            result = default
                    elif config_type == "boolean":
                        result = value_str.lower() in ("true", "1", "yes")
                    elif config_type == "number":
                        try:
                            result = float(value_str) if "." in value_str else int(value_str)
                        except:
                            result = default
                    else:
                        result = value_str
                    
                    # Cache pour 5 minutes
                    self._set_cache(cache_key, result, 300)
                    self._update_query_metrics(time.time() - start_time)
                    return result
                else:
                    return default
                    
        except Exception as e:
            logger.error(f"Erreur récupération configuration: {e}")
            self.metrics["errors"] += 1
            return default
            
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Retourne les métriques de performance complètes"""
        cache_stats = {
            "cache_size": len(self.cache),
            "cache_hits": self.metrics["cache_hits"],
            "cache_misses": self.metrics["cache_misses"],
            "hit_rate": self.metrics["cache_hits"] / max(1, self.metrics["cache_hits"] + self.metrics["cache_misses"])
        }
        
        pool_stats = {
            "pool_size": self.connection_pool.pool_size,
            "active_connections": len(self.connection_pool.active_connections),
            "total_connections_created": self.connection_pool.total_connections
        }
        
        return {
            **self.metrics,
            "cache": cache_stats,
            "connection_pool": pool_stats,
            "database_size_mb": self._get_database_size() / (1024 * 1024)
        }
        
    def _get_database_size(self) -> int:
        """Retourne la taille de la base de données en bytes"""
        try:
            return os.path.getsize(self.db_path)
        except:
            return 0
            
    def cleanup_old_data(self, retention_days: int = 30):
        """Supprime les anciennes données avec gestion optimisée"""
        cutoff_time = time.time() - (retention_days * 24 * 3600)
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Transaction pour atomicité
                cursor.execute('BEGIN IMMEDIATE')
                
                try:
                    # Compter avant suppression
                    cursor.execute('SELECT COUNT(*) FROM attack_logs WHERE timestamp < ?', (cutoff_time,))
                    old_attacks = cursor.fetchone()[0]
                    
                    cursor.execute(
                        'SELECT COUNT(*) FROM blocked_ips WHERE end_time IS NOT NULL AND end_time < ?',
                        (cutoff_time,)
                    )
                    old_blocks = cursor.fetchone()[0]
                    
                    # Supprimer par batch
                    if old_attacks > 0:
                        cursor.execute('DELETE FROM attack_logs WHERE timestamp < ?', (cutoff_time,))
                        
                    if old_blocks > 0:
                        cursor.execute(
                            'DELETE FROM blocked_ips WHERE end_time IS NOT NULL AND end_time < ?',
                            (cutoff_time,)
                        )
                    
                    # Nettoyer les commandes expirées
                    cursor.execute('DELETE FROM commands WHERE status = "executed" AND executed_at < ?', (cutoff_time,))
                    
                    # Nettoyer les statistiques anciennes
                    cursor.execute('DELETE FROM statistics_summary WHERE period_end < ?', (cutoff_time,))
                    
                    cursor.execute('COMMIT')
                    
                    if old_attacks > 0 or old_blocks > 0:
                        logger.info(f"Nettoyage serveur: {old_attacks} logs, {old_blocks} blocs supprimés")
                        
                        # VACUUM si beaucoup de données supprimées
                        if old_attacks > 10000 or old_blocks > 1000:
                            cursor.execute('VACUUM')
                            logger.info("VACUUM serveur exécuté")
                    
                    # Vider le cache après nettoyage
                    with self.cache_lock:
                        self.cache.clear()
                        self.cache_ttl.clear()
                    
                    self._update_query_metrics(time.time() - start_time)
                    
                except Exception as e:
                    cursor.execute('ROLLBACK')
                    raise e
                    
        except Exception as e:
            logger.error(f"Erreur nettoyage serveur: {e}")
            self.metrics["errors"] += 1
            
    def optimize_database(self):
        """Optimise complètement la base de données serveur"""
        logger.info("Optimisation base de données serveur...")
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Analyser les statistiques
                cursor.execute('ANALYZE')
                
                # Optimiser automatiquement
                cursor.execute('PRAGMA optimize')
                
                # Vérifier l'intégrité
                cursor.execute('PRAGMA integrity_check')
                integrity = cursor.fetchone()[0]
                
                if integrity != "ok":
                    logger.error(f"Problème intégrité serveur: {integrity}")
                else:
                    logger.info("Intégrité serveur OK")
                
                # Statistiques de la base
                cursor.execute('PRAGMA page_count')
                pages = cursor.fetchone()[0]
                cursor.execute('PRAGMA page_size')
                page_size = cursor.fetchone()[0]
                db_size = pages * page_size
                
                optimization_time = time.time() - start_time
                logger.info(f"Optimisation serveur terminée en {optimization_time:.2f}s (DB: {db_size/1024/1024:.1f}MB)")
                
        except Exception as e:
            logger.error(f"Erreur optimisation serveur: {e}")
            
    def close(self):
        """Ferme proprement la base de données serveur"""
        logger.info("Fermeture gestionnaire base de données serveur")
        
        try:
            # Arrêter l'executor
            self.executor.shutdown(wait=True, timeout=10)
            
            # Fermer le pool de connexions
            self.connection_pool.close_all()
            
            # Log des métriques finales
            metrics = self.get_performance_metrics()
            logger.info(f"Métriques finales serveur: {metrics}")
            
        except Exception as e:
            logger.error(f"Erreur fermeture serveur: {e}")
        
        try:
            with self.table_locks["agents"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Vérifier si l'agent existe déjà
                    cursor.execute('SELECT agent_id, registered_at FROM agents WHERE agent_id = ?', 
                                 (agent_data["agent_id"],))
                    existing = cursor.fetchone()
                    
                    current_time = time.time()
                    
                    if existing:
                        # Mettre à jour l'agent existant
                        cursor.execute(
                            '''UPDATE agents
                               SET hostname = ?, ip_address = ?, status = 'online', 
                                   last_seen = ?, os_info = ?, version = ?, features = ?,
                                   last_sync = ?
                               WHERE agent_id = ?''',
                            (
                                agent_data["hostname"],
                                agent_data["ip_address"],
                                current_time,
                                json.dumps(agent_data.get("os_info", {})),
                                agent_data.get("version", ""),
                                json.dumps(agent_data.get("features", {})),
                                current_time,
                                agent_data["agent_id"]
                            )
                        )
                        logger.info(f"Agent mis à jour: {agent_data['agent_id']}")
                    else:
                        # Créer un nouvel agent
                        cursor.execute(
                            '''INSERT INTO agents
                               (agent_id, hostname, ip_address, status, registered_at, 
                                last_seen, os_info, version, features, last_sync)
                               VALUES (?, ?, ?, 'online', ?, ?, ?, ?, ?, ?)''',
                            (
                                agent_data["agent_id"],
                                agent_data["hostname"],
                                agent_data["ip_address"],
                                current_time,
                                current_time,
                                json.dumps(agent_data.get("os_info", {})),
                                agent_data.get("version", ""),
                                json.dumps(agent_data.get("features", {})),
                                current_time
                            )
                        )
                        self.metrics["agents_registered"] += 1
                        logger.info(f"Nouvel agent enregistré: {agent_data['agent_id']}")
                        
                    conn.commit()
                    
                    # Invalider le cache des agents
                    with self.cache_lock:
                        expired_keys = [k for k in self.cache.keys() if k.startswith("agents")]
                        for k in expired_keys:
                            self.cache.pop(k, None)
                            self.cache_ttl.pop(k, None)
                    
                    self._update_query_metrics(time.time() - start_time)
                    return True
                    
        except Exception as e:
            logger.error(f"Erreur enregistrement agent: {e}")
            self.metrics["errors"] += 1
            return False
            
    def update_agent_status(self, agent_id: str, status: str = "online", 
                          ip_address: Optional[str] = None) -> bool:
        """Met à jour le statut d'un agent"""
        start_time = time.time()
        
        try:
            with self.table_locks["agents"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    current_time = time.time()
                    
                    if ip_address:
                        cursor.execute(
                            '''UPDATE agents
                               SET status = ?, last_seen = ?, ip_address = ?
                               WHERE agent_id = ?''',
                            (status, current_time, ip_address, agent_id)
                        )
                    else:
                        cursor.execute(
                            '''UPDATE agents
                               SET status = ?, last_seen = ?
                               WHERE agent_id = ?''',
                            (status, current_time, agent_id)
                        )
                    
                    success = cursor.rowcount > 0
                    conn.commit()
                    
                    if success:
                        # Invalider le cache
                        with self.cache_lock:
                            self.cache.pop(f"agent:{agent_id}", None)
                            self.cache_ttl.pop(f"agent:{agent_id}", None)
                    
                    self._update_query_metrics(time.time() - start_time)
                    return success
                    
        except Exception as e:
            logger.error(f"Erreur mise à jour statut agent: {e}")
            self.metrics["errors"] += 1
            return False
            
    def get_agents(self, include_offline: bool = True) -> List[Dict[str, Any]]:
        """Récupère la liste des agents avec cache"""
        cache_key = f"agents:offline_{include_offline}"
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result
            
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
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
                    for field in ["os_info", "features", "performance_metrics"]:
                        if agent.get(field):
                            try:
                                agent[field] = json.loads(agent[field])
                            except:
                                agent[field] = {}
                                
                    agents.append(agent)
                
                # Mettre en cache pour 30 secondes
                self._set_cache(cache_key, agents, 30)
                self._update_query_metrics(time.time() - start_time)
                return agents
                
        except Exception as e:
            logger.error(f"Erreur récupération agents: {e}")
            self.metrics["errors"] += 1
            return []
            
    def add_attack_logs(self, logs: List[Dict[str, Any]]) -> int:
        """Ajoute des logs d'attaques en batch optimisé"""
        if not logs:
            return 0
            
        start_time = time.time()
        count = 0
        
        try:
            with self.table_locks["attack_logs"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Traitement par batch pour performance
                    batch_size = 100
                    for i in range(0, len(logs), batch_size):
                        batch = logs[i:i + batch_size]
                        
                        for log in batch:
                            try:
                                # Validation des champs requis
                                if not all(key in log for key in ["agent_id", "timestamp", "attack_type", "source_ip", "scanner"]):
                                    continue
                                    
                                details_json = json.dumps(log.get("details", {}))
                                severity = log.get("severity", "MEDIUM")
                                received_at = time.time()
                                
                                # Hash pour déduplication
                                hash_data = f"{log['attack_type']}:{log['source_ip']}:{int(log['timestamp']//60)}"
                                attack_hash = hashlib.md5(hash_data.encode()).hexdigest()
                                
                                cursor.execute(
                                    '''INSERT OR IGNORE INTO attack_logs 
                                       (agent_id, timestamp, attack_type, source_ip, scanner, 
                                        details, severity, hash, received_at)
                                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                    (log["agent_id"], log["timestamp"], log["attack_type"],
                                     log["source_ip"], log["scanner"], details_json,
                                     severity, attack_hash, received_at)
                                )
                                
                                if cursor.rowcount > 0:
                                    count += 1
                                    
                            except Exception as e:
                                logger.warning(f"Log d'attaque ignoré: {e}")
                                
                        conn.commit()
                        
            self.metrics["attacks_processed"] += count
            self._update_query_metrics(time.time() - start_time)
            
            if count > 0:
                logger.info(f"{count} logs d'attaques ajoutés au serveur")
                
            return count
            
        except Exception as e:
            logger.error(f"Erreur ajout logs d'attaques: {e}")
            self.metrics["errors"] += 1
            return 0
            
    def add_blocked_ips(self, blocked_ips: List[Dict[str, Any]]) -> int:
        """Ajoute des IPs bloquées en batch optimisé"""
        if not blocked_ips:
            return 0
            
        start_time = time.time()
        count = 0
        
        try:
            with self.table_locks["blocked_ips"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    for block in blocked_ips:
                        try:
                            # Validation des champs requis
                            if not all(key in block for key in ["agent_id", "ip", "timestamp", "reason", "duration"]):
                                continue
                                
                            cursor.execute(
                                '''INSERT OR IGNORE INTO blocked_ips 
                                   (agent_id, ip, timestamp, end_time, reason, duration, received_at)
                                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                (block["agent_id"], block["ip"], block["timestamp"],
                                 block.get("end_time"), block["reason"], block["duration"],
                                 time.time())
                            )
                            
                            if cursor.rowcount > 0:
                                count += 1
                                
                        except Exception as e:
                            logger.warning(f"IP bloquée ignorée: {e}")
                            
                    conn.commit()
                    
            self._update_query_metrics(time.time() - start_time)
            
            if count > 0:
                logger.info(f"{count} IPs bloquées ajoutées au serveur")
                
            return count
            
        except Exception as e:
            logger.error(f"Erreur ajout IPs bloquées: {e}")
            self.metrics["errors"] += 1
            return 0
            
    def get_attack_logs(self, limit: int = 100, offset: int = 0, since: Optional[float] = None,
                       attack_type: Optional[str] = None, agent_id: Optional[str] = None,
                       source_ip: Optional[str] = None) -> List[Dict[str, Any]]:
        """Récupère les logs d'attaques avec filtres optimisés"""
        cache_key = f"attack_logs:{limit}:{offset}:{since}:{attack_type}:{agent_id}:{source_ip}"
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            return cached_result
            
        start_time = time.time()
