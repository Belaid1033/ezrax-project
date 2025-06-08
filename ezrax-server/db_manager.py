#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gestionnaire de base de données SQLite pour le serveur central EZRAX
"""

import os
import json
import time
import logging
import sqlite3
import threading
import queue
import hashlib
import secrets
from typing import Dict, List, Tuple, Any, Optional, Union
from contextlib import contextmanager
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

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
        """Crée une nouvelle connexion optimisée"""
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
            conn.execute("PRAGMA cache_size=20000")  # Cache 20MB
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA mmap_size=536870912")  # Memory mapping 512MB
            conn.execute("PRAGMA optimize")
            
            conn.row_factory = sqlite3.Row
            
            with self.lock:
                self.total_connections += 1
                
            logger.debug(f"Connexion SQLite serveur créée (total: {self.total_connections})")
            return conn
            
        except Exception as e:
            logger.error(f"Erreur création connexion SQLite serveur: {e}")
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
            logger.error(f"Erreur connexion serveur: {e}")
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

class QueryCache:
    """Cache intelligent pour les requêtes serveur"""
    
    def __init__(self, max_size: int = 200, ttl: float = 30.0):
        self.cache = {}
        self.access_times = {}
        self.max_size = max_size
        self.ttl = ttl
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0
        
    def get(self, key: str) -> Optional[Any]:
        """Récupère une valeur du cache"""
        with self.lock:
            if key in self.cache:
                if time.time() - self.access_times[key] < self.ttl:
                    self.hits += 1
                    return self.cache[key]
                else:
                    del self.cache[key]
                    del self.access_times[key]
                    
            self.misses += 1
            return None
            
    def put(self, key: str, value: Any):
        """Stocke une valeur dans le cache"""
        with self.lock:
            if len(self.cache) >= self.max_size:
                self._evict_oldest()
                
            self.cache[key] = value
            self.access_times[key] = time.time()
            
    def _evict_oldest(self):
        """Évince les entrées les plus anciennes"""
        if not self.access_times:
            return
            
        sorted_items = sorted(self.access_times.items(), key=lambda x: x[1])
        to_remove = len(sorted_items) // 4
        
        for key, _ in sorted_items[:to_remove]:
            if key in self.cache:
                del self.cache[key]
            if key in self.access_times:
                del self.access_times[key]
                
    def clear(self):
        """Vide le cache"""
        with self.lock:
            self.cache.clear()
            self.access_times.clear()
            
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du cache"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = self.hits / total_requests if total_requests > 0 else 0
            
            return {
                "size": len(self.cache),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": hit_rate
            }

class AdminManager:
    """Gestionnaire des comptes administrateur"""
    
    def __init__(self, connection_pool):
        self.connection_pool = connection_pool
        self.active_sessions = {}  # {session_id: {user_id, expires_at}}
        self.session_lock = threading.Lock()
        
    def create_admin_user(self, username: str, password: str, email: str = None) -> bool:
        """Crée un utilisateur administrateur"""
        try:
            # Hash sécurisé du mot de passe
            salt = secrets.token_hex(32)
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            password_hash_hex = password_hash.hex()
            
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    '''
                    INSERT INTO admin_users (username, password_hash, salt, email, created_at, is_active)
                    VALUES (?, ?, ?, ?, ?, 1)
                    ''',
                    (username, password_hash_hex, salt, email, time.time())
                )
                conn.commit()
                
            logger.info(f"Utilisateur admin créé: {username}")
            return True
            
        except sqlite3.IntegrityError:
            logger.error(f"Utilisateur admin existe déjà: {username}")
            return False
        except Exception as e:
            logger.error(f"Erreur création utilisateur admin: {e}")
            return False
            
    def authenticate_admin(self, username: str, password: str) -> Optional[str]:
        """Authentifie un administrateur et retourne un token de session"""
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT id, password_hash, salt, is_active FROM admin_users WHERE username = ?',
                    (username,)
                )
                user = cursor.fetchone()
                
                if not user or not user['is_active']:
                    return None
                    
                # Vérifier le mot de passe
                password_hash = hashlib.pbkdf2_hmac(
                    'sha256', 
                    password.encode(), 
                    user['salt'].encode(), 
                    100000
                )
                
                if password_hash.hex() != user['password_hash']:
                    return None
                    
                # Créer une session
                session_id = secrets.token_urlsafe(32)
                expires_at = time.time() + 3600  # 1 heure
                
                with self.session_lock:
                    self.active_sessions[session_id] = {
                        'user_id': user['id'],
                        'username': username,
                        'expires_at': expires_at
                    }
                    
                # Enregistrer la connexion
                cursor.execute(
                    'UPDATE admin_users SET last_login = ? WHERE id = ?',
                    (time.time(), user['id'])
                )
                conn.commit()
                
                logger.info(f"Authentification admin réussie: {username}")
                return session_id
                
        except Exception as e:
            logger.error(f"Erreur authentification admin: {e}")
            return None
            
    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Valide une session admin"""
        with self.session_lock:
            if session_id in self.active_sessions:
                session = self.active_sessions[session_id]
                if time.time() < session['expires_at']:
                    # Prolonger la session
                    session['expires_at'] = time.time() + 3600
                    return session
                else:
                    # Session expirée
                    del self.active_sessions[session_id]
                    
        return None
        
    def logout_admin(self, session_id: str):
        """Déconnecte un administrateur"""
        with self.session_lock:
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
                
    def cleanup_expired_sessions(self):
        """Nettoie les sessions expirées"""
        current_time = time.time()
        with self.session_lock:
            expired_sessions = [
                sid for sid, session in self.active_sessions.items()
                if current_time >= session['expires_at']
            ]
            for sid in expired_sessions:
                del self.active_sessions[sid]

class ServerDatabaseManager:
    """
    Gestionnaire de base de données SQLite optimisé pour le serveur central EZRAX
    """
    
    def __init__(self, db_path="ezrax_server.db"):
        """
        Initialisation du gestionnaire optimisé
        """
        self.db_path = db_path
        self.connection_pool = ConnectionPool(db_path, pool_size=15)
        self.query_cache = QueryCache(max_size=300, ttl=60.0)
        
        # Locks granulaires par table
        self.table_locks = {
            "agents": threading.RLock(),
            "attack_logs": threading.RLock(),
            "blocked_ips": threading.RLock(),
            "commands": threading.RLock(),
            "whitelist": threading.RLock(),
            "admin_users": threading.RLock()
        }
        
        # Thread pool pour opérations asynchrones
        self.executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="Server-DB")
        
        # Métriques de performance
        self.metrics = {
            "queries_executed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "avg_query_time": 0.0,
            "slow_queries": 0,
            "errors": 0,
            "last_maintenance": 0,
            "total_agents": 0,
            "total_attacks": 0,
            "total_blocked_ips": 0
        }
        
        # Gestionnaire des admins
        self.admin_manager = AdminManager(self.connection_pool)
        
        # Initialiser la base de données
        self._init_database()
        self._create_default_admin()
        self._start_maintenance_thread()
        
    def _init_database(self):
        """Initialise la base de données avec toutes les tables optimisées"""
        with self.connection_pool.get_connection() as conn:
            cursor = conn.cursor()
            
            # Table des agents optimisée
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
                health_score REAL DEFAULT 1.0,
                total_attacks INTEGER DEFAULT 0,
                total_blocks INTEGER DEFAULT 0
            )
            ''')
            
            # Table des logs d'attaques avec hash pour éviter doublons
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
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
            ''')
            
            # Table des IPs bloquées optimisée
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
                UNIQUE(agent_id, ip, timestamp),
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
            ''')
            
            # Table des commandes optimisée
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                command_type TEXT NOT NULL,
                command_data TEXT,
                status TEXT DEFAULT 'pending',
                created_at REAL NOT NULL,
                executed_at REAL,
                created_by TEXT,
                priority INTEGER DEFAULT 1,
                FOREIGN KEY (agent_id) REFERENCES agents(agent_id)
            )
            ''')
            
            # Table de la liste blanche optimisée
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                added_at REAL NOT NULL,
                source TEXT NOT NULL,
                description TEXT,
                is_active INTEGER DEFAULT 1,
                added_by TEXT
            )
            ''')
            
            # Table de configuration du serveur
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS server_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL,
                data_type TEXT DEFAULT 'json'
            )
            ''')
            
            # Table des utilisateurs admin
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                email TEXT,
                created_at REAL NOT NULL,
                last_login REAL,
                is_active INTEGER DEFAULT 1,
                permissions TEXT DEFAULT 'admin'
            )
            ''')
            
            # Table des sessions admin
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES admin_users(id)
            )
            ''')
            
            # Table de cache pour statistiques
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics_cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                computed_at REAL NOT NULL,
                expires_at REAL NOT NULL
            )
            ''')
            
            # Indices optimisés
            indices = [
                # Agents
                'CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)',
                'CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen)',
                
                # Attack logs
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_agent_timestamp ON attack_logs(agent_id, timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_source_ip ON attack_logs(source_ip)',
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_type_time ON attack_logs(attack_type, timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_severity ON attack_logs(severity)',
                
                # Blocked IPs
                'CREATE INDEX IF NOT EXISTS idx_blocked_ips_agent_id ON blocked_ips(agent_id)',
                'CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip)',
                'CREATE INDEX IF NOT EXISTS idx_blocked_ips_timestamp ON blocked_ips(timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips(ip, end_time)',
                
                # Commands
                'CREATE INDEX IF NOT EXISTS idx_commands_agent_status ON commands(agent_id, status)',
                'CREATE INDEX IF NOT EXISTS idx_commands_created ON commands(created_at)',
                
                # Whitelist
                'CREATE INDEX IF NOT EXISTS idx_whitelist_ip_active ON whitelist(ip, is_active)',
                
                # Admin
                'CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users(username)',
                'CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires ON admin_sessions(expires_at)'
            ]
            
            for index_sql in indices:
                cursor.execute(index_sql)
                
            conn.commit()
            
        logger.info(f"Base de données serveur initialisée: {self.db_path}")
        
    def _create_default_admin(self):
        """Crée un compte admin par défaut si aucun n'existe"""
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM admin_users WHERE is_active = 1')
                admin_count = cursor.fetchone()[0]
                
                if admin_count == 0:
                    # Créer un admin par défaut
                    default_password = secrets.token_urlsafe(16)
                    success = self.admin_manager.create_admin_user(
                        "admin", 
                        default_password, 
                        "admin@localhost"
                    )
                    
                    if success:
                        logger.warning(f"Compte admin par défaut créé: admin / {default_password}")
                        logger.warning("CHANGEZ LE MOT DE PASSE PAR DÉFAUT IMMÉDIATEMENT!")
                        
        except Exception as e:
            logger.error(f"Erreur création admin par défaut: {e}")
            
    def _start_maintenance_thread(self):
        """Démarre le thread de maintenance automatique"""
        def maintenance_loop():
            while True:
                try:
                    time.sleep(300)  # Toutes les 5 minutes
                    self._perform_maintenance()
                except Exception as e:
                    logger.error(f"Erreur maintenance serveur: {e}")
                    
        maintenance_thread = threading.Thread(
            target=maintenance_loop,
            daemon=True,
            name="Server-Maintenance"
        )
        maintenance_thread.start()
        
    def _perform_maintenance(self):
        """Effectue la maintenance automatique"""
        current_time = time.time()
        
        if current_time - self.metrics["last_maintenance"] < 300:
            return
            
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Nettoyer le cache des statistiques expirées
                cursor.execute('DELETE FROM statistics_cache WHERE expires_at < ?', (current_time,))
                
                # Nettoyer les sessions admin expirées
                cursor.execute('DELETE FROM admin_sessions WHERE expires_at < ?', (current_time,))
                
                # Nettoyer les sessions en mémoire
                self.admin_manager.cleanup_expired_sessions()
                
                # Mettre à jour les métriques globales
                self._update_global_metrics(cursor)
                
                # Optimiser si nécessaire
                cursor.execute('PRAGMA optimize')
                
                conn.commit()
                
            self.metrics["last_maintenance"] = current_time
            logger.debug("Maintenance serveur effectuée")
            
        except Exception as e:
            logger.error(f"Erreur maintenance serveur: {e}")
            
    def _update_global_metrics(self, cursor):
        """Met à jour les métriques globales"""
        try:
            cursor.execute('SELECT COUNT(*) FROM agents')
            self.metrics["total_agents"] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM attack_logs')
            self.metrics["total_attacks"] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM blocked_ips WHERE end_time IS NULL')
            self.metrics["total_blocked_ips"] = cursor.fetchone()[0]
            
        except Exception as e:
            logger.error(f"Erreur mise à jour métriques: {e}")
            
    def _generate_hash(self, agent_id: str, attack_type: str, source_ip: str, 
                      timestamp: float) -> str:
        """Génère un hash unique pour éviter les doublons"""
        signature = f"{agent_id}:{attack_type}:{source_ip}:{int(timestamp//60)}"
        return hashlib.md5(signature.encode()).hexdigest()
        
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
            
    # --- Gestion des agents ---
    
    def register_agent(self, agent_data):
        """Enregistre un agent avec validation renforcée"""
        start_time = time.time()
        
        try:
            with self.table_locks["agents"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('SELECT agent_id FROM agents WHERE agent_id = ?', (agent_data["agent_id"],))
                    existing = cursor.fetchone()
                    
                    current_time = time.time()
                    
                    if existing:
                        # Mettre à jour l'agent existant
                        cursor.execute(
                            '''
                            UPDATE agents
                            SET hostname = ?, ip_address = ?, status = 'online', last_seen = ?,
                                os_info = ?, version = ?, features = ?, health_score = 1.0
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
                            (agent_id, hostname, ip_address, status, registered_at, last_seen, 
                             os_info, version, features, health_score)
                            VALUES (?, ?, ?, 'online', ?, ?, ?, ?, ?, 1.0)
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
                    
                    # Invalider le cache
                    self.query_cache.clear()
                    
                    self._update_query_metrics(time.time() - start_time)
                    
                    logger.info(f"Agent enregistré: {agent_data['agent_id']} ({agent_data['hostname']})")
                    return True
                    
        except Exception as e:
            logger.error(f"Erreur enregistrement agent: {e}")
            self.metrics["errors"] += 1
            return False
            
    def update_agent_status(self, agent_id, status="online", ip_address=None, health_score=None):
        """Met à jour le statut d'un agent avec métriques de santé"""
        start_time = time.time()
        
        try:
            with self.table_locks["agents"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('SELECT agent_id FROM agents WHERE agent_id = ?', (agent_id,))
                    existing = cursor.fetchone()
                    
                    if not existing:
                        logger.warning(f"Agent inexistant: {agent_id}")
                        return False
                        
                    current_time = time.time()
                    
                    # Préparer la requête de mise à jour
                    if ip_address and health_score is not None:
                        cursor.execute(
                            '''
                            UPDATE agents
                            SET status = ?, last_seen = ?, ip_address = ?, health_score = ?
                            WHERE agent_id = ?
                            ''',
                            (status, current_time, ip_address, health_score, agent_id)
                        )
                    elif ip_address:
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
                    
                    # Invalider le cache
                    self.query_cache.clear()
                    
                    self._update_query_metrics(time.time() - start_time)
                    
                    logger.debug(f"Statut agent mis à jour: {agent_id} ({status})")
                    return True
                    
        except Exception as e:
            logger.error(f"Erreur mise à jour statut agent: {e}")
            self.metrics["errors"] += 1
            return False
            
    def get_agents(self, include_offline=True):
        """Récupère la liste des agents avec cache"""
        cache_key = f"agents:{include_offline}"
        cached_result = self.query_cache.get(cache_key)
        
        if cached_result is not None:
            self.metrics["cache_hits"] += 1
            return cached_result
            
        self.metrics["cache_misses"] += 1
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
                    for field in ["os_info", "features"]:
                        if agent[field]:
                            try:
                                agent[field] = json.loads(agent[field])
                            except:
                                agent[field] = {}
                                
                    agents.append(agent)
                    
                # Mettre en cache
                self.query_cache.put(cache_key, agents)
                
                self._update_query_metrics(time.time() - start_time)
                return agents
                
        except Exception as e:
            logger.error(f"Erreur récupération agents: {e}")
            self.metrics["errors"] += 1
            return []
            
    def get_agent(self, agent_id):
        """Récupère les informations d'un agent spécifique"""
        cache_key = f"agent:{agent_id}"
        cached_result = self.query_cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        try:
            with self.connection_pool.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM agents WHERE agent_id = ?', (agent_id,))
                row = cursor.fetchone()
                
                if row:
                    agent = dict(row)
                    
                    for field in ["os_info", "features"]:
                        if agent[field]:
                            try:
                                agent[field] = json.loads(agent[field])
                            except:
                                agent[field] = {}
                                
                    # Mettre en cache
                    self.query_cache.put(cache_key, agent)
                    return agent
                    
                return None
                
        except Exception as e:
            logger.error(f"Erreur récupération agent: {e}")
            return None
            
    # --- Gestion des logs d'attaques ---
    
    def add_attack_logs(self, logs):
        """Ajoute des logs d'attaques avec déduplication"""
        if not logs:
            return 0
            
        start_time = time.time()
        
        try:
            with self.table_locks["attack_logs"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    count = 0
                    for log in logs:
                        if not all(key in log for key in ["agent_id", "timestamp", "attack_type", "source_ip", "scanner"]):
                            logger.warning(f"Log d'attaque incomplet: {log}")
                            continue
                            
                        details = log.get("details", {})
                        if not isinstance(details, str):
                            details = json.dumps(details)
                            
                        # Générer hash pour déduplication
                        attack_hash = self._generate_hash(
                            log["agent_id"], 
                            log["attack_type"], 
                            log["source_ip"], 
                            log["timestamp"]
                        )
                        
                        try:
                            cursor.execute(
                                '''
                                INSERT INTO attack_logs
                                (agent_id, timestamp, attack_type, source_ip, scanner, details, hash)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                                ''',
                                (
                                    log["agent_id"],
                                    log["timestamp"],
                                    log["attack_type"],
                                    log["source_ip"],
                                    log["scanner"],
                                    details,
                                    attack_hash
                                )
                            )
                            count += 1
                        except sqlite3.IntegrityError:
                            # Doublon détecté, ignorer
                            logger.debug(f"Doublon ignoré: {log['attack_type']} de {log['source_ip']}")
                            
                    conn.commit()
                    
                    # Invalider le cache
                    self.query_cache.clear()
                    
                    self._update_query_metrics(time.time() - start_time)
                    
                    logger.info(f"{count} logs d'attaques ajoutés")
                    return count
                    
        except Exception as e:
            logger.error(f"Erreur ajout logs d'attaques: {e}")
            self.metrics["errors"] += 1
            return 0
            
    def get_attack_logs(self, limit=100, offset=0, since=None, attack_type=None, agent_id=None, source_ip=None):
        """Récupère les logs d'attaques avec cache intelligent"""
        cache_key = f"attack_logs:{limit}:{offset}:{since}:{attack_type}:{agent_id}:{source_ip}"
        cached_result = self.query_cache.get(cache_key)
        
        if cached_result is not None:
            self.metrics["cache_hits"] += 1
            return cached_result
            
        self.metrics["cache_misses"] += 1
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = 'SELECT * FROM attack_logs'
                params = []
                
                # Construire les filtres
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
                    
                    if log["details"]:
                        try:
                            log["details"] = json.loads(log["details"])
                        except:
                            pass
                            
                    logs.append(log)
                    
                # Mettre en cache si requête simple
                if limit <= 1000 and offset == 0:
                    self.query_cache.put(cache_key, logs)
                    
                self._update_query_metrics(time.time() - start_time)
                return logs
                
        except Exception as e:
            logger.error(f"Erreur récupération logs d'attaques: {e}")
            self.metrics["errors"] += 1
            return []
            
    # --- Gestion des IPs bloquées ---
    
    def add_blocked_ips(self, blocked_ips):
        """Ajoute des IPs bloquées avec déduplication"""
        if not blocked_ips:
            return 0
            
        start_time = time.time()
        
        try:
            with self.table_locks["blocked_ips"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    count = 0
                    for block in blocked_ips:
                        if not all(key in block for key in ["agent_id", "ip", "timestamp", "reason", "duration"]):
                            logger.warning(f"IP bloquée incomplète: {block}")
                            continue
                            
                        try:
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
                        except sqlite3.IntegrityError:
                            # Doublon détecté
                            logger.debug(f"IP bloquée doublon ignorée: {block['ip']}")
                            
                    conn.commit()
                    
                    # Invalider le cache
                    self.query_cache.clear()
                    
                    self._update_query_metrics(time.time() - start_time)
                    
                    logger.info(f"{count} IPs bloquées ajoutées")
                    return count
                    
        except Exception as e:
            logger.error(f"Erreur ajout IPs bloquées: {e}")
            self.metrics["errors"] += 1
            return 0
            
    def get_blocked_ips(self, include_expired=False, agent_id=None):
        """Récupère la liste des IPs bloquées avec cache"""
        cache_key = f"blocked_ips:{include_expired}:{agent_id}"
        cached_result = self.query_cache.get(cache_key)
        
        if cached_result is not None:
            self.metrics["cache_hits"] += 1
            return cached_result
            
        self.metrics["cache_misses"] += 1
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = 'SELECT * FROM blocked_ips'
                params = []
                
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
                
                result = [dict(row) for row in cursor.fetchall()]
                
                # Mettre en cache
                if not agent_id:  # Cache global seulement
                    self.query_cache.put(cache_key, result)
                    
                self._update_query_metrics(time.time() - start_time)
                return result
                
        except Exception as e:
            logger.error(f"Erreur récupération IPs bloquées: {e}")
            self.metrics["errors"] += 1
            return []
            
    # --- Gestion des commandes ---
    
    def add_command(self, agent_id, command_type, command_data=None, created_by=None, priority=1):
        """Ajoute une commande à la file d'attente avec priorité"""
        start_time = time.time()
        
        try:
            with self.table_locks["commands"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    if command_data is not None and not isinstance(command_data, str):
                        command_data = json.dumps(command_data)
                        
                    current_time = time.time()
                    
                    cursor.execute(
                        '''
                        INSERT INTO commands
                        (agent_id, command_type, command_data, status, created_at, created_by, priority)
                        VALUES (?, ?, ?, 'pending', ?, ?, ?)
                        ''',
                        (agent_id, command_type, command_data, current_time, created_by, priority)
                    )
                    
                    command_id = cursor.lastrowid
                    conn.commit()
                    
                    # Invalider le cache
                    self.query_cache.clear()
                    
                    self._update_query_metrics(time.time() - start_time)
                    
                    logger.info(f"Commande ajoutée: {command_id} ({command_type}) pour {agent_id}")
                    return command_id
                    
        except Exception as e:
            logger.error(f"Erreur ajout commande: {e}")
            self.metrics["errors"] += 1
            return None
            
    def get_pending_commands(self, agent_id):
        """Récupère les commandes en attente pour un agent avec priorité"""
        cache_key = f"pending_commands:{agent_id}"
        cached_result = self.query_cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        try:
            with self.connection_pool.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute(
                    '''
                    SELECT * FROM commands
                    WHERE agent_id = ? AND status = 'pending'
                    ORDER BY priority DESC, created_at ASC
                    ''',
                    (agent_id,)
                )
                
                commands = []
                for row in cursor.fetchall():
                    command = dict(row)
                    
                    if command["command_data"]:
                        try:
                            command["command_data"] = json.loads(command["command_data"])
                        except:
                            pass
                            
                    commands.append(command)
                    
                # Cache court pour éviter spam
                if len(commands) > 0:
                    self.query_cache.put(cache_key, commands)
                    
                return commands
                
        except Exception as e:
            logger.error(f"Erreur récupération commandes: {e}")
            return []
            
    def update_command_status(self, command_id, status):
        """Met à jour le statut d'une commande"""
        try:
            with self.table_locks["commands"]:
                with self.connection_pool.get_connection() as conn:
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
                    
                    # Invalider le cache
                    self.query_cache.clear()
                    
                    logger.info(f"Statut commande mis à jour: {command_id} ({status})")
                    return True
                    
        except Exception as e:
            logger.error(f"Erreur mise à jour statut commande: {e}")
            return False
            
    # --- Gestion de la liste blanche ---
    
    def add_whitelist_entry(self, ip, source, description=None, added_by=None):
        """Ajoute une entrée à la liste blanche"""
        try:
            with self.table_locks["whitelist"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    current_time = time.time()
                    
                    cursor.execute('SELECT ip FROM whitelist WHERE ip = ?', (ip,))
                    existing = cursor.fetchone()
                    
                    if existing:
                        cursor.execute(
                            '''
                            UPDATE whitelist
                            SET source = ?, description = ?, added_at = ?, is_active = 1, added_by = ?
                            WHERE ip = ?
                            ''',
                            (source, description, current_time, added_by, ip)
                        )
                    else:
                        cursor.execute(
                            '''
                            INSERT INTO whitelist
                            (ip, added_at, source, description, added_by)
                            VALUES (?, ?, ?, ?, ?)
                            ''',
                            (ip, current_time, source, description, added_by)
                        )
                        
                    conn.commit()
                    
                    # Invalider le cache
                    self.query_cache.clear()
                    
                    logger.info(f"Entrée ajoutée à la liste blanche: {ip} ({source})")
                    return True
                    
        except Exception as e:
            logger.error(f"Erreur ajout liste blanche: {e}")
            return False
            
    def remove_whitelist_entry(self, ip):
        """Supprime une entrée de la liste blanche"""
        try:
            with self.table_locks["whitelist"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    cursor.execute('DELETE FROM whitelist WHERE ip = ?', (ip,))
                    conn.commit()
                    
                    # Invalider le cache
                    self.query_cache.clear()
                    
                    logger.info(f"Entrée supprimée de la liste blanche: {ip}")
                    return True
                    
        except Exception as e:
            logger.error(f"Erreur suppression liste blanche: {e}")
            return False
            
    def get_whitelist(self):
        """Récupère la liste blanche avec cache"""
        cache_key = "whitelist:active"
        cached_result = self.query_cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        try:
            with self.connection_pool.get_connection() as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM whitelist WHERE is_active = 1 ORDER BY added_at DESC')
                
                result = [dict(row) for row in cursor.fetchall()]
                
                # Mettre en cache
                self.query_cache.put(cache_key, result)
                
                return result
                
        except Exception as e:
            logger.error(f"Erreur récupération liste blanche: {e}")
            return []
            
    # --- Statistiques optimisées ---
    
    def get_global_stats(self):
        """Récupère les statistiques globales avec cache intelligent"""
        cache_key = "global_stats"
        cached_result = self.query_cache.get(cache_key)
        
        if cached_result is not None:
            self.metrics["cache_hits"] += 1
            return cached_result
            
        self.metrics["cache_misses"] += 1
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {
                    "total_agents": 0,
                    "active_agents": 0,
                    "total_attacks": 0,
                    "blocked_ips": 0,
                    "attacks_by_type": {},
                    "attacks_by_day": {},
                    "top_attackers": [],
                    "agent_health": {}
                }
                
                # Requêtes optimisées en parallèle
                cursor.execute('SELECT COUNT(*) FROM agents')
                stats["total_agents"] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM agents WHERE status = "online"')
                stats["active_agents"] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM attack_logs')
                stats["total_attacks"] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM blocked_ips WHERE end_time IS NULL')
                stats["blocked_ips"] = cursor.fetchone()[0]
                
                # Attaques par type
                cursor.execute(
                    '''
                    SELECT attack_type, COUNT(*) AS count
                    FROM attack_logs
                    WHERE timestamp > ?
                    GROUP BY attack_type
                    ORDER BY count DESC
                    ''',
                    (time.time() - 86400,)  # Dernières 24h
                )
                stats["attacks_by_type"] = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Top des attaquants
                cursor.execute(
                    '''
                    SELECT source_ip, COUNT(*) AS count
                    FROM attack_logs
                    WHERE timestamp > ?
                    GROUP BY source_ip
                    ORDER BY count DESC
                    LIMIT 10
                    ''',
                    (time.time() - 86400,)
                )
                stats["top_attackers"] = [{"ip": row[0], "count": row[1]} for row in cursor.fetchall()]
                
                # Santé des agents
                cursor.execute(
                    '''
                    SELECT agent_id, hostname, health_score, last_seen
                    FROM agents
                    WHERE status = 'online'
                    '''
                )
                for row in cursor.fetchall():
                    stats["agent_health"][row[0]] = {
                        "hostname": row[1],
                        "health_score": row[2] or 1.0,
                        "last_seen": row[3]
                    }
                    
                # Mettre en cache
                self.query_cache.put(cache_key, stats)
                
                self._update_query_metrics(time.time() - start_time)
                return stats
                
        except Exception as e:
            logger.error(f"Erreur récupération statistiques globales: {e}")
            self.metrics["errors"] += 1
            return {
                "total_agents": 0,
                "active_agents": 0,
                "total_attacks": 0,
                "blocked_ips": 0,
                "attacks_by_type": {},
                "top_attackers": [],
                "agent_health": {}
            }
            
    def get_agent_stats(self, agent_id):
        """Récupère les statistiques d'un agent spécifique"""
        cache_key = f"agent_stats:{agent_id}"
        cached_result = self.query_cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                stats = {
                    "total_attacks": 0,
                    "blocked_ips": 0,
                    "attacks_by_type": {},
                    "attacks_by_hour": {}
                }
                
                # Statistiques de l'agent
                cursor.execute('SELECT COUNT(*) FROM attack_logs WHERE agent_id = ?', (agent_id,))
                stats["total_attacks"] = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM blocked_ips WHERE agent_id = ? AND end_time IS NULL', (agent_id,))
                stats["blocked_ips"] = cursor.fetchone()[0]
                
                # Attaques par type pour cet agent
                cursor.execute(
                    '''
                    SELECT attack_type, COUNT(*) AS count
                    FROM attack_logs
                    WHERE agent_id = ? AND timestamp > ?
                    GROUP BY attack_type
                    ORDER BY count DESC
                    ''',
                    (agent_id, time.time() - 86400)
                )
                stats["attacks_by_type"] = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Mettre en cache
                self.query_cache.put(cache_key, stats)
                
                return stats
                
        except Exception as e:
            logger.error(f"Erreur récupération statistiques agent: {e}")
            return {
                "total_attacks": 0,
                "blocked_ips": 0,
                "attacks_by_type": {},
                "attacks_by_hour": {}
            }
            
    # --- Configuration du serveur ---
    
    def set_config(self, key, value):
        """Définit une valeur de configuration"""
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
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
                
                logger.debug(f"Configuration serveur mise à jour: {key}")
                return True
                
        except Exception as e:
            logger.error(f"Erreur mise à jour configuration: {e}")
            return False
            
    def get_config(self, key, default=None):
        """Récupère une valeur de configuration"""
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT value FROM server_config WHERE key = ?', (key,))
                row = cursor.fetchone()
                
                if row:
                    value = row[0]
                    
                    try:
                        return json.loads(value)
                    except:
                        return value
                        
                return default
                
        except Exception as e:
            logger.error(f"Erreur récupération configuration: {e}")
            return default
            
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Retourne les métriques de performance complètes"""
        pool_stats = {
            "pool_size": self.connection_pool.pool_size,
            "active_connections": len(self.connection_pool.active_connections),
            "total_connections_created": self.connection_pool.total_connections
        }
        
        cache_stats = self.query_cache.get_stats()
        
        admin_stats = {
            "active_sessions": len(self.admin_manager.active_sessions)
        }
        
        return {
            **self.metrics,
            "connection_pool": pool_stats,
            "query_cache": cache_stats,
            "admin_sessions": admin_stats
        }
        
    def cleanup_old_data(self, retention_days=30):
        """Supprime les anciennes données avec optimisations"""
        cutoff_time = time.time() - (retention_days * 24 * 3600)
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('BEGIN IMMEDIATE')
                
                try:
                    # Compter avant suppression
                    cursor.execute('SELECT COUNT(*) FROM attack_logs WHERE timestamp < ?', (cutoff_time,))
                    old_attacks = cursor.fetchone()[0]
                    
                    cursor.execute('SELECT COUNT(*) FROM blocked_ips WHERE end_time IS NOT NULL AND end_time < ?', (cutoff_time,))
                    old_blocks = cursor.fetchone()[0]
                    
                    # Supprimer par batch
                    if old_attacks > 0:
                        cursor.execute('DELETE FROM attack_logs WHERE timestamp < ?', (cutoff_time,))
                        
                    if old_blocks > 0:
                        cursor.execute('DELETE FROM blocked_ips WHERE end_time IS NOT NULL AND end_time < ?', (cutoff_time,))
                        
                    # Nettoyer le cache des statistiques
                    cursor.execute('DELETE FROM statistics_cache WHERE expires_at < ?', (time.time(),))
                    
                    # Nettoyer les anciennes sessions admin
                    cursor.execute('DELETE FROM admin_sessions WHERE expires_at < ?', (time.time(),))
                    
                    cursor.execute('COMMIT')
                    
                    if old_attacks > 0 or old_blocks > 0:
                        logger.info(f"Nettoyage serveur: {old_attacks} logs d'attaques et {old_blocks} IPs bloquées supprimés")
                        
                        # Optimiser après nettoyage important
                        if old_attacks > 5000 or old_blocks > 5000:
                            cursor.execute('VACUUM')
                            logger.info("VACUUM serveur exécuté")
                            
                    # Invalider tous les caches
                    self.query_cache.clear()
                    
                    self._update_query_metrics(time.time() - start_time)
                    
                except Exception as e:
                    cursor.execute('ROLLBACK')
                    raise e
                    
        except Exception as e:
            logger.error(f"Erreur nettoyage données serveur: {e}")
            self.metrics["errors"] += 1
            
    def close(self):
        """Ferme proprement le gestionnaire de base de données"""
        logger.info("Fermeture du gestionnaire de base de données serveur")
        
        try:
            # Arrêter l'executor
            self.executor.shutdown(wait=True)
            
            # Fermer le pool de connexions
            self.connection_pool.close_all()
            
            # Log des métriques finales
            metrics = self.get_performance_metrics()
            logger.info(f"Métriques finales serveur: {metrics}")
            
        except Exception as e:
            logger.error(f"Erreur fermeture serveur: {e}")
