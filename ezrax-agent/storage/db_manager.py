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
import queue
import hashlib
from typing import Dict, List, Tuple, Any, Optional, Union
from contextlib import contextmanager
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class ConnectionPool:
    """Pool de connexions SQLite optimisé pour les performances """
    
    def __init__(self, db_path: str, pool_size: int = 5, timeout: float = 30.0):
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
        """Crée une nouvelle connexion """
        try:
            conn = sqlite3.connect(
                self.db_path,
                timeout=self.timeout,
                check_same_thread=False,  # Permettre l'usage multi-thread
                isolation_level=None  # Mode autocommit pour les performances
            )
            
            # Optimisations SQLite
            conn.execute("PRAGMA journal_mode=WAL")  # Write-Ahead Logging
            conn.execute("PRAGMA synchronous=NORMAL")  # Compromis perf/sécurité
            conn.execute("PRAGMA cache_size=10000")  # Cache 10MB
            conn.execute("PRAGMA temp_store=MEMORY")  # Tables temp en mémoire
            conn.execute("PRAGMA mmap_size=268435456")  # Memory mapping 256MB
            conn.execute("PRAGMA optimize")  # Optimiser automatiquement
            
            # Configuration des types
            conn.row_factory = sqlite3.Row
            
            with self.lock:
                self.total_connections += 1
                
            logger.debug(f"Connexion SQLite créée (total: {self.total_connections})")
            return conn
            
        except Exception as e:
            logger.error(f"Erreur lors de la création de connexion SQLite: {e}")
            return None
            
    @contextmanager
    def get_connection(self):
        """Context manager pour récupérer une connexion du pool"""
        conn = None
        try:
            try:
                conn = self.pool.get(timeout=self.timeout)
            except queue.Empty:
                logger.warning("Pool de connexions épuisé, création d'une connexion temporaire")
                conn = self._create_connection()
                if not conn:
                    raise RuntimeError("Impossible de créer une connexion à la base de données")
                    

            with self.lock:
                self.active_connections.add(id(conn))  # Utiliser l'ID au lieu de l'objet
            yield conn
            
        except Exception as e:
            logger.error(f"Erreur avec la connexion de base de données: {e}")
            # Fermer la connexion défaillante
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
                    
                    # Remettre la connexion dans le pool si elle est saine
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
                
        # Les connexions actives se fermeront automatiquement
        with self.lock:
            self.active_connections.clear()
                
        logger.info(f"Pool de connexions fermé ({self.total_connections} connexions)")

class QueryCache:
    """Cache intelligent pour les requêtes fréquentes"""
    
    def __init__(self, max_size: int = 100, ttl: float = 60.0):
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
                # Vérifier l'expiration
                if time.time() - self.access_times[key] < self.ttl:
                    self.hits += 1
                    return self.cache[key]
                else:
                    # Expirée
                    del self.cache[key]
                    del self.access_times[key]
                    
            self.misses += 1
            return None
            
    def put(self, key: str, value: Any):
        """Stocke une valeur dans le cache"""
        with self.lock:
            # Nettoyer le cache si plein
            if len(self.cache) >= self.max_size:
                self._evict_oldest()
                
            self.cache[key] = value
            self.access_times[key] = time.time()
            
    def _evict_oldest(self):
        """Évince les entrées les plus anciennes"""
        if not self.access_times:
            return
            
        # Supprimer 25% des entrées les plus anciennes
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

class DatabaseManager:
    """
    Gestionnaire de base de données SQLite pour l'agent EZRAX 
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
        

        self.connection_pool = ConnectionPool(self.db_path, pool_size=8)
        

        self.query_cache = QueryCache(max_size=200, ttl=30.0)
        

        self.table_locks = {
            "attack_logs": threading.RLock(),
            "blocked_ips": threading.RLock(),
            "agent_state": threading.RLock(),
            "whitelist": threading.RLock()
        }
        

        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="DB-Worker")
        

        self.metrics = {
            "queries_executed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "avg_query_time": 0.0,
            "slow_queries": 0,
            "errors": 0,
            "last_maintenance": 0
        }
        
        # Créer le répertoire de la base de données s'il n'existe pas
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Initialiser la base de données
        self._init_database()
        
        # Démarrer la maintenance automatique
        self._start_maintenance_thread()
        
    def _init_database(self):
        """Initialise la base de données SQLite avec les tables optimisées"""
        with self.connection_pool.get_connection() as conn:
            cursor = conn.cursor()
            
            # Table des logs d'attaques avec indices optimisés
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                attack_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                scanner TEXT NOT NULL,
                details TEXT NOT NULL,
                synced INTEGER DEFAULT 0,
                severity TEXT DEFAULT 'MEDIUM',
                hash TEXT UNIQUE  -- NOUVEAU: Pour éviter les doublons
            )
            ''')
            
            # Table des IPs bloquées optimisée
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp REAL NOT NULL,
                end_time REAL,
                reason TEXT NOT NULL,
                duration INTEGER NOT NULL,
                synced INTEGER DEFAULT 0,
                UNIQUE(ip, timestamp)  -- NOUVEAU: Éviter les doublons
            )
            ''')
            
            # Table de configuration/état de l'agent
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS agent_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at REAL NOT NULL,
                data_type TEXT DEFAULT 'json'  -- NOUVEAU: Type de données
            )
            ''')
            
            # Table pour les listes blanches optimisée
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                added_at REAL NOT NULL,
                source TEXT NOT NULL,
                description TEXT,
                is_active INTEGER DEFAULT 1  -- NOUVEAU: Activation/désactivation
            )
            ''')
            

            cursor.execute('''
            CREATE TABLE IF NOT EXISTS statistics_cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                computed_at REAL NOT NULL,
                expires_at REAL NOT NULL
            )
            ''')
            
            # Indices optimisés pour les requêtes courantes
            indices = [
                # Attack logs
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_timestamp ON attack_logs(timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_source_ip ON attack_logs(source_ip)',
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_type_time ON attack_logs(attack_type, timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_synced ON attack_logs(synced)',
                'CREATE INDEX IF NOT EXISTS idx_attack_logs_severity ON attack_logs(severity)',
                
                # Blocked IPs
                'CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips(ip)',
                'CREATE INDEX IF NOT EXISTS idx_blocked_ips_timestamp ON blocked_ips(timestamp)',
                'CREATE INDEX IF NOT EXISTS idx_blocked_ips_end_time ON blocked_ips(end_time)',
                'CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips(ip, end_time)',
                
                # Whitelist
                'CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist(ip)',
                'CREATE INDEX IF NOT EXISTS idx_whitelist_active ON whitelist(is_active)',
                
                # Statistics cache
                'CREATE INDEX IF NOT EXISTS idx_stats_cache_expires ON statistics_cache(expires_at)'
            ]
            
            for index_sql in indices:
                cursor.execute(index_sql)
                
            conn.commit()
            
        logger.info(f"Base de données optimisée initialisée: {self.db_path}")
        
    def _start_maintenance_thread(self):
        """Démarre le thread de maintenance automatique"""
        def maintenance_loop():
            while True:
                try:
                    time.sleep(300)  # Toutes les 5 minutes
                    self._perform_maintenance()
                except Exception as e:
                    logger.error(f"Erreur dans la maintenance DB: {e}")
                    
        maintenance_thread = threading.Thread(
            target=maintenance_loop,
            daemon=True,
            name="DB-Maintenance"
        )
        maintenance_thread.start()
        
    def _perform_maintenance(self):
        """Effectue la maintenance automatique de la base de données"""
        current_time = time.time()
        
        # Éviter la maintenance trop fréquente
        if current_time - self.metrics["last_maintenance"] < 300:
            return
            
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Nettoyer le cache des statistiques expirées
                cursor.execute('DELETE FROM statistics_cache WHERE expires_at < ?', (current_time,))
                
                # Optimiser la base de données
                cursor.execute('PRAGMA optimize')
                
                # Analyser les statistiques (si beaucoup de données)
                cursor.execute('SELECT COUNT(*) FROM attack_logs')
                attack_count = cursor.fetchone()[0]
                
                if attack_count > 10000:
                    cursor.execute('ANALYZE')
                    
                conn.commit()
                
            self.metrics["last_maintenance"] = current_time
            logger.debug("Maintenance automatique de la base de données effectuée")
            
        except Exception as e:
            logger.error(f"Erreur lors de la maintenance: {e}")
            
    def _generate_hash(self, attack_type: str, source_ip: str, details: Dict[str, Any], 
                      timestamp: float) -> str:
        """Génère un hash unique pour éviter les doublons d'attaques"""
        # Créer une signature de l'attaque
        signature = f"{attack_type}:{source_ip}:{int(timestamp//60)}"  # Groupé par minute
        
        # Ajouter des détails importants
        if isinstance(details, dict):
            important_keys = ["packet_count", "distinct_ports", "scan_type"]
            signature += ":" + ":".join(str(details.get(key, "")) for key in important_keys)
            
        return hashlib.md5(signature.encode()).hexdigest()
        
    def add_attack_log(self, attack_type: str, source_ip: str, scanner: str, 
                      details: Dict[str, Any]) -> bool:
        """
        Ajoute un log d'attaque à la base de données 
        """
        start_time = time.time()
        
        try:
            timestamp = time.time()
            details_json = json.dumps(details, ensure_ascii=False)
            severity = details.get("severity", "MEDIUM")
            
            # Générer un hash pour éviter les doublons
            attack_hash = self._generate_hash(attack_type, source_ip, details, timestamp)
            
            with self.table_locks["attack_logs"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    try:
                        cursor.execute(
                            '''
                            INSERT INTO attack_logs 
                            (timestamp, attack_type, source_ip, scanner, details, severity, hash)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            ''',
                            (timestamp, attack_type, source_ip, scanner, details_json, severity, attack_hash)
                        )
                        conn.commit()
                        
                        # Invalider le cache des statistiques
                        self.query_cache.clear()
                        
                        self._update_query_metrics(time.time() - start_time)
                        return True
                        
                    except sqlite3.IntegrityError:
                        # Doublon détecté, ignorer silencieusement
                        logger.debug(f"Doublon d'attaque ignoré: {attack_type} de {source_ip}")
                        return False
                        
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout du log d'attaque: {e}")
            self.metrics["errors"] += 1
            return False
            
    def add_blocked_ip(self, ip: str, reason: str, timestamp: float, duration: int) -> bool:
        """
        Ajoute une IP bloquée à la base de données 
        """
        start_time = time.time()
        
        try:
            with self.table_locks["blocked_ips"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Vérifier si l'IP est déjà bloquée 
                    cursor.execute(
                        'SELECT id FROM blocked_ips WHERE ip = ? AND end_time IS NULL LIMIT 1',
                        (ip,)
                    )
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
                        try:
                            cursor.execute(
                                '''
                                INSERT INTO blocked_ips (ip, timestamp, reason, duration)
                                VALUES (?, ?, ?, ?)
                                ''',
                                (ip, timestamp, reason, duration)
                            )
                        except sqlite3.IntegrityError:
                            # Conflit de contrainte unique, probablement une race condition
                            logger.debug(f"Conflit lors de l'insertion de l'IP bloquée: {ip}")
                            return False
                            
                    conn.commit()
                    self._update_query_metrics(time.time() - start_time)
                    return True
                    
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout de l'IP bloquée: {e}")
            self.metrics["errors"] += 1
            return False
            
    def get_attack_logs(self, limit: int = 100, offset: int = 0, 
                       since: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Récupère les logs d'attaques 
        """
        start_time = time.time()
        
        # Créer une clé de cache
        cache_key = f"attack_logs:{limit}:{offset}:{since or 0}"
        cached_result = self.query_cache.get(cache_key)
        
        if cached_result is not None:
            self.metrics["cache_hits"] += 1
            return cached_result
            
        self.metrics["cache_misses"] += 1
        
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Optimiser la requête avec les indices
                if since is not None:
                    cursor.execute(
                        '''
                        SELECT id, timestamp, attack_type, source_ip, scanner, details, severity
                        FROM attack_logs
                        WHERE timestamp >= ?
                        ORDER BY timestamp DESC
                        LIMIT ? OFFSET ?
                        ''',
                        (since, limit, offset)
                    )
                else:
                    cursor.execute(
                        '''
                        SELECT id, timestamp, attack_type, source_ip, scanner, details, severity
                        FROM attack_logs
                        ORDER BY timestamp DESC
                        LIMIT ? OFFSET ?
                        ''',
                        (limit, offset)
                    )
                
                rows = cursor.fetchall()
                
                # Conversion optimisée avec traitement par batch
                result = []
                for row in rows:
                    log = dict(row)
                    try:
                        log['details'] = json.loads(log['details'])
                    except (json.JSONDecodeError, TypeError):
                        log['details'] = {}
                    result.append(log)
                    
                # Mettre en cache si la requête n'est pas trop spécifique
                if limit <= 1000 and offset == 0:
                    self.query_cache.put(cache_key, result)
                    
                self._update_query_metrics(time.time() - start_time)
                return result
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des logs d'attaques: {e}")
            self.metrics["errors"] += 1
            return []
            
    def get_blocked_ips(self, include_expired: bool = False) -> List[Dict[str, Any]]:
        """
        Récupère la liste des IPs bloquées 
        """
        start_time = time.time()
        
        # Cache pour les IPs actives uniquement
        if not include_expired:
            cache_key = "blocked_ips:active"
            cached_result = self.query_cache.get(cache_key)
            if cached_result is not None:
                self.metrics["cache_hits"] += 1
                return cached_result
            self.metrics["cache_misses"] += 1
            
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                if include_expired:
                    cursor.execute(
                        '''
                        SELECT ip, timestamp, end_time, reason, duration
                        FROM blocked_ips
                        ORDER BY timestamp DESC
                        '''
                    )
                else:
                    cursor.execute(
                        '''
                        SELECT ip, timestamp, end_time, reason, duration
                        FROM blocked_ips
                        WHERE end_time IS NULL
                        ORDER BY timestamp DESC
                        '''
                    )
                
                result = [dict(row) for row in cursor.fetchall()]
                
                # Mettre en cache les IPs actives
                if not include_expired:
                    self.query_cache.put(cache_key, result)
                    
                self._update_query_metrics(time.time() - start_time)
                return result
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des IPs bloquées: {e}")
            self.metrics["errors"] += 1
            return []
            
    def get_unsynced_data(self, max_records: int = 100) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Récupère les données non synchronisées 
        """
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Requête optimisée avec LIMIT et indices
                cursor.execute(
                    '''
                    SELECT id, timestamp, attack_type, source_ip, scanner, details, severity
                    FROM attack_logs
                    WHERE synced = 0
                    ORDER BY timestamp
                    LIMIT ?
                    ''',
                    (max_records,)
                )
                
                attack_logs = []
                for row in cursor.fetchall():
                    log = dict(row)
                    try:
                        log['details'] = json.loads(log['details'])
                    except (json.JSONDecodeError, TypeError):
                        log['details'] = {}
                    log['agent_id'] = self.agent_id
                    attack_logs.append(log)
                    
                # Récupérer les IPs bloquées non synchronisées
                cursor.execute(
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
                for row in cursor.fetchall():
                    blocked_ip = dict(row)
                    blocked_ip['agent_id'] = self.agent_id
                    blocked_ips.append(blocked_ip)
                    
                self._update_query_metrics(time.time() - start_time)
                return (attack_logs, blocked_ips)
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des données non synchronisées: {e}")
            self.metrics["errors"] += 1
            return ([], [])
            
    def mark_as_synced(self, attack_log_ids: List[int], blocked_ip_ids: List[int]) -> bool:
        """
        Marque les données comme synchronisées 
        """
        if not attack_log_ids and not blocked_ip_ids:
            return True
            
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Transaction pour l'atomicité
                cursor.execute('BEGIN IMMEDIATE')
                
                try:
                    # Marquer les logs d'attaques par batch
                    if attack_log_ids:
                        # Utiliser des batch de 500 pour éviter les limites SQLite
                        batch_size = 500
                        for i in range(0, len(attack_log_ids), batch_size):
                            batch = attack_log_ids[i:i + batch_size]
                            placeholders = ','.join('?' * len(batch))
                            cursor.execute(
                                f'UPDATE attack_logs SET synced = 1 WHERE id IN ({placeholders})',
                                batch
                            )
                            
                    # Marquer les IPs bloquées par batch
                    if blocked_ip_ids:
                        batch_size = 500
                        for i in range(0, len(blocked_ip_ids), batch_size):
                            batch = blocked_ip_ids[i:i + batch_size]
                            placeholders = ','.join('?' * len(batch))
                            cursor.execute(
                                f'UPDATE blocked_ips SET synced = 1 WHERE id IN ({placeholders})',
                                batch
                            )
                            
                    cursor.execute('COMMIT')
                    
                    # Invalider les caches pertinents
                    self.query_cache.clear()
                    
                    self._update_query_metrics(time.time() - start_time)
                    return True
                    
                except Exception as e:
                    cursor.execute('ROLLBACK')
                    raise e
                    
        except Exception as e:
            logger.error(f"Erreur lors de la synchronisation: {e}")
            self.metrics["errors"] += 1
            return False
            
    def cleanup_old_data(self):
        """Supprime les anciennes données """
        cutoff_time = time.time() - (self.retention_days * 24 * 3600)
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Transaction pour l'atomicité
                cursor.execute('BEGIN IMMEDIATE')
                
                try:
                    # Compter avant suppression
                    cursor.execute('SELECT COUNT(*) FROM attack_logs WHERE timestamp < ?', (cutoff_time,))
                    old_attacks = cursor.fetchone()[0]
                    
                    cursor.execute('SELECT COUNT(*) FROM blocked_ips WHERE end_time IS NOT NULL AND end_time < ?', (cutoff_time,))
                    old_blocks = cursor.fetchone()[0]
                    
                    # Supprimer par batch pour éviter le verrouillage long
                    if old_attacks > 0:
                        cursor.execute('DELETE FROM attack_logs WHERE timestamp < ?', (cutoff_time,))
                        
                    if old_blocks > 0:
                        cursor.execute('DELETE FROM blocked_ips WHERE end_time IS NOT NULL AND end_time < ?', (cutoff_time,))
                        
                    # Nettoyer le cache des statistiques
                    cursor.execute('DELETE FROM statistics_cache WHERE expires_at < ?', (time.time(),))
                    
                    cursor.execute('COMMIT')
                    
                    if old_attacks > 0 or old_blocks > 0:
                        logger.info(f"Nettoyage des données: {old_attacks} logs d'attaques et {old_blocks} IPs bloquées supprimés")
                        
                        # Optimiser après nettoyage important
                        if old_attacks > 1000 or old_blocks > 1000:
                            cursor.execute('VACUUM')
                            logger.info("VACUUM exécuté après nettoyage important")
                            
                    # Invalider tous les caches
                    self.query_cache.clear()
                    
                    self._update_query_metrics(time.time() - start_time)
                    
                except Exception as e:
                    cursor.execute('ROLLBACK')
                    raise e
                    
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage des données: {e}")
            self.metrics["errors"] += 1
            
    def _update_query_metrics(self, query_time: float):
        """Met à jour les métriques de performance des requêtes"""
        self.metrics["queries_executed"] += 1
        
        # Moyenne mobile de la durée des requêtes
        if self.metrics["avg_query_time"] == 0:
            self.metrics["avg_query_time"] = query_time
        else:
            alpha = 0.1
            self.metrics["avg_query_time"] = (
                alpha * query_time + 
                (1 - alpha) * self.metrics["avg_query_time"]
            )
            
        # Compter les requêtes lentes (>1s)
        if query_time > 1.0:
            self.metrics["slow_queries"] += 1
            logger.warning(f"Requête lente détectée: {query_time:.2f}s")
            
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Retourne les métriques de performance de la base de données"""
        pool_stats = {
            "pool_size": self.connection_pool.pool_size,
            "active_connections": len(self.connection_pool.active_connections),
            "total_connections_created": self.connection_pool.total_connections
        }
        
        cache_stats = self.query_cache.get_stats()
        
        return {
            **self.metrics,
            "connection_pool": pool_stats,
            "query_cache": cache_stats
        }
        
    def update_block_end_time(self, ip: str) -> bool:
        """Met à jour le temps de fin de blocage d'une IP"""
        end_time = time.time()
        
        try:
            with self.table_locks["blocked_ips"]:
                with self.connection_pool.get_connection() as conn:
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
                    
                    # Invalider le cache
                    self.query_cache.clear()
                    return True
                    
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour du temps de fin: {e}")
            return False
            
    def update_whitelist(self, whitelist: List[Dict[str, Any]]):
        """Met à jour la liste blanche des IPs"""
        current_time = time.time()
        
        try:
            with self.table_locks["whitelist"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    
                    # Transaction pour l'atomicité
                    cursor.execute('BEGIN IMMEDIATE')
                    
                    try:
                        # Désactiver toutes les entrées existantes
                        cursor.execute('UPDATE whitelist SET is_active = 0')
                        
                        # Ajouter/réactiver les nouvelles entrées
                        for entry in whitelist:
                            cursor.execute(
                                '''
                                INSERT OR REPLACE INTO whitelist (ip, added_at, source, description, is_active)
                                VALUES (?, ?, ?, ?, 1)
                                ''',
                                (
                                    entry['ip'],
                                    entry.get('added_at', current_time),
                                    entry.get('source', 'central_server'),
                                    entry.get('description', ''),
                                )
                            )
                            
                        cursor.execute('COMMIT')
                        
                        # Invalider le cache
                        self.query_cache.clear()
                        
                        logger.info(f"Liste blanche mise à jour: {len(whitelist)} entrées")
                        
                    except Exception as e:
                        cursor.execute('ROLLBACK')
                        raise e
                        
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour de la liste blanche: {e}")
            
    def get_whitelist(self) -> List[Dict[str, Any]]:
        """Récupère la liste blanche des IPs avec cache"""
        cache_key = "whitelist:active"
        cached_result = self.query_cache.get(cache_key)
        
        if cached_result is not None:
            return cached_result
            
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT ip, added_at, source, description FROM whitelist WHERE is_active = 1')
                result = [dict(row) for row in cursor.fetchall()]
                
                # Mettre en cache
                self.query_cache.put(cache_key, result)
                return result
                
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de la liste blanche: {e}")
            return []
            
    def set_agent_state(self, key: str, value: Any):
        """Définit une valeur dans l'état de l'agent avec type"""
        json_value = json.dumps(value, ensure_ascii=False)
        current_time = time.time()
        data_type = type(value).__name__
        
        try:
            with self.table_locks["agent_state"]:
                with self.connection_pool.get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        '''
                        INSERT OR REPLACE INTO agent_state (key, value, updated_at, data_type)
                        VALUES (?, ?, ?, ?)
                        ''',
                        (key, json_value, current_time, data_type)
                    )
                    conn.commit()
                    
        except Exception as e:
            logger.error(f"Erreur lors de la définition de l'état: {e}")
            
    def get_agent_state(self, key: str, default: Any = None) -> Any:
        """Récupère une valeur de l'état de l'agent"""
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT value, data_type FROM agent_state WHERE key = ?', (key,))
                row = cursor.fetchone()
                
                if row:
                    try:
                        return json.loads(row[0])
                    except (json.JSONDecodeError, TypeError):
                        return row[0]
                else:
                    return default
                    
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'état: {e}")
            return default
            
    def close(self):
        """Ferme proprement la base de données et tous les composants"""
        logger.info("Fermeture du gestionnaire de base de données")
        
        try:
            # Arrêter l'executor
            self.executor.shutdown(wait=True)
            
            # Fermer le pool de connexions
            self.connection_pool.close_all()
            
            # Log des métriques finales
            metrics = self.get_performance_metrics()
            logger.info(f"Métriques finales de la base de données: {metrics}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la fermeture: {e}")
            
    def optimize_database(self):
        """Lance une optimisation complète de la base de données"""
        logger.info("Optimisation complète de la base de données...")
        start_time = time.time()
        
        try:
            with self.connection_pool.get_connection() as conn:
                cursor = conn.cursor()
                
                # Analyser les statistiques
                cursor.execute('ANALYZE')
                
                # Optimiser
                cursor.execute('PRAGMA optimize')
                
                # Vérifier l'intégrité
                cursor.execute('PRAGMA integrity_check')
                integrity_result = cursor.fetchone()[0]
                
                if integrity_result != "ok":
                    logger.error(f"Problème d'intégrité détecté: {integrity_result}")
                else:
                    logger.info("Intégrité de la base de données vérifiée")
                    
                optimization_time = time.time() - start_time
                logger.info(f"Optimisation terminée en {optimization_time:.2f}s")
                
        except Exception as e:
            logger.error(f"Erreur lors de l'optimisation: {e}")
