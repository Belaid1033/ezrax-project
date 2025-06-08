#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gestionnaire de logs pour l'agent EZRAX IDS/IPS
"""

import os
import time
import logging
import json
import sqlite3  
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

class LogManager:
    """
    Gestionnaire de logs pour l'agent EZRAX IDS/IPS 
    """
    
    def __init__(self, config, db_manager):
        """
        Initialisation du gestionnaire de logs
        
        Args:
            config: Configuration de l'agent
            db_manager: Gestionnaire de base de données
        """
        self.config = config
        self.db_manager = db_manager
        self.agent_id = config["AGENT_ID"]
        self.agent_hostname = config["AGENT_HOSTNAME"]
        
        # Répertoire des logs
        self.log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        
        
        self.stats_cache = {
            "data": {},
            "last_update": 0,
            "cache_duration": 30  # 30 secondes
        }
        self.cache_lock = threading.Lock()
        
        # Statistiques en temps réel
        self.stats = {
            "attacks_detected": 0,
            "ips_blocked": 0,
            "start_time": time.time(),
            "last_cleanup": 0
        }
        
        
        self.performance_metrics = {
            "queries_executed": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "avg_query_time": 0.0
        }
        
    def get_attack_summary(self, timeframe: int = 86400) -> Dict[str, Any]:
        """
        Génère un résumé des attaques détectées 
        
        Args:
            timeframe: Période de temps en secondes (par défaut: 24 heures)
            
        Returns:
            Résumé des attaques
        """
        # Vérifier le cache
        cache_key = f"attack_summary_{timeframe}"
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            self.performance_metrics["cache_hits"] += 1
            return cached_result
            
        self.performance_metrics["cache_misses"] += 1
        
        since = time.time() - timeframe
        start_time = time.time()
        
        try:
            logs = self.db_manager.get_attack_logs(limit=5000, since=since)  
            
            if not logs:
                result = {
                    "total_attacks": 0,
                    "unique_sources": 0,
                    "attack_types": {},
                    "top_attackers": [],
                    "timeframe_hours": timeframe / 3600
                }
                self._store_in_cache(cache_key, result)
                return result
                
            
            attack_types = {}
            attackers = {}
            
            for log in logs:
                attack_type = log["attack_type"]
                source_ip = log["source_ip"]
                timestamp = log["timestamp"]
                
                # Compter par type d'attaque
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                
                # Compter par attaquant
                if source_ip not in attackers:
                    attackers[source_ip] = {
                        "count": 0,
                        "attack_types": set(),
                        "first_seen": timestamp,
                        "last_seen": timestamp
                    }
                    
                attacker = attackers[source_ip]
                attacker["count"] += 1
                attacker["attack_types"].add(attack_type)
                attacker["first_seen"] = min(attacker["first_seen"], timestamp)
                attacker["last_seen"] = max(attacker["last_seen"], timestamp)
                
            
            top_attackers = [
                {
                    "ip": ip,
                    "count": data["count"],
                    "attack_types": list(data["attack_types"]),
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"],
                    "attack_frequency": data["count"] / max(1, (data["last_seen"] - data["first_seen"]) / 60)  # attaques/minute
                }
                for ip, data in sorted(attackers.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
            ]
            
            result = {
                "total_attacks": len(logs),
                "unique_sources": len(attackers),
                "timeframe_hours": timeframe / 3600,
                "attack_types": attack_types,
                "top_attackers": top_attackers,
                "analysis_time": time.time() - start_time  
            }
            
            # Stocker en cache
            self._store_in_cache(cache_key, result)
            
            # Mettre à jour les métriques
            query_time = time.time() - start_time
            self._update_query_metrics(query_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du résumé d'attaques: {e}")
            return {
                "total_attacks": 0,
                "unique_sources": 0,
                "attack_types": {},
                "top_attackers": [],
                "error": str(e)
            }
        
    def get_blocked_ips_summary(self) -> Dict[str, Any]:
        """
        Génère un résumé des IPs bloquées 
        
        Returns:
            Résumé des IPs bloquées
        """
        cache_key = "blocked_ips_summary"
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            self.performance_metrics["cache_hits"] += 1
            return cached_result
            
        self.performance_metrics["cache_misses"] += 1
        start_time = time.time()
        
        try:
            blocked_ips = self.db_manager.get_blocked_ips()
            expired_ips = self.db_manager.get_blocked_ips(include_expired=True)
            
            active_blocks = len(blocked_ips)
            total_blocks = len(expired_ips)
            
            
            block_reasons = {}
            block_duration_stats = {"min": float('inf'), "max": 0, "avg": 0, "total": 0}
            
            for block in expired_ips:
                reason = block["reason"]
                block_reasons[reason] = block_reasons.get(reason, 0) + 1
                
                
                if "duration" in block:
                    duration = block["duration"]
                    block_duration_stats["min"] = min(block_duration_stats["min"], duration)
                    block_duration_stats["max"] = max(block_duration_stats["max"], duration)
                    block_duration_stats["total"] += duration
                    
            
            if total_blocks > 0 and block_duration_stats["total"] > 0:
                block_duration_stats["avg"] = block_duration_stats["total"] / total_blocks
            if block_duration_stats["min"] == float('inf'):
                block_duration_stats["min"] = 0
                
            
            recent_blocks = [b for b in blocked_ips if time.time() - b.get("timestamp", 0) < 3600]  # Dernière heure
            
            result = {
                "active_blocks": active_blocks,
                "total_blocks": total_blocks,
                "recent_blocks_1h": len(recent_blocks),
                "block_reasons": block_reasons,
                "block_duration_stats": block_duration_stats,
                "recent_blocks": blocked_ips[:10],  # 10 derniers blocages
                "analysis_time": time.time() - start_time
            }
            
            self._store_in_cache(cache_key, result)
            query_time = time.time() - start_time
            self._update_query_metrics(query_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du résumé des IPs bloquées: {e}")
            return {
                "active_blocks": 0,
                "total_blocks": 0,
                "block_reasons": {},
                "recent_blocks": [],
                "error": str(e)
            }
        
    def get_agent_stats(self) -> Dict[str, Any]:
        """
        Récupère les statistiques globales de l'agent 
        
        Returns:
            Statistiques de l'agent
        """
        cache_key = "agent_stats"
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            # Mettre à jour seulement les métriques temps réel
            cached_result["current_time"] = time.time()
            cached_result["uptime_seconds"] = time.time() - self.stats["start_time"]
            cached_result["uptime_formatted"] = self._format_uptime(cached_result["uptime_seconds"])
            self.performance_metrics["cache_hits"] += 1
            return cached_result
            
        self.performance_metrics["cache_misses"] += 1
        start_time = time.time()
        
        try:
            uptime = time.time() - self.stats["start_time"]
            since_start = self.stats["start_time"]
            
           
            with self.db_manager.lock:
                # Utiliser une seule connexion pour toutes les requêtes
                with sqlite3.connect(self.db_manager.db_path) as conn:
                    cursor = conn.cursor()
                    
                    # Compter les attaques détectées
                    cursor.execute(
                        'SELECT COUNT(*) FROM attack_logs WHERE timestamp >= ?',
                        (since_start,)
                    )
                    attacks_detected = cursor.fetchone()[0]
                    
                    # Compter les IPs bloquées
                    cursor.execute(
                        'SELECT COUNT(*) FROM blocked_ips WHERE timestamp >= ?',
                        (since_start,)
                    )
                    ips_blocked = cursor.fetchone()[0]
                    

                    cursor.execute(
                        '''SELECT 
                            COUNT(DISTINCT source_ip) as unique_attackers,
                            COUNT(DISTINCT attack_type) as attack_types_seen,
                            AVG(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END) as recent_activity_ratio
                        FROM attack_logs WHERE timestamp >= ?''',
                        (time.time() - 3600, since_start)  # Activité dernière heure
                    )
                    additional_stats = cursor.fetchone()
                    
            # Mettre à jour les statistiques locales
            self.stats["attacks_detected"] = attacks_detected
            self.stats["ips_blocked"] = ips_blocked
            
            result = {
                "agent_id": self.agent_id,
                "hostname": self.agent_hostname,
                "uptime_seconds": uptime,
                "uptime_formatted": self._format_uptime(uptime),
                "attacks_detected": attacks_detected,
                "ips_blocked": ips_blocked,
                "unique_attackers": additional_stats[0] if additional_stats else 0,
                "attack_types_seen": additional_stats[1] if additional_stats else 0,
                "start_time": self.stats["start_time"],
                "current_time": time.time(),
                "performance_metrics": self.performance_metrics.copy(),  
                "analysis_time": time.time() - start_time
            }
            
            self._store_in_cache(cache_key, result)
            query_time = time.time() - start_time
            self._update_query_metrics(query_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des statistiques de l'agent: {e}")
            return {
                "agent_id": self.agent_id,
                "hostname": self.agent_hostname,
                "uptime_seconds": 0,
                "uptime_formatted": "0s",
                "attacks_detected": 0,
                "ips_blocked": 0,
                "error": str(e)
            }
        
    def _get_from_cache(self, key: str) -> Optional[Dict[str, Any]]:
        """Récupère une valeur du cache si elle est encore valide"""
        with self.cache_lock:
            current_time = time.time()
            if (key in self.stats_cache["data"] and 
                current_time - self.stats_cache["last_update"] < self.stats_cache["cache_duration"]):
                return self.stats_cache["data"][key].copy()
            return None
            
    def _store_in_cache(self, key: str, value: Dict[str, Any]):
        """Stocke une valeur dans le cache"""
        with self.cache_lock:
            if key not in self.stats_cache["data"]:
                self.stats_cache["data"] = {}
            self.stats_cache["data"][key] = value.copy()
            self.stats_cache["last_update"] = time.time()
            
    def _update_query_metrics(self, query_time: float):
        """Met à jour les métriques de performance des requêtes"""
        self.performance_metrics["queries_executed"] += 1
        
        # Moyenne mobile de la durée des requêtes
        if self.performance_metrics["avg_query_time"] == 0:
            self.performance_metrics["avg_query_time"] = query_time
        else:
            # Moyenne mobile avec facteur de lissage
            alpha = 0.1
            self.performance_metrics["avg_query_time"] = (
                alpha * query_time + 
                (1 - alpha) * self.performance_metrics["avg_query_time"]
            )
            
    def clear_cache(self):
        """Vide le cache - utile pour les tests ou rechargement forcé"""
        with self.cache_lock:
            self.stats_cache["data"] = {}
            self.stats_cache["last_update"] = 0
            logger.debug("Cache des statistiques vidé")
            
    def _format_uptime(self, seconds: float) -> str:
        """
        Formate une durée en secondes en une chaîne lisible
        
        Args:
            seconds: Nombre de secondes
            
        Returns:
            Chaîne formatée
        """
        if seconds < 0:
            return "0s"
            
        days = int(seconds // 86400)
        seconds %= 86400
        hours = int(seconds // 3600)
        seconds %= 3600
        minutes = int(seconds // 60)
        seconds = int(seconds % 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m {seconds}s"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
            
    def export_logs(self, output_format="json", timeframe=86400, max_records=10000) -> Optional[str]:
        """
        Exporte les logs dans un fichier
        
        Args:
            output_format: Format de sortie (json, csv)
            timeframe: Période de temps en secondes
            max_records: Nombre maximum d'enregistrements
            
        Returns:
            Chemin du fichier généré ou None en cas d'erreur
        """
        try:
            since = time.time() - timeframe
            
            
            all_logs = []
            offset = 0
            batch_size = 1000
            
            while len(all_logs) < max_records:
                logs_batch = self.db_manager.get_attack_logs(
                    limit=min(batch_size, max_records - len(all_logs)), 
                    offset=offset,
                    since=since
                )
                
                if not logs_batch:
                    break
                    
                all_logs.extend(logs_batch)
                offset += batch_size
                
                # Éviter les boucles infinies
                if len(logs_batch) < batch_size:
                    break
            
            if not all_logs:
                logger.warning("Aucun log à exporter pour la période spécifiée")
                return None
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ezrax_logs_{timestamp}"
            
            if output_format == "json":
                output_path = os.path.join(self.log_dir, f"{filename}.json")
                export_data = {
                    "metadata": {
                        "agent_id": self.agent_id,
                        "hostname": self.agent_hostname,
                        "export_time": time.time(),
                        "timeframe_seconds": timeframe,
                        "total_records": len(all_logs),
                        "format_version": "1.0"
                    },
                    "logs": all_logs
                }
                
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                    
            elif output_format == "csv":
                import csv
                output_path = os.path.join(self.log_dir, f"{filename}.csv")
                
                with open(output_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    
                    # Écrire l'en-tête avec plus de colonnes
                    writer.writerow([
                        "ID", "Timestamp", "Date", "Attack Type", "Source IP",
                        "Scanner", "Details", "Severity", "Agent ID"
                    ])
                    
                    # Écrire les données
                    for log in all_logs:
                        details = log.get("details", {})
                        if isinstance(details, str):
                            try:
                                details = json.loads(details)
                            except:
                                details = {"raw": details}
                                
                        severity = details.get("severity", "UNKNOWN")
                        
                        writer.writerow([
                            log.get("id", ""),
                            log.get("timestamp", ""),
                            datetime.fromtimestamp(log.get("timestamp", 0)).strftime("%Y-%m-%d %H:%M:%S"),
                            log.get("attack_type", ""),
                            log.get("source_ip", ""),
                            log.get("scanner", ""),
                            json.dumps(details, ensure_ascii=False),
                            severity,
                            self.agent_id
                        ])
            else:
                logger.error(f"Format d'export non supporté: {output_format}")
                return None
                
            logger.info(f"Logs exportés vers {output_path} ({len(all_logs)} enregistrements)")
            return output_path
            
        except Exception as e:
            logger.error(f"Erreur lors de l'export des logs: {e}")
            return None
            
    def cleanup_old_cache(self):
        """Nettoie le cache obsolète - appelé périodiquement"""
        current_time = time.time()
        
        if current_time - self.stats.get("last_cleanup", 0) > 300:  # Toutes les 5 minutes
            with self.cache_lock:
                # Vider le cache s'il est trop ancien
                if (current_time - self.stats_cache["last_update"] > 
                    self.stats_cache["cache_duration"] * 2):
                    self.stats_cache["data"] = {}
                    logger.debug("Cache des statistiques nettoyé (obsolète)")
                    
            self.stats["last_cleanup"] = current_time
            
    def get_performance_report(self) -> Dict[str, Any]:
        """Génère un rapport de performance du LogManager"""
        with self.cache_lock:
            cache_hit_rate = 0
            total_cache_requests = (self.performance_metrics["cache_hits"] + 
                                   self.performance_metrics["cache_misses"])
            
            if total_cache_requests > 0:
                cache_hit_rate = self.performance_metrics["cache_hits"] / total_cache_requests
                
        return {
            "performance_metrics": self.performance_metrics.copy(),
            "cache_stats": {
                "hit_rate": cache_hit_rate,
                "cached_items": len(self.stats_cache["data"]),
                "cache_age": time.time() - self.stats_cache["last_update"]
            },
            "uptime": time.time() - self.stats["start_time"]
        }
