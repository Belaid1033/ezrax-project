#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gestionnaire de logs pour l'agent EZRAX IDS/IPS
"""

import os
import time
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

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
        
        # Statistiques
        self.stats = {
            "attacks_detected": 0,
            "ips_blocked": 0,
            "start_time": time.time()
        }
        
    def get_attack_summary(self, timeframe: int = 86400):
        """
        Génère un résumé des attaques détectées
        
        Args:
            timeframe: Période de temps en secondes (par défaut: 24 heures)
            
        Returns:
            Résumé des attaques
        """
        since = time.time() - timeframe
        logs = self.db_manager.get_attack_logs(limit=1000, since=since)
        
        if not logs:
            return {
                "total_attacks": 0,
                "unique_sources": 0,
                "attack_types": {},
                "top_attackers": []
            }
            
        # Statistiques globales
        attack_types = {}
        attackers = {}
        
        for log in logs:
            attack_type = log["attack_type"]
            source_ip = log["source_ip"]
            
            # Compter par type d'attaque
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            # Compter par attaquant
            if source_ip not in attackers:
                attackers[source_ip] = {
                    "count": 0,
                    "attack_types": set(),
                    "first_seen": log["timestamp"],
                    "last_seen": log["timestamp"]
                }
                
            attacker = attackers[source_ip]
            attacker["count"] += 1
            attacker["attack_types"].add(attack_type)
            attacker["first_seen"] = min(attacker["first_seen"], log["timestamp"])
            attacker["last_seen"] = max(attacker["last_seen"], log["timestamp"])
            
        # Préparer les top_attackers
        top_attackers = []
        for ip, data in sorted(attackers.items(), key=lambda x: x[1]["count"], reverse=True)[:10]:
            top_attackers.append({
                "ip": ip,
                "count": data["count"],
                "attack_types": list(data["attack_types"]),
                "first_seen": data["first_seen"],
                "last_seen": data["last_seen"]
            })
            
        return {
            "total_attacks": len(logs),
            "unique_sources": len(attackers),
            "timeframe_hours": timeframe / 3600,
            "attack_types": attack_types,
            "top_attackers": top_attackers
        }
        
    def get_blocked_ips_summary(self):
        """
        Génère un résumé des IPs bloquées
        
        Returns:
            Résumé des IPs bloquées
        """
        blocked_ips = self.db_manager.get_blocked_ips()
        expired_ips = self.db_manager.get_blocked_ips(include_expired=True)
        
        active_blocks = len(blocked_ips)
        total_blocks = len(expired_ips)
        
        # Regrouper par raison de blocage
        block_reasons = {}
        for block in expired_ips:
            reason = block["reason"]
            block_reasons[reason] = block_reasons.get(reason, 0) + 1
            
        return {
            "active_blocks": active_blocks,
            "total_blocks": total_blocks,
            "block_reasons": block_reasons,
            "recent_blocks": blocked_ips[:10]  # 10 derniers blocages
        }
        
    def get_agent_stats(self):
        """
        Récupère les statistiques globales de l'agent
        
        Returns:
            Statistiques de l'agent
        """
        uptime = time.time() - self.stats["start_time"]
        
        # Mettre à jour les statistiques depuis la base de données
        since_start = self.stats["start_time"]
        
        # Compter les attaques détectées
        with self.db_manager.lock, sqlite3.connect(self.db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT COUNT(*) FROM attack_logs WHERE timestamp >= ?',
                (since_start,)
            )
            self.stats["attacks_detected"] = cursor.fetchone()[0]
            
            # Compter les IPs bloquées
            cursor.execute(
                'SELECT COUNT(*) FROM blocked_ips WHERE timestamp >= ?',
                (since_start,)
            )
            self.stats["ips_blocked"] = cursor.fetchone()[0]
            
        return {
            "agent_id": self.agent_id,
            "hostname": self.agent_hostname,
            "uptime_seconds": uptime,
            "uptime_formatted": self._format_uptime(uptime),
            "attacks_detected": self.stats["attacks_detected"],
            "ips_blocked": self.stats["ips_blocked"],
            "start_time": self.stats["start_time"],
            "current_time": time.time()
        }
        
    def _format_uptime(self, seconds):
        """
        Formate une durée en secondes en une chaîne lisible
        
        Args:
            seconds: Nombre de secondes
            
        Returns:
            Chaîne formatée
        """
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
            
    def export_logs(self, output_format="json", timeframe=86400):
        """
        Exporte les logs dans un fichier
        
        Args:
            output_format: Format de sortie (json, csv)
            timeframe: Période de temps en secondes
            
        Returns:
            Chemin du fichier généré
        """
        since = time.time() - timeframe
        logs = self.db_manager.get_attack_logs(limit=10000, since=since)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ezrax_logs_{timestamp}"
        
        if output_format == "json":
            output_path = os.path.join(self.log_dir, f"{filename}.json")
            with open(output_path, "w") as f:
                json.dump({
                    "agent_id": self.agent_id,
                    "hostname": self.agent_hostname,
                    "export_time": time.time(),
                    "logs": logs
                }, f, indent=2)
                
        elif output_format == "csv":
            import csv
            output_path = os.path.join(self.log_dir, f"{filename}.csv")
            with open(output_path, "w", newline="") as f:
                writer = csv.writer(f)
                # Écrire l'en-tête
                writer.writerow([
                    "ID", "Timestamp", "Date", "Attack Type", "Source IP",
                    "Scanner", "Details"
                ])
                
                # Écrire les données
                for log in logs:
                    writer.writerow([
                        log["id"],
                        log["timestamp"],
                        datetime.fromtimestamp(log["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"),
                        log["attack_type"],
                        log["source_ip"],
                        log["scanner"],
                        json.dumps(log["details"])
                    ])
        else:
            logger.error(f"Format d'export non supporté: {output_format}")
            return None
            
        logger.info(f"Logs exportés vers {output_path}")
        return output_path

# Importation ici pour éviter les imports circulaires
import sqlite3
