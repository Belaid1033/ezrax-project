#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de base pour tous les scanners de l'agent EZRAX IDS/IPS
"""

import time
import logging
import threading
import ipaddress
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
from collections import deque, defaultdict

logger = logging.getLogger(__name__)

class BaseScanner(ABC):
    """Classe de base abstraite pour tous les scanners """
    
    def __init__(self, config: Dict[str, Any], db_manager: Any, ips_manager: Any):
        """
        Initialisation du scanner
        
        Args:
            config: Configuration du scanner
            db_manager: Gestionnaire de base de données
            ips_manager: Gestionnaire IPS
        """
        self.config = config
        self.db_manager = db_manager
        self.ips_manager = ips_manager
        self.active = False
        self.thread = None
        self.stop_event = threading.Event()
        self.name = self.__class__.__name__
        

        self.base_scan_interval = 1.0  # Intervalle de base
        self.min_scan_interval = 0.1   # Minimum 100ms
        self.max_scan_interval = 10.0  # Maximum 10s
        self.current_scan_interval = self.base_scan_interval
        

        self.attack_log_limiter = AttackLogLimiter(max_logs_per_minute=60)
        

        self.performance_metrics = {
            "scan_cycles": 0,
            "attacks_detected": 0,
            "scan_duration_avg": 0.0,
            "scan_duration_max": 0.0,
            "load_factor": 0.0,
            "last_performance_log": 0
        }
        

        self.whitelist_cache = {
            "ips": set(),
            "last_update": 0,
            "update_interval": 30  # 30 secondes
        }
        

        self.anomaly_detector = ScannerAnomalyDetector()
        
    def start(self):
        """Démarre le scanner dans un thread séparé"""
        if self.active:
            logger.warning(f"Scanner {self.name} déjà actif")
            return
        
        logger.info(f"Démarrage du scanner {self.name}")
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name=f"Thread-{self.name}")
        self.thread.daemon = True
        self.thread.start()
        self.active = True
        
    def stop(self):
        """Arrête le scanner"""
        if not self.active:
            return
            
        logger.info(f"Arrêt du scanner {self.name}")
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5.0)
        self.active = False
        
    def _run(self):
        """Boucle principale du scanner avec cycle adaptatif"""
        try:
            self.setup()
            
            while not self.stop_event.is_set():
                cycle_start_time = time.time()
                
                try:
                    # Mettre à jour la whitelist si nécessaire
                    self._update_whitelist_cache()
                    
                    # Exécuter le cycle de scan
                    self.scan_cycle()
                    
                    # Mettre à jour les métriques de performance
                    cycle_duration = time.time() - cycle_start_time
                    self._update_performance_metrics(cycle_duration)
                    
                    # Adapter l'intervalle de scan en fonction de la charge
                    self._adapt_scan_interval(cycle_duration)
                    
                    # Log périodique des performances
                    self._log_performance_if_needed()
                    
                except Exception as e:
                    logger.error(f"Erreur dans le cycle de scan de {self.name}: {e}")
                    # Augmenter l'intervalle en cas d'erreur
                    self.current_scan_interval = min(
                        self.current_scan_interval * 2, 
                        self.max_scan_interval
                    )
                    
                # Attendre avec l'intervalle adaptatif
                self.stop_event.wait(self.current_scan_interval)
                
        except Exception as e:
            logger.error(f"Erreur critique dans le scanner {self.name}: {e}")
        finally:
            self.cleanup()
            
    def _update_whitelist_cache(self):
        """Met à jour le cache de la whitelist depuis la base de données"""
        current_time = time.time()
        
        if (current_time - self.whitelist_cache["last_update"] >= 
            self.whitelist_cache["update_interval"]):
            
            try:
                # Récupérer la whitelist depuis la base de données
                db_whitelist = self.db_manager.get_whitelist()
                
                # Combiner avec la whitelist de configuration
                config_whitelist = set(self.config["ips"]["whitelist"])
                
                # Valider et nettoyer les IPs
                validated_ips = set()
                for entry in db_whitelist:
                    ip = entry.get("ip", "")
                    if self._validate_ip_address(ip):
                        validated_ips.add(ip)
                        
                for ip in config_whitelist:
                    if self._validate_ip_address(ip):
                        validated_ips.add(ip)
                        
                # Mettre à jour le cache
                self.whitelist_cache["ips"] = validated_ips
                self.whitelist_cache["last_update"] = current_time
                
                logger.debug(f"{self.name}: Whitelist mise à jour ({len(validated_ips)} IPs)")
                
            except Exception as e:
                logger.error(f"Erreur lors de la mise à jour de la whitelist: {e}")
                
    def _validate_ip_address(self, ip: str) -> bool:
        """Valide une adresse IP"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    def _update_performance_metrics(self, cycle_duration: float):
        """Met à jour les métriques de performance"""
        metrics = self.performance_metrics
        
        metrics["scan_cycles"] += 1
        
        # Moyenne mobile de la durée des cycles
        if metrics["scan_duration_avg"] == 0:
            metrics["scan_duration_avg"] = cycle_duration
        else:
            # Moyenne mobile avec facteur de lissage
            alpha = 0.1
            metrics["scan_duration_avg"] = (
                alpha * cycle_duration + 
                (1 - alpha) * metrics["scan_duration_avg"]
            )
            
        # Durée maximale
        metrics["scan_duration_max"] = max(metrics["scan_duration_max"], cycle_duration)
        
        # Facteur de charge (durée du cycle / intervalle de scan)
        if self.current_scan_interval > 0:
            metrics["load_factor"] = cycle_duration / self.current_scan_interval
            
    def _adapt_scan_interval(self, cycle_duration: float):
        """Adapte l'intervalle de scan en fonction de la performance"""
        # Calculer le facteur d'adaptation basé sur la durée du cycle
        target_load_factor = 0.5  # 50% de charge cible
        current_load_factor = cycle_duration / self.current_scan_interval
        
        if current_load_factor > target_load_factor * 1.5:
            # Système surchargé, augmenter l'intervalle
            self.current_scan_interval = min(
                self.current_scan_interval * 1.2,
                self.max_scan_interval
            )
        elif current_load_factor < target_load_factor * 0.5:
            # Système sous-chargé, diminuer l'intervalle
            self.current_scan_interval = max(
                self.current_scan_interval * 0.9,
                self.min_scan_interval
            )
            
        # Également considérer le nombre d'attaques détectées récemment
        recent_attacks = self.attack_log_limiter.get_recent_attack_count()
        if recent_attacks > 30:  # Plus de 30 attaques par minute
            # Augmenter légèrement l'intervalle pour éviter la surcharge
            self.current_scan_interval = min(
                self.current_scan_interval * 1.1,
                self.max_scan_interval
            )
            
    def _log_performance_if_needed(self):
        """Log les performances si nécessaire (toutes les 5 minutes)"""
        current_time = time.time()
        
        if (current_time - self.performance_metrics["last_performance_log"] >= 300):
            metrics = self.performance_metrics
            
            logger.info(
                f"{self.name} Performance - "
                f"Cycles: {metrics['scan_cycles']}, "
                f"Attaques: {metrics['attacks_detected']}, "
                f"Durée moy: {metrics['scan_duration_avg']:.3f}s, "
                f"Durée max: {metrics['scan_duration_max']:.3f}s, "
                f"Charge: {metrics['load_factor']:.2f}, "
                f"Intervalle: {self.current_scan_interval:.2f}s"
            )
            
            metrics["last_performance_log"] = current_time
            
    def setup(self):
        """Configuration initiale du scanner (peut être surchargée)"""
        pass
        
    def cleanup(self):
        """Nettoyage des ressources du scanner (peut être surchargée)"""
        pass
        
    def is_ip_whitelisted(self, ip: str) -> bool:
        """
        Vérifie si une adresse IP est dans la liste blanche
        
        Args:
            ip: Adresse IP à vérifier
            
        Returns:
            True si l'IP est dans la liste blanche, False sinon
        """
        # Vérifier le cache de la whitelist
        return ip in self.whitelist_cache["ips"]
        
    def log_attack(self, attack_type: str, source_ip: str, details: Dict[str, Any]):
        """
        Enregistre une attaque détectée avec rate limiting
        
        Args:
            attack_type: Type d'attaque (SYN_FLOOD, UDP_FLOOD, etc.)
            source_ip: Adresse IP source de l'attaque
            details: Détails supplémentaires sur l'attaque
        """
        # Vérifier le rate limiting
        if not self.attack_log_limiter.should_log_attack(source_ip, attack_type):
            logger.debug(f"Attaque {attack_type} de {source_ip} rate-limitée")
            return
            
        # Détecter les anomalies
        anomaly_score = self.anomaly_detector.analyze_attack(attack_type, source_ip, details)
        if anomaly_score > 0:
            details["anomaly_score"] = anomaly_score
            
        # Enregistrement dans la base de données
        self.db_manager.add_attack_log(
            attack_type=attack_type,
            source_ip=source_ip,
            scanner=self.name,
            details=details
        )
        
        # Mettre à jour les métriques
        self.performance_metrics["attacks_detected"] += 1
        
        # Si l'IPS est activé et que le blocage automatique est activé
        if (self.config["ips"]["enabled"] and 
            self.config["ips"]["auto_block"] and 
            not self.is_ip_whitelisted(source_ip)):
            
            # Calculer la durée de blocage basée sur la sévérité
            block_duration = self._calculate_block_duration(attack_type, details)
            
            self.ips_manager.block_ip(
                source_ip, 
                attack_type, 
                duration=block_duration
            )
            
        # Log avec niveau adaptatif
        log_level = self._get_log_level_for_attack(attack_type, anomaly_score)
        logger.log(
            log_level,
            f"Attaque {attack_type} détectée depuis {source_ip}: {details}"
        )
        
    def _calculate_block_duration(self, attack_type: str, details: Dict[str, Any]) -> int:
        """Calcule la durée de blocage basée sur la sévérité de l'attaque"""
        base_duration = self.config["ips"]["block_duration"]
        
        # Facteur basé sur la sévérité
        severity = details.get("severity", "MEDIUM")
        severity_multipliers = {
            "LOW": 0.5,
            "MEDIUM": 1.0,
            "HIGH": 2.0,
            "CRITICAL": 4.0
        }
        
        multiplier = severity_multipliers.get(severity, 1.0)
        
        # Facteur basé sur le type d'attaque
        attack_multipliers = {
            "SYN_FLOOD": 1.0,
            "UDP_FLOOD": 1.0,
            "PORT_SCAN": 1.5,
            "PING_FLOOD": 0.8
        }
        
        multiplier *= attack_multipliers.get(attack_type, 1.0)
        
        # Calculer la durée finale
        duration = int(base_duration * multiplier)
        
        # Limiter la durée (max 24h)
        return min(duration, 86400)
        
    def _get_log_level_for_attack(self, attack_type: str, anomaly_score: float) -> int:
        """Détermine le niveau de log basé sur le type d'attaque et le score d'anomalie"""
        if anomaly_score > 0.8:
            return logging.CRITICAL
        elif anomaly_score > 0.6:
            return logging.ERROR
        elif attack_type in ["SYN_FLOOD", "UDP_FLOOD"]:
            return logging.WARNING
        else:
            return logging.INFO
            
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Retourne les métriques de performance du scanner"""
        metrics = self.performance_metrics.copy()
        metrics["current_scan_interval"] = self.current_scan_interval
        metrics["whitelist_cache_size"] = len(self.whitelist_cache["ips"])
        metrics["rate_limiter_stats"] = self.attack_log_limiter.get_statistics()
        return metrics
        
    @abstractmethod
    def scan_cycle(self):
        """Méthode à implémenter pour chaque scanner"""
        pass


class AttackLogLimiter:
    """Système de rate limiting pour les logs d'attaques"""
    
    def __init__(self, max_logs_per_minute: int = 60):
        self.max_logs_per_minute = max_logs_per_minute
        self.attack_logs = defaultdict(lambda: deque(maxlen=100))
        self.lock = threading.Lock()
        
    def should_log_attack(self, source_ip: str, attack_type: str) -> bool:
        """Détermine si l'attaque doit être loggée"""
        current_time = time.time()
        key = f"{source_ip}:{attack_type}"
        
        with self.lock:
            # Nettoyer les anciens logs (plus de 1 minute)
            recent_logs = [
                timestamp for timestamp in self.attack_logs[key] 
                if current_time - timestamp < 60
            ]
            
            # Mettre à jour la liste
            self.attack_logs[key] = deque(recent_logs, maxlen=100)
            
            # Vérifier si on peut logger
            if len(recent_logs) < self.max_logs_per_minute:
                self.attack_logs[key].append(current_time)
                return True
            else:
                return False
                
    def get_recent_attack_count(self) -> int:
        """Retourne le nombre total d'attaques récentes"""
        current_time = time.time()
        total_count = 0
        
        with self.lock:
            for logs in self.attack_logs.values():
                total_count += len([
                    timestamp for timestamp in logs 
                    if current_time - timestamp < 60
                ])
                
        return total_count
        
    def get_statistics(self) -> Dict[str, Any]:
        """Retourne les statistiques du rate limiter"""
        with self.lock:
            return {
                "tracked_attack_types": len(self.attack_logs),
                "recent_attacks": self.get_recent_attack_count(),
                "max_logs_per_minute": self.max_logs_per_minute
            }


class ScannerAnomalyDetector:
    """Détecteur d'anomalies pour les scanners"""
    
    def __init__(self):
        self.attack_patterns = defaultdict(list)
        self.lock = threading.Lock()
        
    def analyze_attack(self, attack_type: str, source_ip: str, details: Dict[str, Any]) -> float:
        """
        Analyse une attaque pour détecter des anomalies
        
        Returns:
            Score d'anomalie entre 0.0 et 1.0
        """
        anomaly_score = 0.0
        
        # Analyser la fréquence d'attaque de cette IP
        if "attack_rate_pps" in details:
            rate = details["attack_rate_pps"]
            if rate > 1000:  # Plus de 1000 paquets/seconde
                anomaly_score += 0.3
            elif rate > 500:
                anomaly_score += 0.2
            elif rate > 100:
                anomaly_score += 0.1
                
        # Analyser la taille de l'attaque
        if "packet_count" in details:
            packet_count = details["packet_count"]
            if packet_count > 10000:
                anomaly_score += 0.3
            elif packet_count > 5000:
                anomaly_score += 0.2
                
        # Analyser la diversité des cibles (pour les scans de ports)
        if "distinct_ports" in details:
            distinct_ports = details["distinct_ports"]
            if distinct_ports > 1000:
                anomaly_score += 0.4
            elif distinct_ports > 500:
                anomaly_score += 0.2
                
        # Analyser le comportement répétitif
        with self.lock:
            recent_attacks = [
                timestamp for timestamp in self.attack_patterns[source_ip]
                if time.time() - timestamp < 300  # 5 minutes
            ]
            
            if len(recent_attacks) > 10:  # Plus de 10 attaques en 5 minutes
                anomaly_score += 0.3
                
            # Ajouter cette attaque à l'historique
            self.attack_patterns[source_ip].append(time.time())
            
            # Garder seulement les 50 dernières attaques par IP
            if len(self.attack_patterns[source_ip]) > 50:
                self.attack_patterns[source_ip] = self.attack_patterns[source_ip][-50:]
                
        return min(anomaly_score, 1.0)  # Limiter à 1.0
