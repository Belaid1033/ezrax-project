#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner pour détecter les scans de ports
"""

import time
import logging
import threading
import subprocess
import re
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Tuple, Set

from scapy.all import sniff, IP, TCP, UDP
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class PortScanScanner(BaseScanner):
    """Détecte les scans de ports"""
    
    def __init__(self, config, db_manager, ips_manager):
        super().__init__(config, db_manager, ips_manager)
        self.scanner_config = config["scanners"]["port_scan"]
        self.threshold = self.scanner_config["threshold"]
        self.time_window = self.scanner_config["time_window"]
        self.interfaces = config["scanners"]["syn_flood"]["interfaces"]
        
        # Structure de données pour suivre les tentatives de connexion
        self.connection_attempts = defaultdict(dict)
        self.lock = threading.Lock()
        self.sniffer_threads = []
        

        self.local_ports_cache = {
            'tcp': set(),
            'udp': set(),
            'last_update': 0,
            'update_interval': 300  # 5 minutes
        }
        

        self.scan_attempts_detected = 0
        self.packets_analyzed = 0
        
        # Caractéristiques des scans à détecter
        self.scan_types = {
            "SYN_SCAN": {"flags": 0x02, "proto": "TCP"},
            "FIN_SCAN": {"flags": 0x01, "proto": "TCP"},
            "XMAS_SCAN": {"flags": 0x29, "proto": "TCP"},
            "NULL_SCAN": {"flags": 0x00, "proto": "TCP"},
            "ACK_SCAN": {"flags": 0x10, "proto": "TCP"},
            "WINDOW_SCAN": {"flags": 0x10, "proto": "TCP"},
            "UDP_SCAN": {"proto": "UDP"}
        }
        
    def setup(self):
        """Configure et démarre les sniffers sur les interfaces"""
        # Mise à jour initiale du cache des ports
        self.update_local_ports_cache()
        
        # Démarrer un sniffer pour chaque interface (avec limite)
        max_interfaces = min(len(self.interfaces), 3)
        for interface in self.interfaces[:max_interfaces]:
            thread = threading.Thread(
                target=self._start_sniffer,
                args=(interface,),
                name=f"Sniffer-PortScan-{interface}"
            )
            thread.daemon = True
            thread.start()
            self.sniffer_threads.append(thread)
            logger.info(f"Sniffer de scan de ports démarré sur l'interface {interface}")
            
    def update_local_ports_cache(self):
        """
        Met à jour le cache des ports locaux ouverts 
     
        """
        current_time = time.time()
        
        # Vérifier si mise à jour nécessaire
        if (current_time - self.local_ports_cache['last_update'] < 
            self.local_ports_cache['update_interval']):
            return
            
        try:
            # MÉTHODE 1: Utiliser netstat/ss (très rapide)
            tcp_ports, udp_ports = self._get_ports_via_netstat()
            
            # MÉTHODE 2: Fallback avec /proc/net (si netstat échoue)
            if not tcp_ports and not udp_ports:
                tcp_ports, udp_ports = self._get_ports_via_proc()
                
            # Mettre à jour le cache
            with self.lock:
                self.local_ports_cache['tcp'] = tcp_ports
                self.local_ports_cache['udp'] = udp_ports
                self.local_ports_cache['last_update'] = current_time
                
            total_ports = len(tcp_ports) + len(udp_ports)
            logger.info(f"Cache ports mis à jour: {len(tcp_ports)} TCP, {len(udp_ports)} UDP")
            
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour du cache des ports: {e}")
            
    def _get_ports_via_netstat(self) -> Tuple[Set[int], Set[int]]:
        """Récupère les ports via netstat/ss """
        tcp_ports = set()
        udp_ports = set()
        
        try:
            # Utiliser ss (plus moderne que netstat)
            result = subprocess.run(
                ['ss', '-tuln'], 
                capture_output=True, 
                text=True, 
                timeout=5
            )
            
            if result.returncode == 0:
                # Parser la sortie de ss
                for line in result.stdout.split('\n'):
                    if line.startswith('tcp'):
                        match = re.search(r':(\d+)\s', line)
                        if match:
                            tcp_ports.add(int(match.group(1)))
                    elif line.startswith('udp'):
                        match = re.search(r':(\d+)\s', line)
                        if match:
                            udp_ports.add(int(match.group(1)))
            else:
                # Fallback vers netstat
                result = subprocess.run(
                    ['netstat', '-tuln'], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'LISTEN' in line:
                            parts = line.split()
                            if len(parts) >= 4:
                                addr_port = parts[3]
                                if ':' in addr_port:
                                    port = addr_port.split(':')[-1]
                                    try:
                                        port_num = int(port)
                                        if 'tcp' in line.lower():
                                            tcp_ports.add(port_num)
                                        elif 'udp' in line.lower():
                                            udp_ports.add(port_num)
                                    except ValueError:
                                        continue
                                        
        except subprocess.TimeoutExpired:
            logger.warning("Timeout lors de la récupération des ports via netstat/ss")
        except Exception as e:
            logger.error(f"Erreur netstat/ss: {e}")
            
        return tcp_ports, udp_ports
        
    def _get_ports_via_proc(self) -> Tuple[Set[int], Set[int]]:
        """Récupère les ports via /proc/net (méthode de fallback)"""
        tcp_ports = set()
        udp_ports = set()
        
        try:
            # TCP ports
            with open('/proc/net/tcp', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1] != 'local_address':
                        local_addr = parts[1]
                        if ':' in local_addr:
                            port_hex = local_addr.split(':')[1]
                            try:
                                port = int(port_hex, 16)
                                tcp_ports.add(port)
                            except ValueError:
                                continue
                                
            # UDP ports  
            with open('/proc/net/udp', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1] != 'local_address':
                        local_addr = parts[1]
                        if ':' in local_addr:
                            port_hex = local_addr.split(':')[1]
                            try:
                                port = int(port_hex, 16)
                                udp_ports.add(port)
                            except ValueError:
                                continue
                                
        except Exception as e:
            logger.error(f"Erreur lecture /proc/net: {e}")
            
        return tcp_ports, udp_ports
        
    def get_local_ports(self) -> Dict[str, Set[int]]:
        """Retourne les ports locaux depuis le cache"""
        # Mise à jour automatique si nécessaire
        self.update_local_ports_cache()
        
        with self.lock:
            return {
                'tcp': self.local_ports_cache['tcp'].copy(),
                'udp': self.local_ports_cache['udp'].copy()
            }
            
    def _start_sniffer(self, interface):
        """Démarre un sniffer sur une interface spécifique"""
        try:
            # Capturer les paquets TCP et UDP avec filtre optimisé
            sniff(
                iface=interface,
                filter="(tcp and not tcp[tcpflags] & tcp-rst != 0) or udp",
                prn=self._process_packet,
                store=0,
                stop_filter=lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Erreur dans le sniffer de scan de ports sur {interface}: {e}")
            
    def _process_packet(self, packet):
        """Traite un paquet capturé par le sniffer"""
        try:
            if IP not in packet:
                return
                
            src_ip = packet[IP].src
            
            if self.is_ip_whitelisted(src_ip):
                return
                
            self.packets_analyzed += 1
                
            # Traitement des paquets TCP
            if TCP in packet:
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                # Ignorer les connexions établies normales
                if flags & 0x12 == 0x12:  # SYN-ACK
                    return
                if flags & 0x11 == 0x11:  # FIN-ACK
                    return
                    
                # Enregistrer la tentative de connexion
                with self.lock:
                    key = (dst_port, "TCP", flags)
                    self.connection_attempts[src_ip][key] = time.time()
                    
            # Traitement des paquets UDP
            elif UDP in packet:
                dst_port = packet[UDP].dport
                
                # Enregistrer la tentative de connexion UDP
                with self.lock:
                    key = (dst_port, "UDP", None)
                    self.connection_attempts[src_ip][key] = time.time()
                    
        except Exception as e:
            logger.error(f"Erreur lors du traitement d'un paquet pour la détection de scan: {e}")
            
    def scan_cycle(self):
        """Analyse les tentatives de connexion pour détecter les scans de ports"""
        current_time = time.time()
        cutoff_time = current_time - self.time_window
        
        # Mise à jour périodique du cache des ports
        self.update_local_ports_cache()
        
        # Récupérer les ports locaux
        local_ports = self.get_local_ports()
        
        with self.lock:
            # Parcourir toutes les adresses IP sources
            for src_ip, attempts in list(self.connection_attempts.items()):
                # Filtrer les tentatives récentes
                recent_attempts = {
                    k: v for k, v in attempts.items() 
                    if v >= cutoff_time
                }
                
                # Mettre à jour les tentatives récentes
                self.connection_attempts[src_ip] = recent_attempts
                
                # Vérifier si le nombre de ports uniques dépasse le seuil
                unique_ports = set(port for port, _, _ in recent_attempts.keys())
                
                if len(unique_ports) >= self.threshold:
                    # Analyser le type de scan
                    scan_type = self._determine_scan_type(recent_attempts)
                    
                    # Calculer les métriques avancées
                    tcp_ports = local_ports['tcp']
                    udp_ports = local_ports['udp']
                    all_local_ports = tcp_ports.union(udp_ports)
                    
                    targeted_open_ports = unique_ports.intersection(all_local_ports)
                    open_port_ratio = len(targeted_open_ports) / len(unique_ports) if unique_ports else 0
                    
                    # Analyser la distribution des ports
                    port_ranges = self._analyze_port_ranges(unique_ports)
                    scan_velocity = len(unique_ports) / self.time_window
                    
                    details = {
                        "scan_type": scan_type,
                        "port_count": len(unique_ports),
                        "time_window": self.time_window,
                        "threshold": self.threshold,
                        "targeted_open_ports": len(targeted_open_ports),
                        "open_port_ratio": round(open_port_ratio, 3),
                        "scan_velocity_pps": round(scan_velocity, 2),
                        "port_ranges": port_ranges,
                        "severity": self._calculate_scan_severity(len(unique_ports), scan_velocity),
                        "port_range": [min(unique_ports), max(unique_ports)] if unique_ports else [0, 0],
                        "port_sample": sorted(list(unique_ports))[:20]
                    }
                    
                    # Enregistrer l'attaque
                    self.log_attack("PORT_SCAN", src_ip, details)
                    self.scan_attempts_detected += 1
                    
                    # Vider les tentatives pour cette IP après détection
                    self.connection_attempts[src_ip].clear()
                
                # Supprimer les entrées vides
                if not self.connection_attempts[src_ip]:
                    del self.connection_attempts[src_ip]
                    
    def _analyze_port_ranges(self, ports: Set[int]) -> Dict[str, int]:
        """Analyse la distribution des ports scannés"""
        ranges = {
            "well_known": 0,      # 1-1023
            "registered": 0,       # 1024-49151  
            "dynamic": 0,         # 49152-65535
            "sequential": 0       # Ports consécutifs
        }
        
        sorted_ports = sorted(ports)
        
        for port in sorted_ports:
            if port <= 1023:
                ranges["well_known"] += 1
            elif port <= 49151:
                ranges["registered"] += 1
            else:
                ranges["dynamic"] += 1
                
        # Détecter les séquences de ports consécutifs
        consecutive_count = 0
        for i in range(len(sorted_ports) - 1):
            if sorted_ports[i + 1] - sorted_ports[i] == 1:
                consecutive_count += 1
                
        ranges["sequential"] = consecutive_count
        
        return ranges
        
    def _calculate_scan_severity(self, port_count: int, scan_velocity: float) -> str:
        """Calcule la sévérité du scan de ports"""
        if port_count > 1000 or scan_velocity > 100:
            return "CRITICAL"
        elif port_count > 500 or scan_velocity > 50:
            return "HIGH"
        elif port_count > 100 or scan_velocity > 10:
            return "MEDIUM"
        else:
            return "LOW"
            
    def _determine_scan_type(self, attempts):
        """Détermine le type de scan en fonction des caractéristiques des tentatives"""
        # Compter les tentatives par protocole et flags
        counter = defaultdict(int)
        for (_, proto, flags) in attempts.keys():
            if proto == "TCP":
                counter[(proto, flags)] += 1
            else:
                counter[(proto, None)] += 1
                
        # Trouver le type de scan prédominant
        max_count = 0
        dominant_type = "UNKNOWN_SCAN"
        
        for scan_name, characteristics in self.scan_types.items():
            proto = characteristics["proto"]
            flags = characteristics.get("flags")
            
            count = counter.get((proto, flags), 0)
            
            if count > max_count:
                max_count = count
                dominant_type = scan_name
                
        return dominant_type
        
    def get_statistics(self) -> Dict[str, Any]:
        """Retourne les statistiques du scanner"""
        with self.lock:
            cache_info = {
                "tcp_ports": len(self.local_ports_cache['tcp']),
                "udp_ports": len(self.local_ports_cache['udp']),
                "cache_age": time.time() - self.local_ports_cache['last_update']
            }
            
        return {
            "scan_attempts_detected": self.scan_attempts_detected,
            "packets_analyzed": self.packets_analyzed,
            "monitored_ips": len(self.connection_attempts),
            "local_ports_cache": cache_info
        }
        
    def cleanup(self):
        """Nettoyage des ressources du scanner"""
        logger.info("Nettoyage du scanner de scan de ports")
        
        # Log des statistiques finales
        stats = self.get_statistics()
        logger.info(f"Statistiques finales Port Scanner: {stats}")
        
        # Vider les tentatives
        with self.lock:
            self.connection_attempts.clear()
            self.local_ports_cache = {'tcp': set(), 'udp': set(), 'last_update': 0, 'update_interval': 300}
