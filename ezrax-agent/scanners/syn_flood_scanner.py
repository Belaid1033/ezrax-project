#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner pour détecter les attaques SYN Flood
"""

import time
import logging
import threading
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Tuple


from scapy.all import sniff, TCP, IP
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class SynFloodScanner(BaseScanner):
    """Détecte les attaques SYN Flood """
    
    def __init__(self, config, db_manager, ips_manager):
        super().__init__(config, db_manager, ips_manager)
        self.scanner_config = config["scanners"]["syn_flood"]
        self.threshold = self.scanner_config["threshold"]
        self.time_window = self.scanner_config["time_window"]
        self.interfaces = self.scanner_config["interfaces"]
        
        # Structure de données pour suivre les paquets SYN
        self.syn_counters = defaultdict(lambda: deque(maxlen=2000))  # Augmenté pour haute charge
        self.lock = threading.Lock()
        self.sniffer_threads = []
        
        # Nom de la chaîne iptables
        self.chain_name = "EZRAX_IPS"
        

        self.packets_processed = 0
        self.attacks_detected = 0
        self.last_performance_check = time.time()
        

        self._validate_interfaces()
        
    def _validate_interfaces(self):
        """Valide que les interfaces réseau existent"""
        import psutil
        available_interfaces = list(psutil.net_if_addrs().keys())
        
        validated_interfaces = []
        for interface in self.interfaces:
            if interface in available_interfaces:
                validated_interfaces.append(interface)
                logger.info(f"Interface {interface} validée")
            else:
                logger.warning(f"Interface {interface} non trouvée, ignorée")
                
        if not validated_interfaces:
            logger.error("Aucune interface réseau valide trouvée")
            self.interfaces = ["any"]  # Fallback sur toutes les interfaces
        else:
            self.interfaces = validated_interfaces
            
    def setup(self):
        """Configure et démarre les sniffers sur les interfaces"""
        max_threads = min(len(self.interfaces), 4)  
        
        for i, interface in enumerate(self.interfaces[:max_threads]):
            thread = threading.Thread(
                target=self._start_sniffer,
                args=(interface,),
                name=f"Sniffer-{interface}-{i}"
            )
            thread.daemon = True
            thread.start()
            self.sniffer_threads.append(thread)
            logger.info(f"Sniffer SYN Flood démarré sur l'interface {interface}")
            
    def _start_sniffer(self, interface):
        """
        Démarre un sniffer sur une interface spécifique
        
        Args:
            interface: Nom de l'interface à surveiller
        """
        try:
            Filtre BPF spécifique et sécurisé
            bpf_filter = "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0 and not src host 127.0.0.1"
            
            sniff(
                iface=interface if interface != "any" else None,
                filter=bpf_filter,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Erreur dans le sniffer SYN sur {interface}: {e}")
            
    def _process_packet(self, packet):
        """
        Traite un paquet capturé par le sniffer
        
        Args:
            packet: Paquet réseau capturé
        """
        try:
            if not (TCP in packet and IP in packet):
                return
                
            if packet[TCP].flags == 2:  # TCP SYN flag
                timestamp = time.time()
                src_ip = packet[IP].src
                dst_port = packet[TCP].dport
                

                if not self._is_valid_ip(src_ip):
                    return
                    
                if self.is_ip_whitelisted(src_ip):
                    return
                    
                with self.lock:
                    self.syn_counters[src_ip].append((timestamp, dst_port))
                    self.packets_processed += 1
                    
        except Exception as e:
            logger.error(f"Erreur lors du traitement du paquet SYN: {e}")
            
    def _is_valid_ip(self, ip: str) -> bool:
        """Validation basique d'une adresse IP"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return not ipaddress.ip_address(ip).is_private or ip.startswith("192.168.")
        except:
            return False
            
    def scan_cycle(self):
        """Analyse les compteurs de paquets SYN pour détecter les attaques"""
        current_time = time.time()
        cutoff_time = current_time - self.time_window
        

        self._log_performance_metrics(current_time)
        
        with self.lock:
            # Parcourir toutes les adresses IP sources
            for src_ip, packets in list(self.syn_counters.items()):
                # Filtrer les paquets qui sont dans la fenêtre de temps
                recent_packets = [p for p in packets if p[0] >= cutoff_time]
                
                # Mettre à jour la liste des paquets récents
                self.syn_counters[src_ip] = deque(recent_packets, maxlen=2000)
                
                # Vérifier si le nombre de paquets SYN dépasse le seuil
                if len(recent_packets) >= self.threshold:
                    # Compter les ports uniques (détection de scan)
                    dst_ports = set(p[1] for p in recent_packets)
                    is_scan = len(dst_ports) > min(10, self.threshold / 2)
                    

                    attack_rate = len(recent_packets) / self.time_window
                    
                    # Détecter l'attaque
                    attack_type = "PORT_SCAN" if is_scan else "SYN_FLOOD"
                    details = {
                        "packet_count": len(recent_packets),
                        "time_window": self.time_window,
                        "distinct_ports": len(dst_ports),
                        "threshold": self.threshold,
                        "is_scan": is_scan,
                        "attack_rate_pps": round(attack_rate, 2),  # NOUVEAU
                        "severity": self._calculate_severity(len(recent_packets), attack_rate),  # NOUVEAU
                        "top_ports": list(dst_ports)[:10]
                    }
                    
                    # Enregistrer l'attaque
                    self.log_attack(attack_type, src_ip, details)
                    self.attacks_detected += 1
                    
                    # Vider le compteur pour cette IP après détection
                    self.syn_counters[src_ip].clear()
                
                # Supprimer les entrées vides
                if not self.syn_counters[src_ip]:
                    del self.syn_counters[src_ip]
                    
    def _calculate_severity(self, packet_count: int, attack_rate: float) -> str:
        """Calcule la sévérité de l'attaque"""
        if attack_rate > 1000:
            return "CRITICAL"
        elif attack_rate > 500:
            return "HIGH"
        elif attack_rate > 100:
            return "MEDIUM"
        else:
            return "LOW"
            
    def _log_performance_metrics(self, current_time: float):
        """Log des métriques de performance"""
        if current_time - self.last_performance_check >= 60:  # Toutes les minutes
            logger.info(f"SYN Scanner - Paquets traités: {self.packets_processed}, "
                       f"Attaques détectées: {self.attacks_detected}, "
                       f"IPs surveillées: {len(self.syn_counters)}")
            self.last_performance_check = current_time
            
    def get_statistics(self) -> Dict[str, Any]:
        """Retourne les statistiques du scanner"""
        with self.lock:
            return {
                "packets_processed": self.packets_processed,
                "attacks_detected": self.attacks_detected,
                "monitored_ips": len(self.syn_counters),
                "active_threads": len([t for t in self.sniffer_threads if t.is_alive()])
            }
            
    def cleanup(self):
        """Nettoyage des ressources du scanner"""
        logger.info("Nettoyage du scanner SYN Flood")
        
        # Vider les compteurs
        with self.lock:
            self.syn_counters.clear()
            
        # Log final des statistiques
        stats = self.get_statistics()
        logger.info(f"Statistiques finales SYN Scanner: {stats}")
