#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner pour détecter les attaques UDP Flood
"""

import time
import logging
import threading
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Tuple

from scapy.all import sniff, UDP, IP
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class UdpFloodScanner(BaseScanner):
    """Détecte les attaques UDP Flood"""
    
    def __init__(self, config, db_manager, ips_manager):
        super().__init__(config, db_manager, ips_manager)
        self.scanner_config = config["scanners"]["udp_flood"]
        self.threshold = self.scanner_config["threshold"]
        self.time_window = self.scanner_config["time_window"]
        self.interfaces = config["scanners"]["syn_flood"]["interfaces"]  # Réutilisation des interfaces
        
        # Structure de données pour suivre les paquets UDP
        self.udp_counters = defaultdict(lambda: deque(maxlen=1000))
        self.lock = threading.Lock()  # Pour protéger l'accès concurrent aux compteurs
        self.sniffer_threads = []
        
    def setup(self):
        """Configure et démarre les sniffers sur les interfaces"""
        # Démarrer un sniffer pour chaque interface
        for interface in self.interfaces:
            thread = threading.Thread(
                target=self._start_sniffer,
                args=(interface,),
                name=f"Sniffer-UDP-{interface}"
            )
            thread.daemon = True
            thread.start()
            self.sniffer_threads.append(thread)
            logger.info(f"Sniffer UDP Flood démarré sur l'interface {interface}")
            
    def _start_sniffer(self, interface):
        """
        Démarre un sniffer sur une interface spécifique
        
        Args:
            interface: Nom de l'interface à surveiller
        """
        try:
            # Utiliser un filtre BPF pour ne capturer que les paquets UDP
            sniff(
                iface=interface,
                filter="udp",
                prn=self._process_packet,
                store=0,
                stop_filter=lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Erreur dans le sniffer UDP sur {interface}: {e}")
            
    def _process_packet(self, packet):
        """
        Traite un paquet capturé par le sniffer
        
        Args:
            packet: Paquet réseau capturé
        """
        try:
            if UDP in packet:
                timestamp = time.time()
                src_ip = packet[IP].src if IP in packet else packet.src
                dst_port = packet[UDP].dport
                
                if self.is_ip_whitelisted(src_ip):
                    return
                    
                with self.lock:
                    self.udp_counters[src_ip].append((timestamp, dst_port))
        except Exception as e:
            logger.error(f"Erreur lors du traitement du paquet UDP: {e}")
            
    def scan_cycle(self):
        """Analyse les compteurs de paquets UDP pour détecter les attaques"""
        current_time = time.time()
        cutoff_time = current_time - self.time_window
        
        with self.lock:
            # Parcourir toutes les adresses IP sources
            for src_ip, packets in list(self.udp_counters.items()):
                # Filtrer les paquets qui sont dans la fenêtre de temps
                recent_packets = [p for p in packets if p[0] >= cutoff_time]
                
                # Mettre à jour la liste des paquets récents
                self.udp_counters[src_ip] = deque(recent_packets, maxlen=1000)
                
                # Vérifier si le nombre de paquets UDP dépasse le seuil
                if len(recent_packets) >= self.threshold:
                    # Compter les ports uniques (détection de scan)
                    dst_ports = set(p[1] for p in recent_packets)
                    
                    # Analyse des ports ciblés
                    port_frequency = defaultdict(int)
                    for _, port in recent_packets:
                        port_frequency[port] += 1
                    
                    # Trouver les ports les plus ciblés
                    top_targeted_ports = sorted(
                        port_frequency.items(), 
                        key=lambda x: x[1], 
                        reverse=True
                    )[:10]
                    
                    details = {
                        "packet_count": len(recent_packets),
                        "time_window": self.time_window,
                        "distinct_ports": len(dst_ports),
                        "threshold": self.threshold,
                        "top_targeted_ports": [
                            {"port": port, "count": count} 
                            for port, count in top_targeted_ports
                        ]
                    }
                    
                    # Enregistrer l'attaque
                    self.log_attack("UDP_FLOOD", src_ip, details)
                    
                    # Vider le compteur pour cette IP après détection
                    self.udp_counters[src_ip].clear()
                
                # Supprimer les entrées vides
                if not self.udp_counters[src_ip]:
                    del self.udp_counters[src_ip]
                    
    def cleanup(self):
        """Nettoyage des ressources du scanner"""
        # Les sniffers s'arrêteront automatiquement grâce à stop_filter
        logger.info("Nettoyage du scanner UDP Flood")
        
        # Vider les compteurs
        with self.lock:
            self.udp_counters.clear()
