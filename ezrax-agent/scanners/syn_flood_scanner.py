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

from scapy.all import sniff, TCP
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class SynFloodScanner(BaseScanner):
    """Détecte les attaques SYN Flood"""
    
    def __init__(self, config, db_manager, ips_manager):
        super().__init__(config, db_manager, ips_manager)
        self.scanner_config = config["scanners"]["syn_flood"]
        self.threshold = self.scanner_config["threshold"]
        self.time_window = self.scanner_config["time_window"]
        self.interfaces = self.scanner_config["interfaces"]
        
        # Structure de données pour suivre les paquets SYN
        self.syn_counters = defaultdict(lambda: deque(maxlen=1000))
        self.lock = threading.Lock()  # Pour protéger l'accès concurrent aux compteurs
        self.sniffer_threads = []
        
    def setup(self):
        """Configure et démarre les sniffers sur les interfaces"""
        # Démarrer un sniffer pour chaque interface
        for interface in self.interfaces:
            thread = threading.Thread(
                target=self._start_sniffer,
                args=(interface,),
                name=f"Sniffer-{interface}"
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
            # Utiliser un filtre BPF pour ne capturer que les paquets TCP SYN
            sniff(
                iface=interface,
                filter="tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0",
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
            if TCP in packet and packet[TCP].flags == 2:  # TCP SYN flag est 2
                timestamp = time.time()
                src_ip = packet.getlayer(IP).src if hasattr(packet, 'getlayer') and hasattr(packet, 'IP') else packet.src
                dst_port = packet[TCP].dport
                
                if self.is_ip_whitelisted(src_ip):
                    return
                    
                with self.lock:
                    self.syn_counters[src_ip].append((timestamp, dst_port))
        except Exception as e:
            logger.error(f"Erreur lors du traitement du paquet SYN: {e}")
            
    def scan_cycle(self):
        """Analyse les compteurs de paquets SYN pour détecter les attaques"""
        current_time = time.time()
        cutoff_time = current_time - self.time_window
        
        with self.lock:
            # Parcourir toutes les adresses IP sources
            for src_ip, packets in list(self.syn_counters.items()):
                # Filtrer les paquets qui sont dans la fenêtre de temps
                recent_packets = [p for p in packets if p[0] >= cutoff_time]
                
                # Mettre à jour la liste des paquets récents
                self.syn_counters[src_ip] = deque(recent_packets, maxlen=1000)
                
                # Vérifier si le nombre de paquets SYN dépasse le seuil
                if len(recent_packets) >= self.threshold:
                    # Compter les ports uniques (détection de scan)
                    dst_ports = set(p[1] for p in recent_packets)
                    is_scan = len(dst_ports) > min(10, self.threshold / 2)
                    
                    # Détecter l'attaque
                    attack_type = "PORT_SCAN" if is_scan else "SYN_FLOOD"
                    details = {
                        "packet_count": len(recent_packets),
                        "time_window": self.time_window,
                        "distinct_ports": len(dst_ports),
                        "threshold": self.threshold,
                        "is_scan": is_scan,
                        "top_ports": list(dst_ports)[:10]  # Top 10 ports ciblés
                    }
                    
                    # Enregistrer l'attaque
                    self.log_attack(attack_type, src_ip, details)
                    
                    # Vider le compteur pour cette IP après détection
                    self.syn_counters[src_ip].clear()
                
                # Supprimer les entrées vides
                if not self.syn_counters[src_ip]:
                    del self.syn_counters[src_ip]
                    
    def cleanup(self):
        """Nettoyage des ressources du scanner"""
        # Les sniffers s'arrêteront automatiquement grâce à stop_filter
        logger.info("Nettoyage du scanner SYN Flood")
        
        # Vider les compteurs
        with self.lock:
            self.syn_counters.clear()

# Ajout de la dépendance d'importation en bas pour éviter les imports circulaires
from scapy.all import IP
