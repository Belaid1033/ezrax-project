#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner pour détecter les attaques Ping Flood (ICMP Echo Flood)
"""

import time
import logging
import threading
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Tuple

from scapy.all import sniff, IP, ICMP
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class PingFloodScanner(BaseScanner):
    """Détecte les attaques par Ping Flood (ICMP Echo Flood)"""
    
    def __init__(self, config, db_manager, ips_manager):
        super().__init__(config, db_manager, ips_manager)
        self.scanner_config = config["scanners"]["ping_flood"]
        self.threshold = self.scanner_config["threshold"]
        self.time_window = self.scanner_config["time_window"]
        self.interfaces = config["scanners"]["syn_flood"]["interfaces"]  # Réutilisation des interfaces
        
        # Structure de données pour suivre les paquets ICMP
        self.icmp_packets = defaultdict(lambda: deque(maxlen=1000))
        self.lock = threading.Lock()
        self.sniffer_threads = []
        
    def setup(self):
        """Configure et démarre les sniffers sur les interfaces"""
        # Démarrer un sniffer pour chaque interface
        for interface in self.interfaces:
            thread = threading.Thread(
                target=self._start_sniffer,
                args=(interface,),
                name=f"Sniffer-Ping-{interface}"
            )
            thread.daemon = True
            thread.start()
            self.sniffer_threads.append(thread)
            logger.info(f"Sniffer Ping Flood démarré sur l'interface {interface}")
            
    def _start_sniffer(self, interface):
        """
        Démarre un sniffer sur une interface spécifique
        
        Args:
            interface: Nom de l'interface à surveiller
        """
        try:
            # Utiliser un filtre BPF pour ne capturer que les paquets ICMP Echo
            sniff(
                iface=interface,
                filter="icmp and icmp[icmptype] = icmp-echo",
                prn=self._process_packet,
                store=0,
                stop_filter=lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Erreur dans le sniffer Ping sur {interface}: {e}")
            
    def _process_packet(self, packet):
        """
        Traite un paquet capturé par le sniffer
        
        Args:
            packet: Paquet réseau capturé
        """
        try:
            if ICMP in packet and packet[ICMP].type == 8:  # ICMP Echo Request
                timestamp = time.time()
                src_ip = packet[IP].src
                icmp_id = packet[ICMP].id  # Identifiant ICMP
                icmp_seq = packet[ICMP].seq  # Numéro de séquence ICMP
                
                if self.is_ip_whitelisted(src_ip):
                    return
                    
                with self.lock:
                    self.icmp_packets[src_ip].append((timestamp, icmp_id, icmp_seq))
        except Exception as e:
            logger.error(f"Erreur lors du traitement du paquet ICMP: {e}")
            
    def scan_cycle(self):
        """Analyse les paquets ICMP pour détecter les attaques Ping Flood"""
        current_time = time.time()
        cutoff_time = current_time - self.time_window
        
        with self.lock:
            # Parcourir toutes les adresses IP sources
            for src_ip, packets in list(self.icmp_packets.items()):
                # Filtrer les paquets qui sont dans la fenêtre de temps
                recent_packets = [p for p in packets if p[0] >= cutoff_time]
                
                # Mettre à jour la liste des paquets récents
                self.icmp_packets[src_ip] = deque(recent_packets, maxlen=1000)
                
                # Vérifier si le nombre de paquets ICMP dépasse le seuil
                if len(recent_packets) >= self.threshold:
                    # Analyser les ID et séquences pour détecter les motifs
                    icmp_ids = set(p[1] for p in recent_packets)
                    icmp_sequences = [p[2] for p in recent_packets]
                    
                    # Séquence consécutive ou aléatoire?
                    is_sequential = self._check_sequential_sequence(icmp_sequences)
                    
                    details = {
                        "packet_count": len(recent_packets),
                        "time_window": self.time_window,
                        "threshold": self.threshold,
                        "distinct_icmp_ids": len(icmp_ids),
                        "is_sequential": is_sequential,
                        "packets_per_second": len(recent_packets) / self.time_window
                    }
                    
                    # Enregistrer l'attaque
                    self.log_attack("PING_FLOOD", src_ip, details)
                    
                    # Vider le compteur pour cette IP après détection
                    self.icmp_packets[src_ip].clear()
                
                # Supprimer les entrées vides
                if not self.icmp_packets[src_ip]:
                    del self.icmp_packets[src_ip]
                    
    def _check_sequential_sequence(self, sequences):
        """
        Vérifie si une séquence de numéros est majoritairement séquentielle
        
        Args:
            sequences: Liste de numéros de séquence
            
        Returns:
            True si la séquence est plutôt séquentielle, False sinon
        """
        if not sequences or len(sequences) < 3:
            return False
            
        # Trier les séquences
        sorted_seq = sorted(sequences)
        
        # Compter les paires consécutives
        consecutive_count = 0
        for i in range(len(sorted_seq) - 1):
            if sorted_seq[i + 1] - sorted_seq[i] == 1:
                consecutive_count += 1
                
        # Si plus de 50% des paires sont consécutives, considérer comme séquentielle
        return consecutive_count >= (len(sorted_seq) - 1) / 2
        
    def cleanup(self):
        """Nettoyage des ressources du scanner"""
        logger.info("Nettoyage du scanner Ping Flood")
        
        # Vider les compteurs
        with self.lock:
            self.icmp_packets.clear()
