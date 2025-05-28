#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner pour détecter les scans de ports
"""

import time
import logging
import threading
import socket
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Tuple, Set

from scapy.all import sniff, IP, TCP, UDP
from .base_scanner import BaseScanner

logger = logging.getLogger(__name__)

class PortScanScanner(BaseScanner):
    """Détecte les scans de ports (SYN, FIN, XMAS, NULL, ACK, etc.)"""
    
    def __init__(self, config, db_manager, ips_manager):
        super().__init__(config, db_manager, ips_manager)
        self.scanner_config = config["scanners"]["port_scan"]
        self.threshold = self.scanner_config["threshold"]
        self.time_window = self.scanner_config["time_window"]
        self.interfaces = config["scanners"]["syn_flood"]["interfaces"]  # Réutilisation des interfaces
        
        # Structure de données pour suivre les tentatives de connexion
        # {ip_source: {(port_dest, protocole, flags): timestamp}}
        self.connection_attempts = defaultdict(dict)
        self.lock = threading.Lock()
        self.sniffer_threads = []
        
        # Caractéristiques des scans à détecter
        self.scan_types = {
            "SYN_SCAN": {"flags": 0x02, "proto": "TCP"},          # SYN
            "FIN_SCAN": {"flags": 0x01, "proto": "TCP"},          # FIN
            "XMAS_SCAN": {"flags": 0x29, "proto": "TCP"},         # FIN, PSH, URG
            "NULL_SCAN": {"flags": 0x00, "proto": "TCP"},         # Aucun flag
            "ACK_SCAN": {"flags": 0x10, "proto": "TCP"},          # ACK
            "WINDOW_SCAN": {"flags": 0x10, "proto": "TCP"},       # ACK (détecté par réponse)
            "UDP_SCAN": {"proto": "UDP"}                          # UDP
        }
        
        # Obtenir la liste des ports locaux ouverts
        self.local_ports = set()
        self.update_local_ports_interval = 300  # 5 minutes
        self.last_port_update = 0
        
    def update_local_ports(self):
        """Met à jour la liste des ports locaux ouverts"""
        if time.time() - self.last_port_update < self.update_local_ports_interval:
            return
            
        try:
            # TCP ports
            tcp_ports = set()
            for port in range(1, 10000):  # Vérifier les ports de 1 à 10000
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                result = s.connect_ex(('127.0.0.1', port))
                if result == 0:
                    tcp_ports.add(port)
                s.close()
                
            # UDP ports (plus difficile à détecter)
            # Cette méthode est limitée, mais c'est un point de départ
            udp_ports = set()
            common_udp_ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 514, 1900, 5353]
            for port in common_udp_ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.bind(('127.0.0.1', port))
                    s.close()
                except:
                    udp_ports.add(port)
                    
            self.local_ports = tcp_ports.union(udp_ports)
            self.last_port_update = time.time()
            logger.info(f"Ports locaux ouverts détectés: {sorted(self.local_ports)}")
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour des ports locaux: {e}")
            
    def setup(self):
        """Configure et démarre les sniffers sur les interfaces"""
        # Mise à jour des ports locaux
        self.update_local_ports()
        
        # Démarrer un sniffer pour chaque interface
        for interface in self.interfaces:
            thread = threading.Thread(
                target=self._start_sniffer,
                args=(interface,),
                name=f"Sniffer-PortScan-{interface}"
            )
            thread.daemon = True
            thread.start()
            self.sniffer_threads.append(thread)
            logger.info(f"Sniffer de scan de ports démarré sur l'interface {interface}")
            
    def _start_sniffer(self, interface):
        """
        Démarre un sniffer sur une interface spécifique
        
        Args:
            interface: Nom de l'interface à surveiller
        """
        try:
            # Capturer les paquets TCP et UDP
            sniff(
                iface=interface,
                filter="tcp or udp",
                prn=self._process_packet,
                store=0,
                stop_filter=lambda p: self.stop_event.is_set()
            )
        except Exception as e:
            logger.error(f"Erreur dans le sniffer de scan de ports sur {interface}: {e}")
            
    def _process_packet(self, packet):
        """
        Traite un paquet capturé par le sniffer
        
        Args:
            packet: Paquet réseau capturé
        """
        try:
            if IP not in packet:
                return
                
            src_ip = packet[IP].src
            
            if self.is_ip_whitelisted(src_ip):
                return
                
            # Traitement des paquets TCP
            if TCP in packet:
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                
                # Ignorer les connexions établies (SYN-ACK, ACK, etc.)
                if flags & 0x12 == 0x12:  # SYN-ACK
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
        
        # Mise à jour périodique des ports locaux
        self.update_local_ports()
        
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
                    
                    # Calculer le ratio de ports ouverts/fermés ciblés
                    targeted_open_ports = unique_ports.intersection(self.local_ports)
                    open_port_ratio = len(targeted_open_ports) / len(unique_ports) if unique_ports else 0
                    
                    details = {
                        "scan_type": scan_type,
                        "port_count": len(unique_ports),
                        "time_window": self.time_window,
                        "threshold": self.threshold,
                        "targeted_open_ports": len(targeted_open_ports),
                        "open_port_ratio": open_port_ratio,
                        "port_range": [min(unique_ports), max(unique_ports)] if unique_ports else [0, 0],
                        "port_sample": sorted(list(unique_ports))[:20]  # Échantillon de ports
                    }
                    
                    # Enregistrer l'attaque
                    self.log_attack("PORT_SCAN", src_ip, details)
                    
                    # Vider les tentatives pour cette IP après détection
                    self.connection_attempts[src_ip].clear()
                
                # Supprimer les entrées vides
                if not self.connection_attempts[src_ip]:
                    del self.connection_attempts[src_ip]
                    
    def _determine_scan_type(self, attempts):
        """
        Détermine le type de scan en fonction des caractéristiques des tentatives
        
        Args:
            attempts: Dictionnaire des tentatives de connexion
            
        Returns:
            Type de scan détecté
        """
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
        
    def cleanup(self):
        """Nettoyage des ressources du scanner"""
        logger.info("Nettoyage du scanner de scan de ports")
        
        # Vider les tentatives
        with self.lock:
            self.connection_attempts.clear()
