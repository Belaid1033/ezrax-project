#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Package des scanners pour l'agent EZRAX IDS/IPS
"""

from .base_scanner import BaseScanner
from .syn_flood_scanner import SynFloodScanner
from .udp_flood_scanner import UdpFloodScanner
from .port_scan_scanner import PortScanScanner
from .ping_flood_scanner import PingFloodScanner

__all__ = [
    'BaseScanner',
    'SynFloodScanner',
    'UdpFloodScanner',
    'PortScanScanner',
    'PingFloodScanner'
]

def initialize_scanners(config, db_manager, ips_manager):
    """
    Initialise tous les scanners disponibles
    
    Args:
        config: Configuration de l'agent
        db_manager: Gestionnaire de base de données
        ips_manager: Gestionnaire IPS
        
    Returns:
        Liste des scanners initialisés
    """
    scanners = []
    
    # Vérifier si les scanners sont globalement activés
    if not config["scanners"]["enabled"]:
        return scanners
        
    # Initialiser les scanners spécifiques
    scanner_classes = [
        (SynFloodScanner, "syn_flood"),
        (UdpFloodScanner, "udp_flood"),
        (PortScanScanner, "port_scan"),
        (PingFloodScanner, "ping_flood")
    ]
    
    for scanner_class, config_key in scanner_classes:
        if config["scanners"][config_key]["enabled"]:
            scanner = scanner_class(config, db_manager, ips_manager)
            scanners.append(scanner)
            
    return scanners
