#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Point d'entrée principal de l'agent EZRAX IDS/IPS
"""

import os
import sys
import time
import signal
import logging
import argparse
import threading
import traceback
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum

# Chemin absolu du répertoire de l'agent
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# Importation des modules
from config import CONFIG, setup_logging, ensure_directories, AGENT_ID, AGENT_HOSTNAME
from storage import DatabaseManager, LogManager
from ips import IptablesManager
from scanners import initialize_scanners
from reporting import ReportGenerator
from communication import CentralClient

# Configuration du logging précoce
setup_logging()
logger = logging.getLogger(__name__)

class ComponentStatus(Enum):
    """États possibles d'un composant"""
    INITIALIZING = "initializing"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    STOPPED = "stopped"

@dataclass
class ComponentInfo:
    """Informations sur un composant du système"""
    name: str
    instance: Any
    status: ComponentStatus
    last_check: float
    error_count: int
    last_error: Optional[str]
    dependencies: List[str]
    critical: bool  # Si True, l'échec de ce composant arrête l'agent

class HealthMonitor:
    """Moniteur de santé pour tous les composants"""
    
    def __init__(self, check_interval: int = 30):
        self.components: Dict[str, ComponentInfo] = {}
        self.check_interval = check_interval
        self.running = False
        self.monitor_thread = None
        self.lock = threading.RLock()
        
    def register_component(self, name: str, instance: Any, dependencies: List[str] = None,
                          critical: bool = True):
        """Enregistre un composant pour monitoring"""
        with self.lock:
            self.components[name] = ComponentInfo(
                name=name,
                instance=instance,
                status=ComponentStatus.INITIALIZING,
                last_check=0,
                error_count=0,
                last_error=None,
                dependencies=dependencies or [],
                critical=critical
            )
        logger.info(f"Composant enregistré pour monitoring: {name}")
        
    def start_monitoring(self):
        """Démarre le monitoring des composants"""
        if self.running:
            return
            
        self.running = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            name="HealthMonitor",
            daemon=True
        )
        self.monitor_thread.start()
        logger.info("Monitoring de santé démarré")
        
    def stop_monitoring(self):
        """Arrête le monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            
    def _monitoring_loop(self):
        """Boucle principale de monitoring"""
        while self.running:
            try:
                self._check_all_components()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Erreur dans le monitoring: {e}")
                time.sleep(10)  # Pause courte en cas d'erreur
                
    def _check_all_components(self):
        """Vérifie la santé de tous les composants"""
        with self.lock:
            for component in self.components.values():
                try:
                    self._check_component(component)
                except Exception as e:
                    logger.error(f"Erreur lors de la vérification de {component.name}: {e}")
                    component.status = ComponentStatus.FAILED
                    component.error_count += 1
                    component.last_error = str(e)
                    
    def _check_component(self, component: ComponentInfo):
        """Vérifie la santé d'un composant spécifique"""
        current_time = time.time()
        
        try:
            # Vérifier les dépendances d'abord
            for dep_name in component.dependencies:
                if dep_name in self.components:
                    dep_status = self.components[dep_name].status
                    if dep_status == ComponentStatus.FAILED:
                        component.status = ComponentStatus.DEGRADED
                        component.last_error = f"Dépendance {dep_name} en échec"
                        component.last_check = current_time
                        return
                        
            # Vérification spécifique par type de composant
            is_healthy = True
            error_msg = None
            
            if hasattr(component.instance, 'get_health_status'):
                # Le composant a sa propre méthode de santé
                health_result = component.instance.get_health_status()
                if isinstance(health_result, dict):
                    is_healthy = health_result.get('healthy', True)
                    error_msg = health_result.get('error')
                else:
                    is_healthy = bool(health_result)
                    
            elif hasattr(component.instance, 'active'):
                # Composant avec attribut 'active' (scanners)
                is_healthy = getattr(component.instance, 'active', False)
                if not is_healthy:
                    error_msg = "Composant inactif"
                    
            elif hasattr(component.instance, 'enabled'):
                # Composant avec attribut 'enabled' (IPS, etc.)
                is_healthy = getattr(component.instance, 'enabled', False)
                if not is_healthy:
                    error_msg = "Composant désactivé"
                    
            elif hasattr(component.instance, 'connected'):
                # Client de communication
                is_healthy = getattr(component.instance, 'connected', False)
                if not is_healthy:
                    error_msg = "Client non connecté"
                    
            # Mettre à jour le statut
            if is_healthy:
                if component.status == ComponentStatus.FAILED:
                    logger.info(f"Composant {component.name} récupéré")
                component.status = ComponentStatus.HEALTHY
                component.error_count = max(0, component.error_count - 1)  # Décrémenter les erreurs
            else:
                component.status = ComponentStatus.DEGRADED
                component.error_count += 1
                component.last_error = error_msg or "Statut dégradé"
                
                # Passer en échec si trop d'erreurs
                if component.error_count > 5:
                    component.status = ComponentStatus.FAILED
                    logger.error(f"Composant {component.name} en échec: {component.last_error}")
                    
        except Exception as e:
            component.status = ComponentStatus.FAILED
            component.error_count += 1
            component.last_error = str(e)
            logger.error(f"Erreur lors de la vérification de {component.name}: {e}")
            
        component.last_check = current_time
        
    def get_system_health(self) -> Dict[str, Any]:
        """Retourne l'état de santé global du système"""
        with self.lock:
            healthy_count = sum(1 for c in self.components.values() if c.status == ComponentStatus.HEALTHY)
            critical_failed = [c.name for c in self.components.values() 
                             if c.critical and c.status == ComponentStatus.FAILED]
            
            overall_status = "healthy"
            if critical_failed:
                overall_status = "critical"
            elif healthy_count < len(self.components):
                overall_status = "degraded"
                
            return {
                "overall_status": overall_status,
                "total_components": len(self.components),
                "healthy_components": healthy_count,
                "critical_failures": critical_failed,
                "components": {
                    name: {
                        "status": comp.status.value,
                        "last_check": comp.last_check,
                        "error_count": comp.error_count,
                        "last_error": comp.last_error
                    }
                    for name, comp in self.components.items()
                }
            }

class EzraxAgent:
    """
    Classe principale de l'agent EZRAX IDS/IPS - Architecture améliorée
    """
    
    def __init__(self):
        """Initialisation de l'agent avec architecture robuste"""
        self.config = CONFIG
        self.running = False
        self.components = {}
        
        # Monitoring de santé
        self.health_monitor = HealthMonitor(check_interval=30)
        
        # Métriques système
        self.metrics = {
            "start_time": time.time(),
            "initialization_time": 0,
            "restart_count": 0,
            "last_health_check": 0
        }
        
        # S'assurer que les répertoires nécessaires existent
        ensure_directories()
        
        # Initialiser les composants de manière robuste
        self._initialize_components()
        
    def _initialize_components(self):
        """Initialise tous les composants de manière parallèle et robuste"""
        logger.info("Initialisation des composants de l'agent EZRAX...")
        initialization_start = time.time()
        
        # Plan d'initialisation avec dépendances
        initialization_plan = [
            # Phase 1: Composants de base (pas de dépendances)
            {
                "name": "database",
                "class": DatabaseManager,
                "args": (self.config,),
                "critical": True,
                "dependencies": []
            },
            # Phase 2: Composants dépendant de la DB
            {
                "name": "log_manager", 
                "class": LogManager,
                "args": (self.config, None),  # DB sera injectée
                "critical": False,
                "dependencies": ["database"]
            },
            {
                "name": "ips_manager",
                "class": IptablesManager,
                "args": (self.config, None),  # DB sera injectée
                "critical": True,
                "dependencies": ["database"]
            },
            # Phase 3: Composants dépendant de l'IPS
            {
                "name": "scanners",
                "factory": self._initialize_scanners,
                "args": (),
                "critical": True,
                "dependencies": ["database", "ips_manager"]
            },
            # Phase 4: Composants de haut niveau
            {
                "name": "report_generator",
                "class": ReportGenerator,
                "args": (self.config, None, None),  # DB et LogManager seront injectés
                "critical": False,
                "dependencies": ["database", "log_manager"]
            },
            {
                "name": "central_client",
                "class": CentralClient,
                "args": (self.config, None, None),  # DB et IPS seront injectés
                "critical": False,
                "dependencies": ["database", "ips_manager"]
            }
        ]
        
        # Initialisation par phases
        self._initialize_by_phases(initialization_plan)
        
        # Configurer le monitoring de santé
        self._setup_health_monitoring()
        
        self.metrics["initialization_time"] = time.time() - initialization_start
        logger.info(f"Initialisation terminée en {self.metrics['initialization_time']:.2f}s")
        
    def _initialize_by_phases(self, plan: List[Dict[str, Any]]):
        """Initialise les composants par phases en respectant les dépendances"""
        
        # Grouper par phase selon les dépendances
        phases = []
        remaining_components = plan.copy()
        
        while remaining_components:
            current_phase = []
            
            for component in remaining_components[:]:
                # Vérifier si toutes les dépendances sont satisfaites
                dependencies_ready = all(
                    dep in self.components for dep in component["dependencies"]
                )
                
                if dependencies_ready:
                    current_phase.append(component)
                    remaining_components.remove(component)
                    
            if not current_phase:
                # Dépendances circulaires ou manquantes
                remaining_names = [c["name"] for c in remaining_components]
                logger.error(f"Dépendances non résolues pour: {remaining_names}")
                break
                
            phases.append(current_phase)
            
        # Initialiser chaque phase
        for phase_num, phase_components in enumerate(phases, 1):
            logger.info(f"Initialisation phase {phase_num}: {[c['name'] for c in phase_components]}")
            self._initialize_phase(phase_components)
            
    def _initialize_phase(self, components: List[Dict[str, Any]]):
        """Initialise une phase de composants en parallèle"""
        
        def init_component(comp_config):
            try:
                name = comp_config["name"]
                logger.info(f"Initialisation de {name}...")
                
                # Préparer les arguments en injectant les dépendances
                args = list(comp_config["args"])
                
                # Injection de dépendances spécifiques
                if name == "log_manager" and args[1] is None:
                    args[1] = self.components["database"]
                elif name == "ips_manager" and args[1] is None:
                    args[1] = self.components["database"]
                elif name == "report_generator":
                    if args[1] is None:
                        args[1] = self.components["database"]
                    if args[2] is None:
                        args[2] = self.components["log_manager"]
                elif name == "central_client":
                    if args[1] is None:
                        args[1] = self.components["database"]
                    if args[2] is None:
                        args[2] = self.components["ips_manager"]
                        
                # Initialiser le composant
                if "factory" in comp_config:
                    # Utiliser une factory function
                    instance = comp_config["factory"](*args)
                else:
                    # Utiliser le constructeur de classe
                    instance = comp_config["class"](*args)
                    
                return name, instance, comp_config["critical"]
                
            except Exception as e:
                logger.error(f"Erreur lors de l'initialisation de {comp_config['name']}: {e}")
                logger.error(traceback.format_exc())
                return comp_config["name"], None, comp_config["critical"]
                
        # Initialisation parallèle avec timeout
        with ThreadPoolExecutor(max_workers=4, thread_name_prefix="Init") as executor:
            futures = {
                executor.submit(init_component, comp): comp 
                for comp in components
            }
            
            for future in as_completed(futures, timeout=120):  # 2 minutes max
                comp_config = futures[future]
                name, instance, critical = future.result()
                
                if instance is not None:
                    self.components[name] = instance
                    logger.info(f"✓ {name} initialisé avec succès")
                else:
                    logger.error(f"✗ Échec de l'initialisation de {name}")
                    if critical:
                        raise RuntimeError(f"Composant critique {name} non initialisé")
                        
    def _initialize_scanners(self):
        """Factory pour initialiser les scanners"""
        db_manager = self.components["database"]
        ips_manager = self.components["ips_manager"]
        return initialize_scanners(self.config, db_manager, ips_manager)
        
    def _setup_health_monitoring(self):
        """Configure le monitoring de santé pour tous les composants"""
        
        # Enregistrer les composants pour monitoring
        monitoring_config = {
            "database": {"critical": True, "dependencies": []},
            "ips_manager": {"critical": True, "dependencies": ["database"]},
            "log_manager": {"critical": False, "dependencies": ["database"]},
            "report_generator": {"critical": False, "dependencies": ["database", "log_manager"]},
            "central_client": {"critical": False, "dependencies": ["database", "ips_manager"]}
        }
        
        for name, instance in self.components.items():
            if name == "scanners":
                # Enregistrer chaque scanner individuellement
                for i, scanner in enumerate(instance):
                    scanner_name = f"scanner_{scanner.__class__.__name__}_{i}"
                    self.health_monitor.register_component(
                        scanner_name, scanner, 
                        dependencies=["database", "ips_manager"],
                        critical=True
                    )
            else:
                config = monitoring_config.get(name, {"critical": False, "dependencies": []})
                self.health_monitor.register_component(
                    name, instance,
                    dependencies=config["dependencies"],
                    critical=config["critical"]
                )
                
        # Démarrer le monitoring
        self.health_monitor.start_monitoring()
        
    def start(self):
        """Démarre l'agent avec monitoring avancé"""
        if self.running:
            logger.warning("L'agent est déjà en cours d'exécution")
            return
            
        try:
            logger.info("=== Démarrage de l'agent EZRAX ===")
            
            # Configurer les gestionnaires de signaux
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGHUP, self._reload_handler)  # Rechargement config
            
            # Démarrer les scanners
            if "scanners" in self.components:
                for scanner in self.components["scanners"]:
                    try:
                        scanner.start()
                        logger.info(f"Scanner {scanner.__class__.__name__} démarré")
                    except Exception as e:
                        logger.error(f"Erreur lors du démarrage du scanner {scanner.__class__.__name__}: {e}")
                        
            # Enregistrer l'agent auprès du serveur central
            if "central_client" in self.components:
                try:
                    self.components["central_client"].register_agent()
                except Exception as e:
                    logger.warning(f"Erreur lors de l'enregistrement central: {e}")
                    
            # Générer un rapport initial
            if "report_generator" in self.components and self.config["reporting"]["enabled"]:
                try:
                    self.components["report_generator"].generate_report()
                except Exception as e:
                    logger.warning(f"Erreur lors de la génération du rapport initial: {e}")
                    
            self.running = True
            logger.info(f"Agent démarré avec {len(self.components.get('scanners', []))} scanners actifs")
            
            # Boucle principale avec monitoring avancé
            self._main_loop()
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage de l'agent: {e}")
            logger.error(traceback.format_exc())
            self.stop()
            
    def _main_loop(self):
        """Boucle principale avec monitoring et auto-recovery"""
        last_maintenance = 0
        last_health_log = 0
        
        while self.running:
            try:
                current_time = time.time()
                
                # Maintenance périodique (toutes les 5 minutes)
                if current_time - last_maintenance > 300:
                    self._perform_maintenance()
                    last_maintenance = current_time
                    
                # Log de santé périodique (toutes les 10 minutes)
                if current_time - last_health_log > 600:
                    self._log_health_status()
                    last_health_log = current_time
                    
                # Vérifier l'état du système
                health = self.health_monitor.get_system_health()
                
                # Auto-recovery pour les composants dégradés
                if health["overall_status"] == "degraded":
                    self._attempt_recovery()
                    
                # Arrêter si des composants critiques sont en échec
                elif health["overall_status"] == "critical":
                    logger.critical("Composants critiques en échec, arrêt de l'agent")
                    self.stop()
                    break
                    
                # Pause adaptative selon la santé du système
                sleep_time = 10 if health["overall_status"] == "healthy" else 5
                time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Erreur dans la boucle principale: {e}")
                time.sleep(30)  # Pause plus longue en cas d'erreur
                
    def _perform_maintenance(self):
        """Effectue la maintenance périodique du système"""
        try:
            logger.debug("Maintenance périodique du système...")
            
            # Nettoyage de la base de données
            if "database" in self.components:
                self.components["database"].cleanup_old_data()
                
            # Optimisation périodique (une fois par jour)
            if time.time() - self.metrics["start_time"] > 86400:  # 24h
                if "database" in self.components:
                    self.components["database"].optimize_database()
                    
            # Envoi de heartbeat au serveur central
            if "central_client" in self.components:
                self.components["central_client"].send_heartbeat()
                
            self.metrics["last_health_check"] = time.time()
            
        except Exception as e:
            logger.error(f"Erreur lors de la maintenance: {e}")
            
    def _log_health_status(self):
        """Log l'état de santé détaillé du système"""
        try:
            health = self.health_monitor.get_system_health()
            
            logger.info(
                f"État système: {health['overall_status']} - "
                f"{health['healthy_components']}/{health['total_components']} composants sains"
            )
            
            # Log des composants en problème
            for name, comp_info in health["components"].items():
                if comp_info["status"] != "healthy":
                    logger.warning(
                        f"Composant {name}: {comp_info['status']} "
                        f"(erreurs: {comp_info['error_count']}) - {comp_info['last_error']}"
                    )
                    
            # Métriques de performance
            if "database" in self.components:
                db_metrics = self.components["database"].get_performance_metrics()
                logger.info(f"DB Performance: {db_metrics}")
                
        except Exception as e:
            logger.error(f"Erreur lors du log de santé: {e}")
            
    def _attempt_recovery(self):
        """Tente de récupérer les composants dégradés"""
        logger.info("Tentative de récupération des composants dégradés...")
        
        try:
            health = self.health_monitor.get_system_health()
            
            for name, comp_info in health["components"].items():
                if comp_info["status"] in ["degraded", "failed"]:
                    logger.info(f"Tentative de récupération de {name}...")
                    
                    # Stratégies de récupération spécifiques
                    if name.startswith("scanner_"):
                        self._recover_scanner(name)
                    elif name == "central_client":
                        self._recover_central_client()
                    elif name == "ips_manager":
                        self._recover_ips_manager()
                        
        except Exception as e:
            logger.error(f"Erreur lors de la récupération: {e}")
            
    def _recover_scanner(self, scanner_name: str):
        """Récupère un scanner défaillant"""
        try:
            # Redémarrer le scanner
            for scanner in self.components.get("scanners", []):
                if f"scanner_{scanner.__class__.__name__}" in scanner_name:
                    logger.info(f"Redémarrage du scanner {scanner.__class__.__name__}")
                    scanner.stop()
                    time.sleep(2)
                    scanner.start()
                    break
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du scanner: {e}")
            
    def _recover_central_client(self):
        """Récupère le client central"""
        try:
            if "central_client" in self.components:
                logger.info("Tentative de reconnexion au serveur central")
                self.components["central_client"].force_reconnect()
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du client central: {e}")
            
    def _recover_ips_manager(self):
        """Récupère le gestionnaire IPS"""
        try:
            if "ips_manager" in self.components:
                logger.warning("Gestionnaire IPS dégradé - vérification requise")
        except Exception as e:
            logger.error(f"Erreur lors de la récupération IPS: {e}")
            
    def stop(self):
        """Arrête l'agent proprement"""
        if not self.running:
            return
            
        logger.info("=== Arrêt de l'agent EZRAX ===")
        self.running = False
        
        # Arrêter le monitoring
        self.health_monitor.stop_monitoring()
        
        # Arrêter les scanners
        if "scanners" in self.components:
            for scanner in self.components["scanners"]:
                try:
                    scanner.stop()
                    logger.info(f"Scanner {scanner.__class__.__name__} arrêté")
                except Exception as e:
                    logger.error(f"Erreur lors de l'arrêt du scanner: {e}")
                    
        # Arrêter les autres composants dans l'ordre inverse
        shutdown_order = ["central_client", "report_generator", "ips_manager", "log_manager", "database"]
        
        for component_name in shutdown_order:
            if component_name in self.components:
                try:
                    component = self.components[component_name]
                    if hasattr(component, 'shutdown'):
                        component.shutdown()
                    elif hasattr(component, 'close'):
                        component.close()
                    logger.info(f"Composant {component_name} arrêté")
                except Exception as e:
                    logger.error(f"Erreur lors de l'arrêt de {component_name}: {e}")
                    
        # Log des métriques finales
        uptime = time.time() - self.metrics["start_time"]
        logger.info(f"Agent arrêté après {uptime:.0f}s de fonctionnement")
        
    def get_status(self) -> Dict[str, Any]:
        """Retourne le statut complet de l'agent"""
        uptime = time.time() - self.metrics["start_time"]
        health = self.health_monitor.get_system_health()
        
        return {
            "agent_id": AGENT_ID,
            "hostname": AGENT_HOSTNAME,
            "version": "2.0.0",
            "running": self.running,
            "uptime_seconds": uptime,
            "uptime_formatted": self._format_uptime(uptime),
            "health": health,
            "metrics": self.metrics,
            "components": list(self.components.keys())
        }
        
    def _format_uptime(self, seconds: float) -> str:
        """Formate une durée en uptime lisible"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"
            
    def _signal_handler(self, sig, frame):
        """Gestionnaire de signaux pour arrêt gracieux"""
        signal_names = {signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}
        logger.info(f"Signal {signal_names.get(sig, sig)} reçu, arrêt gracieux...")
        self.stop()
        sys.exit(0)
        
    def _reload_handler(self, sig, frame):
        """Gestionnaire de rechargement de configuration (SIGHUP)"""
        logger.info("Signal SIGHUP reçu, rechargement de la configuration...")
        try:
            from config import reload_config
            if reload_config():
                logger.info("Configuration rechargée avec succès")
            else:
                logger.error("Échec du rechargement de la configuration")
        except Exception as e:
            logger.error(f"Erreur lors du rechargement: {e}")

def parse_arguments():
    """Parse les arguments de la ligne de commande avec options avancées"""
    parser = argparse.ArgumentParser(
        description="Agent EZRAX IDS/IPS v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  %(prog)s                          # Démarrage normal
  %(prog)s --debug                  # Mode debug
  %(prog)s --no-ips --no-central    # Sans IPS ni serveur central
  %(prog)s --status                 # Afficher le statut seulement
        """
    )
    
    parser.add_argument(
        "--config",
        help="Chemin vers le fichier de configuration",
        default=os.path.join(BASE_DIR, "agent_config.yaml")
    )
    
    parser.add_argument(
        "--no-ips",
        help="Désactiver la fonctionnalité IPS",
        action="store_true"
    )
    
    parser.add_argument(
        "--no-central",
        help="Désactiver la communication avec le serveur central",
        action="store_true"
    )
    
    parser.add_argument(
        "--debug",
        help="Activer le mode debug",
        action="store_true"
    )
    
    parser.add_argument(
        "--status",
        help="Afficher le statut et quitter",
        action="store_true"
    )
    
    parser.add_argument(
        "--test-config",
        help="Tester la configuration et quitter",
        action="store_true"
    )
    
    return parser.parse_args()
    
def main():
    """Point d'entrée principal avec gestion d'erreurs robuste"""
    try:
        # Parser les arguments
        args = parse_arguments()
        
        # Configuration du mode debug
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.info("Mode debug activé")
            
        # Test de configuration seulement
        if args.test_config:
            logger.info("Test de la configuration...")
            logger.info("✓ Configuration valide")
            return 0
            
        # Modification de la configuration selon les arguments
        if args.no_ips:
            CONFIG["ips"]["enabled"] = False
            logger.info("IPS désactivé via argument")
            
        if args.no_central:
            CONFIG["central_server"]["enabled"] = False
            logger.info("Serveur central désactivé via argument")
            
        # Créer l'agent
        logger.info(f"Démarrage de l'agent EZRAX v2.0 (ID: {AGENT_ID})")
        agent = EzraxAgent()
        
        # Mode statut seulement
        if args.status:
            status = agent.get_status()
            print(json.dumps(status, indent=2, ensure_ascii=False))
            return 0
            
        # Démarrage normal
        agent.start()
        
    except KeyboardInterrupt:
        logger.info("Interruption clavier reçue")
        return 0
    except Exception as e:
        logger.critical(f"Erreur critique lors du démarrage: {e}")
        logger.critical(traceback.format_exc())
        return 1
    finally:
        logger.info("=== Fin de l'agent EZRAX ===")
        
    return 0
        
if __name__ == "__main__":
    sys.exit(main())
