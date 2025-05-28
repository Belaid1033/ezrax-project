#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Générateur de rapports pour l'agent EZRAX IDS/IPS
"""

import os
import time
import logging
import json
import threading
import schedule
from datetime import datetime
from typing import Dict, List, Any, Optional
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Générateur de rapports pour l'agent EZRAX IDS/IPS
    """
    
    def __init__(self, config, db_manager, log_manager):
        """
        Initialisation du générateur de rapports
        
        Args:
            config: Configuration de l'agent
            db_manager: Gestionnaire de base de données
            log_manager: Gestionnaire de logs
        """
        self.config = config
        self.db_manager = db_manager
        self.log_manager = log_manager
        self.enabled = config["reporting"]["enabled"]
        self.interval = config["reporting"]["interval"]
        self.output_dir = config["reporting"]["output_dir"]
        self.agent_id = config["AGENT_ID"]
        self.agent_hostname = config["AGENT_HOSTNAME"]
        
        # Créer le répertoire de sortie s'il n'existe pas
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Répertoire des modèles (templates)
        self.template_dir = os.path.join(os.path.dirname(__file__), "templates")
        os.makedirs(self.template_dir, exist_ok=True)
        self._create_default_templates()
        
        # Initialiser Jinja2
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # Thread pour la génération périodique de rapports
        self.stop_event = threading.Event()
        self.scheduler_thread = None
        
        if self.enabled:
            self._start_scheduler()
            
    def _create_default_templates(self):
        """Crée les modèles par défaut s'ils n'existent pas"""
        # Modèle HTML
        html_template_path = os.path.join(self.template_dir, "report_template.html")
        if not os.path.exists(html_template_path):
            with open(html_template_path, "w") as f:
                f.write("""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EZRAX IDS/IPS - Rapport de Sécurité</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .header {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .section {
            margin-bottom: 30px;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            background-color: #f9f9f9;
        }
        .stats {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
        }
        .stat-card {
            flex: 1;
            min-width: 200px;
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            color: #3498db;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            font-size: 12px;
            color: #7f8c8d;
            border-top: 1px solid #ddd;
            padding-top: 20px;
        }
        .chart-container {
            background-color: #fff;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 15px 0;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>EZRAX IDS/IPS - Rapport de Sécurité</h1>
        <p>
            Agent ID: <strong>{{ agent_id }}</strong><br>
            Hostname: <strong>{{ agent_hostname }}</strong><br>
            Période du rapport: <strong>{{ report_period }}</strong><br>
            Généré le: <strong>{{ generated_at }}</strong>
        </p>
    </div>

    <div class="section">
        <h2>Résumé des Activités</h2>
        <div class="stats">
            <div class="stat-card">
                <h3>Attaques Détectées</h3>
                <div class="stat-value">{{ attack_summary.total_attacks }}</div>
                <p>Sur les dernières {{ attack_summary.timeframe_hours }} heures</p>
            </div>
            <div class="stat-card">
                <h3>Sources Uniques</h3>
                <div class="stat-value">{{ attack_summary.unique_sources }}</div>
                <p>Adresses IP distinctes</p>
            </div>
            <div class="stat-card">
                <h3>IPs Bloquées</h3>
                <div class="stat-value">{{ blocked_summary.active_blocks }}</div>
                <p>Blocages actifs</p>
            </div>
            <div class="stat-card">
                <h3>Uptime Agent</h3>
                <div class="stat-value">{{ agent_stats.uptime_formatted }}</div>
                <p>Depuis le démarrage</p>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>Distribution des Types d'Attaques</h2>
        {% if attack_summary.attack_types %}
            <table>
                <tr>
                    <th>Type d'Attaque</th>
                    <th>Nombre</th>
                    <th>Pourcentage</th>
                </tr>
                {% for attack_type, count in attack_summary.attack_types.items() %}
                <tr>
                    <td>{{ attack_type }}</td>
                    <td>{{ count }}</td>
                    <td>{{ (count / attack_summary.total_attacks * 100) | round(1) }}%</td>
                </tr>
                {% endfor %}
            </table>
        {% else %}
            <p>Aucune attaque détectée pendant la période.</p>
        {% endif %}
    </div>

    <div class="section">
        <h2>Top 10 des Attaquants</h2>
        {% if attack_summary.top_attackers %}
            <table>
                <tr>
                    <th>Adresse IP</th>
                    <th>Nombre d'Attaques</th>
                    <th>Types d'Attaques</th>
                    <th>Première Détection</th>
                    <th>Dernière Détection</th>
                </tr>
                {% for attacker in attack_summary.top_attackers %}
                <tr>
                    <td>{{ attacker.ip }}</td>
                    <td>{{ attacker.count }}</td>
                    <td>{{ attacker.attack_types | join(", ") }}</td>
                    <td>{{ attacker.first_seen | timestamp_to_date }}</td>
                    <td>{{ attacker.last_seen | timestamp_to_date }}</td>
                </tr>
                {% endfor %}
            </table>
        {% else %}
            <p>Aucun attaquant détecté pendant la période.</p>
        {% endif %}
    </div>

    <div class="section">
        <h2>Blocages IP</h2>
        {% if blocked_summary.recent_blocks %}
            <h3>Blocages Récents</h3>
            <table>
                <tr>
                    <th>Adresse IP</th>
                    <th>Raison</th>
                    <th>Début du Blocage</th>
                    <th>Durée</th>
                </tr>
                {% for block in blocked_summary.recent_blocks %}
                <tr>
                    <td>{{ block.ip }}</td>
                    <td>{{ block.reason }}</td>
                    <td>{{ block.timestamp | timestamp_to_date }}</td>
                    <td>{{ block.duration | seconds_to_duration }}</td>
                </tr>
                {% endfor %}
            </table>
            
            <h3>Statistiques des Blocages</h3>
            <div class="stats">
                <div class="stat-card">
                    <h4>Blocages Actifs</h4>
                    <div class="stat-value">{{ blocked_summary.active_blocks }}</div>
                </div>
                <div class="stat-card">
                    <h4>Total des Blocages</h4>
                    <div class="stat-value">{{ blocked_summary.total_blocks }}</div>
                </div>
            </div>
            
            <h3>Raisons des Blocages</h3>
            <table>
                <tr>
                    <th>Raison</th>
                    <th>Nombre</th>
                    <th>Pourcentage</th>
                </tr>
                {% for reason, count in blocked_summary.block_reasons.items() %}
                <tr>
                    <td>{{ reason }}</td>
                    <td>{{ count }}</td>
                    <td>{{ (count / blocked_summary.total_blocks * 100) | round(1) }}%</td>
                </tr>
                {% endfor %}
            </table>
        {% else %}
            <p>Aucun blocage IP pendant la période.</p>
        {% endif %}
    </div>

    <div class="footer">
        <p>Rapport généré par EZRAX IDS/IPS - © {{ current_year }}</p>
    </div>
</body>
</html>""")
                
        # Modèle JSON
        json_template_path = os.path.join(self.template_dir, "report_template.json")
        if not os.path.exists(json_template_path):
            with open(json_template_path, "w") as f:
                f.write("""{
    "report_metadata": {
        "agent_id": "{{ agent_id }}",
        "hostname": "{{ agent_hostname }}",
        "report_period": "{{ report_period }}",
        "generated_at": "{{ generated_at }}",
        "generated_at_timestamp": {{ generated_at_timestamp }}
    },
    "agent_stats": {{ agent_stats | tojson }},
    "attack_summary": {{ attack_summary | tojson }},
    "blocked_summary": {{ blocked_summary | tojson }}
}""")
                
        # Modèle Texte
        text_template_path = os.path.join(self.template_dir, "report_template.txt")
        if not os.path.exists(text_template_path):
            with open(text_template_path, "w") as f:
                f.write("""===============================================
EZRAX IDS/IPS - RAPPORT DE SÉCURITÉ
===============================================

INFORMATIONS GÉNÉRALES
----------------------
Agent ID: {{ agent_id }}
Hostname: {{ agent_hostname }}
Période du rapport: {{ report_period }}
Généré le: {{ generated_at }}

RÉSUMÉ DES ACTIVITÉS
--------------------
Attaques Détectées: {{ attack_summary.total_attacks }} (sur les dernières {{ attack_summary.timeframe_hours }} heures)
Sources Uniques: {{ attack_summary.unique_sources }}
IPs Bloquées (actives): {{ blocked_summary.active_blocks }}
Uptime Agent: {{ agent_stats.uptime_formatted }}

DISTRIBUTION DES TYPES D'ATTAQUES
---------------------------------
{% if attack_summary.attack_types %}
{% for attack_type, count in attack_summary.attack_types.items() %}
{{ attack_type }}: {{ count }} ({{ (count / attack_summary.total_attacks * 100) | round(1) }}%)
{% endfor %}
{% else %}
Aucune attaque détectée pendant la période.
{% endif %}

TOP 10 DES ATTAQUANTS
---------------------
{% if attack_summary.top_attackers %}
{% for attacker in attack_summary.top_attackers %}
IP: {{ attacker.ip }}
  Nombre d'attaques: {{ attacker.count }}
  Types d'attaques: {{ attacker.attack_types | join(", ") }}
  Première détection: {{ attacker.first_seen | timestamp_to_date }}
  Dernière détection: {{ attacker.last_seen | timestamp_to_date }}
{% endfor %}
{% else %}
Aucun attaquant détecté pendant la période.
{% endif %}

BLOCAGES IP
-----------
{% if blocked_summary.recent_blocks %}
Blocages Récents:
{% for block in blocked_summary.recent_blocks %}
  IP: {{ block.ip }}
  Raison: {{ block.reason }}
  Début: {{ block.timestamp | timestamp_to_date }}
  Durée: {{ block.duration | seconds_to_duration }}
{% endfor %}

Statistiques des Blocages:
  Blocages Actifs: {{ blocked_summary.active_blocks }}
  Total des Blocages: {{ blocked_summary.total_blocks }}

Raisons des Blocages:
{% for reason, count in blocked_summary.block_reasons.items() %}
  {{ reason }}: {{ count }} ({{ (count / blocked_summary.total_blocks * 100) | round(1) }}%)
{% endfor %}
{% else %}
Aucun blocage IP pendant la période.
{% endif %}

===============================================
Rapport généré par EZRAX IDS/IPS - © {{ current_year }}
===============================================""")
                
    def _start_scheduler(self):
        """Démarre le planificateur pour la génération périodique de rapports"""
        # Générer le premier rapport immédiatement
        schedule.every().day.at("00:00").do(self.generate_daily_report)
        
        # Générer un rapport toutes les X heures
        hours_interval = max(1, self.interval // 3600)
        schedule.every(hours_interval).hours.do(self.generate_report)
        
        # Démarrer le thread du planificateur
        self.scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            name="ReportScheduler"
        )
        self.scheduler_thread.daemon = True
        self.scheduler_thread.start()
        logger.info(f"Planificateur de rapports démarré (intervalle: {hours_interval} heures)")
        
    def _scheduler_loop(self):
        """Boucle du planificateur"""
        while not self.stop_event.is_set():
            schedule.run_pending()
            self.stop_event.wait(1)  # Vérifier toutes les secondes
            
    def generate_report(self, timeframe=None, output_formats=None):
        """
        Génère un rapport
        
        Args:
            timeframe: Période de temps en secondes (par défaut: 24 heures)
            output_formats: Liste des formats de sortie (par défaut: html, json)
            
        Returns:
            Liste des chemins des fichiers générés
        """
        if not self.enabled:
            logger.warning("Générateur de rapports désactivé")
            return []
            
        if timeframe is None:
            timeframe = 24 * 3600  # 24 heures par défaut
            
        if output_formats is None:
            output_formats = ["html", "json"]
            
        # Préparation des données
        current_time = time.time()
        generated_at = datetime.fromtimestamp(current_time).strftime("%Y-%m-%d %H:%M:%S")
        report_period = f"dernières {timeframe // 3600} heures"
        
        # Obtenir les données
        attack_summary = self.log_manager.get_attack_summary(timeframe)
        blocked_summary = self.log_manager.get_blocked_ips_summary()
        agent_stats = self.log_manager.get_agent_stats()
        
        # Configurer Jinja2
        self.jinja_env.filters["timestamp_to_date"] = lambda ts: datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        self.jinja_env.filters["seconds_to_duration"] = lambda s: f"{s // 3600}h {(s % 3600) // 60}m {s % 60}s"
        self.jinja_env.filters["tojson"] = lambda obj: json.dumps(obj)
        
        # Contexte du modèle
        context = {
            "agent_id": self.agent_id,
            "agent_hostname": self.agent_hostname,
            "report_period": report_period,
            "generated_at": generated_at,
            "generated_at_timestamp": current_time,
            "attack_summary": attack_summary,
            "blocked_summary": blocked_summary,
            "agent_stats": agent_stats,
            "current_year": datetime.now().year
        }
        
        # Générer les rapports dans les formats demandés
        output_files = []
        
        for output_format in output_formats:
            try:
                output_file = self._generate_report_file(context, output_format)
                if output_file:
                    output_files.append(output_file)
            except Exception as e:
                logger.error(f"Erreur lors de la génération du rapport {output_format}: {e}")
                
        return output_files
        
    def _generate_report_file(self, context, output_format):
        """
        Génère un fichier de rapport dans un format spécifique
        
        Args:
            context: Contexte du modèle
            output_format: Format de sortie
            
        Returns:
            Chemin du fichier généré
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ezrax_report_{timestamp}.{output_format}"
        output_path = os.path.join(self.output_dir, filename)
        
        try:
            if output_format in ["html", "json", "txt"]:
                # Charger le modèle
                template = self.jinja_env.get_template(f"report_template.{output_format}")
                
                # Rendre le modèle
                output = template.render(**context)
                
                # Écrire le fichier
                with open(output_path, "w") as f:
                    f.write(output)
                    
                logger.info(f"Rapport généré: {output_path}")
                return output_path
            else:
                logger.error(f"Format de rapport non supporté: {output_format}")
                return None
        except Exception as e:
            logger.error(f"Erreur lors de la génération du rapport {output_format}: {e}")
            return None
            
    def generate_daily_report(self):
        """Génère un rapport quotidien"""
        # Générer un rapport pour les dernières 24 heures
        return self.generate_report(
            timeframe=24 * 3600,
            output_formats=["html", "json", "txt"]
        )
        
    def generate_weekly_report(self):
        """Génère un rapport hebdomadaire"""
        # Générer un rapport pour les 7 derniers jours
        return self.generate_report(
            timeframe=7 * 24 * 3600,
            output_formats=["html", "json", "txt"]
        )
        
    def shutdown(self):
        """Arrête proprement le générateur de rapports"""
        if self.enabled:
            logger.info("Arrêt du générateur de rapports")
            self.stop_event.set()
            
            if self.scheduler_thread and self.scheduler_thread.is_alive():
                self.scheduler_thread.join(timeout=2.0)
