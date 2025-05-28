#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interface graphique Tkinter pour le serveur central EZRAX
"""

import os
import sys
import time
import json
import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import ttkthemes
from typing import Dict, List, Any, Optional
from datetime import datetime

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("ezrax_server.log")
    ]
)
logger = logging.getLogger(__name__)

# Importation des modules du serveur
from server_api import EzraxServerAPI
from db_manager import ServerDatabaseManager

class EzraxServerGUI:
    """
    Interface graphique pour le serveur central EZRAX
    """
    
    def __init__(self, root):
        """
        Initialisation de l'interface graphique
        
        Args:
            root: Fenêtre racine Tkinter
        """
        self.root = root
        self.root.title("EZRAX IDS/IPS - Serveur Central")
        self.root.geometry("1200x800")
        
        # Style Tkinter
        self.style = ttkthemes.ThemedStyle(self.root)
        self.style.set_theme("arc")  # Thème moderne
        
        # Variables
        self.selected_agent = tk.StringVar()
        self.filter_timeframe = tk.StringVar(value="24h")
        self.filter_attack_type = tk.StringVar(value="Tous")
        
        # Composants du serveur
        self.db_manager = ServerDatabaseManager()
        self.server_api = EzraxServerAPI(self.db_manager)
        
        # État
        self.agents = {}
        self.selected_agent_data = None
        self.running = True
        
        # Thread de mise à jour
        self.update_thread = threading.Thread(target=self._update_loop)
        self.update_thread.daemon = True
        
        # Créer l'interface
        self._create_gui()
        
        # Démarrer l'API et le thread de mise à jour
        self._start_server()
        
    def _create_gui(self):
        """Crée l'interface graphique"""
        # Panneau principal
        main_pane = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Panneau gauche (liste des agents et tableau de bord)
        left_frame = ttk.Frame(main_pane)
        
        # Panneau des agents
        agents_frame = ttk.LabelFrame(left_frame, text="Agents")
        agents_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Liste des agents
        self.agents_treeview = ttk.Treeview(
            agents_frame,
            columns=("hostname", "status", "ip", "last_seen"),
            show="headings"
        )
        self.agents_treeview.heading("hostname", text="Hostname")
        self.agents_treeview.heading("status", text="Statut")
        self.agents_treeview.heading("ip", text="IP")
        self.agents_treeview.heading("last_seen", text="Dernière activité")
        
        self.agents_treeview.column("hostname", width=150)
        self.agents_treeview.column("status", width=80)
        self.agents_treeview.column("ip", width=120)
        self.agents_treeview.column("last_seen", width=150)
        
        self.agents_treeview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.agents_treeview.bind("<<TreeviewSelect>>", self._on_agent_selected)
        
        # Boutons d'action pour les agents
        agents_buttons_frame = ttk.Frame(agents_frame)
        agents_buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            agents_buttons_frame,
            text="Rafraîchir",
            command=self._refresh_agents
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            agents_buttons_frame,
            text="Détails",
            command=self._show_agent_details
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            agents_buttons_frame,
            text="Commandes",
            command=self._show_agent_commands
        ).pack(side=tk.LEFT, padx=5)
        
        # Tableau de bord global
        dashboard_frame = ttk.LabelFrame(left_frame, text="Tableau de Bord Global")
        dashboard_frame.pack(fill=tk.BOTH, padx=5, pady=5)
        
        # Statistiques globales
        stats_frame = ttk.Frame(dashboard_frame)
        stats_frame.pack(fill=tk.X, expand=True, padx=5, pady=5)
        
        # Nombre d'agents
        ttk.Label(stats_frame, text="Agents:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.agents_count_label = ttk.Label(stats_frame, text="0")
        self.agents_count_label.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Agents actifs
        ttk.Label(stats_frame, text="Agents actifs:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.active_agents_label = ttk.Label(stats_frame, text="0")
        self.active_agents_label.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Total des attaques
        ttk.Label(stats_frame, text="Attaques détectées:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.attacks_count_label = ttk.Label(stats_frame, text="0")
        self.attacks_count_label.grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        # IPs bloquées
        ttk.Label(stats_frame, text="IPs bloquées:").grid(row=1, column=2, sticky=tk.W, padx=5, pady=2)
        self.blocked_ips_label = ttk.Label(stats_frame, text="0")
        self.blocked_ips_label.grid(row=1, column=3, sticky=tk.W, padx=5, pady=2)
        
        # Séparateur
        ttk.Separator(dashboard_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=5, pady=5)
        
        # Statut du serveur
        status_frame = ttk.Frame(dashboard_frame)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(status_frame, text="Statut du serveur:").pack(side=tk.LEFT, padx=5)
        self.server_status_label = ttk.Label(status_frame, text="En cours d'initialisation...")
        self.server_status_label.pack(side=tk.LEFT, padx=5)
        
        # Panneau droit (onglets)
        right_frame = ttk.Frame(main_pane)
        
        # Notebook pour les onglets
        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Onglet des attaques
        self.attacks_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.attacks_tab, text="Attaques")
        
        # Filtres pour les attaques
        filters_frame = ttk.Frame(self.attacks_tab)
        filters_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filters_frame, text="Période:").pack(side=tk.LEFT, padx=5)
        ttk.Combobox(
            filters_frame,
            textvariable=self.filter_timeframe,
            values=["1h", "6h", "12h", "24h", "7j", "30j"],
            width=5
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filters_frame, text="Type:").pack(side=tk.LEFT, padx=5)
        ttk.Combobox(
            filters_frame,
            textvariable=self.filter_attack_type,
            values=["Tous", "SYN_FLOOD", "UDP_FLOOD", "PORT_SCAN", "PING_FLOOD"],
            width=10
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            filters_frame,
            text="Appliquer",
            command=self._refresh_attacks
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            filters_frame,
            text="Exporter",
            command=self._export_attacks
        ).pack(side=tk.LEFT, padx=5)
        
        # Liste des attaques
        self.attacks_treeview = ttk.Treeview(
            self.attacks_tab,
            columns=("timestamp", "attack_type", "source_ip", "agent", "details"),
            show="headings"
        )
        self.attacks_treeview.heading("timestamp", text="Horodatage")
        self.attacks_treeview.heading("attack_type", text="Type d'attaque")
        self.attacks_treeview.heading("source_ip", text="IP Source")
        self.attacks_treeview.heading("agent", text="Agent")
        self.attacks_treeview.heading("details", text="Détails")
        
        self.attacks_treeview.column("timestamp", width=150)
        self.attacks_treeview.column("attack_type", width=100)
        self.attacks_treeview.column("source_ip", width=120)
        self.attacks_treeview.column("agent", width=150)
        self.attacks_treeview.column("details", width=300)
        
        # Scrollbar pour la liste des attaques
        attacks_scrollbar = ttk.Scrollbar(self.attacks_tab, orient=tk.VERTICAL, command=self.attacks_treeview.yview)
        self.attacks_treeview.configure(yscrollcommand=attacks_scrollbar.set)
        
        attacks_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.attacks_treeview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Onglet des IPs bloquées
        self.blocked_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.blocked_tab, text="IPs Bloquées")
        
        # Liste des IPs bloquées
        self.blocked_treeview = ttk.Treeview(
            self.blocked_tab,
            columns=("ip", "reason", "timestamp", "duration", "agent"),
            show="headings"
        )
        self.blocked_treeview.heading("ip", text="Adresse IP")
        self.blocked_treeview.heading("reason", text="Raison")
        self.blocked_treeview.heading("timestamp", text="Début")
        self.blocked_treeview.heading("duration", text="Durée")
        self.blocked_treeview.heading("agent", text="Agent")
        
        self.blocked_treeview.column("ip", width=120)
        self.blocked_treeview.column("reason", width=150)
        self.blocked_treeview.column("timestamp", width=150)
        self.blocked_treeview.column("duration", width=100)
        self.blocked_treeview.column("agent", width=150)
        
        # Scrollbar pour la liste des IPs bloquées
        blocked_scrollbar = ttk.Scrollbar(self.blocked_tab, orient=tk.VERTICAL, command=self.blocked_treeview.yview)
        self.blocked_treeview.configure(yscrollcommand=blocked_scrollbar.set)
        
        blocked_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.blocked_treeview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Boutons d'action pour les IPs bloquées
        blocked_buttons_frame = ttk.Frame(self.blocked_tab)
        blocked_buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            blocked_buttons_frame,
            text="Rafraîchir",
            command=self._refresh_blocked_ips
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            blocked_buttons_frame,
            text="Débloquer",
            command=self._unblock_ip
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            blocked_buttons_frame,
            text="Ajouter à la liste blanche",
            command=self._add_to_whitelist
        ).pack(side=tk.LEFT, padx=5)
        
        # Onglet de la liste blanche
        self.whitelist_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.whitelist_tab, text="Liste Blanche")
        
        # Liste des IPs dans la liste blanche
        self.whitelist_treeview = ttk.Treeview(
            self.whitelist_tab,
            columns=("ip", "added_at", "source", "description"),
            show="headings"
        )
        self.whitelist_treeview.heading("ip", text="Adresse IP")
        self.whitelist_treeview.heading("added_at", text="Ajouté le")
        self.whitelist_treeview.heading("source", text="Source")
        self.whitelist_treeview.heading("description", text="Description")
        
        self.whitelist_treeview.column("ip", width=120)
        self.whitelist_treeview.column("added_at", width=150)
        self.whitelist_treeview.column("source", width=100)
        self.whitelist_treeview.column("description", width=300)
        
        # Scrollbar pour la liste blanche
        whitelist_scrollbar = ttk.Scrollbar(self.whitelist_tab, orient=tk.VERTICAL, command=self.whitelist_treeview.yview)
        self.whitelist_treeview.configure(yscrollcommand=whitelist_scrollbar.set)
        
        whitelist_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.whitelist_treeview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Boutons d'action pour la liste blanche
        whitelist_buttons_frame = ttk.Frame(self.whitelist_tab)
        whitelist_buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            whitelist_buttons_frame,
            text="Rafraîchir",
            command=self._refresh_whitelist
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            whitelist_buttons_frame,
            text="Ajouter",
            command=self._add_whitelist_entry
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            whitelist_buttons_frame,
            text="Supprimer",
            command=self._remove_whitelist_entry
        ).pack(side=tk.LEFT, padx=5)
        
        # Onglet de logs
        self.logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_tab, text="Logs")
        
        # Zone de texte pour les logs
        self.logs_text = scrolledtext.ScrolledText(self.logs_tab, wrap=tk.WORD)
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configurer le gestionnaire de logs pour afficher dans l'interface
        log_handler = LogTextHandler(self.logs_text)
        log_handler.setLevel(logging.INFO)
        log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        log_handler.setFormatter(log_formatter)
        logger.addHandler(log_handler)
        
        # Boutons de contrôle pour les logs
        logs_buttons_frame = ttk.Frame(self.logs_tab)
        logs_buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            logs_buttons_frame,
            text="Effacer",
            command=lambda: self.logs_text.delete(1.0, tk.END)
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            logs_buttons_frame,
            text="Enregistrer",
            command=self._save_logs
        ).pack(side=tk.LEFT, padx=5)
        
        # Ajouter les panneaux au panneau principal
        main_pane.add(left_frame, weight=1)
        main_pane.add(right_frame, weight=2)
        
        # Barre d'état
        self.status_bar = ttk.Label(
            self.root,
            text="Serveur EZRAX démarré",
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def _start_server(self):
        """Démarre le serveur API et le thread de mise à jour"""
        try:
            # Démarrer le serveur API dans un thread
            self.server_thread = threading.Thread(target=self.server_api.start)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            # Démarrer le thread de mise à jour
            self.update_thread.start()
            
            # Mettre à jour le statut
            self.server_status_label.config(text="En cours d'exécution", foreground="green")
            self.status_bar.config(text=f"Serveur EZRAX démarré sur {self.server_api.host}:{self.server_api.port}")
            
            logger.info(f"Serveur EZRAX démarré sur {self.server_api.host}:{self.server_api.port}")
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du serveur: {e}")
            self.server_status_label.config(text="Erreur", foreground="red")
            messagebox.showerror("Erreur", f"Erreur lors du démarrage du serveur: {e}")
            
    def _update_loop(self):
        """Boucle de mise à jour de l'interface"""
        while self.running:
            try:
                # Mettre à jour les données
                self._refresh_agents()
                self._refresh_global_stats()
                
                # Mettre à jour les onglets si nécessaire
                if self.notebook.index(self.notebook.select()) == 0:  # Onglet des attaques
                    self._refresh_attacks()
                elif self.notebook.index(self.notebook.select()) == 1:  # Onglet des IPs bloquées
                    self._refresh_blocked_ips()
                elif self.notebook.index(self.notebook.select()) == 2:  # Onglet de la liste blanche
                    self._refresh_whitelist()
                    
                # Pause
                time.sleep(5)  # Mise à jour toutes les 5 secondes
                
            except Exception as e:
                logger.error(f"Erreur dans la boucle de mise à jour: {e}")
                time.sleep(10)  # Pause plus longue en cas d'erreur
                
    def _refresh_agents(self):
        """Rafraîchit la liste des agents"""
        try:
            # Récupérer les agents
            agents = self.db_manager.get_agents()
            
            # Effacer la liste
            for item in self.agents_treeview.get_children():
                self.agents_treeview.delete(item)
                
            # Mémoriser les agents
            self.agents = {agent["agent_id"]: agent for agent in agents}
            
            # Ajouter les agents à la liste
            for agent in agents:
                status = "En ligne" if agent["status"] == "online" else "Hors ligne"
                status_color = "green" if status == "En ligne" else "red"
                
                last_seen = datetime.fromtimestamp(agent["last_seen"]).strftime("%Y-%m-%d %H:%M:%S") if agent["last_seen"] else "Jamais"
                
                self.agents_treeview.insert(
                    "",
                    tk.END,
                    values=(
                        agent["hostname"],
                        status,
                        agent["ip_address"],
                        last_seen
                    ),
                    tags=(agent["agent_id"], status_color)
                )
                
            # Configurer les couleurs
            self.agents_treeview.tag_configure("green", foreground="green")
            self.agents_treeview.tag_configure("red", foreground="red")
            
        except Exception as e:
            logger.error(f"Erreur lors du rafraîchissement des agents: {e}")
            
    def _refresh_global_stats(self):
        """Rafraîchit les statistiques globales"""
        try:
            # Récupérer les statistiques
            stats = self.db_manager.get_global_stats()
            
            # Mettre à jour les labels
            self.agents_count_label.config(text=str(stats["total_agents"]))
            self.active_agents_label.config(text=str(stats["active_agents"]))
            self.attacks_count_label.config(text=str(stats["total_attacks"]))
            self.blocked_ips_label.config(text=str(stats["blocked_ips"]))
            
        except Exception as e:
            logger.error(f"Erreur lors du rafraîchissement des statistiques: {e}")
            
    def _refresh_attacks(self):
        """Rafraîchit la liste des attaques"""
        try:
            # Convertir la période en secondes
            timeframe = self.filter_timeframe.get()
            seconds = 3600  # 1 heure par défaut
            
            if timeframe.endswith("h"):
                seconds = int(timeframe[:-1]) * 3600
            elif timeframe.endswith("j"):
                seconds = int(timeframe[:-1]) * 86400
                
            # Filtrer par type d'attaque
            attack_type = None if self.filter_attack_type.get() == "Tous" else self.filter_attack_type.get()
            
            # Récupérer les attaques
            attacks = self.db_manager.get_attack_logs(
                limit=1000,
                since=time.time() - seconds,
                attack_type=attack_type,
                agent_id=self.selected_agent.get() if self.selected_agent.get() else None
            )
            
            # Effacer la liste
            for item in self.attacks_treeview.get_children():
                self.attacks_treeview.delete(item)
                
            # Ajouter les attaques à la liste
            for attack in attacks:
                timestamp = datetime.fromtimestamp(attack["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                
                # Récupérer le nom de l'agent
                agent_name = "Inconnu"
                if attack["agent_id"] in self.agents:
                    agent_name = self.agents[attack["agent_id"]]["hostname"]
                    
                # Formater les détails
                details = attack["details"]
                if isinstance(details, str):
                    try:
                        details = json.loads(details)
                    except:
                        pass
                        
                details_str = ", ".join(f"{k}: {v}" for k, v in details.items() if k in ["packet_count", "distinct_ports", "is_scan", "distinct_icmp_ids"])
                
                self.attacks_treeview.insert(
                    "",
                    tk.END,
                    values=(
                        timestamp,
                        attack["attack_type"],
                        attack["source_ip"],
                        agent_name,
                        details_str
                    )
                )
                
        except Exception as e:
            logger.error(f"Erreur lors du rafraîchissement des attaques: {e}")
            
    def _refresh_blocked_ips(self):
        """Rafraîchit la liste des IPs bloquées"""
        try:
            # Récupérer les IPs bloquées
            blocked_ips = self.db_manager.get_blocked_ips(
                include_expired=False,
                agent_id=self.selected_agent.get() if self.selected_agent.get() else None
            )
            
            # Effacer la liste
            for item in self.blocked_treeview.get_children():
                self.blocked_treeview.delete(item)
                
            # Ajouter les IPs bloquées à la liste
            for block in blocked_ips:
                timestamp = datetime.fromtimestamp(block["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                
                # Formater la durée
                duration_seconds = block["duration"]
                duration = f"{duration_seconds // 3600}h {(duration_seconds % 3600) // 60}m"
                
                # Récupérer le nom de l'agent
                agent_name = "Inconnu"
                if block["agent_id"] in self.agents:
                    agent_name = self.agents[block["agent_id"]]["hostname"]
                    
                self.blocked_treeview.insert(
                    "",
                    tk.END,
                    values=(
                        block["ip"],
                        block["reason"],
                        timestamp,
                        duration,
                        agent_name
                    )
                )
                
        except Exception as e:
            logger.error(f"Erreur lors du rafraîchissement des IPs bloquées: {e}")
            
    def _refresh_whitelist(self):
        """Rafraîchit la liste blanche"""
        try:
            # Récupérer la liste blanche
            whitelist = self.db_manager.get_whitelist()
            
            # Effacer la liste
            for item in self.whitelist_treeview.get_children():
                self.whitelist_treeview.delete(item)
                
            # Ajouter les entrées à la liste
            for entry in whitelist:
                added_at = datetime.fromtimestamp(entry["added_at"]).strftime("%Y-%m-%d %H:%M:%S")
                
                self.whitelist_treeview.insert(
                    "",
                    tk.END,
                    values=(
                        entry["ip"],
                        added_at,
                        entry["source"],
                        entry["description"]
                    )
                )
                
        except Exception as e:
            logger.error(f"Erreur lors du rafraîchissement de la liste blanche: {e}")
            
    def _on_agent_selected(self, event):
        """
        Gère la sélection d'un agent dans la liste
        
        Args:
            event: Événement de sélection
        """
        try:
            # Récupérer l'élément sélectionné
            selected_items = self.agents_treeview.selection()
            if not selected_items:
                return
                
            # Récupérer l'agent_id de l'élément sélectionné
            agent_id = self.agents_treeview.item(selected_items[0], "tags")[0]
            self.selected_agent.set(agent_id)
            
            # Récupérer les données de l'agent
            if agent_id in self.agents:
                self.selected_agent_data = self.agents[agent_id]
                
            # Rafraîchir les données
            self._refresh_attacks()
            self._refresh_blocked_ips()
            
        except Exception as e:
            logger.error(f"Erreur lors de la sélection d'un agent: {e}")
            
    def _show_agent_details(self):
        """Affiche les détails d'un agent sélectionné"""
        if not self.selected_agent_data:
            messagebox.showinfo("Information", "Veuillez sélectionner un agent")
            return
            
        # Créer une fenêtre de dialogue
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Détails de l'agent: {self.selected_agent_data['hostname']}")
        dialog.geometry("600x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Cadre pour les informations
        info_frame = ttk.Frame(dialog, padding=10)
        info_frame.pack(fill=tk.BOTH, expand=True)
        
        # Afficher les informations de l'agent
        row = 0
        for key, value in self.selected_agent_data.items():
            if key in ["os_info", "features"]:
                # Formater les dictionnaires
                if isinstance(value, dict):
                    formatted_value = json.dumps(value, indent=2)
                    
                    ttk.Label(info_frame, text=f"{key}:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
                    
                    text_widget = scrolledtext.ScrolledText(info_frame, height=10, width=60, wrap=tk.WORD)
                    text_widget.insert(tk.END, formatted_value)
                    text_widget.config(state=tk.DISABLED)
                    text_widget.grid(row=row, column=1, sticky=tk.W, padx=5, pady=2)
                    
                    row += 1
            elif key != "agent_id":
                # Formater les timestamps
                if key in ["last_seen", "registered_at"] and value:
                    value = datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
                    
                ttk.Label(info_frame, text=f"{key}:").grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
                ttk.Label(info_frame, text=str(value)).grid(row=row, column=1, sticky=tk.W, padx=5, pady=2)
                
                row += 1
                
        # Bouton de fermeture
        ttk.Button(
            dialog,
            text="Fermer",
            command=dialog.destroy
        ).pack(pady=10)
        
    def _show_agent_commands(self):
        """Affiche les commandes disponibles pour un agent sélectionné"""
        if not self.selected_agent_data:
            messagebox.showinfo("Information", "Veuillez sélectionner un agent")
            return
            
        # Créer une fenêtre de dialogue
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Commandes pour l'agent: {self.selected_agent_data['hostname']}")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Cadre pour les commandes
        commands_frame = ttk.Frame(dialog, padding=10)
        commands_frame.pack(fill=tk.BOTH, expand=True)
        
        # Variables
        command_type = tk.StringVar(value="restart")
        ip_to_block = tk.StringVar()
        block_reason = tk.StringVar(value="MANUAL_BLOCK")
        block_duration = tk.IntVar(value=3600)
        
        # Sélection de la commande
        ttk.Label(commands_frame, text="Type de commande:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=10)
        ttk.Combobox(
            commands_frame,
            textvariable=command_type,
            values=["restart", "block_ip", "unblock_ip", "generate_report"],
            state="readonly",
            width=15
        ).grid(row=0, column=1, sticky=tk.W, padx=5, pady=10)
        
        # Formulaire pour le blocage d'IP
        ip_frame = ttk.LabelFrame(commands_frame, text="Blocage d'IP")
        ip_frame.grid(row=1, column=0, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=5)
        
        ttk.Label(ip_frame, text="Adresse IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(ip_frame, textvariable=ip_to_block, width=20).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(ip_frame, text="Raison:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(ip_frame, textvariable=block_reason, width=20).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(ip_frame, text="Durée (secondes):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(ip_frame, textvariable=block_duration, width=10).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Bouton d'envoi
        ttk.Button(
            dialog,
            text="Envoyer la commande",
            command=lambda: self._send_command(
                command_type.get(),
                {
                    "ip": ip_to_block.get(),
                    "reason": block_reason.get(),
                    "duration": block_duration.get()
                }
            )
        ).pack(pady=10)
        
        # Bouton de fermeture
        ttk.Button(
            dialog,
            text="Fermer",
            command=dialog.destroy
        ).pack(pady=5)
        
    def _send_command(self, command_type, command_data):
        """
        Envoie une commande à un agent
        
        Args:
            command_type: Type de commande
            command_data: Données de la commande
        """
        if not self.selected_agent.get():
            messagebox.showinfo("Information", "Veuillez sélectionner un agent")
            return
            
        try:
            # Envoyer la commande
            self.db_manager.add_command(
                agent_id=self.selected_agent.get(),
                command_type=command_type,
                command_data=command_data
            )
            
            messagebox.showinfo("Succès", f"Commande {command_type} envoyée à l'agent")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de la commande: {e}")
            messagebox.showerror("Erreur", f"Erreur lors de l'envoi de la commande: {e}")
            
    def _export_attacks(self):
        """Exporte les attaques dans un fichier CSV"""
        try:
            # Demander le nom du fichier
            filename = tk.filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("Fichiers CSV", "*.csv"), ("Tous les fichiers", "*.*")]
            )
            
            if not filename:
                return
                
            # Convertir la période en secondes
            timeframe = self.filter_timeframe.get()
            seconds = 3600  # 1 heure par défaut
            
            if timeframe.endswith("h"):
                seconds = int(timeframe[:-1]) * 3600
            elif timeframe.endswith("j"):
                seconds = int(timeframe[:-1]) * 86400
                
            # Filtrer par type d'attaque
            attack_type = None if self.filter_attack_type.get() == "Tous" else self.filter_attack_type.get()
            
            # Récupérer les attaques
            attacks = self.db_manager.get_attack_logs(
                limit=10000,
                since=time.time() - seconds,
                attack_type=attack_type,
                agent_id=self.selected_agent.get() if self.selected_agent.get() else None
            )
            
            # Exporter en CSV
            import csv
            with open(filename, "w", newline="") as f:
                writer = csv.writer(f)
                
                # Écrire l'en-tête
                writer.writerow([
                    "ID", "Horodatage", "Type d'attaque", "IP Source", "Agent", "Détails"
                ])
                
                # Écrire les données
                for attack in attacks:
                    timestamp = datetime.fromtimestamp(attack["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Récupérer le nom de l'agent
                    agent_name = "Inconnu"
                    if attack["agent_id"] in self.agents:
                        agent_name = self.agents[attack["agent_id"]]["hostname"]
                        
                    # Formater les détails
                    details = attack["details"]
                    if isinstance(details, str):
                        try:
                            details = json.loads(details)
                        except:
                            pass
                            
                    details_str = json.dumps(details)
                    
                    writer.writerow([
                        attack["id"],
                        timestamp,
                        attack["attack_type"],
                        attack["source_ip"],
                        agent_name,
                        details_str
                    ])
                    
            messagebox.showinfo("Succès", f"Exportation réussie: {len(attacks)} attaques exportées dans {filename}")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exportation des attaques: {e}")
            messagebox.showerror("Erreur", f"Erreur lors de l'exportation des attaques: {e}")
            
    def _unblock_ip(self):
        """Débloque une IP sélectionnée"""
        try:
            # Récupérer l'élément sélectionné
            selected_items = self.blocked_treeview.selection()
            if not selected_items:
                messagebox.showinfo("Information", "Veuillez sélectionner une IP à débloquer")
                return
                
            # Récupérer l'IP de l'élément sélectionné
            ip = self.blocked_treeview.item(selected_items[0], "values")[0]
            
            # Demander confirmation
            if not messagebox.askyesno("Confirmation", f"Voulez-vous vraiment débloquer l'IP {ip} ?"):
                return
                
            # Débloquer l'IP
            if self.selected_agent.get():
                # Envoyer une commande de déblocage à l'agent
                self.db_manager.add_command(
                    agent_id=self.selected_agent.get(),
                    command_type="unblock_ip",
                    command_data={"ip": ip}
                )
                
                messagebox.showinfo("Succès", f"Commande de déblocage de l'IP {ip} envoyée à l'agent")
            else:
                messagebox.showinfo("Information", "Veuillez sélectionner un agent pour débloquer l'IP")
                
        except Exception as e:
            logger.error(f"Erreur lors du déblocage de l'IP: {e}")
            messagebox.showerror("Erreur", f"Erreur lors du déblocage de l'IP: {e}")
            
    def _add_to_whitelist(self):
        """Ajoute une IP à la liste blanche"""
        try:
            # Récupérer l'élément sélectionné
            selected_items = self.blocked_treeview.selection()
            if not selected_items:
                messagebox.showinfo("Information", "Veuillez sélectionner une IP à ajouter à la liste blanche")
                return
                
            # Récupérer l'IP de l'élément sélectionné
            ip = self.blocked_treeview.item(selected_items[0], "values")[0]
            
            # Demander confirmation
            if not messagebox.askyesno("Confirmation", f"Voulez-vous vraiment ajouter l'IP {ip} à la liste blanche ?"):
                return
                
            # Ajouter l'IP à la liste blanche
            self.db_manager.add_whitelist_entry(
                ip=ip,
                source="manual",
                description="Ajouté manuellement depuis l'interface"
            )
            
            # Rafraîchir la liste blanche
            self._refresh_whitelist()
            
            messagebox.showinfo("Succès", f"IP {ip} ajoutée à la liste blanche")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout à la liste blanche: {e}")
            messagebox.showerror("Erreur", f"Erreur lors de l'ajout à la liste blanche: {e}")
            
    def _add_whitelist_entry(self):
        """Ajoute une entrée à la liste blanche"""
        # Créer une fenêtre de dialogue
        dialog = tk.Toplevel(self.root)
        dialog.title("Ajouter à la liste blanche")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Variables
        ip = tk.StringVar()
        description = tk.StringVar()
        
        # Formulaire
        form_frame = ttk.Frame(dialog, padding=10)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(form_frame, text="Adresse IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(form_frame, textvariable=ip, width=20).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Description:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(form_frame, textvariable=description, width=30).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Bouton de validation
        ttk.Button(
            dialog,
            text="Ajouter",
            command=lambda: self._add_whitelist_entry_callback(ip.get(), description.get(), dialog)
        ).pack(pady=10)
        
        # Bouton d'annulation
        ttk.Button(
            dialog,
            text="Annuler",
            command=dialog.destroy
        ).pack(pady=5)
        
    def _add_whitelist_entry_callback(self, ip, description, dialog):
        """
        Callback pour l'ajout d'une entrée à la liste blanche
        
        Args:
            ip: Adresse IP
            description: Description
            dialog: Fenêtre de dialogue
        """
        try:
            # Vérifier l'IP
            if not ip:
                messagebox.showinfo("Information", "Veuillez saisir une adresse IP")
                return
                
            # Ajouter l'IP à la liste blanche
            self.db_manager.add_whitelist_entry(
                ip=ip,
                source="manual",
                description=description
            )
            
            # Fermer le dialogue
            dialog.destroy()
            
            # Rafraîchir la liste blanche
            self._refresh_whitelist()
            
            messagebox.showinfo("Succès", f"IP {ip} ajoutée à la liste blanche")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout à la liste blanche: {e}")
            messagebox.showerror("Erreur", f"Erreur lors de l'ajout à la liste blanche: {e}")
            
    def _remove_whitelist_entry(self):
        """Supprime une entrée de la liste blanche"""
        try:
            # Récupérer l'élément sélectionné
            selected_items = self.whitelist_treeview.selection()
            if not selected_items:
                messagebox.showinfo("Information", "Veuillez sélectionner une IP à supprimer de la liste blanche")
                return
                
            # Récupérer l'IP de l'élément sélectionné
            ip = self.whitelist_treeview.item(selected_items[0], "values")[0]
            
            # Demander confirmation
            if not messagebox.askyesno("Confirmation", f"Voulez-vous vraiment supprimer l'IP {ip} de la liste blanche ?"):
                return
                
            # Supprimer l'IP de la liste blanche
            self.db_manager.remove_whitelist_entry(ip)
            
            # Rafraîchir la liste blanche
            self._refresh_whitelist()
            
            messagebox.showinfo("Succès", f"IP {ip} supprimée de la liste blanche")
            
        except Exception as e:
            logger.error(f"Erreur lors de la suppression de la liste blanche: {e}")
            messagebox.showerror("Erreur", f"Erreur lors de la suppression de la liste blanche: {e}")
            
    def _save_logs(self):
        """Enregistre les logs dans un fichier"""
        try:
            # Demander le nom du fichier
            filename = tk.filedialog.asksaveasfilename(
                defaultextension=".log",
                filetypes=[("Fichiers log", "*.log"), ("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
            )
            
            if not filename:
                return
                
            # Enregistrer les logs
            with open(filename, "w") as f:
                f.write(self.logs_text.get(1.0, tk.END))
                
            messagebox.showinfo("Succès", f"Logs enregistrés dans {filename}")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement des logs: {e}")
            messagebox.showerror("Erreur", f"Erreur lors de l'enregistrement des logs: {e}")
            
    def on_closing(self):
        """Gère la fermeture de l'application"""
        if messagebox.askokcancel("Quitter", "Voulez-vous vraiment quitter ?"):
            # Arrêter le serveur API
            try:
                self.running = False
                self.server_api.stop()
            except:
                pass
                
            # Fermer la fenêtre
            self.root.destroy()
            
class LogTextHandler(logging.Handler):
    """
    Handler pour afficher les logs dans un widget Text
    """
    
    def __init__(self, text_widget):
        """
        Initialisation du handler
        
        Args:
            text_widget: Widget Text pour afficher les logs
        """
        super().__init__()
        self.text_widget = text_widget
        
    def emit(self, record):
        """
        Affiche un log dans le widget Text
        
        Args:
            record: Enregistrement de log
        """
        msg = self.format(record) + "\n"
        
        def _add_log():
            self.text_widget.configure(state=tk.NORMAL)
            self.text_widget.insert(tk.END, msg)
            self.text_widget.see(tk.END)
            self.text_widget.configure(state=tk.DISABLED)
            
        # Ajouter le log dans le thread principal
        self.text_widget.after(0, _add_log)
        
def main():
    """Point d'entrée principal"""
    # Créer la fenêtre principale
    root = tk.Tk()
    app = EzraxServerGUI(root)
    
    # Configurer la fermeture
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Démarrer la boucle principale
    root.mainloop()
    
if __name__ == "__main__":
    main()
