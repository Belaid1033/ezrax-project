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
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import ttkthemes
from typing import Dict, List, Any, Optional
from datetime import datetime
import hashlib
import secrets

logger = logging.getLogger(__name__)

class LoginDialog:
    """Dialogue de connexion administrateur"""
    
    def __init__(self, parent, db_manager):
        self.parent = parent
        self.db_manager = db_manager
        self.result = None
        
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Connexion Administrateur")
        self.dialog.geometry("400x300")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        
        self.dialog.geometry("+%d+%d" % (
            parent.winfo_rootx() + 50,
            parent.winfo_rooty() + 50
        ))
        
        self.setup_ui()
        
    def setup_ui(self):
        """Configure l'interface de connexion"""
        
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        
        title_label = ttk.Label(
            main_frame, 
            text="EZRAX Central Server", 
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=(0, 20))
        
        
        fields_frame = ttk.Frame(main_frame)
        fields_frame.pack(fill=tk.X, pady=(0, 20))
        
        
        ttk.Label(fields_frame, text="Nom d'utilisateur:").pack(anchor=tk.W)
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(fields_frame, textvariable=self.username_var, width=30)
        self.username_entry.pack(fill=tk.X, pady=(5, 10))
        
       
        ttk.Label(fields_frame, text="Mot de passe:").pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(fields_frame, textvariable=self.password_var, show="*", width=30)
        self.password_entry.pack(fill=tk.X, pady=(5, 10))
        
        
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X)
        
        ttk.Button(
            buttons_frame,
            text="Se connecter",
            command=self.login
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            buttons_frame,
            text="Annuler",
            command=self.cancel
        ).pack(side=tk.LEFT)
        
        
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var, foreground="red")
        self.status_label.pack(pady=(10, 0))
        
        
        info_frame = ttk.LabelFrame(main_frame, text="Information")
        info_frame.pack(fill=tk.X, pady=(20, 0))
        
        info_text = ("Si c'est votre première connexion, utilisez:\n"
                    "Nom d'utilisateur: admin\n"
                    "Le mot de passe se trouve dans les logs du serveur.")
        
        ttk.Label(info_frame, text=info_text, font=("Arial", 9)).pack(pady=10)
        
        
        self.username_entry.focus()
        
       
        self.dialog.bind('<Return>', lambda e: self.login())
        
    def login(self):
        """Tente de connecter l'utilisateur"""
        username = self.username_var.get().strip()
        password = self.password_var.get()
        
        if not username or not password:
            self.status_var.set("Veuillez saisir le nom d'utilisateur et le mot de passe")
            return
            
       
        try:
            session_id = self.db_manager.admin_manager.authenticate_admin(username, password)
            
            if session_id:
                self.result = {
                    'username': username,
                    'session_id': session_id
                }
                self.dialog.destroy()
            else:
                self.status_var.set("Nom d'utilisateur ou mot de passe incorrect")
                
        except Exception as e:
            logger.error(f"Erreur lors de l'authentification: {e}")
            self.status_var.set("Erreur lors de l'authentification")
            
    def cancel(self):
        """Annule la connexion"""
        self.result = None
        self.dialog.destroy()

class CreateAdminDialog:
    """Dialogue pour créer un nouvel administrateur"""
    
    def __init__(self, parent, db_manager):
        self.parent = parent
        self.db_manager = db_manager
        self.result = None
        
       
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Créer un Administrateur")
        self.dialog.geometry("400x350")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Centrer la fenêtre
        self.dialog.geometry("+%d+%d" % (
            parent.winfo_rootx() + 50,
            parent.winfo_rooty() + 50
        ))
        
        self.setup_ui()
        
    def setup_ui(self):
        """Configure l'interface de création d'admin"""
      
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
    
        title_label = ttk.Label(
            main_frame, 
            text="Créer un Administrateur", 
            font=("Arial", 14, "bold")
        )
        title_label.pack(pady=(0, 20))
        
      
        fields_frame = ttk.Frame(main_frame)
        fields_frame.pack(fill=tk.X, pady=(0, 20))
        
       
        ttk.Label(fields_frame, text="Nom d'utilisateur:").pack(anchor=tk.W)
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(fields_frame, textvariable=self.username_var, width=30)
        self.username_entry.pack(fill=tk.X, pady=(5, 10))
        
      
        ttk.Label(fields_frame, text="Email (optionnel):").pack(anchor=tk.W)
        self.email_var = tk.StringVar()
        self.email_entry = ttk.Entry(fields_frame, textvariable=self.email_var, width=30)
        self.email_entry.pack(fill=tk.X, pady=(5, 10))
        
    
        ttk.Label(fields_frame, text="Mot de passe:").pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(fields_frame, textvariable=self.password_var, show="*", width=30)
        self.password_entry.pack(fill=tk.X, pady=(5, 10))
        
        
        ttk.Label(fields_frame, text="Confirmer le mot de passe:").pack(anchor=tk.W)
        self.confirm_password_var = tk.StringVar()
        self.confirm_password_entry = ttk.Entry(fields_frame, textvariable=self.confirm_password_var, show="*", width=30)
        self.confirm_password_entry.pack(fill=tk.X, pady=(5, 10))
        
     
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X)
        
        ttk.Button(
            buttons_frame,
            text="Créer",
            command=self.create_admin
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(
            buttons_frame,
            text="Annuler",
            command=self.cancel
        ).pack(side=tk.LEFT)
        
        
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var, foreground="red")
        self.status_label.pack(pady=(10, 0))
        
       
        self.username_entry.focus()
        
    def create_admin(self):
        """Crée un nouvel administrateur"""
        username = self.username_var.get().strip()
        email = self.email_var.get().strip()
        password = self.password_var.get()
        confirm_password = self.confirm_password_var.get()
        
     
        if not username:
            self.status_var.set("Le nom d'utilisateur est requis")
            return
            
        if len(username) < 3:
            self.status_var.set("Le nom d'utilisateur doit faire au moins 3 caractères")
            return
            
        if not password:
            self.status_var.set("Le mot de passe est requis")
            return
            
        if len(password) < 6:
            self.status_var.set("Le mot de passe doit faire au moins 6 caractères")
            return
            
        if password != confirm_password:
            self.status_var.set("Les mots de passe ne correspondent pas")
            return
            
      
        try:
            success = self.db_manager.admin_manager.create_admin_user(username, password, email)
            
            if success:
                self.result = {'username': username}
                messagebox.showinfo("Succès", f"Administrateur '{username}' créé avec succès")
                self.dialog.destroy()
            else:
                self.status_var.set("Erreur lors de la création (utilisateur existant?)")
                
        except Exception as e:
            logger.error(f"Erreur lors de la création d'admin: {e}")
            self.status_var.set("Erreur lors de la création")
            
    def cancel(self):
        """Annule la création"""
        self.result = None
        self.dialog.destroy()

class EzraxServerGUI:
    """
    Interface graphique optimisée pour le serveur central EZRAX avec authentification
    """
    
    def __init__(self, root, db_manager, server_api=None):
        """
        Initialisation de l'interface graphique sécurisée
        """
        self.root = root
        self.db_manager = db_manager
        self.server_api = server_api
        
       
        self.root.title("EZRAX Central Server - Non connecté")
        self.root.geometry("1400x900")
        
        
        try:
            self.style = ttkthemes.ThemedStyle(self.root)
            self.style.set_theme("equilux")  # Thème sombre moderne
        except:
            self.style = ttk.Style()
            
        
        self.current_session = None
        self.authenticated = False
        
        
        self.selected_agent = tk.StringVar()
        self.filter_timeframe = tk.StringVar(value="24h")
        self.filter_attack_type = tk.StringVar(value="Tous")
        
        
        self.agents = {}
        self.selected_agent_data = None
        self.running = True
        self.auto_refresh = tk.BooleanVar(value=True)
        
       
        self.update_thread = None
        
       
        self._create_gui()
        
        
        self._show_login()
        
    def _create_gui(self):
        """Crée l'interface graphique complète"""
        
        self._create_menu()
        
        
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        
        self.login_frame = ttk.Frame(self.main_container)
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
       
        self.main_interface = ttk.Frame(self.main_container)
        
        self._create_main_interface()
        
    def _create_menu(self):
        """Crée le menu principal"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Fichier", menu=file_menu)
        file_menu.add_command(label="Se déconnecter", command=self._logout)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.on_closing)
        
        
        self.admin_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Administration", menu=self.admin_menu)
        self.admin_menu.add_command(label="Créer un administrateur", command=self._create_admin_user)
        self.admin_menu.add_command(label="Gérer les utilisateurs", command=self._manage_users)
        self.admin_menu.add_separator()
        self.admin_menu.add_command(label="Configuration serveur", command=self._server_config)
        
       
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Outils", menu=tools_menu)
        tools_menu.add_command(label="Exporter les données", command=self._export_data)
        tools_menu.add_command(label="Nettoyer la base de données", command=self._cleanup_database)
        tools_menu.add_separator()
        tools_menu.add_command(label="Métriques de performance", command=self._show_performance_metrics)
        
       
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Aide", menu=help_menu)
        help_menu.add_command(label="À propos", command=self._show_about)
        
        
        self._set_menu_state("disabled")
        
    def _set_menu_state(self, state):
        """Active/désactive les menus selon l'état de connexion"""
        try:
            self.admin_menu.entryconfig("Créer un administrateur", state=state)
            self.admin_menu.entryconfig("Gérer les utilisateurs", state=state)
            self.admin_menu.entryconfig("Configuration serveur", state=state)
        except:
            pass
            
    def _create_main_interface(self):
        """Crée l'interface principale (après authentification)"""
        
        status_frame = ttk.Frame(self.main_interface)
        status_frame.pack(fill=tk.X, padx=5, pady=5)
        
       
        session_frame = ttk.LabelFrame(status_frame, text="Session")
        session_frame.pack(side=tk.LEFT, padx=(0, 10))
        
        self.session_info_label = ttk.Label(session_frame, text="Non connecté")
        self.session_info_label.pack(padx=10, pady=5)
        
        
        controls_frame = ttk.LabelFrame(status_frame, text="Contrôles")
        controls_frame.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Checkbutton(
            controls_frame,
            text="Actualisation automatique",
            variable=self.auto_refresh
        ).pack(side=tk.LEFT, padx=5, pady=5)
        
        ttk.Button(
            controls_frame,
            text="Actualiser maintenant",
            command=self._refresh_all_data
        ).pack(side=tk.LEFT, padx=5, pady=5)
        
        
        server_status_frame = ttk.LabelFrame(status_frame, text="Serveur")
        server_status_frame.pack(side=tk.RIGHT)
        
        self.server_status_label = ttk.Label(server_status_frame, text="En cours d'exécution", foreground="green")
        self.server_status_label.pack(padx=10, pady=5)
        
        
        main_pane = ttk.PanedWindow(self.main_interface, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
       
        left_frame = ttk.Frame(main_pane)
        
       
        agents_frame = ttk.LabelFrame(left_frame, text="Agents Connectés")
        agents_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        
        self.agents_treeview = ttk.Treeview(
            agents_frame,
            columns=("hostname", "status", "ip", "health", "attacks", "last_seen"),
            show="headings"
        )
        self.agents_treeview.heading("hostname", text="Hostname")
        self.agents_treeview.heading("status", text="Statut")
        self.agents_treeview.heading("ip", text="IP")
        self.agents_treeview.heading("health", text="Santé")
        self.agents_treeview.heading("attacks", text="Attaques")
        self.agents_treeview.heading("last_seen", text="Dernière activité")
        
        self.agents_treeview.column("hostname", width=120)
        self.agents_treeview.column("status", width=80)
        self.agents_treeview.column("ip", width=100)
        self.agents_treeview.column("health", width=60)
        self.agents_treeview.column("attacks", width=80)
        self.agents_treeview.column("last_seen", width=130)
        
       
        agents_scrollbar = ttk.Scrollbar(agents_frame, orient=tk.VERTICAL, command=self.agents_treeview.yview)
        self.agents_treeview.configure(yscrollcommand=agents_scrollbar.set)
        
        agents_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.agents_treeview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.agents_treeview.bind("<<TreeviewSelect>>", self._on_agent_selected)
        
        
        agents_buttons_frame = ttk.Frame(agents_frame)
        agents_buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            agents_buttons_frame,
            text="Détails",
            command=self._show_agent_details
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            agents_buttons_frame,
            text="Envoyer commande",
            command=self._send_agent_command
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            agents_buttons_frame,
            text="Historique",
            command=self._show_agent_history
        ).pack(side=tk.LEFT, padx=5)
        
        
        dashboard_frame = ttk.LabelFrame(left_frame, text="Tableau de Bord Global")
        dashboard_frame.pack(fill=tk.BOTH, padx=5, pady=5)
        

        stats_frame = ttk.Frame(dashboard_frame)
        stats_frame.pack(fill=tk.X, expand=True, padx=5, pady=5)
        
        
        for i in range(4):
            stats_frame.columnconfigure(i, weight=1)
            

        self._create_stat_widgets(stats_frame)
        

        right_frame = ttk.Frame(main_pane)
        

        self.notebook = ttk.Notebook(right_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        

        self._create_attacks_tab()
        self._create_blocked_ips_tab()
        self._create_whitelist_tab()
        self._create_statistics_tab()
        self._create_logs_tab()
        

        main_pane.add(left_frame, weight=1)
        main_pane.add(right_frame, weight=2)
        
    def _create_stat_widgets(self, parent):
        """Crée les widgets de statistiques"""

        agents_stat_frame = ttk.LabelFrame(parent, text="Agents")
        agents_stat_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        self.agents_count_label = ttk.Label(agents_stat_frame, text="0", font=("Arial", 16, "bold"))
        self.agents_count_label.pack(pady=5)
        
        self.active_agents_label = ttk.Label(agents_stat_frame, text="0 actifs", font=("Arial", 10))
        self.active_agents_label.pack()
        

        attacks_stat_frame = ttk.LabelFrame(parent, text="Attaques")
        attacks_stat_frame.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        self.attacks_count_label = ttk.Label(attacks_stat_frame, text="0", font=("Arial", 16, "bold"))
        self.attacks_count_label.pack(pady=5)
        
        self.attacks_today_label = ttk.Label(attacks_stat_frame, text="0 aujourd'hui", font=("Arial", 10))
        self.attacks_today_label.pack()
        

        blocked_stat_frame = ttk.LabelFrame(parent, text="IPs Bloquées")
        blocked_stat_frame.grid(row=0, column=2, padx=5, pady=5, sticky="ew")
        
        self.blocked_ips_label = ttk.Label(blocked_stat_frame, text="0", font=("Arial", 16, "bold"))
        self.blocked_ips_label.pack(pady=5)
        
        self.blocked_today_label = ttk.Label(blocked_stat_frame, text="0 aujourd'hui", font=("Arial", 10))
        self.blocked_today_label.pack()
        

        perf_stat_frame = ttk.LabelFrame(parent, text="Performance")
        perf_stat_frame.grid(row=0, column=3, padx=5, pady=5, sticky="ew")
        
        self.response_time_label = ttk.Label(perf_stat_frame, text="0ms", font=("Arial", 16, "bold"))
        self.response_time_label.pack(pady=5)
        
        self.requests_label = ttk.Label(perf_stat_frame, text="0 requêtes", font=("Arial", 10))
        self.requests_label.pack()
        
    def _create_attacks_tab(self):
        """Crée l'onglet des attaques"""
        self.attacks_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.attacks_tab, text="Attaques")
        

        filters_frame = ttk.Frame(self.attacks_tab)
        filters_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filters_frame, text="Période:").pack(side=tk.LEFT, padx=5)
        ttk.Combobox(
            filters_frame,
            textvariable=self.filter_timeframe,
            values=["1h", "6h", "12h", "24h", "7j", "30j"],
            width=5,
            state="readonly"
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filters_frame, text="Type:").pack(side=tk.LEFT, padx=5)
        ttk.Combobox(
            filters_frame,
            textvariable=self.filter_attack_type,
            values=["Tous", "SYN_FLOOD", "UDP_FLOOD", "PORT_SCAN", "PING_FLOOD"],
            width=12,
            state="readonly"
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
        

        self.attacks_treeview = ttk.Treeview(
            self.attacks_tab,
            columns=("timestamp", "attack_type", "source_ip", "agent", "severity", "details"),
            show="headings"
        )
        self.attacks_treeview.heading("timestamp", text="Horodatage")
        self.attacks_treeview.heading("attack_type", text="Type")
        self.attacks_treeview.heading("source_ip", text="IP Source")
        self.attacks_treeview.heading("agent", text="Agent")
        self.attacks_treeview.heading("severity", text="Sévérité")
        self.attacks_treeview.heading("details", text="Détails")
        
        self.attacks_treeview.column("timestamp", width=140)
        self.attacks_treeview.column("attack_type", width=100)
        self.attacks_treeview.column("source_ip", width=120)
        self.attacks_treeview.column("agent", width=120)
        self.attacks_treeview.column("severity", width=80)
        self.attacks_treeview.column("details", width=300)
        

        attacks_scrollbar = ttk.Scrollbar(self.attacks_tab, orient=tk.VERTICAL, command=self.attacks_treeview.yview)
        self.attacks_treeview.configure(yscrollcommand=attacks_scrollbar.set)
        
        attacks_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.attacks_treeview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def _create_blocked_ips_tab(self):
        """Crée l'onglet des IPs bloquées"""
        self.blocked_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.blocked_tab, text="IPs Bloquées")
        

        controls_frame = ttk.Frame(self.blocked_tab)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.include_expired_var = tk.BooleanVar()
        ttk.Checkbutton(
            controls_frame,
            text="Inclure les expirées",
            variable=self.include_expired_var,
            command=self._refresh_blocked_ips
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            controls_frame,
            text="Rafraîchir",
            command=self._refresh_blocked_ips
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            controls_frame,
            text="Bloquer IP",
            command=self._manual_block_ip
        ).pack(side=tk.LEFT, padx=5)
        

        self.blocked_treeview = ttk.Treeview(
            self.blocked_tab,
            columns=("ip", "reason", "timestamp", "duration", "agent", "status"),
            show="headings"
        )
        self.blocked_treeview.heading("ip", text="Adresse IP")
        self.blocked_treeview.heading("reason", text="Raison")
        self.blocked_treeview.heading("timestamp", text="Début")
        self.blocked_treeview.heading("duration", text="Durée")
        self.blocked_treeview.heading("agent", text="Agent")
        self.blocked_treeview.heading("status", text="Statut")
        
        self.blocked_treeview.column("ip", width=120)
        self.blocked_treeview.column("reason", width=150)
        self.blocked_treeview.column("timestamp", width=140)
        self.blocked_treeview.column("duration", width=100)
        self.blocked_treeview.column("agent", width=120)
        self.blocked_treeview.column("status", width=80)
        

        blocked_scrollbar = ttk.Scrollbar(self.blocked_tab, orient=tk.VERTICAL, command=self.blocked_treeview.yview)
        self.blocked_treeview.configure(yscrollcommand=blocked_scrollbar.set)
        
        blocked_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.blocked_treeview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        

        self.blocked_context_menu = tk.Menu(self.root, tearoff=0)
        self.blocked_context_menu.add_command(label="Débloquer", command=self._unblock_selected_ip)
        self.blocked_context_menu.add_command(label="Ajouter à la liste blanche", command=self._add_ip_to_whitelist)
        
        self.blocked_treeview.bind("<Button-3>", self._show_blocked_context_menu)
        
    def _create_whitelist_tab(self):
        """Crée l'onglet de la liste blanche"""
        self.whitelist_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.whitelist_tab, text="Liste Blanche")
        

        controls_frame = ttk.Frame(self.whitelist_tab)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            controls_frame,
            text="Ajouter IP",
            command=self._add_whitelist_entry
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            controls_frame,
            text="Importer depuis fichier",
            command=self._import_whitelist
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            controls_frame,
            text="Exporter",
            command=self._export_whitelist
        ).pack(side=tk.LEFT, padx=5)
        

        self.whitelist_treeview = ttk.Treeview(
            self.whitelist_tab,
            columns=("ip", "added_at", "source", "added_by", "description"),
            show="headings"
        )
        self.whitelist_treeview.heading("ip", text="Adresse IP")
        self.whitelist_treeview.heading("added_at", text="Ajouté le")
        self.whitelist_treeview.heading("source", text="Source")
        self.whitelist_treeview.heading("added_by", text="Ajouté par")
        self.whitelist_treeview.heading("description", text="Description")
        
        self.whitelist_treeview.column("ip", width=120)
        self.whitelist_treeview.column("added_at", width=140)
        self.whitelist_treeview.column("source", width=100)
        self.whitelist_treeview.column("added_by", width=100)
        self.whitelist_treeview.column("description", width=300)
        

        whitelist_scrollbar = ttk.Scrollbar(self.whitelist_tab, orient=tk.VERTICAL, command=self.whitelist_treeview.yview)
        self.whitelist_treeview.configure(yscrollcommand=whitelist_scrollbar.set)
        
        whitelist_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.whitelist_treeview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        

        self.whitelist_context_menu = tk.Menu(self.root, tearoff=0)
        self.whitelist_context_menu.add_command(label="Modifier", command=self._edit_whitelist_entry)
        self.whitelist_context_menu.add_command(label="Supprimer", command=self._remove_whitelist_entry)
        
        self.whitelist_treeview.bind("<Button-3>", self._show_whitelist_context_menu)
        
    def _create_statistics_tab(self):
        """Crée l'onglet des statistiques"""
        self.statistics_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.statistics_tab, text="Statistiques")
        

        canvas = tk.Canvas(self.statistics_tab)
        scrollbar = ttk.Scrollbar(self.statistics_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        

        self._create_detailed_statistics(scrollable_frame)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def _create_detailed_statistics(self, parent):
        """Crée les statistiques détaillées"""

        attacks_stats_frame = ttk.LabelFrame(parent, text="Statistiques des Attaques")
        attacks_stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.attacks_stats_text = scrolledtext.ScrolledText(
            attacks_stats_frame, 
            height=10, 
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.attacks_stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        

        agents_stats_frame = ttk.LabelFrame(parent, text="Statistiques des Agents")
        agents_stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.agents_stats_text = scrolledtext.ScrolledText(
            agents_stats_frame, 
            height=8, 
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.agents_stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        

        server_perf_frame = ttk.LabelFrame(parent, text="Performance du Serveur")
        server_perf_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.server_perf_text = scrolledtext.ScrolledText(
            server_perf_frame, 
            height=8, 
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.server_perf_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def _create_logs_tab(self):
        """Crée l'onglet de logs"""
        self.logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_tab, text="Logs")
        

        logs_controls_frame = ttk.Frame(self.logs_tab)
        logs_controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.log_level_var = tk.StringVar(value="INFO")
        ttk.Label(logs_controls_frame, text="Niveau:").pack(side=tk.LEFT, padx=5)
        ttk.Combobox(
            logs_controls_frame,
            textvariable=self.log_level_var,
            values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            width=10,
            state="readonly"
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            logs_controls_frame,
            text="Rafraîchir",
            command=self._refresh_logs
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            logs_controls_frame,
            text="Effacer",
            command=self._clear_logs
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            logs_controls_frame,
            text="Enregistrer",
            command=self._save_logs
        ).pack(side=tk.LEFT, padx=5)
        

        self.logs_text = scrolledtext.ScrolledText(self.logs_tab, wrap=tk.WORD)
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        

        log_handler = LogTextHandler(self.logs_text)
        log_handler.setLevel(logging.INFO)
        log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        log_handler.setFormatter(log_formatter)
        logger.addHandler(log_handler)
        
    def _show_login(self):
        """Affiche l'écran de connexion"""

        self.main_interface.pack_forget()
        

        for widget in self.login_frame.winfo_children():
            widget.destroy()
            

        login_container = ttk.Frame(self.login_frame)
        login_container.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        

        title_label = ttk.Label(
            login_container, 
            text="EZRAX Central Server", 
            font=("Arial", 24, "bold")
        )
        title_label.pack(pady=(0, 30))
        
        subtitle_label = ttk.Label(
            login_container, 
            text="Authentification requise", 
            font=("Arial", 12)
        )
        subtitle_label.pack(pady=(0, 30))
        

        buttons_frame = ttk.Frame(login_container)
        buttons_frame.pack()
        
        ttk.Button(
            buttons_frame,
            text="Se connecter",
            command=self._authenticate,
            width=20
        ).pack(pady=10)
        
        ttk.Button(
            buttons_frame,
            text="Créer un administrateur",
            command=self._create_admin_from_login,
            width=20
        ).pack(pady=5)
        
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
    def _authenticate(self):
        """Lance le dialogue d'authentification"""
        login_dialog = LoginDialog(self.root, self.db_manager)
        self.root.wait_window(login_dialog.dialog)
        
        if login_dialog.result:
            self.current_session = login_dialog.result
            self.authenticated = True
            self._show_main_interface()
            
    def _create_admin_from_login(self):
        """Crée un admin depuis l'écran de connexion"""
        create_dialog = CreateAdminDialog(self.root, self.db_manager)
        self.root.wait_window(create_dialog.dialog)
        
        if create_dialog.result:
            messagebox.showinfo(
                "Succès", 
                f"Administrateur '{create_dialog.result['username']}' créé avec succès.\n"
                "Vous pouvez maintenant vous connecter."
            )
            
    def _show_main_interface(self):
        """Affiche l'interface principale après authentification"""

        self.login_frame.pack_forget()
        

        self.main_interface.pack(fill=tk.BOTH, expand=True)
        

        username = self.current_session['username']
        self.root.title(f"EZRAX Central Server - Connecté en tant que {username}")
        self.session_info_label.config(text=f"Connecté: {username}")
        

        self._set_menu_state("normal")
        

        self._start_update_thread()
        

        self._refresh_all_data()
        
    def _start_update_thread(self):
        """Démarre le thread de mise à jour automatique"""
        if self.update_thread and self.update_thread.is_alive():
            return
            
        def update_loop():
            while self.running and self.authenticated:
                try:
                    if self.auto_refresh.get():
                        self._refresh_all_data()
                    time.sleep(10)  # Mise à jour toutes les 10 secondes
                except Exception as e:
                    logger.error(f"Erreur dans la boucle de mise à jour: {e}")
                    time.sleep(30)
                    
        self.update_thread = threading.Thread(target=update_loop, daemon=True)
        self.update_thread.start()
        
    def _refresh_all_data(self):
        """Rafraîchit toutes les données de l'interface"""
        try:
            self._refresh_agents()
            self._refresh_global_stats()
            self._refresh_attacks()
            self._refresh_blocked_ips()
            self._refresh_whitelist()
            self._refresh_detailed_statistics()
        except Exception as e:
            logger.error(f"Erreur lors du rafraîchissement: {e}")
            
    def _refresh_agents(self):
        """Rafraîchit la liste des agents"""
        try:
            agents = self.db_manager.get_agents()
            

            for item in self.agents_treeview.get_children():
                self.agents_treeview.delete(item)
                

            self.agents = {agent["agent_id"]: agent for agent in agents}
            

            for agent in agents:
                status = "En ligne" if agent["status"] == "online" else "Hors ligne"
                status_color = "green" if status == "En ligne" else "red"
                

                health_score = agent.get("health_score", 1.0)
                health_display = f"{health_score:.0%}" if health_score else "N/A"
                

                attack_count = agent.get("total_attacks", 0)
                
                last_seen = datetime.fromtimestamp(agent["last_seen"]).strftime("%Y-%m-%d %H:%M:%S") if agent["last_seen"] else "Jamais"
                
                self.agents_treeview.insert(
                    "",
                    tk.END,
                    values=(
                        agent["hostname"],
                        status,
                        agent["ip_address"],
                        health_display,
                        attack_count,
                        last_seen
                    ),
                    tags=(agent["agent_id"], status_color)
                )
                

            self.agents_treeview.tag_configure("green", foreground="green")
            self.agents_treeview.tag_configure("red", foreground="red")
            
        except Exception as e:
            logger.error(f"Erreur lors du rafraîchissement des agents: {e}")
            
    def _refresh_global_stats(self):
        """Rafraîchit les statistiques globales"""
        try:
            stats = self.db_manager.get_global_stats()
            

            self.agents_count_label.config(text=str(stats["total_agents"]))
            self.active_agents_label.config(text=f"{stats['active_agents']} actifs")
            self.attacks_count_label.config(text=str(stats["total_attacks"]))
            self.blocked_ips_label.config(text=str(stats["blocked_ips"]))
            

            today_start = time.time() - (time.time() % 86400)
            today_attacks = sum(
                count for attack_type, count in stats["attacks_by_type"].items()
            )
            self.attacks_today_label.config(text=f"{today_attacks} aujourd'hui")
            

            if self.server_api:
                api_metrics = self.server_api.get_api_metrics()
                avg_response_time = api_metrics["api_metrics"].get("avg_response_time", 0)
                total_requests = api_metrics["api_metrics"].get("requests_total", 0)
                
                self.response_time_label.config(text=f"{avg_response_time*1000:.0f}ms")
                self.requests_label.config(text=f"{total_requests} requêtes")
                
        except Exception as e:
            logger.error(f"Erreur lors du rafraîchissement des statistiques: {e}")
            
    def _refresh_attacks(self):
        """Rafraîchit la liste des attaques"""
        try:

            timeframe = self.filter_timeframe.get()
            seconds = 3600  # 1 heure par défaut
            
            if timeframe.endswith("h"):
                seconds = int(timeframe[:-1]) * 3600
            elif timeframe.endswith("j"):
                seconds = int(timeframe[:-1]) * 86400
                

            attack_type = None if self.filter_attack_type.get() == "Tous" else self.filter_attack_type.get()
            

            attacks = self.db_manager.get_attack_logs(
                limit=1000,
                since=time.time() - seconds,
                attack_type=attack_type,
                agent_id=self.selected_agent.get() if self.selected_agent.get() else None
            )
            

            for item in self.attacks_treeview.get_children():
                self.attacks_treeview.delete(item)
                

            for attack in attacks:
                timestamp = datetime.fromtimestamp(attack["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                

                agent_name = "Inconnu"
                if attack["agent_id"] in self.agents:
                    agent_name = self.agents[attack["agent_id"]]["hostname"]
                    

                details = attack.get("details", {})
                if isinstance(details, str):
                    try:
                        details = json.loads(details)
                    except:
                        pass
                        
                details_str = ", ".join(
                    f"{k}: {v}" for k, v in details.items() 
                    if k in ["packet_count", "distinct_ports", "severity", "attack_rate_pps"]
                )[:100]  # Limiter la longueur
                
                severity = details.get("severity", "MEDIUM") if isinstance(details, dict) else "MEDIUM"
                
                self.attacks_treeview.insert(
                    "",
                    tk.END,
                    values=(
                        timestamp,
                        attack["attack_type"],
                        attack["source_ip"],
                        agent_name,
                        severity,
                        details_str
                    )
                )
                
        except Exception as e:
            logger.error(f"Erreur lors du rafraîchissement des attaques: {e}")
            
    def _refresh_blocked_ips(self):
        """Rafraîchit la liste des IPs bloquées"""
        try:
            include_expired = self.include_expired_var.get()
            

            blocked_ips = self.db_manager.get_blocked_ips(
                include_expired=include_expired,
                agent_id=self.selected_agent.get() if self.selected_agent.get() else None
            )
            

            for item in self.blocked_treeview.get_children():
                self.blocked_treeview.delete(item)
                

            for block in blocked_ips:
                timestamp = datetime.fromtimestamp(block["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                

                duration_seconds = block["duration"]
                hours = duration_seconds // 3600
                minutes = (duration_seconds % 3600) // 60
                duration = f"{hours}h {minutes}m"
                

                agent_name = "Inconnu"
                if block["agent_id"] in self.agents:
                    agent_name = self.agents[block["agent_id"]]["hostname"]
                    

                current_time = time.time()
                if block.get("end_time"):
                    status = "Expiré"
                elif current_time > block["timestamp"] + duration_seconds:
                    status = "Expiré"
                else:
                    status = "Actif"
                    
                self.blocked_treeview.insert(
                    "",
                    tk.END,
                    values=(
                        block["ip"],
                        block["reason"],
                        timestamp,
                        duration,
                        agent_name,
                        status
                    )
                )
                
        except Exception as e:
            logger.error(f"Erreur lors du rafraîchissement des IPs bloquées: {e}")
            
    def _refresh_whitelist(self):
        """Rafraîchit la liste blanche"""
        try:

            whitelist = self.db_manager.get_whitelist()
            

            for item in self.whitelist_treeview.get_children():
                self.whitelist_treeview.delete(item)
                

            for entry in whitelist:
                added_at = datetime.fromtimestamp(entry["added_at"]).strftime("%Y-%m-%d %H:%M:%S")
                
                self.whitelist_treeview.insert(
                    "",
                    tk.END,
                    values=(
                        entry["ip"],
                        added_at,
                        entry["source"],
                        entry.get("added_by", "N/A"),
                        entry.get("description", "")
                    )
                )
                
        except Exception as e:
            logger.error(f"Erreur lors du rafraîchissement de la liste blanche: {e}")
            
    def _refresh_detailed_statistics(self):
        """Rafraîchit les statistiques détaillées"""
        try:
            stats = self.db_manager.get_global_stats()
            

            self.attacks_stats_text.config(state=tk.NORMAL)
            self.attacks_stats_text.delete(1.0, tk.END)
            
            attacks_text = "=== STATISTIQUES DES ATTAQUES ===\n\n"
            attacks_text += f"Total des attaques: {stats['total_attacks']}\n\n"
            
            if stats["attacks_by_type"]:
                attacks_text += "Répartition par type:\n"
                for attack_type, count in sorted(stats["attacks_by_type"].items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / stats['total_attacks'] * 100) if stats['total_attacks'] > 0 else 0
                    attacks_text += f"  {attack_type}: {count} ({percentage:.1f}%)\n"
                    
            attacks_text += "\nTop 10 des attaquants:\n"
            for i, attacker in enumerate(stats["top_attackers"][:10], 1):
                attacks_text += f"  {i}. {attacker['ip']}: {attacker['count']} attaques\n"
                
            self.attacks_stats_text.insert(tk.END, attacks_text)
            self.attacks_stats_text.config(state=tk.DISABLED)
            

            self.agents_stats_text.config(state=tk.NORMAL)
            self.agents_stats_text.delete(1.0, tk.END)
            
            agents_text = "=== STATISTIQUES DES AGENTS ===\n\n"
            agents_text += f"Total des agents: {stats['total_agents']}\n"
            agents_text += f"Agents actifs: {stats['active_agents']}\n\n"
            
            if stats["agent_health"]:
                agents_text += "Santé des agents:\n"
                for agent_id, health_info in stats["agent_health"].items():
                    hostname = health_info["hostname"]
                    health_score = health_info["health_score"]
                    agents_text += f"  {hostname}: {health_score:.0%}\n"
                    
            self.agents_stats_text.insert(tk.END, agents_text)
            self.agents_stats_text.config(state=tk.DISABLED)
            

            self.server_perf_text.config(state=tk.NORMAL)
            self.server_perf_text.delete(1.0, tk.END)
            
            server_text = "=== PERFORMANCE DU SERVEUR ===\n\n"
            
            if self.server_api:
                api_metrics = self.server_api.get_api_metrics()
                server_text += f"Requêtes totales: {api_metrics['api_metrics']['requests_total']}\n"
                server_text += f"Requêtes réussies: {api_metrics['api_metrics']['requests_success']}\n"
                server_text += f"Requêtes échouées: {api_metrics['api_metrics']['requests_failed']}\n"
                server_text += f"Temps de réponse moyen: {api_metrics['api_metrics']['avg_response_time']*1000:.0f}ms\n"
                server_text += f"Agents actifs: {len(api_metrics['api_metrics']['active_agents'])}\n"
                

            db_metrics = self.db_manager.get_performance_metrics()
            server_text += f"\nBase de données:\n"
            server_text += f"  Requêtes exécutées: {db_metrics['queries_executed']}\n"
            server_text += f"  Cache hit rate: {db_metrics['query_cache']['hit_rate']:.1%}\n"
            server_text += f"  Connexions actives: {db_metrics['connection_pool']['active_connections']}\n"
            server_text += f"  Temps de requête moyen: {db_metrics['avg_query_time']*1000:.0f}ms\n"
            
            self.server_perf_text.insert(tk.END, server_text)
            self.server_perf_text.config(state=tk.DISABLED)
            
        except Exception as e:
            logger.error(f"Erreur lors du rafraîchissement des statistiques détaillées: {e}")
            

    
    def _on_agent_selected(self, event):
        """Gère la sélection d'un agent dans la liste"""
        try:
            selected_items = self.agents_treeview.selection()
            if not selected_items:
                return
                

            agent_id = self.agents_treeview.item(selected_items[0], "tags")[0]
            self.selected_agent.set(agent_id)
            

            if agent_id in self.agents:
                self.selected_agent_data = self.agents[agent_id]
                

            self._refresh_attacks()
            self._refresh_blocked_ips()
            
        except Exception as e:
            logger.error(f"Erreur lors de la sélection d'un agent: {e}")
            

    
    def _show_agent_details(self):
        """Affiche les détails d'un agent sélectionné"""
        if not self.selected_agent_data:
            messagebox.showinfo("Information", "Veuillez sélectionner un agent")
            return
            

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Détails de l'agent: {self.selected_agent_data['hostname']}")
        dialog.geometry("700x500")
        dialog.transient(self.root)
        dialog.grab_set()
        

        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        

        info_frame = ttk.Frame(notebook)
        notebook.add(info_frame, text="Informations")
        
        info_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD)
        info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        

        info_content = f"Agent ID: {self.selected_agent_data['agent_id']}\n"
        info_content += f"Hostname: {self.selected_agent_data['hostname']}\n"
        info_content += f"Adresse IP: {self.selected_agent_data['ip_address']}\n"
        info_content += f"Statut: {self.selected_agent_data['status']}\n"
        
        if self.selected_agent_data.get('last_seen'):
            last_seen = datetime.fromtimestamp(self.selected_agent_data['last_seen'])
            info_content += f"Dernière activité: {last_seen.strftime('%Y-%m-%d %H:%M:%S')}\n"
            
        if self.selected_agent_data.get('registered_at'):
            registered = datetime.fromtimestamp(self.selected_agent_data['registered_at'])
            info_content += f"Enregistré le: {registered.strftime('%Y-%m-%d %H:%M:%S')}\n"
            
        info_content += f"Version: {self.selected_agent_data.get('version', 'N/A')}\n"
        
        health_score = self.selected_agent_data.get('health_score', 1.0)
        info_content += f"Score de santé: {health_score:.0%}\n\n"
        

        os_info = self.selected_agent_data.get('os_info', {})
        if isinstance(os_info, dict) and os_info:
            info_content += "=== INFORMATIONS SYSTÈME ===\n"
            for key, value in os_info.items():
                info_content += f"{key}: {value}\n"
            info_content += "\n"
            

        features = self.selected_agent_data.get('features', {})
        if isinstance(features, dict) and features:
            info_content += "=== FONCTIONNALITÉS ===\n"
            info_content += json.dumps(features, indent=2)
            
        info_text.insert(tk.END, info_content)
        info_text.config(state=tk.DISABLED)
        

        stats_frame = ttk.Frame(notebook)
        notebook.add(stats_frame, text="Statistiques")
        
        stats_text = scrolledtext.ScrolledText(stats_frame, wrap=tk.WORD)
        stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        

        try:
            agent_stats = self.db_manager.get_agent_stats(self.selected_agent_data['agent_id'])
            
            stats_content = f"=== STATISTIQUES DE L'AGENT ===\n\n"
            stats_content += f"Total des attaques détectées: {agent_stats['total_attacks']}\n"
            stats_content += f"IPs actuellement bloquées: {agent_stats['blocked_ips']}\n\n"
            
            if agent_stats['attacks_by_type']:
                stats_content += "Répartition des attaques par type:\n"
                for attack_type, count in agent_stats['attacks_by_type'].items():
                    percentage = (count / agent_stats['total_attacks'] * 100) if agent_stats['total_attacks'] > 0 else 0
                    stats_content += f"  {attack_type}: {count} ({percentage:.1f}%)\n"
                    
            stats_text.insert(tk.END, stats_content)
            
        except Exception as e:
            stats_text.insert(tk.END, f"Erreur lors du chargement des statistiques: {e}")
            
        stats_text.config(state=tk.DISABLED)
        

        ttk.Button(
            dialog,
            text="Fermer",
            command=dialog.destroy
        ).pack(pady=10)
        
    def _send_agent_command(self):
        """Envoie une commande à un agent sélectionné"""
        if not self.selected_agent_data:
            messagebox.showinfo("Information", "Veuillez sélectionner un agent")
            return
            

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Envoyer une commande à: {self.selected_agent_data['hostname']}")
        dialog.geometry("500x400")
        dialog.transient(self.root)
        dialog.grab_set()
        

        commands_frame = ttk.Frame(dialog, padding=10)
        commands_frame.pack(fill=tk.BOTH, expand=True)
        

        command_type = tk.StringVar(value="restart")
        ip_to_block = tk.StringVar()
        block_reason = tk.StringVar(value="MANUAL_BLOCK")
        block_duration = tk.IntVar(value=3600)
        priority = tk.IntVar(value=1)
        

        ttk.Label(commands_frame, text="Type de commande:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=10)
        ttk.Combobox(
            commands_frame,
            textvariable=command_type,
            values=["restart", "block_ip", "unblock_ip", "generate_report", "update_config"],
            state="readonly",
            width=15
        ).grid(row=0, column=1, sticky=tk.W, padx=5, pady=10)
        

        ttk.Label(commands_frame, text="Priorité:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Combobox(
            commands_frame,
            textvariable=priority,
            values=[1, 2, 3, 4, 5],
            state="readonly",
            width=5
        ).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        

        ip_frame = ttk.LabelFrame(commands_frame, text="Blocage d'IP")
        ip_frame.grid(row=2, column=0, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=10)
        
        ttk.Label(ip_frame, text="Adresse IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(ip_frame, textvariable=ip_to_block, width=20).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(ip_frame, text="Raison:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(ip_frame, textvariable=block_reason, width=20).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(ip_frame, text="Durée (secondes):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(ip_frame, textvariable=block_duration, width=10).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        

        buttons_frame = ttk.Frame(dialog)
        buttons_frame.pack(pady=10)
        
        def send_command():
            try:
                cmd_type = command_type.get()
                cmd_data = {}
                
                if cmd_type in ["block_ip", "unblock_ip"]:
                    ip = ip_to_block.get().strip()
                    if not ip:
                        messagebox.showerror("Erreur", "Adresse IP requise")
                        return
                    cmd_data["ip"] = ip
                    
                    if cmd_type == "block_ip":
                        cmd_data["reason"] = block_reason.get()
                        cmd_data["duration"] = block_duration.get()
                        

                command_id = self.db_manager.add_command(
                    self.selected_agent_data['agent_id'],
                    cmd_type,
                    cmd_data,
                    self.current_session['username'],
                    priority.get()
                )
                
                if command_id:
                    messagebox.showinfo("Succès", f"Commande {cmd_type} envoyée à l'agent")
                    dialog.destroy()
                else:
                    messagebox.showerror("Erreur", "Erreur lors de l'envoi de la commande")
                    
            except Exception as e:
                logger.error(f"Erreur lors de l'envoi de la commande: {e}")
                messagebox.showerror("Erreur", f"Erreur lors de l'envoi de la commande: {e}")
                
        ttk.Button(
            buttons_frame,
            text="Envoyer la commande",
            command=send_command
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Fermer",
            command=dialog.destroy
        ).pack(side=tk.LEFT, padx=5)
        
    def _show_agent_history(self):
        """Affiche l'historique d'un agent"""
        if not self.selected_agent_data:
            messagebox.showinfo("Information", "Veuillez sélectionner un agent")
            return
            

        messagebox.showinfo(
            "Historique", 
            f"Historique de l'agent {self.selected_agent_data['hostname']}\n\n"
            "Cette fonctionnalité affichera l'historique détaillé des attaques "
            "et des actions de cet agent."
        )
        

    
    def _show_blocked_context_menu(self, event):
        """Affiche le menu contextuel pour les IPs bloquées"""
        try:
            self.blocked_context_menu.post(event.x_root, event.y_root)
        except:
            pass
            
    def _show_whitelist_context_menu(self, event):
        """Affiche le menu contextuel pour la liste blanche"""
        try:
            self.whitelist_context_menu.post(event.x_root, event.y_root)
        except:
            pass
            
    def _unblock_selected_ip(self):
        """Débloque une IP sélectionnée"""
        try:
            selected_items = self.blocked_treeview.selection()
            if not selected_items:
                messagebox.showinfo("Information", "Veuillez sélectionner une IP à débloquer")
                return
                
            ip = self.blocked_treeview.item(selected_items[0], "values")[0]
            
            if messagebox.askyesno("Confirmation", f"Voulez-vous vraiment débloquer l'IP {ip} ?"):

                if self.selected_agent.get():
                    agent_id = self.selected_agent.get()
                    command_id = self.db_manager.add_command(
                        agent_id,
                        "unblock_ip",
                        {"ip": ip},
                        self.current_session['username']
                    )
                    if command_id:
                        messagebox.showinfo("Succès", f"Commande de déblocage envoyée pour {ip}")
                    else:
                        messagebox.showerror("Erreur", "Erreur lors de l'envoi de la commande")
                else:
                    messagebox.showinfo("Information", "Veuillez sélectionner un agent pour débloquer l'IP")
                    
        except Exception as e:
            logger.error(f"Erreur lors du déblocage de l'IP: {e}")
            messagebox.showerror("Erreur", f"Erreur lors du déblocage de l'IP: {e}")
            
    def _add_ip_to_whitelist(self):
        """Ajoute une IP à la liste blanche depuis les IPs bloquées"""
        try:
            selected_items = self.blocked_treeview.selection()
            if not selected_items:
                messagebox.showinfo("Information", "Veuillez sélectionner une IP")
                return
                
            ip = self.blocked_treeview.item(selected_items[0], "values")[0]
            

            description = simpledialog.askstring(
                "Description",
                f"Description pour l'IP {ip} dans la liste blanche:",
                initialvalue="Ajouté depuis les IPs bloquées"
            )
            
            if description is not None:
                success = self.db_manager.add_whitelist_entry(
                    ip, "manual", description, self.current_session['username']
                )
                
                if success:
                    messagebox.showinfo("Succès", f"IP {ip} ajoutée à la liste blanche")
                    self._refresh_whitelist()
                else:
                    messagebox.showerror("Erreur", "Erreur lors de l'ajout à la liste blanche")
                    
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout à la liste blanche: {e}")
            messagebox.showerror("Erreur", f"Erreur: {e}")
            
    def _add_whitelist_entry(self):
        """Ajoute une entrée à la liste blanche"""

        dialog = tk.Toplevel(self.root)
        dialog.title("Ajouter à la liste blanche")
        dialog.geometry("400x250")
        dialog.transient(self.root)
        dialog.grab_set()
        

        ip = tk.StringVar()
        description = tk.StringVar()
        

        form_frame = ttk.Frame(dialog, padding=10)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(form_frame, text="Adresse IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(form_frame, textvariable=ip, width=30).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Description:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(form_frame, textvariable=description, width=30).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        

        buttons_frame = ttk.Frame(dialog)
        buttons_frame.pack(pady=10)
        
        def add_entry():
            try:
                ip_addr = ip.get().strip()
                desc = description.get().strip()
                
                if not ip_addr:
                    messagebox.showerror("Erreur", "Adresse IP requise")
                    return
                    

                try:
                    import ipaddress
                    ipaddress.ip_address(ip_addr)
                except ValueError:
                    messagebox.showerror("Erreur", "Adresse IP invalide")
                    return
                    
                success = self.db_manager.add_whitelist_entry(
                    ip_addr, "manual", desc, self.current_session['username']
                )
                
                if success:
                    messagebox.showinfo("Succès", f"IP {ip_addr} ajoutée à la liste blanche")
                    dialog.destroy()
                    self._refresh_whitelist()
                else:
                    messagebox.showerror("Erreur", "Erreur lors de l'ajout (IP déjà présente?)")
                    
            except Exception as e:
                logger.error(f"Erreur lors de l'ajout à la liste blanche: {e}")
                messagebox.showerror("Erreur", f"Erreur: {e}")
                
        ttk.Button(buttons_frame, text="Ajouter", command=add_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Annuler", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
    def _edit_whitelist_entry(self):
        """Modifie une entrée de la liste blanche"""
        selected_items = self.whitelist_treeview.selection()
        if not selected_items:
            messagebox.showinfo("Information", "Veuillez sélectionner une entrée")
            return
            

        values = self.whitelist_treeview.item(selected_items[0], "values")
        ip, added_at, source, added_by, description = values
        
        messagebox.showinfo(
            "Détails de l'entrée",
            f"IP: {ip}\n"
            f"Ajouté le: {added_at}\n"
            f"Source: {source}\n"
            f"Ajouté par: {added_by}\n"
            f"Description: {description}"
        )
        
    def _remove_whitelist_entry(self):
        """Supprime une entrée de la liste blanche"""
        try:
            selected_items = self.whitelist_treeview.selection()
            if not selected_items:
                messagebox.showinfo("Information", "Veuillez sélectionner une entrée")
                return
                
            ip = self.whitelist_treeview.item(selected_items[0], "values")[0]
            
            if messagebox.askyesno("Confirmation", f"Voulez-vous vraiment supprimer l'IP {ip} de la liste blanche ?"):
                success = self.db_manager.remove_whitelist_entry(ip)
                
                if success:
                    messagebox.showinfo("Succès", f"IP {ip} supprimée de la liste blanche")
                    self._refresh_whitelist()
                else:
                    messagebox.showerror("Erreur", "Erreur lors de la suppression")
                    
        except Exception as e:
            logger.error(f"Erreur lors de la suppression: {e}")
            messagebox.showerror("Erreur", f"Erreur: {e}")
            
    def _manual_block_ip(self):
        """Bloque manuellement une IP"""

        dialog = tk.Toplevel(self.root)
        dialog.title("Bloquer une IP")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        

        ip = tk.StringVar()
        reason = tk.StringVar(value="MANUAL_BLOCK")
        duration = tk.IntVar(value=3600)
        agent_choice = tk.StringVar(value="all")
        

        form_frame = ttk.Frame(dialog, padding=10)
        form_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(form_frame, text="Adresse IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(form_frame, textvariable=ip, width=30).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Raison:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(form_frame, textvariable=reason, width=30).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Durée (secondes):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(form_frame, textvariable=duration, width=15).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(form_frame, text="Agents cibles:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        

        agents_frame = ttk.Frame(form_frame)
        agents_frame.grid(row=4, column=0, columnspan=2, sticky=tk.W+tk.E, padx=5, pady=5)
        
        ttk.Radiobutton(agents_frame, text="Tous les agents", variable=agent_choice, value="all").pack(anchor=tk.W)
        
        for agent_id, agent_data in self.agents.items():
            if agent_data['status'] == 'online':
                ttk.Radiobutton(
                    agents_frame, 
                    text=f"{agent_data['hostname']} ({agent_data['ip_address']})",
                    variable=agent_choice, 
                    value=agent_id
                ).pack(anchor=tk.W)
                

        buttons_frame = ttk.Frame(dialog)
        buttons_frame.pack(pady=10)
        
        def block_ip():
            try:
                ip_addr = ip.get().strip()
                block_reason = reason.get().strip()
                block_duration = duration.get()
                target_agent = agent_choice.get()
                
                if not ip_addr or not block_reason:
                    messagebox.showerror("Erreur", "IP et raison requises")
                    return
                    

                try:
                    import ipaddress
                    ipaddress.ip_address(ip_addr)
                except ValueError:
                    messagebox.showerror("Erreur", "Adresse IP invalide")
                    return
                    
                if block_duration <= 0:
                    messagebox.showerror("Erreur", "Durée invalide")
                    return
                    

                command_data = {
                    "ip": ip_addr,
                    "reason": block_reason,
                    "duration": block_duration
                }
                
                if target_agent == "all":

                    commands_sent = 0
                    for agent_id, agent_data in self.agents.items():
                        if agent_data['status'] == 'online':
                            command_id = self.db_manager.add_command(
                                agent_id, "block_ip", command_data, self.current_session['username']
                            )
                            if command_id:
                                commands_sent += 1
                                
                    messagebox.showinfo("Succès", f"Commande de blocage envoyée à {commands_sent} agents")
                else:

                    command_id = self.db_manager.add_command(
                        target_agent, "block_ip", command_data, self.current_session['username']
                    )
                    if command_id:
                        messagebox.showinfo("Succès", "Commande de blocage envoyée")
                    else:
                        messagebox.showerror("Erreur", "Erreur lors de l'envoi de la commande")
                        
                dialog.destroy()
                
            except Exception as e:
                logger.error(f"Erreur lors du blocage manuel: {e}")
                messagebox.showerror("Erreur", f"Erreur: {e}")
                
        ttk.Button(buttons_frame, text="Bloquer", command=block_ip).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Annuler", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        

    
    def _logout(self):
        """Déconnecte l'utilisateur"""
        if messagebox.askyesno("Déconnexion", "Voulez-vous vraiment vous déconnecter ?"):

            if self.current_session:
                session_id = self.current_session.get('session_id')
                if session_id:
                    self.db_manager.admin_manager.logout_admin(session_id)
                    
            self.current_session = None
            self.authenticated = False
            

            self.running = False
            

            self.root.title("EZRAX Central Server - Non connecté")
            self._set_menu_state("disabled")
            

            self._show_login()
            
    def _create_admin_user(self):
        """Crée un nouvel utilisateur administrateur"""
        create_dialog = CreateAdminDialog(self.root, self.db_manager)
        self.root.wait_window(create_dialog.dialog)
        
    def _manage_users(self):
        """Gère les utilisateurs administrateurs"""
        messagebox.showinfo(
            "Gestion des utilisateurs",
            "Cette fonctionnalité permettra de gérer les comptes administrateurs.\n"
            "Pour l'instant, utilisez 'Créer un administrateur' depuis le menu."
        )
        
    def _server_config(self):
        """Configuration du serveur"""
        messagebox.showinfo(
            "Configuration serveur",
            "Cette fonctionnalité permettra de configurer les paramètres du serveur.\n"
            "Les paramètres sont actuellement configurés via les fichiers de configuration."
        )
        
    def _export_attacks(self):
        """Exporte les attaques en CSV"""
        try:
            from tkinter import filedialog
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("Fichiers CSV", "*.csv"), ("Tous les fichiers", "*.*")]
            )
            
            if not filename:
                return
                

            timeframe = self.filter_timeframe.get()
            seconds = 3600
            
            if timeframe.endswith("h"):
                seconds = int(timeframe[:-1]) * 3600
            elif timeframe.endswith("j"):
                seconds = int(timeframe[:-1]) * 86400
                
            attack_type = None if self.filter_attack_type.get() == "Tous" else self.filter_attack_type.get()
            
            attacks = self.db_manager.get_attack_logs(
                limit=10000,
                since=time.time() - seconds,
                attack_type=attack_type
            )
            

            import csv
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                
                writer.writerow([
                    "ID", "Horodatage", "Date", "Type d'attaque", "IP Source", 
                    "Agent", "Scanner", "Sévérité", "Détails"
                ])
                
                for attack in attacks:
                    timestamp = datetime.fromtimestamp(attack["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                    
                    agent_name = "Inconnu"
                    if attack["agent_id"] in self.agents:
                        agent_name = self.agents[attack["agent_id"]]["hostname"]
                        
                    details = attack.get("details", {})
                    if isinstance(details, str):
                        try:
                            details = json.loads(details)
                        except:
                            pass
                            
                    severity = details.get("severity", "MEDIUM") if isinstance(details, dict) else "MEDIUM"
                    details_str = json.dumps(details) if isinstance(details, dict) else str(details)
                    
                    writer.writerow([
                        attack.get("id", ""),
                        attack["timestamp"],
                        timestamp,
                        attack["attack_type"],
                        attack["source_ip"],
                        agent_name,
                        attack.get("scanner", ""),
                        severity,
                        details_str
                    ])
                    
            messagebox.showinfo("Succès", f"Exportation réussie: {len(attacks)} attaques exportées dans {filename}")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exportation des attaques: {e}")
            messagebox.showerror("Erreur", f"Erreur lors de l'exportation: {e}")
            
    def _export_data(self):
        """Exporte toutes les données"""
        messagebox.showinfo(
            "Export des données",
            "Cette fonctionnalité permettra d'exporter toutes les données du serveur.\n"
            "Utilisez les boutons d'export individuels pour l'instant."
        )
        
    def _import_whitelist(self):
        """Importe une liste blanche depuis un fichier"""
        try:
            from tkinter import filedialog
            
            filename = filedialog.askopenfilename(
                filetypes=[("Fichiers texte", "*.txt"), ("Fichiers CSV", "*.csv"), ("Tous les fichiers", "*.*")]
            )
            
            if not filename:
                return
                
            imported_count = 0
            
            with open(filename, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                        

                    ip = line.split(",")[0].split()[0]
                    

                    try:
                        import ipaddress
                        ipaddress.ip_address(ip)
                        

                        success = self.db_manager.add_whitelist_entry(
                            ip, "import", f"Importé depuis {filename} ligne {line_num}", 
                            self.current_session['username']
                        )
                        
                        if success:
                            imported_count += 1
                            
                    except ValueError:
                        logger.warning(f"IP invalide ligne {line_num}: {ip}")
                        continue
                        
            self._refresh_whitelist()
            messagebox.showinfo("Succès", f"{imported_count} adresses IP importées avec succès")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'importation: {e}")
            messagebox.showerror("Erreur", f"Erreur lors de l'importation: {e}")
            
    def _export_whitelist(self):
        """Exporte la liste blanche"""
        try:
            from tkinter import filedialog
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Fichiers texte", "*.txt"), ("Fichiers CSV", "*.csv"), ("Tous les fichiers", "*.*")]
            )
            
            if not filename:
                return
                
            whitelist = self.db_manager.get_whitelist()
            
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"# Liste blanche EZRAX - Exportée le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Format: IP, Description\n\n")
                
                for entry in whitelist:
                    description = entry.get("description", "").replace(",", ";")
                    f.write(f"{entry['ip']}, {description}\n")
                    
            messagebox.showinfo("Succès", f"Liste blanche exportée: {len(whitelist)} entrées dans {filename}")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'exportation de la liste blanche: {e}")
            messagebox.showerror("Erreur", f"Erreur: {e}")
            
    def _cleanup_database(self):
        """Nettoie la base de données"""
        if messagebox.askyesno(
            "Nettoyage de la base de données",
            "Cette opération supprimera les anciennes données selon la politique de rétention.\n"
            "Voulez-vous continuer ?"
        ):
            try:
                self.db_manager.cleanup_old_data()
                messagebox.showinfo("Succès", "Base de données nettoyée avec succès")
                self._refresh_all_data()
            except Exception as e:
                logger.error(f"Erreur lors du nettoyage: {e}")
                messagebox.showerror("Erreur", f"Erreur lors du nettoyage: {e}")
                
    def _show_performance_metrics(self):
        """Affiche les métriques de performance détaillées"""

        dialog = tk.Toplevel(self.root)
        dialog.title("Métriques de Performance")
        dialog.geometry("800x600")
        dialog.transient(self.root)
        dialog.grab_set()
        

        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        

        db_frame = ttk.Frame(notebook)
        notebook.add(db_frame, text="Base de données")
        
        db_text = scrolledtext.ScrolledText(db_frame, wrap=tk.WORD)
        db_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        try:
            db_metrics = self.db_manager.get_performance_metrics()
            
            db_content = "=== MÉTRIQUES DE LA BASE DE DONNÉES ===\n\n"
            db_content += f"Requêtes exécutées: {db_metrics['queries_executed']}\n"
            db_content += f"Requêtes lentes: {db_metrics['slow_queries']}\n"
            db_content += f"Erreurs: {db_metrics['errors']}\n"
            db_content += f"Temps de requête moyen: {db_metrics['avg_query_time']*1000:.2f}ms\n\n"
            
            db_content += "Pool de connexions:\n"
            pool_stats = db_metrics['connection_pool']
            db_content += f"  Taille du pool: {pool_stats['pool_size']}\n"
            db_content += f"  Connexions actives: {pool_stats['active_connections']}\n"
            db_content += f"  Total créées: {pool_stats['total_connections_created']}\n\n"
            
            db_content += "Cache des requêtes:\n"
            cache_stats = db_metrics['query_cache']
            db_content += f"  Taille: {cache_stats['size']}/{cache_stats['max_size']}\n"
            db_content += f"  Hits: {cache_stats['hits']}\n"
            db_content += f"  Misses: {cache_stats['misses']}\n"
            db_content += f"  Taux de réussite: {cache_stats['hit_rate']:.1%}\n"
            
            db_text.insert(tk.END, db_content)
            
        except Exception as e:
            db_text.insert(tk.END, f"Erreur lors du chargement des métriques DB: {e}")
            
        db_text.config(state=tk.DISABLED)
        

        api_frame = ttk.Frame(notebook)
        notebook.add(api_frame, text="API")
        
        api_text = scrolledtext.ScrolledText(api_frame, wrap=tk.WORD)
        api_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        try:
            if self.server_api:
                api_metrics = self.server_api.get_api_metrics()
                
                api_content = "=== MÉTRIQUES DE L'API ===\n\n"
                
                main_metrics = api_metrics['api_metrics']
                api_content += f"Requêtes totales: {main_metrics['requests_total']}\n"
                api_content += f"Requêtes réussies: {main_metrics['requests_success']}\n"
                api_content += f"Requêtes échouées: {main_metrics['requests_failed']}\n"
                api_content += f"Requêtes limitées: {main_metrics['requests_rate_limited']}\n"
                api_content += f"Temps de réponse moyen: {main_metrics['avg_response_time']*1000:.2f}ms\n"
                api_content += f"Agents actifs: {len(main_metrics['active_agents'])}\n"
                api_content += f"Connexions admin: {main_metrics['admin_logins']}\n\n"
                
                api_content += "Rate Limiters:\n"
                for name, stats in api_metrics['rate_limiters'].items():
                    api_content += f"  {name.capitalize()}:\n"
                    api_content += f"    Clients actifs: {stats['active_clients']}\n"
                    api_content += f"    Requêtes trackées: {stats['total_requests_tracked']}\n"
                    api_content += f"    Limite: {stats['max_requests_per_window']}/{stats['window_seconds']}s\n"
                    
                api_text.insert(tk.END, api_content)
            else:
                api_text.insert(tk.END, "API non disponible")
                
        except Exception as e:
            api_text.insert(tk.END, f"Erreur lors du chargement des métriques API: {e}")
            
        api_text.config(state=tk.DISABLED)
        

        buttons_frame = ttk.Frame(dialog)
        buttons_frame.pack(pady=10)
        
        ttk.Button(
            buttons_frame,
            text="Rafraîchir",
            command=lambda: self._refresh_performance_dialog(notebook)
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            buttons_frame,
            text="Fermer",
            command=dialog.destroy
        ).pack(side=tk.LEFT, padx=5)
        
    def _refresh_performance_dialog(self, notebook):
        """Rafraîchit les métriques dans le dialogue"""

        notebook.master.destroy()
        self._show_performance_metrics()
        
    def _refresh_logs(self):
        """Rafraîchit les logs affichés"""

        pass
        
    def _clear_logs(self):
        """Efface les logs affichés"""
        if messagebox.askyesno("Confirmation", "Voulez-vous vraiment effacer les logs affichés ?"):
            self.logs_text.delete(1.0, tk.END)
            
    def _save_logs(self):
        """Enregistre les logs dans un fichier"""
        try:
            from tkinter import filedialog
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".log",
                filetypes=[("Fichiers log", "*.log"), ("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
            )
            
            if not filename:
                return
                
            with open(filename, "w", encoding="utf-8") as f:
                f.write(self.logs_text.get(1.0, tk.END))
                
            messagebox.showinfo("Succès", f"Logs enregistrés dans {filename}")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement des logs: {e}")
            messagebox.showerror("Erreur", f"Erreur: {e}")
            
    def _show_about(self):
        """Affiche les informations À propos"""
        about_text = """EZRAX Central Server v2.0

Système centralisé de gestion IDS/IPS

Fonctionnalités:
• Gestion centralisée des agents
• Analyse des attaques en temps réel
• Blocage automatique des IP malveillantes
• Interface d'administration sécurisée
• Métriques de performance avancées
• API REST complète

Développé avec Python, Flask, Tkinter et SQLite

© 2025 EZRAX Project by Belaid Ahouari"""

        messagebox.showinfo("À propos d'EZRAX Central Server", about_text)
        
    def on_closing(self):
        """Gère la fermeture de l'application"""
        if messagebox.askokcancel("Quitter", "Voulez-vous vraiment quitter ?"):

            if self.current_session:
                self._logout()
                

            self.running = False
            

            if self.server_api:
                try:
                    self.server_api.stop()
                except:
                    pass
                    

            self.root.destroy()

class LogTextHandler(logging.Handler):
    """Handler pour afficher les logs dans un widget Text"""
    
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        
    def emit(self, record):
        """Affiche un log dans le widget Text"""
        msg = self.format(record) + "\n"
        
        def _add_log():
            try:
                self.text_widget.configure(state=tk.NORMAL)
                self.text_widget.insert(tk.END, msg)
                self.text_widget.see(tk.END)
                

                lines = int(self.text_widget.index('end-1c').split('.')[0])
                if lines > 1000:
                    self.text_widget.delete(1.0, f"{lines-500}.0")
                    
                self.text_widget.configure(state=tk.DISABLED)
            except:
                pass  
                

        try:
            self.text_widget.after(0, _add_log)
        except:
            pass  

def main():
    """Point d'entrée principal pour l'interface graphique"""

    from db_manager import ServerDatabaseManager
    from server_api import EzraxServerAPI
    

    root = tk.Tk()
    

    db_manager = ServerDatabaseManager()
    server_api = EzraxServerAPI(db_manager, enable_admin_api=True)
    

    app = EzraxServerGUI(root, db_manager, server_api)
    

    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    

    api_thread = threading.Thread(target=server_api.start, daemon=True)
    api_thread.start()
    

    root.mainloop()
    
if __name__ == "__main__":
    main()
