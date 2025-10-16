# EZRAX IDS/IPS - Système de Détection et Prévention d'Intrusions Distribué
![EZRAX (1)](https://github.com/user-attachments/assets/1a321353-8d55-4607-b966-8008cabdd5a5)
**EZRAX est un système de détection et de prévention d'intrusions (IDS/IPS) open-source, basé sur une architecture agent-serveur. Il est conçu pour offrir une surveillance réseau proactive et une réponse automatisée aux menaces, tout en centralisant la gestion et la supervision.**

Le nom **EZRAX** vient de la langue Amazighe et signifie *"il t'a vu"*, incarnant la vigilance constante qui est au cœur du système.

---

## 📜 Table des Matières

- [Fonctionnalités Clés](#-fonctionnalités-clés)
- [Architecture](#-architecture)
- [Technologies Utilisées](#-technologies-utilisées)
- [Installation](#-installation)
  - [Prérequis](#prérequis)
  - [Installation du Serveur](#installation-du-serveur)
  - [Installation de l'Agent](#installation-de-l-agent)
- [Démarrage Rapide](#-démarrage-rapide)
- [Démonstration](#-démonstration)
- [Contribuer](#-contribuer)
- [Licence](#-licence)

---

## ✨ Fonctionnalités Clés

- **Architecture Distribuée :** Agents légers déployés sur les hôtes, gérés par un serveur central.
- **Détection Comportementale :** Scanners spécialisés pour identifier en temps réel :
  - 🔥 **SYN Flood**
  - 🌊 **UDP Flood**
  - 🔊 **Ping Flood**
  - 🚪 **Scans de Ports** (TCP & UDP)
- **Prévention Active (IPS) :** Blocage automatique des adresses IP malveillantes via l'intégration avec `iptables`.
- **Gestion Centralisée :**
  - **API REST Sécurisée** pour la communication entre les composants.
  - **Interface Graphique d'Administration** (GUI) pour la supervision en temps réel, la gestion des alertes et des politiques de sécurité.
- **Sécurité Robuste :**
  - Authentification des agents par **Clé API**.
  - Authentification des administrateurs par **Token JWT**.
  - Respect des bonnes pratiques de sécurité (OWASP, NIST).
- **Configuration Flexible :** Gestion via des fichiers `.yaml`, `.json` et `.env`.
- **Scripts de Déploiement :** Outils en ligne de commande (`ezraxtl`, `ezraxtl-agent`) pour une installation et une gestion simplifiées.

---

## 🏗️ Architecture

EZRAX est basé sur un modèle agent-serveur classique pour combiner détection locale et supervision centrale.

![Architecture EZRAX](chemin/vers/votre/diagramme_architecture.png) <!-- Remplacez par le chemin de votre diagramme d'architecture -->

1.  **Agent EZRAX :**
    - Installé sur chaque hôte à surveiller.
    - **Capture et Analyse** le trafic réseau local avec **Scapy**.
    - **Bloque** les menaces via **`iptables`**.
    - **Communique** les alertes au serveur central.
    - **Stocke** les événements localement en cas de déconnexion.

2.  **Serveur EZRAX :**
    - **Agrège** les alertes de tous les agents.
    - **Expose une API REST** pour la communication.
    - **Fournit une GUI** pour l'administration et la visualisation.
    - **Gère les configurations** (whitelist) et envoie des commandes aux agents.

---

## 🛠️ Technologies Utilisées

| Composant | Technologie | Rôle |
| :--- | :--- | :--- |
| **Langage Principal** | ![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white) | Développement de l'ensemble du système |
| **Agent - Détection** | **Scapy** | Analyse et manipulation de paquets réseau |
| **Agent - Prévention**| **iptables** | Pare-feu de l'hôte pour le blocage d'IPs |
| **Serveur - API** | ![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white) | Framework pour l'API REST |
| **Serveur - GUI** | **Tkinter** | Interface graphique d'administration |
| **Base de Données** | **SQLite** | Stockage local (agent) et centralisé (serveur) |
| **Sécurité Admin** | **JWT** | Authentification par token pour l'API admin |
| **Communication** | **Requests** | Client HTTP pour la communication agent-serveur |

---

## 🚀 Installation

### Prérequis

- **Système d'exploitation :** Distributions basées sur Debian/Ubuntu (Server ou Desktop).
- **Python :** Version 3.8 ou supérieure.
- **Privilèges :** Accès `sudo` ou `root` pour l'installation.

### Installation du Serveur

1.  Clonez ce dépôt sur la machine destinée à héberger le serveur :
    ```bash
    git clone https://github.com/votre_nom/ezrax-ids.git
    cd ezrax-ids/server
    ```

2.  Exécutez le script d'installation :
    ```bash
    sudo bash setup_server.sh
    ```
3.  **Important :** Notez la **Clé API** affichée à la fin de l'installation. Vous en aurez besoin pour configurer les agents.

### Installation de l'Agent

1.  Clonez ce dépôt sur chaque machine que vous souhaitez surveiller :
    ```bash
    git clone https://github.com/votre_nom/ezrax-ids.git
    cd ezrax-ids/agent
    ```

2.  Exécutez le script d'installation :
    ```bash
    sudo bash install_agent.sh
    ```

3.  **Configurez l'agent :**
    - Éditez le fichier de secrets pour y mettre la clé API du serveur :
      ```bash
      sudo nano /etc/ezrax-agent/.env
      # Remplacez "changez_moi_en_production" par la clé API du serveur.
      ```
    - Éditez le fichier de configuration pour indiquer l'IP du serveur et l'interface à surveiller :
      ```bash
      sudo nano /opt/ezrax-agent/agent_config.yaml
      # Modifiez central_server.host et scanners.*.interfaces
      ```

---

## ⚡ Démarrage Rapide

**Sur la machine Serveur :**

```bash
# Démarrer le serveur en mode console
sudo ezraxtl start

# Démarrer le serveur avec l'interface graphique (nécessite une session X11)
sudo ezraxtl gui

# Consulter les logs du serveur
sudo ezraxtl logs

# Consulter le statut du serveur
sudo ezraxtl status
```

**Sur chaque machine Agent :**
```bash
# Démarrer l'agent
sudo ezraxtl-agent start

# Consulter les logs de l'agent
sudo ezraxtl-agent logs

# Consulter le statut de l'agent
sudo ezraxtl-agent status
```

