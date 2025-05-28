#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Proxy pour l'API Grafana du serveur EZRAX
"""

import os
import json
import logging
import requests
from flask import Flask, request, Response, jsonify

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration du proxy
EZRAX_URL = "http://localhost:5000"  # URL du serveur EZRAX
API_KEY = "09eefb2d-0479-4fc3-8d3e-a1ca586291de"  # Remplacez par votre clé API

# Routes Grafana connues
GRAFANA_ROUTES = [
    "agents",
    "attacks",
    "blocked_ips",
    "stats"
]

@app.route('/', methods=['GET'])
def home():
    """Page d'accueil pour vérifier que le proxy fonctionne"""
    return jsonify({
        "status": "ok",
        "message": "EZRAX Grafana Proxy is running",
        "available_routes": GRAFANA_ROUTES
    })

@app.route('/search', methods=['POST'])
def search():
    """Endpoint requis par Grafana SimpleJSON pour lister les métriques disponibles"""
    logger.info("Grafana search request received")
    return jsonify(GRAFANA_ROUTES)

@app.route('/query', methods=['POST'])
def query():
    """
    Endpoint principal pour les requêtes Grafana
    
    Le format de requête de Grafana SimpleJSON:
    {
        "targets": [
            { "target": "stats", "refId": "A", ... },
            { "target": "agents", "refId": "B", ... }
        ],
        "range": { "from": "...", "to": "..." },
        ...
    }
    """
    logger.info(f"Grafana query request received: {request.json}")
    
    try:
        data = request.get_json()
        if not data or 'targets' not in data:
            logger.error("Invalid request format")
            return jsonify([])
            
        results = []
        
        # Traiter chaque cible demandée
        for target in data['targets']:
            if 'target' not in target:
                continue
                
            route = target['target']
            
            if route not in GRAFANA_ROUTES:
                logger.warning(f"Unknown route requested: {route}")
                continue
                
            # Faire la requête au serveur EZRAX
            ezrax_url = f"{EZRAX_URL}/api/grafana/{route}"
            logger.info(f"Forwarding request to {ezrax_url}")
            
            headers = {
                'X-API-Key': API_KEY,
                'Content-Type': 'application/json'
            }
            
            response = requests.get(
                ezrax_url,
                headers=headers,
                params=request.args
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully received data from {route}")
                
                # Formater la réponse pour Grafana
                route_data = response.json()
                
                # Si la réponse est une liste, utiliser directement
                if isinstance(route_data, list):
                    results.append({
                        "target": route,
                        "datapoints": [[len(route_data), int(data['range']['to'].split('.')[0])]]
                    })
                    
                    # Ajouter chaque élément comme une série
                    for i, item in enumerate(route_data):
                        results.append({
                            "target": f"{route}_{i}",
                            "datapoints": [[item, int(data['range']['to'].split('.')[0])]],
                            "type": "table",
                            "columns": [{"text": k} for k in item.keys()] if isinstance(item, dict) else [{"text": "value"}],
                            "rows": [[v for v in item.values()]] if isinstance(item, dict) else [[item]]
                        })
                # Si c'est un dictionnaire, convertir en séries
                elif isinstance(route_data, dict):
                    for key, value in route_data.items():
                        if isinstance(value, dict):
                            # Traiter les dictionnaires imbriqués
                            for subkey, subvalue in value.items():
                                results.append({
                                    "target": f"{route}.{key}.{subkey}",
                                    "datapoints": [[subvalue, int(data['range']['to'].split('.')[0])]]
                                })
                        else:
                            results.append({
                                "target": f"{route}.{key}",
                                "datapoints": [[value, int(data['range']['to'].split('.')[0])]]
                            })
            else:
                logger.error(f"Error getting data from {route}: {response.status_code}")
                logger.error(f"Response: {response.text}")
                
        logger.info(f"Returning {len(results)} results to Grafana")
        return jsonify(results)
        
    except Exception as e:
        logger.exception(f"Error processing Grafana query: {e}")
        return jsonify([])

@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
    """Proxy pour toutes les autres requêtes"""
    logger.info(f"Proxying request to {path}")
    
    url = f"{EZRAX_URL}/api/grafana/{path}"
    headers = {
        'X-API-Key': API_KEY
    }
    
    # Ajouter les en-têtes de la requête originale
    for header in request.headers:
        if header[0] not in ['Host', 'Content-Length']:
            headers[header[0]] = header[1]
            
    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            params=request.args,
            json=request.get_json(silent=True)
        )
        
        logger.info(f"Response from {url}: {resp.status_code}")
        
        return Response(
            resp.content,
            status=resp.status_code,
            content_type=resp.headers.get('content-type', 'application/json')
        )
    except Exception as e:
        logger.exception(f"Proxy error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting EZRAX Grafana Proxy on port 5002")
    app.run(host='0.0.0.0', port=5002, debug=True)
