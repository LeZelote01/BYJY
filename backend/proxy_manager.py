#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Advanced Proxy Manager V1.0
Gestionnaire avancé de proxies et VPN pour furtivité maximale
Features: Tor Integration, Proxy Chaining, Quality Testing, Auto-Rotation
"""

import os
import sys
import time
import json
import random
import socket
import threading
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import logging
import requests
from urllib.parse import urlparse
import concurrent.futures
import re

logger = logging.getLogger(__name__)

# Import pour Tor/SOCKS
try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False
    logger.warning("⚠️ PySocks not available - Tor functionality limited")

class ProxyManager:
    """
    Gestionnaire avancé de proxies avec support Tor, rotation automatique et tests de qualité
    """
    
    def __init__(self, config_path: str = None):
        self.config_path = Path(config_path) if config_path else Path(__file__).parent.parent / "data" / "proxy_config.json"
        self.proxies = []
        self.current_proxy_index = 0
        self.proxy_stats = {}
        self.tor_available = False
        self.rotation_count = 0
        self.last_rotation = datetime.now()
        self.quality_check_interval = 1800  # 30 minutes au lieu de 5 minutes
        
        # Configuration
        self.config = {
            "auto_rotation": True,
            "rotation_interval": 50,  # requêtes avant rotation
            "quality_threshold": 0.7,  # Score minimum pour utiliser un proxy
            "timeout": 5,  # Réduit de 10 à 5 secondes
            "max_retries": 2,  # Réduit de 3 à 2
            "tor_enabled": False,  # Désactivé par défaut pour éviter les délais
            "proxy_chains": False,  # Désactivé par défaut
            "chain_length": 2,
            "monitoring_enabled": False,  # Désactivé par défaut pour accélérer le démarrage
            "monitoring_interval": 1800,  # 30 minutes
            "verbose_logging": False,  # Nouveau: contrôler la verbosité des logs
            "fetch_external_proxies": False,  # Nouveau: désactiver les appels externes
            "test_urls": [
                "http://httpbin.org/ip",
                "https://api.ipify.org",
                "http://icanhazip.com"
            ]
        }
        
        # Initialiser
        self._load_config()
        self._initialize_tor()
        self._load_proxy_sources()
        
        # Démarrer le monitoring seulement si activé
        if self.config.get("monitoring_enabled", True):
            self._start_quality_monitoring()
        else:
            logger.info("⚠️ Proxy quality monitoring is disabled")
        
        logger.info("✅ Advanced Proxy Manager initialized")
    
    def _load_config(self):
        """Charger la configuration des proxies"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    saved_config = json.load(f)
                self.config.update(saved_config)
            except Exception as e:
                logger.warning(f"Failed to load proxy config: {e}")
        
        self._save_config()
    
    def _save_config(self):
        """Sauvegarder la configuration"""
        try:
            self.config_path.parent.mkdir(exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save proxy config: {e}")
    
    def _initialize_tor(self):
        """Initialiser la connexion Tor"""
        if not self.config.get("tor_enabled", False):
            logger.info("ℹ️ Tor is disabled in configuration - can be enabled in stealth settings")
            return
            
        if not SOCKS_AVAILABLE:
            logger.warning("⚠️ PySocks not available - Tor functionality limited. Install with: pip install PySocks")
            return
        
        try:
            # Vérifier si Tor est en cours d'exécution
            self._check_tor_service()
            
            if self.tor_available:
                # Ajouter Tor à la liste des proxies
                tor_proxy = {
                    "id": "tor_default",
                    "type": "socks5",
                    "host": "127.0.0.1",
                    "port": 9050,
                    "username": None,
                    "password": None,
                    "country": "unknown",
                    "quality_score": 0.9,  # Score élevé par défaut pour Tor
                    "response_time": 0.0,
                    "last_tested": datetime.now().isoformat(),
                    "success_rate": 1.0,
                    "is_tor": True,
                    "active": True
                }
                
                self.proxies.append(tor_proxy)
                logger.info("✅ Tor network available and added to proxy list")
            else:
                logger.info("💡 Tor not available - you can enable it later in proxy settings")
            
        except Exception as e:
            logger.info(f"ℹ️ Tor initialization skipped: {e}")
            logger.info("💡 This is normal if Tor is not installed. You can install Tor and enable it in settings.")
    
    def _check_tor_service(self):
        """Vérifier si le service Tor est disponible"""
        if not SOCKS_AVAILABLE:
            logger.info("⚠️ PySocks not available - Tor functionality disabled")
            return
            
        if not self.config.get("tor_enabled", False):
            logger.info("ℹ️ Tor is disabled in configuration")
            return
            
        try:
            # Test de connexion SOCKS5 vers Tor
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            sock.settimeout(5)
            
            # Test de connexion vers un service connu
            sock.connect(("check.torproject.org", 80))
            sock.close()
            
            self.tor_available = True
            logger.info("✅ Tor service is running and accessible")
            
        except Exception as e:
            self.tor_available = False
            logger.info(f"ℹ️ Tor service not available (this is normal if not installed): {e}")
            logger.info("💡 To enable Tor: 1) Install Tor service 2) Enable in stealth configuration")
    
    def _load_proxy_sources(self):
        """Charger des proxies depuis différentes sources"""
        self.proxies = []  # Reset proxy list
        
        # 1. Charger Tor si disponible
        if self.tor_available:
            tor_proxy = {
                "id": "tor_default",
                "type": "socks5",
                "host": "127.0.0.1",
                "port": 9050,
                "username": None,
                "password": None,
                "country": "TOR",
                "quality_score": 0.9,
                "response_time": 0.0,
                "last_tested": datetime.now().isoformat(),
                "success_rate": 1.0,
                "is_tor": True,
                "active": True,
                "source": "tor"
            }
            self.proxies.append(tor_proxy)
        
        # 2. Charger des proxies publics depuis des APIs
        public_proxies = self._fetch_public_proxies()
        self.proxies.extend(public_proxies)
        
        # 3. Proxies de secours (statiques et fiables)
        fallback_proxies = [
            {"host": "httpbin.org", "port": 80, "type": "http", "country": "US"},
            {"host": "proxy.toolslib.net", "port": 8080, "type": "http", "country": "FR"},
            {"host": "proxy.novologic.com", "port": 3128, "type": "http", "country": "FR"},
        ]
        
        # Ajouter les proxies de secours
        for i, proxy_data in enumerate(fallback_proxies):
            proxy = {
                "id": f"fallback_{i}",
                "type": proxy_data["type"],
                "host": proxy_data["host"],
                "port": proxy_data["port"],
                "username": proxy_data.get("username"),
                "password": proxy_data.get("password"),
                "country": proxy_data.get("country", "unknown"),
                "quality_score": 0.0,
                "response_time": 0.0,
                "last_tested": None,
                "success_rate": 0.0,
                "is_tor": False,
                "active": False,
                "source": "fallback"
            }
            self.proxies.append(proxy)
        
        logger.info(f"✅ Loaded {len(self.proxies)} proxies from various sources")
    
    def _fetch_public_proxies(self) -> List[Dict]:
        """Récupérer des proxies publics depuis des sources fiables"""
        public_proxies = []
        
        # Vérifier si les appels externes sont activés
        if not self.config.get("fetch_external_proxies", False):
            logger.info("ℹ️ External proxy fetching is disabled - using only fallback proxies")
            return public_proxies
        
        # Source 1: ProxyScrape API
        try:
            proxyscrape_proxies = self._fetch_from_proxyscrape()
            public_proxies.extend(proxyscrape_proxies)
            logger.info(f"✅ Fetched {len(proxyscrape_proxies)} proxies from ProxyScrape")
        except Exception as e:
            logger.warning(f"⚠️ Failed to fetch from ProxyScrape: {e}")
        
        # Source 2: Free Proxy List API  
        try:
            freeproxy_proxies = self._fetch_from_freeproxy_api()
            public_proxies.extend(freeproxy_proxies)
            logger.info(f"✅ Fetched {len(freeproxy_proxies)} proxies from FreeProxy API")
        except Exception as e:
            logger.warning(f"⚠️ Failed to fetch from FreeProxy API: {e}")
        
        # Source 3: GitHub proxy lists (secours)
        try:
            github_proxies = self._fetch_from_github_sources()
            public_proxies.extend(github_proxies)
            logger.info(f"✅ Fetched {len(github_proxies)} proxies from GitHub sources")
        except Exception as e:
            logger.warning(f"⚠️ Failed to fetch from GitHub sources: {e}")
        
        # Filtrer et limiter le nombre de proxies
        filtered_proxies = self._filter_and_limit_proxies(public_proxies)
        
        return filtered_proxies
    
    def _fetch_from_proxyscrape(self) -> List[Dict]:
        """Récupérer des proxies depuis ProxyScrape API"""
        proxies = []
        
        # ProxyScrape API endpoints
        apis = [
            "https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
            "https://api.proxyscrape.com/v2/?request=get&protocol=socks5&timeout=5000&country=all"
        ]
        
        for api_url in apis:
            try:
                response = requests.get(api_url, timeout=3)  # Réduit de 10 à 3 secondes
                if response.status_code == 200:
                    proxy_list = response.text.strip().split('\n')
                    
                    for proxy_line in proxy_list[:10]:  # Limiter à 10 par source
                        if ':' in proxy_line:
                            host, port = proxy_line.strip().split(':')
                            proxy_type = 'socks5' if 'socks5' in api_url else 'http'
                            
                            proxy = {
                                "id": f"proxyscrape_{len(proxies)}",
                                "type": proxy_type,
                                "host": host,
                                "port": int(port),
                                "username": None,
                                "password": None,
                                "country": "unknown",
                                "quality_score": 0.0,
                                "response_time": 0.0,
                                "last_tested": None,
                                "success_rate": 0.0,
                                "is_tor": False,
                                "active": False,
                                "source": "proxyscrape"
                            }
                            proxies.append(proxy)
                            
            except Exception as e:
                logger.debug(f"ProxyScrape API error: {e}")
                continue
        
        return proxies
    
    def _fetch_from_freeproxy_api(self) -> List[Dict]:
        """Récupérer des proxies depuis des APIs de proxies gratuits"""
        proxies = []
        
        # Liste de proxies publics connus et fiables
        known_proxies = [
            {"host": "20.203.61.207", "port": 80, "type": "http", "country": "US"},
            {"host": "51.75.126.150", "port": 3128, "type": "http", "country": "FR"},
            {"host": "103.148.72.126", "port": 80, "type": "http", "country": "BD"},
            {"host": "165.154.243.252", "port": 80, "type": "http", "country": "US"},
            {"host": "190.110.111.148", "port": 999, "type": "http", "country": "EC"},
            {"host": "103.127.1.130", "port": 80, "type": "http", "country": "BD"},
            {"host": "157.230.34.152", "port": 80, "type": "http", "country": "US"},
            {"host": "195.158.18.80", "port": 3128, "type": "http", "country": "FR"},
            {"host": "103.148.72.192", "port": 80, "type": "http", "country": "BD"},
            {"host": "41.65.236.43", "port": 1981, "type": "http", "country": "TN"}
        ]
        
        for i, proxy_data in enumerate(known_proxies):
            proxy = {
                "id": f"freeproxy_{i}",
                "type": proxy_data["type"],
                "host": proxy_data["host"],
                "port": proxy_data["port"],
                "username": None,
                "password": None,
                "country": proxy_data["country"],
                "quality_score": 0.0,
                "response_time": 0.0,
                "last_tested": None,
                "success_rate": 0.0,
                "is_tor": False,
                "active": False,
                "source": "freeproxy_api"
            }
            proxies.append(proxy)
        
        return proxies
    
    def _fetch_from_github_sources(self) -> List[Dict]:
        """Récupérer des proxies depuis des sources GitHub publiques"""
        proxies = []
        
        # Sources GitHub connues pour les proxies
        github_sources = [
            "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
            "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt"
        ]
        
        for source_url in github_sources:
            try:
                response = requests.get(source_url, timeout=10)
                if response.status_code == 200:
                    proxy_lines = response.text.strip().split('\n')
                    
                    for proxy_line in proxy_lines[:5]:  # Limiter à 5 par source
                        if ':' in proxy_line and '.' in proxy_line:
                            try:
                                host, port = proxy_line.strip().split(':')
                                # Validation basique de l'IP
                                if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
                                    proxy = {
                                        "id": f"github_{len(proxies)}",
                                        "type": "http",
                                        "host": host,
                                        "port": int(port),
                                        "username": None,
                                        "password": None,
                                        "country": "unknown",
                                        "quality_score": 0.0,
                                        "response_time": 0.0,
                                        "last_tested": None,
                                        "success_rate": 0.0,
                                        "is_tor": False,
                                        "active": False,
                                        "source": "github"
                                    }
                                    proxies.append(proxy)
                            except (ValueError, IndexError):
                                continue
                                
            except Exception as e:
                logger.debug(f"GitHub source error for {source_url}: {e}")
                continue
        
        return proxies
    
    def _filter_and_limit_proxies(self, proxies: List[Dict]) -> List[Dict]:
        """Filtrer et limiter le nombre de proxies"""
        # Supprimer les doublons basés sur host:port
        seen = set()
        unique_proxies = []
        
        for proxy in proxies:
            key = f"{proxy['host']}:{proxy['port']}"
            if key not in seen:
                seen.add(key)
                unique_proxies.append(proxy)
        
        # Limiter à 20 proxies maximum pour éviter la surcharge
        limited_proxies = unique_proxies[:20]
        
        logger.info(f"✅ Filtered to {len(limited_proxies)} unique proxies")
        return limited_proxies
    
    def refresh_proxy_sources(self) -> Dict[str, Any]:
        """Actualiser la liste des proxies depuis toutes les sources"""
        logger.info("🔄 Refreshing proxy sources...")
        
        old_count = len(self.proxies)
        
        # Sauvegarder les statistiques des proxies existants
        old_stats = {}
        for proxy in self.proxies:
            key = f"{proxy['host']}:{proxy['port']}"
            old_stats[key] = {
                'quality_score': proxy.get('quality_score', 0.0),
                'success_rate': proxy.get('success_rate', 0.0),
                'response_time': proxy.get('response_time', 0.0)
            }
        
        # Recharger les sources
        self._initialize_tor()
        self._load_proxy_sources()
        
        # Restaurer les statistiques pour les proxies qui existent encore
        for proxy in self.proxies:
            key = f"{proxy['host']}:{proxy['port']}"
            if key in old_stats:
                proxy['quality_score'] = old_stats[key]['quality_score']
                proxy['success_rate'] = old_stats[key]['success_rate']
                proxy['response_time'] = old_stats[key]['response_time']
                proxy['active'] = proxy['quality_score'] >= self.config['quality_threshold']
        
        new_count = len(self.proxies)
        
        result = {
            "message": "Proxy sources refreshed successfully",
            "old_count": old_count,
            "new_count": new_count,
            "added": new_count - old_count,
            "sources": list(set(p.get('source', 'unknown') for p in self.proxies)),
            "countries": list(set(p.get('country', 'unknown') for p in self.proxies))
        }
        
        logger.info(f"✅ Proxy refresh completed: {old_count} → {new_count} proxies")
        return result
    
    def _start_quality_monitoring(self):
        """Démarrer le monitoring de qualité en arrière-plan"""
        monitoring_interval = self.config.get("monitoring_interval", 1800)
        
        def monitoring_loop():
            while True:
                try:
                    self.test_all_proxies()
                    time.sleep(monitoring_interval)
                except Exception as e:
                    logger.error(f"Proxy monitoring error: {e}")
                    time.sleep(60)
        
        monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitor_thread.start()
        logger.info(f"✅ Proxy quality monitoring started (interval: {monitoring_interval}s)")
    
    def test_proxy(self, proxy: Dict[str, Any]) -> Dict[str, Any]:
        """Tester la qualité d'un proxy individuel"""
        start_time = time.time()
        test_results = {
            "success": False,
            "response_time": 0.0,
            "ip_leaked": False,
            "working_urls": 0,
            "total_urls": len(self.config["test_urls"]),
            "error": None
        }
        
        try:
            # Configuration du proxy pour requests
            proxy_url = self._format_proxy_url(proxy)
            proxies_config = {
                "http": proxy_url,
                "https": proxy_url
            }
            
            # Tester plusieurs URLs
            working_count = 0
            total_response_time = 0.0
            
            for test_url in self.config["test_urls"]:
                try:
                    response = requests.get(
                        test_url,
                        proxies=proxies_config,
                        timeout=self.config["timeout"],
                        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                    )
                    
                    if response.status_code == 200:
                        working_count += 1
                        total_response_time += time.time() - start_time
                        
                        # Vérifier si l'IP a fuité
                        if "ip" in test_url.lower():
                            response_ip = response.text.strip()
                            if response_ip == self._get_real_ip():
                                test_results["ip_leaked"] = True
                    
                except requests.RequestException as e:
                    logger.debug(f"Test failed for {test_url} via {proxy['host']}: {e}")
                    continue
            
            test_results["working_urls"] = working_count
            test_results["success"] = working_count > 0
            test_results["response_time"] = total_response_time / max(working_count, 1)
            
            # Calculer le score de qualité
            quality_score = (working_count / len(self.config["test_urls"])) * 0.7
            if test_results["response_time"] < 2.0:
                quality_score += 0.2
            if not test_results["ip_leaked"]:
                quality_score += 0.1
            
            proxy["quality_score"] = quality_score
            proxy["response_time"] = test_results["response_time"]
            proxy["last_tested"] = datetime.now().isoformat()
            proxy["active"] = quality_score >= self.config["quality_threshold"]
            
            # Mettre à jour les statistiques
            proxy_id = proxy["id"]
            if proxy_id not in self.proxy_stats:
                self.proxy_stats[proxy_id] = {"tests": 0, "successes": 0}
            
            self.proxy_stats[proxy_id]["tests"] += 1
            if test_results["success"]:
                self.proxy_stats[proxy_id]["successes"] += 1
            
            proxy["success_rate"] = self.proxy_stats[proxy_id]["successes"] / self.proxy_stats[proxy_id]["tests"]
            
            logger.debug(f"Proxy {proxy['host']}:{proxy['port']} - Quality: {quality_score:.2f}")
            
        except Exception as e:
            test_results["error"] = str(e)
            proxy["active"] = False
            logger.warning(f"Proxy test error for {proxy['host']}:{proxy['port']}: {e}")
        
        return test_results
    
    def test_all_proxies(self):
        """Tester tous les proxies en parallèle"""
        verbose_logging = self.config.get("verbose_logging", False)
        
        if verbose_logging:
            logger.info("🔍 Testing all proxies for quality...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.test_proxy, proxy): proxy for proxy in self.proxies}
            
            for future in concurrent.futures.as_completed(futures):
                proxy = futures[future]
                try:
                    result = future.result()
                    if verbose_logging:
                        if result["success"]:
                            logger.debug(f"✅ Proxy {proxy['host']} passed quality test")
                        else:
                            logger.debug(f"❌ Proxy {proxy['host']} failed quality test")
                except Exception as e:
                    if verbose_logging:
                        logger.warning(f"Proxy test exception for {proxy['host']}: {e}")
        
        active_count = len([p for p in self.proxies if p.get("active", False)])
        
        # Toujours afficher le résumé final, mais moins fréquemment
        if verbose_logging or (hasattr(self, '_last_summary_time') and 
                              (datetime.now() - self._last_summary_time).total_seconds() > 3600):
            logger.info(f"✅ Proxy testing completed - {active_count}/{len(self.proxies)} proxies active")
            self._last_summary_time = datetime.now()
        elif not hasattr(self, '_last_summary_time'):
            logger.info(f"✅ Proxy testing completed - {active_count}/{len(self.proxies)} proxies active")
            self._last_summary_time = datetime.now()
    
    def get_best_proxy(self, country: str = None, proxy_type: str = None) -> Optional[Dict[str, Any]]:
        """Obtenir le meilleur proxy selon les critères"""
        available_proxies = [p for p in self.proxies if p.get("active", False)]
        
        if not available_proxies:
            logger.warning("⚠️ No active proxies available")
            return None
        
        # Filtrer par pays si spécifié
        if country:
            country_proxies = [p for p in available_proxies if p.get("country", "").upper() == country.upper()]
            if country_proxies:
                available_proxies = country_proxies
        
        # Filtrer par type si spécifié
        if proxy_type:
            type_proxies = [p for p in available_proxies if p.get("type", "") == proxy_type]
            if type_proxies:
                available_proxies = type_proxies
        
        # Trier par score de qualité
        available_proxies.sort(key=lambda x: x.get("quality_score", 0), reverse=True)
        
        return available_proxies[0] if available_proxies else None
    
    def get_current_proxy(self) -> Optional[Dict[str, Any]]:
        """Obtenir le proxy actuellement utilisé"""
        active_proxies = [p for p in self.proxies if p.get("active", False)]
        
        if not active_proxies:
            return None
        
        if self.current_proxy_index >= len(active_proxies):
            self.current_proxy_index = 0
        
        return active_proxies[self.current_proxy_index]
    
    def rotate_proxy(self) -> Optional[Dict[str, Any]]:
        """Effectuer une rotation vers le prochain proxy"""
        active_proxies = [p for p in self.proxies if p.get("active", False)]
        
        if len(active_proxies) <= 1:
            return self.get_current_proxy()
        
        self.current_proxy_index = (self.current_proxy_index + 1) % len(active_proxies)
        self.rotation_count += 1
        self.last_rotation = datetime.now()
        
        current = self.get_current_proxy()
        if current:
            logger.info(f"🔄 Rotated to proxy: {current['host']}:{current['port']} ({current['country']})")
        
        return current
    
    def get_proxy_config_for_requests(self, proxy: Dict[str, Any] = None) -> Dict[str, str]:
        """Obtenir la configuration proxy pour requests"""
        if not proxy:
            proxy = self.get_current_proxy()
        
        if not proxy:
            return {}
        
        proxy_url = self._format_proxy_url(proxy)
        return {
            "http": proxy_url,
            "https": proxy_url
        }
    
    def _format_proxy_url(self, proxy: Dict[str, Any]) -> str:
        """Formater l'URL du proxy"""
        auth = ""
        if proxy.get("username") and proxy.get("password"):
            auth = f"{proxy['username']}:{proxy['password']}@"
        
        return f"{proxy['type']}://{auth}{proxy['host']}:{proxy['port']}"
    
    def _get_real_ip(self) -> str:
        """Obtenir la vraie adresse IP (sans proxy)"""
        try:
            response = requests.get("https://api.ipify.org", timeout=5)
            return response.text.strip()
        except:
            return "unknown"
    
    def get_anonymity_status(self) -> Dict[str, Any]:
        """Vérifier le statut d'anonymat actuel"""
        current_proxy = self.get_current_proxy()
        
        if not current_proxy:
            return {
                "anonymous": False,
                "current_ip": self._get_real_ip(),
                "proxy_used": None,
                "tor_active": False
            }
        
        try:
            # Tester l'IP avec le proxy actuel
            proxy_config = self.get_proxy_config_for_requests(current_proxy)
            response = requests.get("https://api.ipify.org", proxies=proxy_config, timeout=10)
            proxy_ip = response.text.strip()
            real_ip = self._get_real_ip()
            
            return {
                "anonymous": proxy_ip != real_ip,
                "current_ip": proxy_ip,
                "real_ip": real_ip,
                "proxy_used": f"{current_proxy['host']}:{current_proxy['port']}",
                "proxy_country": current_proxy.get("country", "unknown"),
                "tor_active": current_proxy.get("is_tor", False)
            }
            
        except Exception as e:
            logger.error(f"Failed to check anonymity status: {e}")
            return {
                "anonymous": False,
                "error": str(e),
                "proxy_used": f"{current_proxy['host']}:{current_proxy['port']}"
            }
    
    def get_proxy_statistics(self) -> Dict[str, Any]:
        """Obtenir les statistiques des proxies"""
        active_count = len([p for p in self.proxies if p.get("active", False)])
        total_count = len(self.proxies)
        
        if not self.proxies:
            return {"error": "No proxies configured"}
        
        avg_quality = sum(p.get("quality_score", 0) for p in self.proxies) / total_count
        avg_response_time = sum(p.get("response_time", 0) for p in self.proxies if p.get("response_time", 0) > 0)
        avg_response_time = avg_response_time / max(1, len([p for p in self.proxies if p.get("response_time", 0) > 0]))
        
        countries = {}
        types = {}
        
        for proxy in self.proxies:
            country = proxy.get("country", "unknown")
            proxy_type = proxy.get("type", "unknown")
            
            countries[country] = countries.get(country, 0) + 1
            types[proxy_type] = types.get(proxy_type, 0) + 1
        
        return {
            "total_proxies": total_count,
            "active_proxies": active_count,
            "success_rate": (active_count / total_count) * 100 if total_count > 0 else 0,
            "average_quality": avg_quality,
            "average_response_time": avg_response_time,
            "rotation_count": self.rotation_count,
            "last_rotation": self.last_rotation.isoformat(),
            "tor_available": self.tor_available,
            "countries": countries,
            "types": types,
            "current_proxy": self.get_current_proxy()
        }

# Factory functions
def get_proxy_manager(config_path: str = None) -> ProxyManager:
    """Obtenir une instance du gestionnaire de proxies"""
    return ProxyManager(config_path)

# Global instance
_proxy_manager = None

def get_global_proxy_manager() -> ProxyManager:
    """Obtenir l'instance globale du gestionnaire de proxies"""
    global _proxy_manager
    if _proxy_manager is None:
        _proxy_manager = get_proxy_manager()
    return _proxy_manager