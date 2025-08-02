#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Stealth Engine V1.0
Moteur central de furtivité et d'évasion pour tous les modules
Features: Anti-détection, Obfuscation, Proxy Management, Timing Control
"""

import os
import sys
import time
import random
import hashlib
import base64
import json
import requests
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import logging
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

class StealthEngine:
    """
    Moteur central de furtivité pour le CyberSec Assistant
    Gère tous les aspects d'évasion et de masquage
    """
    
    def __init__(self, config_path: str = None):
        self.config_path = Path(config_path) if config_path else Path(__file__).parent.parent / "data" / "stealth_config.json"
        self.proxies_list = []
        self.user_agents = []
        self.current_proxy_index = 0
        self.stealth_score = 100.0
        self.detection_alerts = []
        self.obfuscation_enabled = True
        self.anti_forensics_enabled = True
        
        # Initialiser la configuration
        self._load_stealth_config()
        self._load_user_agents()
        self._load_proxies()
        
        # Démarrer le monitoring de furtivité
        self._start_stealth_monitoring()
    
    def _load_stealth_config(self):
        """Charger la configuration de furtivité"""
        default_config = {
            "stealth_level": 10,  # 1-10, 10 = maximum stealth
            "obfuscation_level": 10,
            "anti_detection": True,
            "proxy_rotation": True,
            "timing_randomization": True,
            "user_agent_rotation": True,
            "process_masking": True,
            "memory_encryption": True,
            "network_evasion": True,
            "forensics_cleanup": True,
            "min_request_delay": 2.0,
            "max_request_delay": 8.0,
            "max_requests_per_minute": 12,
            "proxy_rotation_interval": 50,  # requêtes avant rotation
            "detection_threshold": 3,  # alertes avant arrêt automatique
            "profiles": {
                "maximum_stealth": {
                    "stealth_level": 10,
                    "min_request_delay": 5.0,
                    "max_request_delay": 15.0,
                    "max_requests_per_minute": 4
                },
                "balanced": {
                    "stealth_level": 7,
                    "min_request_delay": 1.0,
                    "max_request_delay": 4.0,
                    "max_requests_per_minute": 20
                },
                "fast_recon": {
                    "stealth_level": 5,
                    "min_request_delay": 0.5,
                    "max_request_delay": 2.0,
                    "max_requests_per_minute": 60
                }
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    saved_config = json.load(f)
                default_config.update(saved_config)
            except Exception as e:
                logger.warning(f"Failed to load stealth config: {e}")
        
        self.config = default_config
        self._save_stealth_config()
    
    def _save_stealth_config(self):
        """Sauvegarder la configuration de furtivité"""
        try:
            self.config_path.parent.mkdir(exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save stealth config: {e}")
    
    def _load_user_agents(self):
        """Charger la liste des User-Agents légitimes"""
        self.user_agents = [
            # Chrome Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            
            # Firefox Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0",
            
            # Chrome macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            
            # Safari macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
            
            # Chrome Linux
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
            
            # Edge Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
            
            # Mobile User Agents
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/119.0 Firefox/119.0",
            "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36"
        ]
        
        logger.info(f"✅ Loaded {len(self.user_agents)} legitimate user agents")
    
    def _load_proxies(self):
        """Charger la liste des proxies (Tor, HTTP, SOCKS)"""
        # Proxies par défaut (à remplacer par des proxies réels en production)
        self.proxies_list = [
            {"type": "tor", "host": "127.0.0.1", "port": 9050, "active": False},
            {"type": "http", "host": "proxy1.example.com", "port": 8080, "active": False},
            {"type": "socks5", "host": "proxy2.example.com", "port": 1080, "active": False}
        ]
        
        # Vérifier la disponibilité de Tor
        self._check_tor_availability()
        
        logger.info(f"✅ Loaded {len(self.proxies_list)} proxy configurations")
    
    def _check_tor_availability(self):
        """Vérifier si Tor est disponible"""
        if not self.config.get("tor_enabled", False):
            logger.info("ℹ️ Tor is disabled in stealth configuration")
            return
            
        try:
            import socks
            import socket
            
            # Test de connexion Tor
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket
            
            # Test simple
            test_socket = socket.socket()
            test_socket.settimeout(5)
            test_socket.connect(("check.torproject.org", 80))
            test_socket.close()
            
            # Marquer Tor comme actif
            for proxy in self.proxies_list:
                if proxy["type"] == "tor":
                    proxy["active"] = True
            
            logger.info("✅ Tor network is available")
            
        except ImportError:
            logger.info("ℹ️ PySocks not available - Tor functionality disabled. Install with: pip install PySocks")
        except Exception as e:
            logger.info(f"ℹ️ Tor network not available (this is normal if not installed): {e}")
            logger.info("💡 To enable Tor: 1) Install Tor service 2) Enable in stealth configuration")
    
    def _start_stealth_monitoring(self):
        """Démarrer le monitoring de furtivité en arrière-plan"""
        def monitoring_loop():
            while True:
                self._update_stealth_score()
                self._check_detection_alerts()
                time.sleep(30)  # Check every 30 seconds
        
        monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
        monitor_thread.start()
        logger.info("✅ Stealth monitoring started")
    
    def get_random_user_agent(self) -> str:
        """Obtenir un User-Agent aléatoire légitime"""
        return random.choice(self.user_agents)
    
    def get_stealth_headers(self, target_url: str = None) -> Dict[str, str]:
        """Générer des headers HTTP furtifs et légitimes"""
        headers = {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice([
                "en-US,en;q=0.5", "en-GB,en;q=0.5", "fr-FR,fr;q=0.5", 
                "de-DE,de;q=0.5", "es-ES,es;q=0.5"
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": random.choice(["1", "0"]),
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Cache-Control": random.choice(["no-cache", "max-age=0"]),
        }
        
        # Ajouter le Referer si nécessaire
        if target_url and random.random() > 0.3:  # 70% chance d'avoir un referer
            parsed_url = urlparse(target_url)
            potential_referers = [
                f"https://www.google.com/search?q={parsed_url.netloc}",
                f"https://duckduckgo.com/?q={parsed_url.netloc}",
                f"https://{parsed_url.netloc}",
                "https://www.google.com/",
                "https://www.bing.com/"
            ]
            headers["Referer"] = random.choice(potential_referers)
        
        return headers
    
    def get_current_proxy(self) -> Optional[Dict[str, Any]]:
        """Obtenir le proxy actuel pour les requêtes"""
        if not self.config.get("proxy_rotation", False):
            return None
        
        if not self.proxies_list:
            return None
        
        # Rotation automatique des proxies
        if self.current_proxy_index >= len(self.proxies_list):
            self.current_proxy_index = 0
        
        proxy = self.proxies_list[self.current_proxy_index]
        
        if proxy.get("active", False):
            return {
                "http": f"socks5://{proxy['host']}:{proxy['port']}" if proxy["type"] == "tor" 
                       else f"{proxy['type']}://{proxy['host']}:{proxy['port']}",
                "https": f"socks5://{proxy['host']}:{proxy['port']}" if proxy["type"] == "tor"
                        else f"{proxy['type']}://{proxy['host']}:{proxy['port']}"
            }
        
        return None
    
    def rotate_proxy(self):
        """Effectuer une rotation manuelle des proxies"""
        if self.proxies_list:
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies_list)
            logger.debug(f"🔄 Proxy rotated to index {self.current_proxy_index}")
    
    def apply_stealth_timing(self, base_delay: float = None) -> float:
        """Appliquer un délai aléatoire pour éviter la détection"""
        if not base_delay:
            min_delay = self.config.get("min_request_delay", 1.0)
            max_delay = self.config.get("max_request_delay", 5.0)
        else:
            min_delay = base_delay * 0.5
            max_delay = base_delay * 2.0
        
        # Délai avec distribution normale pour plus de réalisme
        mean_delay = (min_delay + max_delay) / 2
        std_dev = (max_delay - min_delay) / 6
        delay = max(min_delay, random.normalvariate(mean_delay, std_dev))
        
        time.sleep(delay)
        return delay
    
    def obfuscate_string(self, text: str) -> str:
        """Obfusquer une chaîne de caractères"""
        if not self.obfuscation_enabled:
            return text
        
        obfuscation_level = self.config.get("obfuscation_level", 5)
        
        if obfuscation_level >= 8:
            # Chiffrement AES
            key = Fernet.generate_key()
            f = Fernet(key)
            encrypted = f.encrypt(text.encode())
            return base64.b64encode(encrypted).decode()
        
        elif obfuscation_level >= 5:
            # XOR simple avec clé
            key = random.randint(1, 255)
            obfuscated = ''.join(chr(ord(c) ^ key) for c in text)
            return base64.b64encode(obfuscated.encode()).decode()
        
        else:
            # Base64 simple
            return base64.b64encode(text.encode()).decode()
    
    def deobfuscate_string(self, obfuscated_text: str, method: str = "auto") -> str:
        """Désobfusquer une chaîne de caractères"""
        try:
            # Auto-détection du méthode (simple pour l'exemple)
            decoded = base64.b64decode(obfuscated_text.encode()).decode()
            return decoded
        except Exception:
            return obfuscated_text
    
    def create_stealth_session(self) -> requests.Session:
        """Créer une session HTTP furtive"""
        session = requests.Session()
        
        # Appliquer les headers furtifs
        session.headers.update(self.get_stealth_headers())
        
        # Configurer les proxies si activés
        proxy_config = self.get_current_proxy()
        if proxy_config:
            session.proxies.update(proxy_config)
        
        # Configurer les timeouts
        session.timeout = (10, 30)  # (connect, read)
        
        # Désactiver les redirects automatiques pour plus de contrôle
        session.max_redirects = 3
        
        return session
    
    def stealth_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Effectuer une requête HTTP furtive"""
        session = self.create_stealth_session()
        
        # Appliquer le délai de furtivité
        self.apply_stealth_timing()
        
        # Log de la requête (obfusqué)
        logger.debug(f"🕵️ Stealth {method.upper()} request to {self.obfuscate_string(url)}")
        
        try:
            response = session.request(method, url, **kwargs)
            
            # Vérifier les indicateurs de détection
            self._check_response_for_detection(response)
            
            # Rotation automatique des proxies
            if self.current_proxy_index % self.config.get("proxy_rotation_interval", 50) == 0:
                self.rotate_proxy()
            
            return response
            
        except Exception as e:
            logger.warning(f"⚠️ Stealth request failed: {e}")
            raise
        finally:
            session.close()
    
    def _check_response_for_detection(self, response: requests.Response):
        """Vérifier la réponse pour des signes de détection"""
        detection_indicators = [
            "blocked", "forbidden", "rate limit", "captcha", 
            "bot detected", "security", "firewall", "protection"
        ]
        
        response_text = response.text.lower()
        
        for indicator in detection_indicators:
            if indicator in response_text:
                self._add_detection_alert(f"Possible detection: {indicator} in response")
                break
        
        # Vérifier les codes de statut suspects
        if response.status_code in [403, 429, 503]:
            self._add_detection_alert(f"Suspicious HTTP status: {response.status_code}")
        
        # Vérifier les headers suspects
        suspicious_headers = ["cf-ray", "x-blocked-by", "x-security"]
        for header in response.headers:
            if any(suspect in header.lower() for suspect in suspicious_headers):
                self._add_detection_alert(f"Suspicious header detected: {header}")
    
    def _add_detection_alert(self, message: str):
        """Ajouter une alerte de détection"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "severity": "warning"
        }
        
        self.detection_alerts.append(alert)
        self.stealth_score = max(0, self.stealth_score - 5)
        
        logger.warning(f"🚨 Detection alert: {message}")
        
        # Arrêt automatique si trop d'alertes
        if len(self.detection_alerts) >= self.config.get("detection_threshold", 3):
            logger.critical("🛑 Too many detection alerts - enabling maximum stealth mode")
            self.enable_profile("maximum_stealth")
    
    def _update_stealth_score(self):
        """Mettre à jour le score de furtivité"""
        base_score = 100.0
        
        # Pénalités basées sur les alertes récentes
        recent_alerts = [
            alert for alert in self.detection_alerts 
            if datetime.fromisoformat(alert["timestamp"]) > datetime.now() - timedelta(hours=1)
        ]
        
        alert_penalty = len(recent_alerts) * 10
        self.stealth_score = max(0, base_score - alert_penalty)
        
        # Récupération progressive si pas d'alertes récentes
        if not recent_alerts:
            self.stealth_score = min(100, self.stealth_score + 1)
    
    def _check_detection_alerts(self):
        """Vérifier et nettoyer les alertes anciennes"""
        # Supprimer les alertes de plus de 24h
        cutoff_time = datetime.now() - timedelta(hours=24)
        self.detection_alerts = [
            alert for alert in self.detection_alerts
            if datetime.fromisoformat(alert["timestamp"]) > cutoff_time
        ]
    
    def enable_profile(self, profile_name: str):
        """Activer un profil de furtivité"""
        if profile_name not in self.config.get("profiles", {}):
            logger.error(f"❌ Unknown stealth profile: {profile_name}")
            return False
        
        profile = self.config["profiles"][profile_name]
        
        # Appliquer les paramètres du profil
        for key, value in profile.items():
            self.config[key] = value
        
        logger.info(f"✅ Stealth profile '{profile_name}' activated")
        self._save_stealth_config()
        return True
    
    def get_stealth_status(self) -> Dict[str, Any]:
        """Obtenir le statut complet de furtivité"""
        return {
            "stealth_score": self.stealth_score,
            "stealth_level": self.config.get("stealth_level", 5),
            "obfuscation_enabled": self.obfuscation_enabled,
            "proxy_rotation": self.config.get("proxy_rotation", False),
            "active_proxies": len([p for p in self.proxies_list if p.get("active", False)]),
            "detection_alerts": len(self.detection_alerts),
            "recent_alerts": len([
                alert for alert in self.detection_alerts 
                if datetime.fromisoformat(alert["timestamp"]) > datetime.now() - timedelta(hours=1)
            ]),
            "anti_forensics": self.anti_forensics_enabled,
            "current_profile": self._get_current_profile(),
            "last_updated": datetime.now().isoformat()
        }
    
    def _get_current_profile(self) -> str:
        """Déterminer le profil actuel basé sur la configuration"""
        current_level = self.config.get("stealth_level", 5)
        
        if current_level >= 9:
            return "maximum_stealth"
        elif current_level >= 6:
            return "balanced" 
        else:
            return "fast_recon"
    
    async def get_stealth_profile(self, profile_type: str = "default") -> Dict[str, Any]:
        """Obtenir un profil de furtivité spécifique pour un type d'analyse"""
        profile_configs = {
            "default": {
                "file_access_delay": 0.5,
                "memory_access_delay": 1.0,
                "network_request_delay": 2.0,
                "stealth_techniques": ["obfuscation", "timing_randomization"],
                "anti_detection": True
            },
            "file_analysis": {
                "file_access_delay": 0.2,
                "timestamp_preservation": True,
                "memory_mapped_access": True,
                "stealth_techniques": ["hardlink_access", "timestamp_restoration"],
                "anti_detection": True
            },
            "memory_analysis": {
                "memory_access_delay": 0.5,
                "process_hiding": True,
                "kernel_level_access": True,
                "stealth_techniques": ["memory_dumping_furtif", "anti_debug"],
                "anti_detection": True
            },
            "network_analysis": {
                "packet_delay": 1.0,
                "capture_filtering": True,
                "monitor_mode": True,
                "stealth_techniques": ["monitor_mode_stealth", "packet_fragmentation"],
                "anti_detection": True
            },
            "forensic_analysis": {
                "file_access_delay": 0.1,
                "timeline_obfuscation": True,
                "evidence_preservation": True,
                "stealth_techniques": ["indirect_access", "metadata_preservation"],
                "anti_detection": True
            }
        }
        
        # Retourner le profil demandé ou le profil par défaut
        return profile_configs.get(profile_type, profile_configs["default"])
    
    async def calculate_stealth_score(self) -> float:
        """Calculer le score de furtivité actuel"""
        return self.stealth_score / 100.0
    
    def cleanup_forensics(self):
        """Nettoyage anti-forensique"""
        if not self.anti_forensics_enabled:
            return
        
        try:
            # Nettoyer les logs temporaires
            temp_logs = [
                "/tmp/stealth_*.log",
                "/var/tmp/stealth_*.tmp",
                "~/.cache/stealth/*"
            ]
            
            for pattern in temp_logs:
                for file_path in Path(pattern).parent.glob(Path(pattern).name):
                    if file_path.exists():
                        file_path.unlink()
            
            # Nettoyer l'historique des commandes (si applicable)
            history_files = [
                Path.home() / ".bash_history",
                Path.home() / ".zsh_history",
                Path.home() / ".python_history"
            ]
            
            for hist_file in history_files:
                if hist_file.exists():
                    # Supprimer les dernières entrées liées au stealth
                    with open(hist_file, 'r') as f:
                        lines = f.readlines()
                    
                    cleaned_lines = [
                        line for line in lines 
                        if not any(keyword in line.lower() for keyword in 
                                 ['stealth', 'nmap', 'scan', 'brute', 'hack'])
                    ]
                    
                    with open(hist_file, 'w') as f:
                        f.writelines(cleaned_lines)
            
            logger.info("🧹 Anti-forensics cleanup completed")
            
        except Exception as e:
            logger.warning(f"⚠️ Anti-forensics cleanup failed: {e}")

# Factory function
def get_stealth_engine(config_path: str = None) -> StealthEngine:
    """Obtenir une instance du moteur de furtivité"""
    return StealthEngine(config_path)

# Global instance
_stealth_engine = None

def get_global_stealth_engine() -> StealthEngine:
    """Obtenir l'instance globale du moteur de furtivité"""
    global _stealth_engine
    if _stealth_engine is None:
        _stealth_engine = get_stealth_engine()
    return _stealth_engine