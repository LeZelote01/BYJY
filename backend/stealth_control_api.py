#!/usr/bin/env python3
"""
API endpoints pour contrôler les fonctionnalités de furtivité (Tor/Proxy)
Permet d'activer/désactiver dynamiquement depuis l'interface utilisateur
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from stealth_engine import get_global_stealth_engine
from proxy_manager import get_global_proxy_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/stealth-control", tags=["stealth-control"])

class StealthConfigUpdate(BaseModel):
    tor_enabled: Optional[bool] = None
    proxy_rotation: Optional[bool] = None
    monitoring_enabled: Optional[bool] = None
    stealth_level: Optional[int] = None
    profile: Optional[str] = None

class ProxyConfigUpdate(BaseModel):
    tor_enabled: Optional[bool] = None
    auto_rotation: Optional[bool] = None
    monitoring_enabled: Optional[bool] = None
    verbose_logging: Optional[bool] = None

@router.get("/status")
async def get_stealth_status():
    """Obtenir le statut complet des fonctionnalités de furtivité"""
    try:
        stealth_engine = get_global_stealth_engine()
        proxy_manager = get_global_proxy_manager()
        
        stealth_status = stealth_engine.get_stealth_status()
        proxy_stats = proxy_manager.get_proxy_statistics()
        
        return {
            "stealth": stealth_status,
            "proxy": proxy_stats,
            "tor_available": proxy_manager.tor_available,
            "tor_enabled": stealth_engine.config.get("tor_enabled", False),
            "proxy_rotation_enabled": stealth_engine.config.get("proxy_rotation", False),
            "monitoring_enabled": proxy_manager.config.get("monitoring_enabled", False),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get stealth status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stealth status: {e}")

@router.get("/profiles")
async def get_stealth_profiles():
    """Obtenir la liste des profils de furtivité disponibles"""
    try:
        stealth_engine = get_global_stealth_engine()
        profiles = stealth_engine.config.get("profiles", {})
        
        return {
            "profiles": profiles,
            "current_profile": stealth_engine._get_current_profile(),
            "available_profiles": list(profiles.keys())
        }
    except Exception as e:
        logger.error(f"Failed to get stealth profiles: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stealth profiles: {e}")

@router.post("/enable-tor")
async def enable_tor():
    """Activer Tor et les fonctionnalités proxy"""
    try:
        stealth_engine = get_global_stealth_engine()
        proxy_manager = get_global_proxy_manager()
        
        # Mettre à jour les configurations
        stealth_engine.config["tor_enabled"] = True
        stealth_engine.config["proxy_rotation"] = True
        proxy_manager.config["tor_enabled"] = True
        proxy_manager.config["auto_rotation"] = True
        proxy_manager.config["monitoring_enabled"] = True
        
        # Sauvegarder les configurations
        stealth_engine._save_stealth_config()
        proxy_manager._save_config()
        
        # Ré-initialiser Tor
        proxy_manager._initialize_tor()
        stealth_engine._check_tor_availability()
        
        # Démarrer le monitoring si pas déjà fait
        if not hasattr(proxy_manager, '_monitoring_started'):
            proxy_manager._start_quality_monitoring()
            proxy_manager._monitoring_started = True
        
        return {
            "message": "Tor enabled successfully",
            "tor_available": proxy_manager.tor_available,
            "active_proxies": len([p for p in proxy_manager.proxies if p.get("active", False)]),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to enable Tor: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to enable Tor: {e}")

@router.post("/disable-tor")
async def disable_tor():
    """Désactiver Tor et les fonctionnalités proxy"""
    try:
        stealth_engine = get_global_stealth_engine()
        proxy_manager = get_global_proxy_manager()
        
        # Mettre à jour les configurations
        stealth_engine.config["tor_enabled"] = False
        stealth_engine.config["proxy_rotation"] = False
        proxy_manager.config["tor_enabled"] = False
        proxy_manager.config["auto_rotation"] = False
        proxy_manager.config["monitoring_enabled"] = False
        
        # Sauvegarder les configurations
        stealth_engine._save_stealth_config()
        proxy_manager._save_config()
        
        # Désactiver tous les proxies Tor
        for proxy in proxy_manager.proxies:
            if proxy.get("is_tor", False):
                proxy["active"] = False
        
        return {
            "message": "Tor disabled successfully",
            "tor_available": False,
            "active_proxies": len([p for p in proxy_manager.proxies if p.get("active", False)]),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to disable Tor: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to disable Tor: {e}")

@router.post("/update-stealth-config")
async def update_stealth_config(config_update: StealthConfigUpdate):
    """Mettre à jour la configuration de furtivité"""
    try:
        stealth_engine = get_global_stealth_engine()
        
        # Mettre à jour les paramètres spécifiés
        if config_update.tor_enabled is not None:
            stealth_engine.config["tor_enabled"] = config_update.tor_enabled
        
        if config_update.proxy_rotation is not None:
            stealth_engine.config["proxy_rotation"] = config_update.proxy_rotation
        
        if config_update.stealth_level is not None:
            if 1 <= config_update.stealth_level <= 10:
                stealth_engine.config["stealth_level"] = config_update.stealth_level
            else:
                raise ValueError("Stealth level must be between 1 and 10")
        
        if config_update.profile is not None:
            if stealth_engine.enable_profile(config_update.profile):
                logger.info(f"Switched to stealth profile: {config_update.profile}")
            else:
                raise ValueError(f"Unknown profile: {config_update.profile}")
        
        # Sauvegarder
        stealth_engine._save_stealth_config()
        
        return {
            "message": "Stealth configuration updated successfully",
            "current_config": {
                "tor_enabled": stealth_engine.config.get("tor_enabled", False),
                "proxy_rotation": stealth_engine.config.get("proxy_rotation", False),
                "stealth_level": stealth_engine.config.get("stealth_level", 5),
                "current_profile": stealth_engine._get_current_profile()
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to update stealth config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update stealth config: {e}")

@router.post("/update-proxy-config")
async def update_proxy_config(config_update: ProxyConfigUpdate):
    """Mettre à jour la configuration des proxies"""
    try:
        proxy_manager = get_global_proxy_manager()
        
        # Mettre à jour les paramètres spécifiés
        if config_update.tor_enabled is not None:
            proxy_manager.config["tor_enabled"] = config_update.tor_enabled
        
        if config_update.auto_rotation is not None:
            proxy_manager.config["auto_rotation"] = config_update.auto_rotation
        
        if config_update.monitoring_enabled is not None:
            proxy_manager.config["monitoring_enabled"] = config_update.monitoring_enabled
        
        if config_update.verbose_logging is not None:
            proxy_manager.config["verbose_logging"] = config_update.verbose_logging
        
        # Sauvegarder
        proxy_manager._save_config()
        
        return {
            "message": "Proxy configuration updated successfully",
            "current_config": {
                "tor_enabled": proxy_manager.config.get("tor_enabled", False),
                "auto_rotation": proxy_manager.config.get("auto_rotation", False),
                "monitoring_enabled": proxy_manager.config.get("monitoring_enabled", False),
                "verbose_logging": proxy_manager.config.get("verbose_logging", False)
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to update proxy config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update proxy config: {e}")

@router.post("/test-tor-connection")
async def test_tor_connection():
    """Tester la connexion Tor"""
    try:
        proxy_manager = get_global_proxy_manager()
        
        # Re-vérifier la disponibilité de Tor
        proxy_manager._check_tor_service()
        
        if proxy_manager.tor_available:
            # Tester l'anonymat
            anonymity_status = proxy_manager.get_anonymity_status()
            
            return {
                "tor_available": True,
                "connection_test": "success",
                "anonymity_status": anonymity_status,
                "message": "Tor connection is working properly",
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "tor_available": False,
                "connection_test": "failed",
                "message": "Tor service is not available. Please install and start Tor service.",
                "installation_help": {
                    "ubuntu_debian": "sudo apt install tor && sudo systemctl start tor",
                    "centos_rhel": "sudo yum install tor && sudo systemctl start tor",
                    "windows": "Download Tor Browser or install Tor as a service",
                    "macos": "brew install tor && brew services start tor"
                },
                "timestamp": datetime.now().isoformat()
            }
        
    except Exception as e:
        logger.error(f"Failed to test Tor connection: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to test Tor connection: {e}")

@router.get("/anonymity-status")
async def get_anonymity_status():
    """Obtenir le statut d'anonymat actuel"""
    try:
        proxy_manager = get_global_proxy_manager()
        anonymity_status = proxy_manager.get_anonymity_status()
        
        return {
            "anonymity_status": anonymity_status,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get anonymity status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get anonymity status: {e}")

@router.post("/rotate-proxy")
async def rotate_proxy():
    """Effectuer une rotation manuelle des proxies"""
    try:
        proxy_manager = get_global_proxy_manager()
        
        old_proxy = proxy_manager.get_current_proxy()
        new_proxy = proxy_manager.rotate_proxy()
        
        return {
            "message": "Proxy rotation completed",
            "old_proxy": old_proxy.get("host", "none") if old_proxy else "none",
            "new_proxy": new_proxy.get("host", "none") if new_proxy else "none",
            "rotation_count": proxy_manager.rotation_count,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to rotate proxy: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to rotate proxy: {e}")

@router.get("/installation-guide")
async def get_installation_guide():
    """Obtenir le guide d'installation pour Tor et les dépendances"""
    return {
        "tor_installation": {
            "ubuntu_debian": {
                "commands": [
                    "sudo apt update",
                    "sudo apt install tor",
                    "sudo systemctl start tor",
                    "sudo systemctl enable tor"
                ],
                "verification": "sudo systemctl status tor"
            },
            "centos_rhel_fedora": {
                "commands": [
                    "sudo yum install epel-release",
                    "sudo yum install tor",
                    "sudo systemctl start tor",
                    "sudo systemctl enable tor"
                ],
                "verification": "sudo systemctl status tor"
            },
            "windows": {
                "method1": "Download and install Tor Browser from https://www.torproject.org/",
                "method2": "Install Tor as Windows service using Tor Expert Bundle",
                "verification": "Check if port 9050 is listening"
            },
            "macos": {
                "commands": [
                    "brew install tor",
                    "brew services start tor"
                ],
                "verification": "brew services list | grep tor"
            }
        },
        "python_dependencies": {
            "required": ["PySocks", "requests[socks]", "urllib3[socks]"],
            "install_command": "pip install PySocks requests[socks] urllib3[socks]"
        },
        "configuration": {
            "tor_config_file": "/etc/tor/torrc (Linux) or Tor Browser/Browser/TorBrowser/Data/Tor/torrc",
            "default_ports": {
                "socks": 9050,
                "control": 9051
            }
        }
    }