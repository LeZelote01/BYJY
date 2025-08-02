#!/usr/bin/env python3
"""
CyberSec Assistant Portable - User Proxy Configuration API
API endpoints pour gérer la configuration des proxies utilisateurs
"""

import logging
from typing import Dict, List, Any, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, validator

from proxy_user_config_manager import get_global_user_config_manager
from tor_installer import get_tor_installer

logger = logging.getLogger(__name__)

# Router pour l'API de configuration utilisateur
router = APIRouter(prefix="/api/proxy-config", tags=["User Proxy Configuration"])

# Models Pydantic
class TorConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    auto_start: Optional[bool] = None
    use_as_primary: Optional[bool] = None

class GeneralConfigUpdate(BaseModel):
    use_external_proxies: Optional[bool] = None
    stealth_level: Optional[int] = None
    auto_rotate_proxies: Optional[bool] = None
    
    @validator('stealth_level')
    def validate_stealth_level(cls, v):
        if v is not None and not (1 <= v <= 10):
            raise ValueError('stealth_level must be between 1 and 10')
        return v

class ProxyAdd(BaseModel):
    proxy_url: str
    
    @validator('proxy_url')
    def validate_proxy_url(cls, v):
        if not v or not ('://' in v):
            raise ValueError('Invalid proxy URL format')
        return v

class ProxyRemove(BaseModel):
    proxy_url: str

class ExternalProxiesConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    auto_test_proxies: Optional[bool] = None
    minimum_quality_score: Optional[float] = None
    test_timeout: Optional[int] = None
    
    @validator('minimum_quality_score')
    def validate_score(cls, v):
        if v is not None and not (0.0 <= v <= 1.0):
            raise ValueError('minimum_quality_score must be between 0.0 and 1.0')
        return v

# Obtenir l'instance du gestionnaire de configuration
config_manager = get_global_user_config_manager()

@router.get("/status")
async def get_proxy_config_status():
    """Obtenir le statut de la configuration des proxies"""
    try:
        # Configuration utilisateur
        user_config = config_manager.get_full_config()
        
        # Statut de Tor
        tor_installer = get_tor_installer()
        tor_status = tor_installer.get_installation_status()
        
        return {
            "success": True,
            "user_config": user_config,
            "tor_installation": tor_status,
            "config_file": str(config_manager.config_path)
        }
    except Exception as e:
        logger.error(f"Failed to get proxy config status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get status: {e}")

@router.get("/config")
async def get_user_config():
    """Obtenir la configuration utilisateur complète"""
    try:
        config = config_manager.get_full_config()
        return {
            "success": True,
            "config": config
        }
    except Exception as e:
        logger.error(f"Failed to get user config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get config: {e}")

@router.get("/config/tor")
async def get_tor_config():
    """Obtenir la configuration Tor spécifiquement"""
    try:
        tor_config = config_manager.get_tor_config()
        
        # Ajouter le statut d'installation
        tor_installer = get_tor_installer()
        tor_status = tor_installer.get_installation_status()
        
        return {
            "success": True,
            "tor_config": tor_config,
            "installation_status": tor_status
        }
    except Exception as e:
        logger.error(f"Failed to get Tor config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get Tor config: {e}")

@router.post("/config/tor/update")
async def update_tor_config(updates: TorConfigUpdate):
    """Mettre à jour la configuration Tor"""
    try:
        config_manager.update_tor_settings(
            enabled=updates.enabled,
            auto_start=updates.auto_start,
            use_as_primary=updates.use_as_primary
        )
        
        return {
            "success": True,
            "message": "Tor configuration updated successfully",
            "updated_config": config_manager.get_tor_config()
        }
    except Exception as e:
        logger.error(f"Failed to update Tor config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update Tor config: {e}")

@router.post("/config/general/update")
async def update_general_config(updates: GeneralConfigUpdate):
    """Mettre à jour la configuration générale"""
    try:
        config_manager.update_general_settings(
            use_external_proxies=updates.use_external_proxies,
            stealth_level=updates.stealth_level,
            auto_rotate=updates.auto_rotate_proxies
        )
        
        return {
            "success": True,
            "message": "General configuration updated successfully",
            "updated_config": config_manager.get_general_config()
        }
    except Exception as e:
        logger.error(f"Failed to update general config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update general config: {e}")

@router.get("/config/external-proxies")
async def get_external_proxies_config():
    """Obtenir la configuration des proxies externes"""
    try:
        external_config = config_manager.get_external_proxies_config()
        return {
            "success": True,
            "external_proxies_config": external_config
        }
    except Exception as e:
        logger.error(f"Failed to get external proxies config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get external proxies config: {e}")

@router.post("/config/external-proxies/update")
async def update_external_proxies_config(updates: ExternalProxiesConfigUpdate):
    """Mettre à jour la configuration des proxies externes"""
    try:
        # Mettre à jour les paramètres un par un
        if updates.enabled is not None:
            config_manager.set_value('external_proxies', 'enabled', updates.enabled)
        if updates.auto_test_proxies is not None:
            config_manager.set_value('external_proxies', 'auto_test_proxies', updates.auto_test_proxies)
        if updates.minimum_quality_score is not None:
            config_manager.set_value('external_proxies', 'minimum_quality_score', updates.minimum_quality_score)
        if updates.test_timeout is not None:
            config_manager.set_value('external_proxies', 'test_timeout', updates.test_timeout)
        
        config_manager.save_config()
        
        return {
            "success": True,
            "message": "External proxies configuration updated successfully",
            "updated_config": config_manager.get_external_proxies_config()
        }
    except Exception as e:
        logger.error(f"Failed to update external proxies config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update external proxies config: {e}")

@router.post("/proxies/add")
async def add_external_proxy(proxy: ProxyAdd):
    """Ajouter un proxy externe à la liste"""
    try:
        success = config_manager.add_external_proxy(proxy.proxy_url)
        
        if success:
            return {
                "success": True,
                "message": f"Proxy {proxy.proxy_url} added successfully",
                "proxy_list": config_manager.get_proxy_list()
            }
        else:
            return {
                "success": False,
                "message": f"Proxy {proxy.proxy_url} already exists in the list"
            }
    except Exception as e:
        logger.error(f"Failed to add proxy: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to add proxy: {e}")

@router.post("/proxies/remove")
async def remove_external_proxy(proxy: ProxyRemove):
    """Supprimer un proxy externe de la liste"""
    try:
        success = config_manager.remove_external_proxy(proxy.proxy_url)
        
        if success:
            return {
                "success": True,
                "message": f"Proxy {proxy.proxy_url} removed successfully",
                "proxy_list": config_manager.get_proxy_list()
            }
        else:
            return {
                "success": False,
                "message": f"Proxy {proxy.proxy_url} not found in the list"
            }
    except Exception as e:
        logger.error(f"Failed to remove proxy: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to remove proxy: {e}")

@router.get("/proxies/list")
async def get_proxy_list():
    """Obtenir la liste des proxies externes"""
    try:
        proxy_list = config_manager.get_proxy_list()
        return {
            "success": True,
            "proxy_list": proxy_list,
            "count": len(proxy_list)
        }
    except Exception as e:
        logger.error(f"Failed to get proxy list: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get proxy list: {e}")

@router.post("/tor/install")
async def install_tor(background_tasks: BackgroundTasks):
    """Installer Tor automatiquement"""
    try:
        tor_installer = get_tor_installer()
        
        # Vérifier si Tor est déjà installé
        status = tor_installer.get_installation_status()
        if status["installed"]:
            return {
                "success": True,
                "message": "Tor is already installed",
                "status": status
            }
        
        # Installation en arrière-plan
        def install_tor_background():
            try:
                result = tor_installer.install_tor()
                logger.info(f"Tor installation result: {result}")
            except Exception as e:
                logger.error(f"Background Tor installation failed: {e}")
        
        background_tasks.add_task(install_tor_background)
        
        return {
            "success": True,
            "message": "Tor installation started in background. Check status in a few minutes.",
            "status": status
        }
    except Exception as e:
        logger.error(f"Failed to start Tor installation: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start Tor installation: {e}")

@router.get("/tor/status")
async def get_tor_status():
    """Obtenir le statut d'installation de Tor"""
    try:
        tor_installer = get_tor_installer()
        status = tor_installer.get_installation_status()
        
        return {
            "success": True,
            "tor_status": status
        }
    except Exception as e:
        logger.error(f"Failed to get Tor status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get Tor status: {e}")

@router.post("/config/reset")
async def reset_config_to_defaults():
    """Réinitialiser la configuration aux valeurs par défaut"""
    try:
        config_manager.reset_to_defaults()
        
        return {
            "success": True,
            "message": "Configuration reset to defaults successfully",
            "config": config_manager.get_full_config()
        }
    except Exception as e:
        logger.error(f"Failed to reset config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to reset config: {e}")

@router.get("/config/file-content")
async def get_config_file_content():
    """Obtenir le contenu brut du fichier de configuration pour édition directe"""
    try:
        if not config_manager.config_path.exists():
            return {
                "success": False,
                "message": "Configuration file does not exist"
            }
        
        with open(config_manager.config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        return {
            "success": True,
            "file_path": str(config_manager.config_path),
            "content": content
        }
    except Exception as e:
        logger.error(f"Failed to get config file content: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get config file content: {e}")

@router.get("/validate")
async def validate_current_config():
    """Valider la configuration actuelle"""
    try:
        config = config_manager.get_full_config()
        validation_results = {
            "valid": True,
            "warnings": [],
            "errors": []
        }
        
        # Validation des paramètres
        stealth_level = config["general"]["stealth_level"]
        if not (1 <= stealth_level <= 10):
            validation_results["errors"].append(f"Invalid stealth_level: {stealth_level} (must be 1-10)")
            validation_results["valid"] = False
        
        # Validation des proxies
        proxy_list = config["external_proxies"]["proxy_list"]
        invalid_proxies = []
        for proxy in proxy_list:
            if not ('://' in proxy):
                invalid_proxies.append(proxy)
        
        if invalid_proxies:
            validation_results["warnings"].append(f"Invalid proxy URLs: {invalid_proxies}")
        
        # Validation Tor
        tor_config = config["tor"]
        if tor_config["enabled"]:
            tor_installer = get_tor_installer()
            tor_status = tor_installer.get_installation_status()
            if not tor_status["installed"]:
                validation_results["warnings"].append("Tor is enabled but not installed")
        
        return {
            "success": True,
            "validation": validation_results
        }
    except Exception as e:
        logger.error(f"Failed to validate config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to validate config: {e}")

# Routes d'information
@router.get("/help")
async def get_configuration_help():
    """Obtenir l'aide pour la configuration des proxies"""
    return {
        "success": True,
        "help": {
            "proxy_formats": [
                "http://proxy.example.com:8080",
                "https://proxy.example.com:8080", 
                "socks4://proxy.example.com:1080",
                "socks5://proxy.example.com:1080",
                "http://username:password@proxy.example.com:8080"
            ],
            "stealth_levels": {
                "1-3": "Basic stealth, high speed",
                "4-6": "Moderate stealth, balanced speed/anonymity", 
                "7-10": "Maximum stealth, reduced speed"
            },
            "sections": {
                "general": "Basic proxy configuration",
                "tor": "Tor network settings",
                "external_proxies": "External proxy servers",
                "safety": "Security and safety checks",
                "advanced": "Advanced options for experts"
            },
            "config_file": str(config_manager.config_path)
        }
    }