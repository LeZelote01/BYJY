#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Stealth API Module V1.0
API endpoints pour la gestion de la furtivité et de l'évasion
Features: Stealth Management, Proxy Control, Obfuscation, Anti-Detection
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel

# Import des modules de furtivité
from stealth_engine import get_global_stealth_engine
from proxy_manager import get_global_proxy_manager
from obfuscation_toolkit import get_obfuscator

logger = logging.getLogger(__name__)

# Router pour les endpoints de furtivité
router = APIRouter(prefix="/api/stealth", tags=["stealth"])

# Modèles Pydantic pour l'API
class StealthConfig(BaseModel):
    stealth_level: int = 8  # 1-10
    obfuscation_level: int = 7  # 1-10
    proxy_rotation: bool = True
    anti_detection: bool = True
    timing_randomization: bool = True
    process_masking: bool = True
    memory_encryption: bool = True

class ProxyConfig(BaseModel):
    auto_rotation: bool = True
    rotation_interval: int = 50
    quality_threshold: float = 0.7
    tor_enabled: bool = True
    proxy_chains: bool = False
    chain_length: int = 2

class ObfuscationRequest(BaseModel):
    code: str
    language: str = "python"
    level: int = 8

class StealthTestRequest(BaseModel):
    target_url: str
    test_type: str = "basic"  # basic, advanced, full
    use_proxy: bool = True

# Endpoints de statut et configuration

@router.get("/status")
async def get_stealth_status():
    """Obtenir le statut complet de furtivité"""
    try:
        stealth_engine = get_global_stealth_engine()
        proxy_manager = get_global_proxy_manager()
        
        stealth_status = stealth_engine.get_stealth_status()
        proxy_stats = proxy_manager.get_proxy_statistics()
        anonymity_status = proxy_manager.get_anonymity_status()
        
        return {
            "stealth": stealth_status,
            "proxies": proxy_stats,
            "anonymity": anonymity_status,
            "timestamp": datetime.now().isoformat(),
            "overall_stealth_score": stealth_status.get("stealth_score", 0)
        }
        
    except Exception as e:
        logger.error(f"Failed to get stealth status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stealth status: {e}")

@router.get("/config")
async def get_stealth_config():
    """Obtenir la configuration de furtivité"""
    try:
        stealth_engine = get_global_stealth_engine()
        proxy_manager = get_global_proxy_manager()
        
        return {
            "stealth_config": {
                "stealth_level": stealth_engine.config.get("stealth_level", 8),
                "obfuscation_enabled": stealth_engine.obfuscation_enabled,
                "anti_forensics_enabled": stealth_engine.anti_forensics_enabled,
                "min_request_delay": stealth_engine.config.get("min_request_delay", 2.0),
                "max_request_delay": stealth_engine.config.get("max_request_delay", 8.0),
                "max_requests_per_minute": stealth_engine.config.get("max_requests_per_minute", 12)
            },
            "proxy_config": proxy_manager.config,
            "available_profiles": list(stealth_engine.config.get("profiles", {}).keys())
        }
        
    except Exception as e:
        logger.error(f"Failed to get stealth config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stealth config: {e}")

@router.post("/config")
async def update_stealth_config(config: StealthConfig):
    """Mettre à jour la configuration de furtivité"""
    try:
        stealth_engine = get_global_stealth_engine()
        
        # Valider les niveaux
        if not (1 <= config.stealth_level <= 10):
            raise HTTPException(status_code=400, detail="Stealth level must be between 1-10")
        
        if not (1 <= config.obfuscation_level <= 10):
            raise HTTPException(status_code=400, detail="Obfuscation level must be between 1-10")
        
        # Appliquer la configuration
        stealth_engine.config.update({
            "stealth_level": config.stealth_level,
            "obfuscation_level": config.obfuscation_level,
            "proxy_rotation": config.proxy_rotation,
            "anti_detection": config.anti_detection,
            "timing_randomization": config.timing_randomization,
            "process_masking": config.process_masking,
            "memory_encryption": config.memory_encryption
        })
        
        stealth_engine.obfuscation_enabled = config.obfuscation_level > 0
        stealth_engine.anti_forensics_enabled = config.memory_encryption
        stealth_engine._save_stealth_config()
        
        logger.info(f"Stealth configuration updated - Level: {config.stealth_level}")
        
        return {
            "message": "Stealth configuration updated successfully",
            "new_config": stealth_engine.config
        }
        
    except Exception as e:
        logger.error(f"Failed to update stealth config: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update stealth config: {e}")

# Endpoints de gestion des profils

@router.get("/profiles")
async def get_stealth_profiles():
    """Obtenir tous les profils de furtivité disponibles"""
    try:
        stealth_engine = get_global_stealth_engine()
        profiles = stealth_engine.config.get("profiles", {})
        
        return {
            "profiles": profiles,
            "current_profile": stealth_engine._get_current_profile(),
            "total_profiles": len(profiles)
        }
        
    except Exception as e:
        logger.error(f"Failed to get stealth profiles: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stealth profiles: {e}")

@router.post("/profiles/{profile_name}/activate")
async def activate_stealth_profile(profile_name: str):
    """Activer un profil de furtivité"""
    try:
        stealth_engine = get_global_stealth_engine()
        
        if stealth_engine.enable_profile(profile_name):
            logger.info(f"Activated stealth profile: {profile_name}")
            return {
                "message": f"Profile '{profile_name}' activated successfully",
                "active_profile": profile_name,
                "new_config": stealth_engine.config
            }
        else:
            raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")
            
    except Exception as e:
        logger.error(f"Failed to activate profile {profile_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to activate profile: {e}")

# Endpoints de gestion des proxies

@router.get("/proxies")
async def get_proxy_list():
    """Obtenir la liste de tous les proxies"""
    try:
        proxy_manager = get_global_proxy_manager()
        stats = proxy_manager.get_proxy_statistics()
        
        return {
            "statistics": stats,
            "proxies": [
                {
                    "id": proxy["id"],
                    "host": proxy["host"],
                    "port": proxy["port"],
                    "type": proxy["type"],
                    "country": proxy.get("country", "unknown"),
                    "active": proxy.get("active", False),
                    "quality_score": proxy.get("quality_score", 0.0),
                    "response_time": proxy.get("response_time", 0.0),
                    "is_tor": proxy.get("is_tor", False),
                    "last_tested": proxy.get("last_tested")
                }
                for proxy in proxy_manager.proxies
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to get proxy list: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get proxy list: {e}")

@router.post("/proxies/rotate")
async def rotate_proxy():
    """Effectuer une rotation manuelle des proxies"""
    try:
        proxy_manager = get_global_proxy_manager()
        new_proxy = proxy_manager.rotate_proxy()
        
        if new_proxy:
            return {
                "message": "Proxy rotated successfully",
                "new_proxy": {
                    "host": new_proxy["host"],
                    "port": new_proxy["port"],
                    "country": new_proxy.get("country", "unknown"),
                    "type": new_proxy["type"],
                    "quality_score": new_proxy.get("quality_score", 0.0)
                }
            }
        else:
            raise HTTPException(status_code=503, detail="No active proxies available for rotation")
            
    except Exception as e:
        logger.error(f"Failed to rotate proxy: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to rotate proxy: {e}")

@router.post("/proxies/test")
async def test_all_proxies(background_tasks: BackgroundTasks):
    """Lancer les tests de qualité sur tous les proxies"""
    try:
        proxy_manager = get_global_proxy_manager()
        
        # Lancer les tests en arrière-plan
        background_tasks.add_task(proxy_manager.test_all_proxies)
        
        return {
            "message": "Proxy quality tests started in background",
            "total_proxies": len(proxy_manager.proxies),
            "test_urls": proxy_manager.config["test_urls"]
        }
        
    except Exception as e:
        logger.error(f"Failed to start proxy tests: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start proxy tests: {e}")

@router.get("/proxies/anonymity")
async def check_anonymity():
    """Vérifier le statut d'anonymat actuel"""
    try:
        proxy_manager = get_global_proxy_manager()
        anonymity_status = proxy_manager.get_anonymity_status()
        
        return anonymity_status
        
    except Exception as e:
        logger.error(f"Failed to check anonymity: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to check anonymity: {e}")

@router.post("/proxies/refresh")
async def refresh_proxy_sources(background_tasks: BackgroundTasks):
    """Actualiser la liste des proxies depuis toutes les sources"""
    try:
        proxy_manager = get_global_proxy_manager()
        
        # Lancer l'actualisation en arrière-plan
        result = proxy_manager.refresh_proxy_sources()
        
        # Tester les nouveaux proxies en arrière-plan
        background_tasks.add_task(proxy_manager.test_all_proxies)
        
        return {
            "status": "success",
            "refresh_result": result,
            "message": "Proxy sources refreshed and quality tests started in background"
        }
        
    except Exception as e:
        logger.error(f"Failed to refresh proxy sources: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to refresh proxy sources: {e}")

@router.post("/proxies/tor/new-circuit")
async def request_new_tor_circuit():
    """Demander un nouveau circuit Tor"""
    try:
        proxy_manager = get_global_proxy_manager()
        
        if proxy_manager.start_tor_new_circuit():
            return {
                "message": "New Tor circuit requested successfully",
                "tor_available": proxy_manager.tor_available
            }
        else:
            raise HTTPException(status_code=503, detail="Failed to request new Tor circuit")
            
    except Exception as e:
        logger.error(f"Failed to request new Tor circuit: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to request new Tor circuit: {e}")

# Endpoints d'obfuscation

@router.post("/obfuscate")
async def obfuscate_code(request: ObfuscationRequest):
    """Obfusquer du code"""
    try:
        if not request.code.strip():
            raise HTTPException(status_code=400, detail="Code cannot be empty")
        
        if request.language.lower() != "python":
            raise HTTPException(status_code=400, detail="Only Python code obfuscation is currently supported")
        
        if not (1 <= request.level <= 10):
            raise HTTPException(status_code=400, detail="Obfuscation level must be between 1-10")
        
        obfuscator = get_obfuscator(request.level)
        obfuscated_code = obfuscator.obfuscate_python_code(request.code)
        stats = obfuscator.get_obfuscation_stats()
        
        return {
            "original_code": request.code,
            "obfuscated_code": obfuscated_code,
            "obfuscation_level": request.level,
            "statistics": stats,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Code obfuscation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Code obfuscation failed: {e}")

@router.post("/obfuscate/string")
async def obfuscate_string(text: str, level: int = 5):
    """Obfusquer une chaîne de caractères"""
    try:
        if not text.strip():
            raise HTTPException(status_code=400, detail="Text cannot be empty")
        
        if not (1 <= level <= 10):
            raise HTTPException(status_code=400, detail="Obfuscation level must be between 1-10")
        
        stealth_engine = get_global_stealth_engine()
        stealth_engine.config["obfuscation_level"] = level
        
        obfuscated = stealth_engine.obfuscate_string(text)
        
        return {
            "original_text": text,
            "obfuscated_text": obfuscated,
            "level": level,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"String obfuscation failed: {e}")
        raise HTTPException(status_code=500, detail=f"String obfuscation failed: {e}")

# Endpoints de test et validation

@router.post("/test")
async def run_stealth_test(request: StealthTestRequest):
    """Exécuter un test de furtivité"""
    try:
        stealth_engine = get_global_stealth_engine()
        proxy_manager = get_global_proxy_manager()
        
        test_results = {
            "target_url": request.target_url,
            "test_type": request.test_type,
            "timestamp": datetime.now().isoformat(),
            "proxy_used": None,
            "response_time": 0.0,
            "detection_indicators": [],
            "success": False
        }
        
        if request.use_proxy:
            current_proxy = proxy_manager.get_current_proxy()
            if current_proxy:
                test_results["proxy_used"] = f"{current_proxy['host']}:{current_proxy['port']}"
        
        # Effectuer une requête de test furtive
        try:
            import time
            start_time = time.time()
            
            response = stealth_engine.stealth_request("GET", request.target_url)
            test_results["response_time"] = time.time() - start_time
            test_results["status_code"] = response.status_code
            test_results["success"] = response.status_code == 200
            
            # Analyser la réponse pour des indicateurs de détection
            response_text = response.text.lower()
            detection_keywords = ["blocked", "captcha", "bot", "security", "forbidden"]
            
            for keyword in detection_keywords:
                if keyword in response_text:
                    test_results["detection_indicators"].append(keyword)
            
            test_results["detected"] = len(test_results["detection_indicators"]) > 0
            
        except Exception as e:
            test_results["error"] = str(e)
            test_results["success"] = False
        
        return test_results
        
    except Exception as e:
        logger.error(f"Stealth test failed: {e}")
        raise HTTPException(status_code=500, detail=f"Stealth test failed: {e}")

@router.get("/alerts")
async def get_detection_alerts():
    """Obtenir les alertes de détection récentes"""
    try:
        stealth_engine = get_global_stealth_engine()
        
        return {
            "alerts": stealth_engine.detection_alerts,
            "total_alerts": len(stealth_engine.detection_alerts),
            "recent_alerts": len([
                alert for alert in stealth_engine.detection_alerts
                if (datetime.now() - datetime.fromisoformat(alert["timestamp"])).seconds < 3600
            ]),
            "stealth_score": stealth_engine.stealth_score
        }
        
    except Exception as e:
        logger.error(f"Failed to get detection alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get detection alerts: {e}")

@router.delete("/alerts")
async def clear_detection_alerts():
    """Effacer toutes les alertes de détection"""
    try:
        stealth_engine = get_global_stealth_engine()
        alerts_count = len(stealth_engine.detection_alerts)
        
        stealth_engine.detection_alerts.clear()
        stealth_engine.stealth_score = 100.0  # Réinitialiser le score
        
        return {
            "message": f"Cleared {alerts_count} detection alerts",
            "new_stealth_score": stealth_engine.stealth_score
        }
        
    except Exception as e:
        logger.error(f"Failed to clear alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear alerts: {e}")

# Endpoints de nettoyage et maintenance

@router.post("/cleanup")
async def run_anti_forensics_cleanup():
    """Exécuter le nettoyage anti-forensique"""
    try:
        stealth_engine = get_global_stealth_engine()
        stealth_engine.cleanup_forensics()
        
        return {
            "message": "Anti-forensics cleanup completed successfully",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Anti-forensics cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=f"Anti-forensics cleanup failed: {e}")

@router.get("/statistics")
async def get_stealth_statistics():
    """Obtenir les statistiques complètes de furtivité"""
    try:
        stealth_engine = get_global_stealth_engine()
        proxy_manager = get_global_proxy_manager()
        
        stealth_stats = stealth_engine.get_stealth_status()
        proxy_stats = proxy_manager.get_proxy_statistics()
        
        return {
            "stealth_statistics": stealth_stats,
            "proxy_statistics": proxy_stats,
            "combined_score": (stealth_stats.get("stealth_score", 0) + 
                             (proxy_stats.get("success_rate", 0) * 0.01 * 100)) / 2,
            "recommendation": _get_stealth_recommendation(stealth_stats, proxy_stats),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get stealth statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get stealth statistics: {e}")

def _get_stealth_recommendation(stealth_stats: Dict, proxy_stats: Dict) -> str:
    """Générer une recommandation basée sur les statistiques"""
    stealth_score = stealth_stats.get("stealth_score", 0)
    proxy_success = proxy_stats.get("success_rate", 0)
    
    if stealth_score >= 90 and proxy_success >= 80:
        return "Excellent stealth configuration - maintain current settings"
    elif stealth_score >= 70 and proxy_success >= 60:
        return "Good stealth level - consider activating 'maximum_stealth' profile for sensitive operations"
    elif stealth_score >= 50:
        return "Moderate stealth - increase obfuscation level and enable more proxy rotation"
    else:
        return "Low stealth detected - immediately activate 'maximum_stealth' profile and check for detection alerts"