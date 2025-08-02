#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Evasion Management API V1.0
API REST pour la gestion avancée de l'évasion et des contre-mesures
Features: Profile Management, Detection Events, Real-time Adaptation
"""

import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

from evasion_manager import get_global_evasion_manager

logger = logging.getLogger(__name__)

# Router pour les endpoints d'évasion
router = APIRouter(prefix="/api/evasion", tags=["evasion"])

# Modèles Pydantic pour l'API
class ProfileConfig(BaseModel):
    description: str
    stealth_level: int = Field(ge=1, le=10)
    techniques: List[str] = []
    timing_profile: Dict[str, float] = {
        "min_delay": 1.0,
        "max_delay": 3.0,
        "burst_limit": 5
    }
    proxy_settings: Dict[str, Any] = {
        "enabled": True,
        "rotation_interval": 60
    }
    obfuscation_settings: Dict[str, Any] = {
        "level": 5,
        "string_obfuscation": True
    }
    anti_forensics: bool = True
    detection_thresholds: Dict[str, float] = {
        "rate_limit": 0.5,
        "captcha": 0.4,
        "block": 0.6
    }

class DetectionEventReport(BaseModel):
    event_type: str
    source: str
    details: Dict[str, Any] = {}

class ProfileImportData(BaseModel):
    profiles: List[Dict[str, Any]]

# Endpoints principaux

@router.get("/status")
async def get_evasion_status():
    """Obtenir le statut complet du système d'évasion"""
    try:
        evasion_manager = get_global_evasion_manager()
        status = evasion_manager.get_evasion_status()
        
        return {
            "status": "active",
            "evasion_data": status,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get evasion status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get evasion status: {e}")

@router.get("/profiles")
async def get_all_profiles():
    """Obtenir tous les profils d'évasion disponibles"""
    try:
        evasion_manager = get_global_evasion_manager()
        status = evasion_manager.get_evasion_status()
        
        return {
            "profiles": status["available_profiles"],
            "current_profile": status["current_profile"]["name"],
            "total_profiles": len(status["available_profiles"])
        }
        
    except Exception as e:
        logger.error(f"Failed to get profiles: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get profiles: {e}")

@router.post("/profiles/{profile_name}/activate")
async def activate_profile(profile_name: str):
    """Activer un profil d'évasion spécifique"""
    try:
        evasion_manager = get_global_evasion_manager()
        
        if evasion_manager.activate_profile(profile_name):
            return {
                "message": f"Profile '{profile_name}' activated successfully",
                "active_profile": profile_name,
                "timestamp": datetime.now().isoformat()
            }
        else:
            raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to activate profile {profile_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to activate profile: {e}")

@router.post("/profiles/{profile_name}")
async def create_custom_profile(profile_name: str, config: ProfileConfig):
    """Créer un nouveau profil d'évasion personnalisé"""
    try:
        evasion_manager = get_global_evasion_manager()
        
        if evasion_manager.create_custom_profile(profile_name, config.dict()):
            return {
                "message": f"Custom profile '{profile_name}' created successfully",
                "profile_name": profile_name,
                "stealth_level": config.stealth_level
            }
        else:
            raise HTTPException(status_code=400, detail=f"Failed to create profile '{profile_name}'")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create custom profile {profile_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create custom profile: {e}")

@router.delete("/profiles/{profile_name}")
async def delete_profile(profile_name: str):
    """Supprimer un profil d'évasion personnalisé"""
    try:
        evasion_manager = get_global_evasion_manager()
        
        if evasion_manager.delete_profile(profile_name):
            return {
                "message": f"Profile '{profile_name}' deleted successfully"
            }
        else:
            raise HTTPException(status_code=400, detail=f"Cannot delete profile '{profile_name}' (may be default or not found)")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete profile {profile_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete profile: {e}")

@router.post("/detection-events")
async def report_detection_event(event: DetectionEventReport):
    """Signaler un événement de détection"""
    try:
        evasion_manager = get_global_evasion_manager()
        evasion_manager.report_detection_event(
            event_type=event.event_type,
            source=event.source,
            details=event.details
        )
        
        return {
            "message": "Detection event reported successfully",
            "event_type": event.event_type,
            "source": event.source,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to report detection event: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to report detection event: {e}")

@router.post("/success")
async def report_success(source: str = "general"):
    """Signaler une opération réussie"""
    try:
        evasion_manager = get_global_evasion_manager()
        evasion_manager.report_success(source)
        
        return {
            "message": "Success reported",
            "source": source,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to report success: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to report success: {e}")

@router.get("/metrics")
async def get_evasion_metrics():
    """Obtenir les métriques détaillées d'évasion"""
    try:
        evasion_manager = get_global_evasion_manager()
        status = evasion_manager.get_evasion_status()
        
        return {
            "metrics": status["metrics"],
            "recent_detections": status["recent_detections"],
            "detection_events": status["detection_events"],
            "recommendations": status["recommendations"],
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get evasion metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get evasion metrics: {e}")

@router.get("/recommendations")
async def get_recommendations():
    """Obtenir des recommandations d'évasion basées sur l'activité récente"""
    try:
        evasion_manager = get_global_evasion_manager()
        status = evasion_manager.get_evasion_status()
        
        return {
            "recommendations": status["recommendations"],
            "current_profile": status["current_profile"],
            "metrics_summary": {
                "success_rate": status["metrics"]["success_rate"],
                "detection_rate": status["metrics"]["detection_rate"],
                "recent_detections": status["recent_detections"]
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get recommendations: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get recommendations: {e}")

@router.post("/profiles/export")
async def export_profiles():
    """Exporter tous les profils d'évasion"""
    try:
        evasion_manager = get_global_evasion_manager()
        export_data = evasion_manager.export_profiles()
        
        return {
            "message": "Profiles exported successfully",
            "export_data": export_data,
            "profiles_count": len(export_data["profiles"]),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to export profiles: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to export profiles: {e}")

@router.post("/profiles/import")
async def import_profiles(data: ProfileImportData):
    """Importer des profils d'évasion"""
    try:
        evasion_manager = get_global_evasion_manager()
        
        if evasion_manager.import_profiles(data.dict()):
            return {
                "message": "Profiles imported successfully",
                "imported_count": len(data.profiles),
                "timestamp": datetime.now().isoformat()
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to import profiles")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to import profiles: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to import profiles: {e}")

@router.get("/detection-events")
async def get_detection_events(limit: int = 50):
    """Obtenir l'historique des événements de détection"""
    try:
        evasion_manager = get_global_evasion_manager()
        status = evasion_manager.get_evasion_status()
        
        # Limiter le nombre d'événements retournés
        events = status["detection_events"][-limit:] if len(status["detection_events"]) > limit else status["detection_events"]
        
        # Statistiques des événements
        event_stats = {}
        for event in status["detection_events"]:
            event_type = event["type"]
            event_stats[event_type] = event_stats.get(event_type, 0) + 1
        
        return {
            "detection_events": events,
            "total_events": len(status["detection_events"]),
            "recent_events": status["recent_detections"],
            "event_statistics": event_stats,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get detection events: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get detection events: {e}")

@router.delete("/detection-events")
async def clear_detection_events():
    """Effacer l'historique des événements de détection"""
    try:
        evasion_manager = get_global_evasion_manager()
        
        # Sauvegarder le nombre d'événements avant suppression
        status = evasion_manager.get_evasion_status()
        events_count = len(status["detection_events"])
        
        # Effacer les événements
        evasion_manager.detection_events.clear()
        
        return {
            "message": f"Cleared {events_count} detection events",
            "cleared_count": events_count,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to clear detection events: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to clear detection events: {e}")

@router.get("/techniques")
async def get_available_techniques():
    """Obtenir la liste des techniques d'évasion disponibles"""
    try:
        available_techniques = {
            "basic": [
                "basic_headers",
                "user_agent_rotation",
                "timing_randomization"
            ],
            "intermediate": [
                "referer_spoofing",
                "request_fingerprint_masking",
                "source_port_randomization",
                "packet_fragmentation"
            ],
            "advanced": [
                "advanced_headers",
                "tcp_fingerprint_evasion",
                "dns_over_https",
                "traffic_obfuscation",
                "decoy_scanning"
            ],
            "expert": [
                "idle_zombie_scanning",
                "ultra_slow_scanning",
                "deep_packet_inspection_evasion",
                "statistical_traffic_analysis_evasion"
            ]
        }
        
        return {
            "techniques": available_techniques,
            "total_techniques": sum(len(techniques) for techniques in available_techniques.values()),
            "categories": list(available_techniques.keys())
        }
        
    except Exception as e:
        logger.error(f"Failed to get available techniques: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get available techniques: {e}")

@router.post("/test-profile")
async def test_profile_effectiveness(profile_name: str, background_tasks: BackgroundTasks):
    """Tester l'efficacité d'un profil d'évasion"""
    try:
        evasion_manager = get_global_evasion_manager()
        
        # Vérifier que le profil existe
        if profile_name not in evasion_manager.profiles:
            raise HTTPException(status_code=404, detail=f"Profile '{profile_name}' not found")
        
        # Programmer le test en arrière-plan
        background_tasks.add_task(_test_profile_background, profile_name)
        
        return {
            "message": f"Profile effectiveness test started for '{profile_name}'",
            "profile_name": profile_name,
            "test_initiated": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to test profile {profile_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to test profile: {e}")

async def _test_profile_background(profile_name: str):
    """Test de profil en arrière-plan"""
    try:
        evasion_manager = get_global_evasion_manager()
        
        # Sauvegarder le profil actuel
        current_profile = evasion_manager.current_profile.name
        
        # Activer le profil à tester
        evasion_manager.activate_profile(profile_name)
        
        # Effectuer quelques tests basiques
        test_urls = [
            "https://httpbin.org/ip",
            "https://httpbin.org/user-agent",
            "https://httpbin.org/headers"
        ]
        
        success_count = 0
        total_tests = len(test_urls)
        
        for url in test_urls:
            try:
                response = evasion_manager.stealth_engine.stealth_request("GET", url)
                if response.status_code == 200:
                    success_count += 1
                    evasion_manager.report_success(f"profile_test_{profile_name}")
                else:
                    evasion_manager.report_detection_event(
                        "test_failure",
                        f"profile_test_{profile_name}",
                        {"status_code": response.status_code, "url": url}
                    )
            except Exception as e:
                evasion_manager.report_detection_event(
                    "test_error",
                    f"profile_test_{profile_name}",
                    {"error": str(e), "url": url}
                )
        
        # Restaurer le profil original
        evasion_manager.activate_profile(current_profile)
        
        # Log des résultats
        test_success_rate = (success_count / total_tests) * 100
        logger.info(f"Profile test completed for {profile_name}: {test_success_rate:.1f}% success rate")
        
    except Exception as e:
        logger.error(f"Profile test background task failed: {e}")

@router.get("/health")
async def health_check():
    """Vérifier la santé du système d'évasion"""
    try:
        evasion_manager = get_global_evasion_manager()
        status = evasion_manager.get_evasion_status()
        
        # Évaluer la santé du système
        health_score = 100
        issues = []
        
        # Vérifier le taux de succès
        if status["metrics"]["success_rate"] < 70:
            health_score -= 30
            issues.append("Low success rate detected")
        
        # Vérifier les détections récentes
        if status["recent_detections"] > 10:
            health_score -= 20
            issues.append("High detection frequency")
        
        # Vérifier si les proxies fonctionnent
        if not evasion_manager.proxy_manager.get_current_proxy():
            health_score -= 15
            issues.append("No active proxy detected")
        
        health_status = "healthy" if health_score >= 80 else "degraded" if health_score >= 50 else "unhealthy"
        
        return {
            "health_status": health_status,
            "health_score": health_score,
            "issues": issues,
            "current_profile": status["current_profile"]["name"],
            "recommendations": status["recommendations"],
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {e}")