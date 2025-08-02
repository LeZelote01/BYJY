#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Reconnaissance API V1.0
API REST pour les fonctionnalités de reconnaissance furtive
Features: Network Scanning, OSINT Collection, Service Detection
"""

import os
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel, validator
import ipaddress

from stealth_network_scanner import get_global_stealth_scanner, ScanTarget
from stealth_osint_collector import get_global_osint_collector

logger = logging.getLogger(__name__)

# Router pour les endpoints de reconnaissance
router = APIRouter(prefix="/api/reconnaissance", tags=["reconnaissance"])

# Models Pydantic
class NetworkScanRequest(BaseModel):
    target: str
    ports: str = "1-1000"
    scan_type: str = "syn"
    stealth_level: int = 7
    
    @validator('target')
    def validate_target(cls, v):
        """Valider la cible (IP ou hostname)"""
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            # Peut être un hostname - validation basique
            if len(v) > 0 and '.' in v:
                return v
            raise ValueError("Invalid target format")
    
    @validator('stealth_level')
    def validate_stealth_level(cls, v):
        if not 1 <= v <= 10:
            raise ValueError("Stealth level must be between 1 and 10")
        return v

class OSINTRequest(BaseModel):
    target: str
    collect_subdomains: bool = True
    collect_emails: bool = True
    collect_social_media: bool = False
    collect_certificates: bool = True
    stealth_level: int = 8

class PortScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class ScanStatusResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    progress: float
    start_time: str
    end_time: Optional[str]
    open_ports_count: int
    services_count: int
    stealth_score: float

# Dépendances
def get_scanner():
    """Obtenir l'instance du scanner"""
    return get_global_stealth_scanner()

def get_osint_collector():
    """Obtenir l'instance du collecteur OSINT"""
    return get_global_osint_collector()

# Endpoints

@router.get("/")
async def reconnaissance_info():
    """Information sur les modules de reconnaissance disponibles"""
    return {
        "name": "Stealth Reconnaissance Module",
        "version": "1.0",
        "capabilities": [
            "Network scanning with stealth techniques",
            "OSINT collection and analysis", 
            "Service detection and fingerprinting",
            "Vulnerability identification",
            "Anti-detection and evasion"
        ],
        "stealth_features": [
            "Decoy scanning",
            "Packet fragmentation", 
            "Timing randomization",
            "Source port spoofing",
            "Proxy rotation",
            "Anti-forensics cleanup"
        ],
        "available_modules": {
            "network_scanner": True,
            "osint_collector": True,
            "service_detector": True,
            "vulnerability_scanner": True
        }
    }

@router.post("/network/scan", response_model=PortScanResponse)
async def start_network_scan(
    request: NetworkScanRequest,
    background_tasks: BackgroundTasks,
    scanner = Depends(get_scanner)
):
    """Démarrer un scan réseau furtif"""
    try:
        # Créer la cible de scan
        target = ScanTarget(
            host=request.target,
            ports=request.ports,
            scan_type=request.scan_type,
            stealth_level=request.stealth_level
        )
        
        # Démarrer le scan
        scan_id = scanner.create_stealth_scan(target)
        
        logger.info(f"🕵️ Network scan initiated: {scan_id} -> {request.target}")
        
        return PortScanResponse(
            scan_id=scan_id,
            status="initiated",
            message=f"Stealth scan started with level {request.stealth_level}"
        )
        
    except Exception as e:
        logger.error(f"❌ Failed to start network scan: {e}")
        raise HTTPException(status_code=500, detail=f"Scan initiation failed: {str(e)}")

@router.get("/network/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str, scanner = Depends(get_scanner)):
    """Obtenir le statut d'un scan"""
    try:
        status = scanner.get_scan_status(scan_id)
        
        if not status:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return ScanStatusResponse(**status)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get scan status: {e}")
        raise HTTPException(status_code=500, detail=f"Status retrieval failed: {str(e)}")

@router.get("/network/scan/{scan_id}/results")
async def get_scan_results(scan_id: str, scanner = Depends(get_scanner)):
    """Obtenir les résultats complets d'un scan"""
    try:
        results = scanner.get_scan_results(scan_id)
        
        if not results:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get scan results: {e}")
        raise HTTPException(status_code=500, detail=f"Results retrieval failed: {str(e)}")

@router.get("/network/scans")
async def list_active_scans(scanner = Depends(get_scanner)):
    """Lister tous les scans actifs"""
    try:
        scans = scanner.list_active_scans()
        
        return {
            "active_scans": scans,
            "total_count": len(scans),
            "running_count": len([s for s in scans if s and s.get("status") == "running"]),
            "completed_count": len([s for s in scans if s and s.get("status") == "completed"])
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to list scans: {e}")
        raise HTTPException(status_code=500, detail=f"Scan listing failed: {str(e)}")

@router.delete("/network/scan/{scan_id}")
async def cancel_scan(scan_id: str, scanner = Depends(get_scanner)):
    """Annuler un scan en cours"""
    try:
        cancelled = scanner.cancel_scan(scan_id)
        
        if not cancelled:
            raise HTTPException(status_code=404, detail="Scan not found or already completed")
        
        return {"message": f"Scan {scan_id} cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to cancel scan: {e}")
        raise HTTPException(status_code=500, detail=f"Scan cancellation failed: {str(e)}")

@router.post("/osint/collect")
async def start_osint_collection(
    request: OSINTRequest,
    background_tasks: BackgroundTasks,
    osint_collector = Depends(get_osint_collector)
):
    """Démarrer une collecte OSINT furtive"""
    try:
        # Créer la tâche de collecte
        collection_id = osint_collector.start_collection(
            target=request.target,
            collect_subdomains=request.collect_subdomains,
            collect_emails=request.collect_emails,
            collect_social_media=request.collect_social_media,
            collect_certificates=request.collect_certificates,
            stealth_level=request.stealth_level
        )
        
        logger.info(f"🕵️ OSINT collection initiated: {collection_id} -> {request.target}")
        
        return {
            "collection_id": collection_id,
            "status": "initiated",
            "target": request.target,
            "message": f"OSINT collection started with stealth level {request.stealth_level}"
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to start OSINT collection: {e}")
        raise HTTPException(status_code=500, detail=f"OSINT collection failed: {str(e)}")

@router.get("/osint/collection/{collection_id}/status")
async def get_osint_status(collection_id: str, osint_collector = Depends(get_osint_collector)):
    """Obtenir le statut d'une collecte OSINT"""
    try:
        status = osint_collector.get_collection_status(collection_id)
        
        if not status:
            raise HTTPException(status_code=404, detail="Collection not found")
        
        return status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get OSINT status: {e}")
        raise HTTPException(status_code=500, detail=f"OSINT status retrieval failed: {str(e)}")

@router.get("/osint/collection/{collection_id}/results")
async def get_osint_results(collection_id: str, osint_collector = Depends(get_osint_collector)):
    """Obtenir les résultats d'une collecte OSINT"""
    try:
        results = osint_collector.get_collection_results(collection_id)
        
        if not results:
            raise HTTPException(status_code=404, detail="Collection not found")
        
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get OSINT results: {e}")
        raise HTTPException(status_code=500, detail=f"OSINT results retrieval failed: {str(e)}")

@router.get("/statistics")
async def get_reconnaissance_statistics(
    scanner = Depends(get_scanner),
    osint_collector = Depends(get_osint_collector)
):
    """Obtenir les statistiques générales de reconnaissance"""
    try:
        scanner_stats = scanner.get_scanner_statistics()
        osint_stats = osint_collector.get_collector_statistics()
        
        return {
            "network_scanner": scanner_stats,
            "osint_collector": osint_stats,
            "total_operations": scanner_stats.get("total_scans", 0) + osint_stats.get("total_collections", 0),
            "stealth_capabilities": {
                "decoy_scanning": True,
                "proxy_rotation": scanner_stats.get("proxy_enabled", False),
                "fragmentation": True,
                "timing_evasion": True,
                "anti_forensics": True
            }
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to get reconnaissance statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Statistics retrieval failed: {str(e)}")

@router.get("/targets/validate/{target}")
async def validate_target(target: str):
    """Valider une cible avant scan"""
    try:
        # Vérifier si c'est une IP valide
        try:
            ip = ipaddress.ip_address(target)
            is_private = ip.is_private
            is_reserved = ip.is_reserved
            
            return {
                "target": target,
                "type": "ip_address",
                "valid": True,
                "is_private": is_private,
                "is_reserved": is_reserved,
                "warnings": [
                    "Scanning private networks requires authorization",
                    "Ensure you have permission to scan this target"
                ] if is_private else []
            }
            
        except ValueError:
            # Peut être un hostname
            import socket
            try:
                socket.gethostbyname(target)
                return {
                    "target": target,
                    "type": "hostname",
                    "valid": True,
                    "warnings": [
                        "Hostname resolved successfully",
                        "Ensure you have permission to scan this target"
                    ]
                }
            except socket.gaierror:
                return {
                    "target": target,
                    "type": "unknown",
                    "valid": False,
                    "error": "Hostname resolution failed"
                }
        
    except Exception as e:
        logger.error(f"❌ Target validation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Target validation failed: {str(e)}")

# Endpoints pour les profils de scan
@router.get("/profiles")
async def get_scan_profiles():
    """Obtenir les profils de scan prédéfinis"""
    return {
        "profiles": {
            "quick_scan": {
                "name": "Quick Scan",
                "ports": "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080",
                "stealth_level": 5,
                "description": "Scan rapide des ports les plus courants"
            },
            "comprehensive_scan": {
                "name": "Comprehensive Scan", 
                "ports": "1-65535",
                "stealth_level": 7,
                "description": "Scan complet de tous les ports avec niveau de furtivité élevé"
            },
            "stealth_scan": {
                "name": "Maximum Stealth",
                "ports": "1-1000",
                "stealth_level": 10,
                "description": "Scan furtif maximum avec toutes les techniques d'évasion"
            },
            "web_scan": {
                "name": "Web Services",
                "ports": "80,443,8080,8443,8000,8008,9000,9090",
                "stealth_level": 6,
                "description": "Scan ciblé sur les services web"
            },
            "database_scan": {
                "name": "Database Services",
                "ports": "1433,3306,5432,1521,27017,6379,11211",
                "stealth_level": 8,
                "description": "Scan ciblé sur les services de base de données"
            }
        }
    }

@router.post("/profiles/scan")
async def start_profile_scan(
    profile: str,
    target: str,
    background_tasks: BackgroundTasks,
    scanner = Depends(get_scanner)
):
    """Démarrer un scan avec un profil prédéfini"""
    try:
        # Obtenir les profils
        profiles_response = await get_scan_profiles()
        profiles = profiles_response["profiles"]
        
        if profile not in profiles:
            raise HTTPException(status_code=400, detail="Profile not found")
        
        profile_config = profiles[profile]
        
        # Créer la requête de scan
        scan_request = NetworkScanRequest(
            target=target,
            ports=profile_config["ports"],
            stealth_level=profile_config["stealth_level"]
        )
        
        # Démarrer le scan
        result = await start_network_scan(scan_request, background_tasks, scanner)
        
        return {
            **result.dict(),
            "profile_used": profile,
            "profile_description": profile_config["description"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Profile scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Profile scan failed: {str(e)}")