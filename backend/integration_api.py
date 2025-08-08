#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Integration API V1.0
API REST pour l'intégration de la furtivité dans tous les modules
Features: Terminal Integration, Monitoring Integration, Database Integration
"""

import logging
from datetime import datetime
from typing import Dict, List, Any, Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from stealth_integration import get_global_stealth_integration

logger = logging.getLogger(__name__)

# Router pour les endpoints d'intégration
router = APIRouter(prefix="/api/integration", tags=["integration"])

# Modèles Pydantic
class CommandExecutionRequest(BaseModel):
    command: str
    working_directory: Optional[str] = None

class ProcessFilterRequest(BaseModel):
    include_hidden: bool = False

# Endpoints d'intégration du terminal furtif

@router.post("/terminal/execute")
async def execute_stealth_command(request: CommandExecutionRequest):
    """Exécuter une commande avec intégration furtive"""
    try:
        integration = get_global_stealth_integration()
        stealth_terminal = integration["stealth_terminal"]
        
        result = stealth_terminal.execute_stealth_command(
            command=request.command,
            working_dir=request.working_directory
        )
        
        return {
            "message": "Command executed with stealth integration",
            "execution_result": result,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to execute stealth command: {e}")
        raise HTTPException(status_code=500, detail=f"Command execution failed: {e}")

@router.get("/terminal/history")
async def get_obfuscated_command_history(limit: int = 50):
    """Obtenir l'historique obfusqué des commandes"""
    try:
        integration = get_global_stealth_integration()
        stealth_terminal = integration["stealth_terminal"]
        
        history = stealth_terminal.get_obfuscated_history(limit=limit)
        
        return {
            "obfuscated_history": history,
            "total_entries": len(history),
            "limit": limit,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get command history: {e}")
        raise HTTPException(status_code=500, detail=f"History retrieval failed: {e}")

@router.delete("/terminal/cleanup")
async def cleanup_terminal_traces():
    """Nettoyer toutes les traces du terminal furtif"""
    try:
        integration = get_global_stealth_integration()
        stealth_terminal = integration["stealth_terminal"]
        
        stealth_terminal.cleanup_all()
        
        return {
            "message": "Terminal traces cleaned up successfully",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to cleanup terminal traces: {e}")
        raise HTTPException(status_code=500, detail=f"Terminal cleanup failed: {e}")

# Endpoints d'intégration du monitoring furtif

@router.get("/monitoring/processes")
async def get_filtered_processes(include_hidden: bool = False):
    """Obtenir la liste des processus avec filtrage furtif"""
    try:
        integration = get_global_stealth_integration()
        stealth_monitoring = integration["stealth_monitoring"]
        
        processes = stealth_monitoring.get_filtered_processes(include_hidden=include_hidden)
        
        return {
            "processes": processes,
            "total_processes": len(processes),
            "hidden_processes_included": include_hidden,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get filtered processes: {e}")
        raise HTTPException(status_code=500, detail=f"Process filtering failed: {e}")

@router.post("/monitoring/whitelist/{process_name}")
async def add_process_to_whitelist(process_name: str):
    """Ajouter un processus à la whitelist (toujours visible)"""
    try:
        integration = get_global_stealth_integration()
        stealth_monitoring = integration["stealth_monitoring"]
        
        stealth_monitoring.add_process_to_whitelist(process_name)
        
        return {
            "message": f"Process '{process_name}' added to whitelist",
            "process_name": process_name,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to add process to whitelist: {e}")
        raise HTTPException(status_code=500, detail=f"Whitelist operation failed: {e}")

@router.post("/monitoring/hide/{process_name}")
async def hide_process(process_name: str):
    """Masquer un processus spécifique"""
    try:
        integration = get_global_stealth_integration()
        stealth_monitoring = integration["stealth_monitoring"]
        
        stealth_monitoring.hide_process(process_name)
        
        return {
            "message": f"Process '{process_name}' will be hidden from monitoring",
            "process_name": process_name,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to hide process: {e}")
        raise HTTPException(status_code=500, detail=f"Process hiding failed: {e}")

@router.get("/monitoring/metrics")
async def get_stealth_monitoring_metrics():
    """Obtenir les métriques du monitoring furtif"""
    try:
        integration = get_global_stealth_integration()
        stealth_monitoring = integration["stealth_monitoring"]
        
        metrics = stealth_monitoring.get_stealth_metrics()
        
        return {
            "metrics": metrics,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get monitoring metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Metrics retrieval failed: {e}")

# Endpoints d'intégration de la base de données furtive

@router.post("/database/obfuscate")
async def obfuscate_sensitive_data(data: str, table_name: Optional[str] = None):
    """Obfusquer des données sensibles avant stockage"""
    try:
        integration = get_global_stealth_integration()
        stealth_database = integration["stealth_database"]
        
        if not stealth_database:
            raise HTTPException(status_code=400, detail="Database stealth integration not configured")
        
        obfuscated_data = stealth_database.obfuscate_sensitive_data(data, table_name)
        
        return {
            "original_length": len(data),
            "obfuscated_data": obfuscated_data,
            "obfuscated_length": len(obfuscated_data),
            "table_name": table_name,
            "is_sensitive_table": stealth_database._is_sensitive_table(table_name) if table_name else False,
            "timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to obfuscate data: {e}")
        raise HTTPException(status_code=500, detail=f"Data obfuscation failed: {e}")

# Endpoints de gestion générale de l'intégration

@router.get("/status")
async def get_integration_status():
    """Obtenir le statut complet de l'intégration furtive"""
    try:
        integration = get_global_stealth_integration()
        
        # Statut des composants
        terminal_status = hasattr(integration["stealth_terminal"], 'stealth_engine')
        monitoring_status = hasattr(integration["stealth_monitoring"], 'stealth_engine')
        database_status = integration["stealth_database"] is not None
        
        # Métriques du monitoring si disponible
        monitoring_metrics = {}
        if monitoring_status:
            monitoring_metrics = integration["stealth_monitoring"].get_stealth_metrics()
        
        return {
            "integration_status": {
                "terminal_integration": terminal_status,
                "monitoring_integration": monitoring_status,
                "database_integration": database_status
            },
            "monitoring_metrics": monitoring_metrics,
            "available_features": {
                "stealth_command_execution": terminal_status,
                "process_filtering": monitoring_status,
                "data_obfuscation": database_status,
                "command_history_obfuscation": terminal_status,
                "forensics_cleanup": terminal_status
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get integration status: {e}")
        raise HTTPException(status_code=500, detail=f"Status retrieval failed: {e}")

@router.post("/initialize")
async def initialize_stealth_integration(database_path: Optional[str] = None):
    """Initialiser ou réinitialiser l'intégration furtive"""
    try:
        global _global_stealth_integration
        
        # Réinitialiser l'instance globale
        from stealth_integration import get_stealth_integration
        _global_stealth_integration = get_stealth_integration(database_path)
        
        return {
            "message": "Stealth integration initialized successfully",
            "database_integration": database_path is not None,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to initialize integration: {e}")
        raise HTTPException(status_code=500, detail=f"Integration initialization failed: {e}")

@router.get("/capabilities")
async def get_integration_capabilities():
    """Obtenir les capacités disponibles de l'intégration furtive"""
    try:
        capabilities = {
            "terminal_stealth": {
                "command_obfuscation": True,
                "sensitive_command_detection": True,
                "execution_environment_masking": True,
                "trace_cleanup": True,
                "history_obfuscation": True
            },
            "monitoring_stealth": {
                "process_filtering": True,
                "sensitive_process_hiding": True,
                "process_information_obfuscation": True,
                "whitelist_management": True,
                "metrics_collection": True
            },
            "database_stealth": {
                "data_obfuscation": True,
                "sensitive_table_detection": True,
                "encryption_support": True
            },
            "forensics_protection": {
                "command_trace_cleanup": True,
                "temporary_file_cleanup": True,
                "history_manipulation": True,
                "environment_masking": True
            }
        }
        
        return {
            "capabilities": capabilities,
            "total_features": sum(len(features) for features in capabilities.values()),
            "categories": list(capabilities.keys()),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get capabilities: {e}")
        raise HTTPException(status_code=500, detail=f"Capabilities retrieval failed: {e}")

@router.get("/health")
async def health_check():
    """Vérifier la santé de l'intégration furtive"""
    try:
        integration = get_global_stealth_integration()
        
        health_status = {
            "overall": "healthy",
            "issues": [],
            "components": {}
        }
        
        # Vérifier chaque composant
        try:
            terminal = integration["stealth_terminal"]
            health_status["components"]["terminal"] = {
                "status": "healthy",
                "stealth_engine": hasattr(terminal, 'stealth_engine'),
                "evasion_manager": hasattr(terminal, 'evasion_manager')
            }
        except Exception as e:
            health_status["components"]["terminal"] = {"status": "error", "error": str(e)}
            health_status["issues"].append(f"Terminal component error: {e}")
        
        try:
            monitoring = integration["stealth_monitoring"]
            metrics = monitoring.get_stealth_metrics()
            health_status["components"]["monitoring"] = {
                "status": "healthy",
                "metrics": metrics,
                "hidden_processes": metrics["hidden_processes"]
            }
        except Exception as e:
            health_status["components"]["monitoring"] = {"status": "error", "error": str(e)}
            health_status["issues"].append(f"Monitoring component error: {e}")
        
        database = integration["stealth_database"]
        if database:
            health_status["components"]["database"] = {
                "status": "healthy",
                "encryption_available": hasattr(database, 'encryption_key')
            }
        else:
            health_status["components"]["database"] = {"status": "not_configured"}
        
        # Déterminer le statut global
        if health_status["issues"]:
            health_status["overall"] = "degraded" if len(health_status["issues"]) < 2 else "unhealthy"
        
        return {
            "health": health_status,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {e}")

# Instance globale pour éviter les imports circulaires
_global_stealth_integration = None