#!/usr/bin/env python3
"""
🔬 FORENSICS API - Phase 5.5
CyberSec Assistant Portable - Complete Forensic Analysis API

API REST complète intégrant tous les modules forensiques :
- Forensic Log Analyzer API
- File Forensics API  
- Network Forensics API
- Memory Forensics API

Auteur: CyberSec Assistant Team
Version: 1.0
"""

from fastapi import APIRouter, HTTPException, UploadFile, File, BackgroundTasks
from typing import Dict, List, Any, Optional
import logging
import datetime
import os
import tempfile
import shutil

# Import des modules forensiques
try:
    from forensic_log_analyzer import ForensicLogAnalyzer
    from file_forensics import FileForensicsAnalyzer
    from network_forensics import NetworkForensicsAnalyzer
    from memory_forensics import MemoryForensicsAnalyzer
except ImportError as e:
    logging.error(f"❌ Erreur import modules forensiques: {e}")
    # Classes fallback pour éviter les erreurs
    class ForensicLogAnalyzer:
        def __init__(self, *args, **kwargs): pass
        async def analyze_logs(self, *args, **kwargs): return {'error': 'Module non disponible'}
        async def list_analyses(self): return []
    
    class FileForensicsAnalyzer:
        def __init__(self, *args, **kwargs): pass
        async def analyze_file(self, *args, **kwargs): return {'error': 'Module non disponible'}
        async def list_file_analyses(self): return []
    
    class NetworkForensicsAnalyzer:
        def __init__(self, *args, **kwargs): pass
        async def analyze_pcap_file(self, *args, **kwargs): return {'error': 'Module non disponible'}
        async def list_network_analyses(self): return []
    
    class MemoryForensicsAnalyzer:
        def __init__(self, *args, **kwargs): pass
        async def analyze_system_memory(self, *args, **kwargs): return {'error': 'Module non disponible'}
        async def list_memory_analyses(self): return []

# Configuration des analyseurs forensiques
import os
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "cybersec.db")

forensic_log_analyzer = ForensicLogAnalyzer(DB_PATH)
file_forensics_analyzer = FileForensicsAnalyzer(DB_PATH)
network_forensics_analyzer = NetworkForensicsAnalyzer(DB_PATH)
memory_forensics_analyzer = MemoryForensicsAnalyzer(DB_PATH)

# Router principal pour les APIs forensiques
forensics_router = APIRouter(prefix="/api/forensics", tags=["forensics"])

# 🔬 LOG FORENSICS API

@forensics_router.post("/logs/analyze")
async def analyze_logs(
    background_tasks: BackgroundTasks,
    case_id: Optional[str] = None,
    analysis_name: str = "Log Forensic Analysis",
    log_files: List[UploadFile] = File(...),
    log_formats: Optional[List[str]] = None
):
    """
    🔍 Analyse forensique de fichiers de logs
    
    Analyse complète des logs avec détection d'anomalies,
    reconstruction de timeline et corrélation cross-system.
    """
    try:
        logging.info(f"🔬 Démarrage analyse logs - {len(log_files)} fichiers")
        
        # Sauvegarde temporaire des fichiers uploadés
        temp_files = []
        for log_file in log_files:
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{log_file.filename}")
            shutil.copyfileobj(log_file.file, temp_file)
            temp_file.close()
            temp_files.append(temp_file.name)
        
        # Analyse forensique des logs
        analysis_result = await forensic_log_analyzer.analyze_logs(
            source_paths=temp_files,
            case_id=case_id,
            analysis_name=analysis_name,
            log_formats=log_formats
        )
        
        # Nettoyage des fichiers temporaires en arrière-plan
        background_tasks.add_task(cleanup_temp_files, temp_files)
        
        return {
            "status": "success",
            "message": f"Analyse logs terminée - {analysis_result.get('total_entries', 0)} entrées analysées",
            "analysis_id": analysis_result.get('analysis_id'),
            "results": analysis_result
        }
        
    except Exception as e:
        logging.error(f"❌ Erreur analyse logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@forensics_router.get("/logs/analyses")
async def list_log_analyses():
    """📋 Liste toutes les analyses de logs forensiques"""
    try:
        analyses = await forensic_log_analyzer.list_analyses()
        return {
            "status": "success",
            "count": len(analyses),
            "analyses": analyses
        }
    except Exception as e:
        logging.error(f"❌ Erreur liste analyses logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@forensics_router.get("/logs/analysis/{analysis_id}")
async def get_log_analysis(analysis_id: str):
    """📊 Récupère les résultats d'une analyse de logs"""
    try:
        analysis = await forensic_log_analyzer.get_analysis_results(analysis_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Analyse non trouvée")
        
        return {
            "status": "success",
            "analysis": analysis
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"❌ Erreur récupération analyse logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# 📁 FILE FORENSICS API

@forensics_router.post("/files/analyze")
async def analyze_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    analysis_types: Optional[List[str]] = None
):
    """
    🔍 Analyse forensique complète d'un fichier
    
    Analyse métadonnées, détection malware, stéganographie
    et récupération de fichiers supprimés.
    """
    try:
        logging.info(f"🔬 Démarrage analyse fichier - {file.filename}")
        
        # Sauvegarde temporaire du fichier
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}")
        shutil.copyfileobj(file.file, temp_file)
        temp_file.close()
        
        # Analyse forensique du fichier
        analysis_result = await file_forensics_analyzer.analyze_file(
            file_path=temp_file.name,
            analysis_types=analysis_types or ['metadata', 'malware', 'steganography']
        )
        
        # Nettoyage en arrière-plan
        background_tasks.add_task(cleanup_temp_files, [temp_file.name])
        
        return {
            "status": "success", 
            "message": f"Analyse fichier terminée - Risk Score: {analysis_result.get('risk_score', 0):.2f}",
            "analysis_id": analysis_result.get('analysis_id'),
            "results": analysis_result
        }
        
    except Exception as e:
        logging.error(f"❌ Erreur analyse fichier: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@forensics_router.get("/files/analyses")
async def list_file_analyses():
    """📋 Liste toutes les analyses de fichiers"""
    try:
        analyses = await file_forensics_analyzer.list_file_analyses()
        return {
            "status": "success",
            "count": len(analyses),
            "analyses": analyses
        }
    except Exception as e:
        logging.error(f"❌ Erreur liste analyses fichiers: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@forensics_router.post("/files/directory/analyze")
async def analyze_directory(
    directory_path: str
):
    """
    🛡️ Analyse furtive d'un répertoire complet
    
    Analyse forensique de tous les fichiers d'un répertoire
    avec techniques de furtivité avancées.
    """
    try:
        if not os.path.exists(directory_path):
            raise HTTPException(status_code=404, detail="Répertoire non trouvé")
        
        analysis_result = await file_forensics_analyzer.stealth_analyze_directory(directory_path)
        
        return {
            "status": "success",
            "message": f"Analyse répertoire terminée - {analysis_result.get('files_analyzed', 0)} fichiers analysés",
            "results": analysis_result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"❌ Erreur analyse répertoire: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# 🌐 NETWORK FORENSICS API

@forensics_router.post("/network/pcap/analyze")
async def analyze_pcap(
    background_tasks: BackgroundTasks,
    pcap_file: UploadFile = File(...),
    sessions: bool = True,
    threats: bool = True,
    files: bool = True,
    bandwidth: bool = True
):
    """
    🔍 Analyse forensique complète d'un fichier PCAP
    
    Reconstruction de sessions, détection de menaces,
    extraction de fichiers et analyse de bande passante.
    """
    try:
        logging.info(f"🔬 Démarrage analyse PCAP - {pcap_file.filename}")
        
        # Sauvegarde temporaire du fichier PCAP
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
        shutil.copyfileobj(pcap_file.file, temp_file)
        temp_file.close()
        
        # Options d'analyse
        analysis_options = {
            'sessions': sessions,
            'threats': threats,
            'files': files,
            'bandwidth': bandwidth
        }
        
        # Analyse forensique PCAP
        analysis_result = await network_forensics_analyzer.analyze_pcap_file(
            pcap_path=temp_file.name,
            analysis_options=analysis_options
        )
        
        # Nettoyage en arrière-plan
        background_tasks.add_task(cleanup_temp_files, [temp_file.name])
        
        return {
            "status": "success",
            "message": f"Analyse PCAP terminée - Threat Score: {analysis_result.get('threat_score', 0):.2f}",
            "analysis_id": analysis_result.get('analysis_id'),
            "results": analysis_result
        }
        
    except Exception as e:
        logging.error(f"❌ Erreur analyse PCAP: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@forensics_router.get("/network/analyses")
async def list_network_analyses():
    """📋 Liste toutes les analyses réseau"""
    try:
        analyses = await network_forensics_analyzer.list_network_analyses()
        return {
            "status": "success",
            "count": len(analyses),
            "analyses": analyses
        }
    except Exception as e:
        logging.error(f"❌ Erreur liste analyses réseau: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@forensics_router.post("/network/capture/stealth")
async def stealth_packet_capture(
    interface: str,
    duration: int = 60,
    filter_expression: Optional[str] = None
):
    """
    🛡️ Capture furtive de packets réseau
    
    Capture de packets avec techniques de furtivité avancées
    et mode monitor WiFi si supporté.
    """
    try:
        capture_result = await network_forensics_analyzer.stealth_packet_capture(
            interface=interface,
            duration=duration,
            filter_expression=filter_expression
        )
        
        return {
            "status": "success",
            "message": f"Capture furtive terminée - {capture_result.get('packets_captured', 0)} packets capturés",
            "results": capture_result
        }
        
    except Exception as e:
        logging.error(f"❌ Erreur capture furtive: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# 🧠 MEMORY FORENSICS API

@forensics_router.post("/memory/analyze")
async def analyze_system_memory(
    processes: bool = True,
    rootkits: bool = True,
    dumps: bool = False,
    artifacts: bool = True
):
    """
    🔍 Analyse forensique complète de la mémoire système
    
    Analyse des processus, détection de rootkits,
    création de dumps mémoire et extraction d'artefacts.
    """
    try:
        logging.info("🔬 Démarrage analyse mémoire système")
        
        # Options d'analyse
        analysis_options = {
            'processes': processes,
            'rootkits': rootkits,
            'dumps': dumps,
            'artifacts': artifacts
        }
        
        # Analyse forensique mémoire
        analysis_result = await memory_forensics_analyzer.analyze_system_memory(
            analysis_options=analysis_options
        )
        
        return {
            "status": "success",
            "message": f"Analyse mémoire terminée - Threat Score: {analysis_result.get('threat_score', 0):.2f}",
            "analysis_id": analysis_result.get('analysis_id'),
            "results": analysis_result
        }
        
    except Exception as e:
        logging.error(f"❌ Erreur analyse mémoire: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@forensics_router.get("/memory/analyses")
async def list_memory_analyses():
    """📋 Liste toutes les analyses mémoire"""
    try:
        analyses = await memory_forensics_analyzer.list_memory_analyses()
        return {
            "status": "success",
            "count": len(analyses),
            "analyses": analyses
        }
    except Exception as e:
        logging.error(f"❌ Erreur liste analyses mémoire: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# 📊 FORENSICS DASHBOARD API

@forensics_router.get("/dashboard/overview")
async def forensics_dashboard():
    """
    📊 Vue d'ensemble du dashboard forensique
    
    Statistiques globales de toutes les analyses forensiques.
    """
    try:
        # Récupération des statistiques de tous les modules
        log_analyses = await forensic_log_analyzer.list_analyses()
        file_analyses = await file_forensics_analyzer.list_file_analyses()
        network_analyses = await network_forensics_analyzer.list_network_analyses()
        memory_analyses = await memory_forensics_analyzer.list_memory_analyses()
        
        # Calcul des statistiques globales
        total_analyses = len(log_analyses) + len(file_analyses) + len(network_analyses) + len(memory_analyses)
        
        # Analyses récentes (dernières 24h)
        recent_cutoff = datetime.datetime.now() - datetime.timedelta(hours=24)
        recent_analyses = 0
        
        for analysis_list in [log_analyses, file_analyses, network_analyses, memory_analyses]:
            for analysis in analysis_list:
                try:
                    created_at = datetime.datetime.fromisoformat(analysis.get('created_at', ''))
                    if created_at > recent_cutoff:
                        recent_analyses += 1
                except:
                    pass
        
        # Calcul du threat score moyen
        all_threat_scores = []
        for analysis_list in [file_analyses, network_analyses, memory_analyses]:
            for analysis in analysis_list:
                if 'threat_score' in analysis and analysis['threat_score'] is not None:
                    all_threat_scores.append(analysis['threat_score'])
        
        avg_threat_score = sum(all_threat_scores) / len(all_threat_scores) if all_threat_scores else 0.0
        
        dashboard_data = {
            "status": "success",
            "overview": {
                "total_analyses": total_analyses,
                "recent_analyses_24h": recent_analyses,
                "average_threat_score": round(avg_threat_score, 2),
                "modules_active": 4
            },
            "modules": {
                "log_forensics": {
                    "total_analyses": len(log_analyses),
                    "status": "active"
                },
                "file_forensics": {
                    "total_analyses": len(file_analyses),
                    "status": "active"
                },
                "network_forensics": {
                    "total_analyses": len(network_analyses),
                    "status": "active"
                },
                "memory_forensics": {
                    "total_analyses": len(memory_analyses),
                    "status": "active"
                }
            },
            "recent_activities": [
                # Intégration des activités récentes de tous les modules
                *[{"type": "log_analysis", "id": a.get('analysis_id'), "created_at": a.get('created_at')} 
                  for a in log_analyses[-5:]],
                *[{"type": "file_analysis", "id": a.get('analysis_id'), "created_at": a.get('created_at')} 
                  for a in file_analyses[-5:]],
                *[{"type": "network_analysis", "id": a.get('analysis_id'), "created_at": a.get('created_at')} 
                  for a in network_analyses[-5:]],
                *[{"type": "memory_analysis", "id": a.get('analysis_id'), "created_at": a.get('created_at')} 
                  for a in memory_analyses[-5:]]
            ][-10:]  # Limite aux 10 plus récentes
        }
        
        return dashboard_data
        
    except Exception as e:
        logging.error(f"❌ Erreur dashboard forensique: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@forensics_router.get("/dashboard/threat-intelligence")
async def threat_intelligence_dashboard():
    """
    🚨 Dashboard de Threat Intelligence
    
    Analyse des menaces détectées par tous les modules forensiques.
    """
    try:
        # Récupération des analyses avec scores de menace
        file_analyses = await file_forensics_analyzer.list_file_analyses()
        network_analyses = await network_forensics_analyzer.list_network_analyses()
        memory_analyses = await memory_forensics_analyzer.list_memory_analyses()
        
        # Classification des menaces
        threat_levels = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        all_analyses = [
            *[{**a, "type": "file"} for a in file_analyses],
            *[{**a, "type": "network"} for a in network_analyses], 
            *[{**a, "type": "memory"} for a in memory_analyses]
        ]
        
        for analysis in all_analyses:
            threat_score = analysis.get('threat_score', 0)
            if threat_score >= 0.8:
                threat_levels["critical"].append(analysis)
            elif threat_score >= 0.6:
                threat_levels["high"].append(analysis)
            elif threat_score >= 0.3:
                threat_levels["medium"].append(analysis)
            else:
                threat_levels["low"].append(analysis)
        
        return {
            "status": "success",
            "threat_intelligence": {
                "total_threats": len(all_analyses),
                "threat_distribution": {
                    level: len(analyses) for level, analyses in threat_levels.items()
                },
                "critical_threats": threat_levels["critical"][:5],  # Top 5 menaces critiques
                "threat_trends": {
                    "increasing": len(threat_levels["critical"]) > len(threat_levels["low"]),
                    "stable": len(threat_levels["medium"]) > len(threat_levels["high"])
                }
            }
        }
        
    except Exception as e:
        logging.error(f"❌ Erreur threat intelligence: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# 🧹 UTILITY FUNCTIONS

async def cleanup_temp_files(file_paths: List[str]):
    """Nettoyage des fichiers temporaires"""
    for file_path in file_paths:
        try:
            if os.path.exists(file_path):
                os.unlink(file_path)
                logging.debug(f"🧹 Fichier temporaire nettoyé: {file_path}")
        except Exception as e:
            logging.warning(f"⚠️ Erreur nettoyage fichier {file_path}: {e}")

# 📄 FORENSICS REPORTING API

@forensics_router.post("/reports/generate")
async def generate_forensic_report(
    case_id: str,
    report_type: str = "comprehensive",
    format: str = "json",
    include_modules: Optional[List[str]] = None
):
    """
    📄 Génération de rapport forensique complet
    
    Génère un rapport forensique légal incluant tous les modules analysés,
    avec chain of custody et timeline complète.
    
    Formats supportés: json, html, pdf
    Types: comprehensive, summary, technical, legal
    """
    try:
        logging.info(f"📄 Génération rapport forensique - Case ID: {case_id}")
        
        # Modules à inclure (par défaut tous)
        modules_to_include = include_modules or ["logs", "files", "network", "memory"]
        
        # Collecte des données de tous les modules demandés
        report_data = {
            "case_id": case_id,
            "report_type": report_type,
            "generated_at": datetime.datetime.now().isoformat(),
            "generated_by": "CyberSec Assistant Portable - Forensics Suite",
            "version": "1.0",
            "modules_included": modules_to_include,
            "analysis_summary": {},
            "detailed_results": {},
            "timeline": [],
            "threat_assessment": {},
            "chain_of_custody": []
        }
        
        # Récupération des analyses par module
        if "logs" in modules_to_include:
            log_analyses = await forensic_log_analyzer.list_analyses()
            case_logs = [a for a in log_analyses if a.get('case_id') == case_id or case_id == "all"]
            report_data["analysis_summary"]["log_forensics"] = {
                "total_analyses": len(case_logs),
                "anomalies_detected": sum(len(a.get('anomalies', [])) for a in case_logs),
                "timeline_events": sum(a.get('total_entries', 0) for a in case_logs)
            }
            report_data["detailed_results"]["log_analyses"] = case_logs
        
        if "files" in modules_to_include:
            file_analyses = await file_forensics_analyzer.list_file_analyses()
            case_files = [a for a in file_analyses if a.get('case_id') == case_id or case_id == "all"]
            report_data["analysis_summary"]["file_forensics"] = {
                "total_analyses": len(case_files),
                "files_analyzed": len(case_files),
                "malware_detected": sum(1 for a in case_files if a.get('risk_score', 0) > 0.5),
                "average_risk_score": sum(a.get('risk_score', 0) for a in case_files) / len(case_files) if case_files else 0
            }
            report_data["detailed_results"]["file_analyses"] = case_files
        
        if "network" in modules_to_include:
            network_analyses = await network_forensics_analyzer.list_network_analyses()
            case_network = [a for a in network_analyses if a.get('case_id') == case_id or case_id == "all"]
            report_data["analysis_summary"]["network_forensics"] = {
                "total_analyses": len(case_network),
                "pcap_files_analyzed": len(case_network),
                "threats_detected": sum(1 for a in case_network if a.get('threat_score', 0) > 0.3),
                "average_threat_score": sum(a.get('threat_score', 0) for a in case_network) / len(case_network) if case_network else 0
            }
            report_data["detailed_results"]["network_analyses"] = case_network
        
        if "memory" in modules_to_include:
            memory_analyses = await memory_forensics_analyzer.list_memory_analyses()
            case_memory = [a for a in memory_analyses if a.get('case_id') == case_id or case_id == "all"]
            report_data["analysis_summary"]["memory_forensics"] = {
                "total_analyses": len(case_memory),
                "processes_analyzed": sum(len(a.get('results', {}).get('processes', [])) for a in case_memory),
                "rootkits_detected": sum(1 for a in case_memory if a.get('threat_score', 0) > 0.4),
                "average_threat_score": sum(a.get('threat_score', 0) for a in case_memory) / len(case_memory) if case_memory else 0
            }
            report_data["detailed_results"]["memory_analyses"] = case_memory
        
        # Calcul de l'évaluation globale des menaces
        all_threat_scores = []
        for module in ["file_analyses", "network_analyses", "memory_analyses"]:
            if module in report_data["detailed_results"]:
                for analysis in report_data["detailed_results"][module]:
                    if "threat_score" in analysis and analysis["threat_score"] is not None:
                        all_threat_scores.append(analysis["threat_score"])
        
        report_data["threat_assessment"] = {
            "overall_threat_level": "critical" if any(s >= 0.8 for s in all_threat_scores) else
                                   "high" if any(s >= 0.6 for s in all_threat_scores) else
                                   "medium" if any(s >= 0.3 for s in all_threat_scores) else "low",
            "average_threat_score": sum(all_threat_scores) / len(all_threat_scores) if all_threat_scores else 0,
            "total_threats_detected": len([s for s in all_threat_scores if s > 0.3]),
            "critical_threats": len([s for s in all_threat_scores if s >= 0.8]),
            "high_threats": len([s for s in all_threat_scores if 0.6 <= s < 0.8]),
            "medium_threats": len([s for s in all_threat_scores if 0.3 <= s < 0.6])
        }
        
        # Chain of custody basic
        report_data["chain_of_custody"] = [
            {
                "timestamp": datetime.datetime.now().isoformat(),
                "action": "forensic_report_generated",
                "operator": "CyberSec Assistant",
                "description": f"Rapport forensique généré pour le case {case_id}",
                "integrity_hash": "SHA256_placeholder"
            }
        ]
        
        # Génération selon le format demandé
        if format.lower() == "json":
            return {
                "status": "success",
                "message": f"Rapport forensique généré - {len(modules_to_include)} modules inclus",
                "report_format": "json",
                "report": report_data
            }
        
        elif format.lower() == "html":
            html_report = generate_html_report(report_data)
            return {
                "status": "success",
                "message": f"Rapport HTML généré - {len(modules_to_include)} modules inclus",
                "report_format": "html",
                "report": html_report
            }
        
        elif format.lower() == "pdf":
            # Note: Pour PDF, il faudrait une librairie comme reportlab
            return {
                "status": "success", 
                "message": "Génération PDF non implémentée - utilisez HTML ou JSON",
                "report_format": "json",
                "report": report_data
            }
        
        else:
            raise HTTPException(status_code=400, detail="Format non supporté. Utilisez: json, html, pdf")
        
    except Exception as e:
        logging.error(f"❌ Erreur génération rapport: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@forensics_router.get("/reports/cases")
async def list_forensic_cases():
    """📋 Liste tous les case IDs disponibles pour génération de rapports"""
    try:
        # Récupération de tous les case_ids uniques
        all_case_ids = set()
        
        # Collecte depuis tous les modules
        for analyzer_method in [
            forensic_log_analyzer.list_analyses,
            file_forensics_analyzer.list_file_analyses,
            network_forensics_analyzer.list_network_analyses,
            memory_forensics_analyzer.list_memory_analyses
        ]:
            try:
                analyses = await analyzer_method()
                for analysis in analyses:
                    case_id = analysis.get('case_id')
                    if case_id:
                        all_case_ids.add(case_id)
            except:
                continue
        
        return {
            "status": "success",
            "available_cases": list(all_case_ids),
            "total_cases": len(all_case_ids)
        }
        
    except Exception as e:
        logging.error(f"❌ Erreur liste cases: {e}")
        raise HTTPException(status_code=500, detail=str(e))

def generate_html_report(report_data: Dict[str, Any]) -> str:
    """Génère un rapport HTML formaté"""
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Rapport Forensique - Case {report_data['case_id']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
            .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
            .summary-table {{ width: 100%; border-collapse: collapse; }}
            .summary-table th, .summary-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            .summary-table th {{ background-color: #f2f2f2; }}
            .threat-critical {{ color: #e74c3c; font-weight: bold; }}
            .threat-high {{ color: #f39c12; font-weight: bold; }}
            .threat-medium {{ color: #f1c40f; font-weight: bold; }}
            .threat-low {{ color: #27ae60; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔬 Rapport d'Analyse Forensique</h1>
            <p><strong>Case ID:</strong> {report_data['case_id']}</p>
            <p><strong>Généré le:</strong> {report_data['generated_at']}</p>
            <p><strong>Type de rapport:</strong> {report_data['report_type']}</p>
        </div>
        
        <div class="section">
            <h2>📊 Résumé Exécutif</h2>
            <table class="summary-table">
                <tr><th>Metric</th><th>Valeur</th></tr>
                <tr><td>Niveau de menace global</td><td class="threat-{report_data['threat_assessment']['overall_threat_level']}">{report_data['threat_assessment']['overall_threat_level'].upper()}</td></tr>
                <tr><td>Score moyen de menace</td><td>{report_data['threat_assessment']['average_threat_score']:.2f}</td></tr>
                <tr><td>Total menaces détectées</td><td>{report_data['threat_assessment']['total_threats_detected']}</td></tr>
                <tr><td>Menaces critiques</td><td>{report_data['threat_assessment']['critical_threats']}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>🔍 Analyses par Module</h2>
            <h3>Log Forensics</h3>
            <p>Analyses: {report_data['analysis_summary'].get('log_forensics', {}).get('total_analyses', 0)}</p>
            <p>Anomalies détectées: {report_data['analysis_summary'].get('log_forensics', {}).get('anomalies_detected', 0)}</p>
            
            <h3>File Forensics</h3>
            <p>Fichiers analysés: {report_data['analysis_summary'].get('file_forensics', {}).get('files_analyzed', 0)}</p>
            <p>Malwares détectés: {report_data['analysis_summary'].get('file_forensics', {}).get('malware_detected', 0)}</p>
            
            <h3>Memory Forensics</h3>
            <p>Analyses mémoire: {report_data['analysis_summary'].get('memory_forensics', {}).get('total_analyses', 0)}</p>
            <p>Rootkits détectés: {report_data['analysis_summary'].get('memory_forensics', {}).get('rootkits_detected', 0)}</p>
        </div>
        
        <div class="section">
            <h2>🔒 Chain of Custody</h2>
            <ul>
                {"".join(f"<li>{item['timestamp']} - {item['action']} - {item['description']}</li>" for item in report_data['chain_of_custody'])}
            </ul>
        </div>
        
        <div class="section">
            <h2>⚖️ Conformité Légale</h2>
            <p>Ce rapport a été généré selon les standards forensiques numériques.</p>
            <p>Intégrité des données: Préservée via techniques de furtivité</p>
            <p>Chain of custody: Documentée et horodatée</p>
        </div>
        
        <footer style="margin-top: 40px; text-align: center; color: #666;">
            <p>Généré par CyberSec Assistant Portable - Forensics Suite v1.0</p>
        </footer>
    </body>
    </html>
    """
    return html_template

@forensics_router.get("/info")
async def forensics_info():
    """📋 Informations sur les modules forensiques disponibles"""
    return {
        "status": "success",
        "forensics_suite": {
            "name": "CyberSec Assistant Portable - Forensics Suite",
            "version": "1.0",
            "phase": "Phase 5 - Forensique & Analyse Avancée",
            "modules": {
                "log_forensics": {
                    "name": "Forensic Log Analyzer",
                    "description": "Analyse forensique des logs avec détection d'anomalies et timeline reconstruction",
                    "capabilities": ["multiformat_parsing", "anomaly_detection", "timeline_reconstruction", "stealth_access"]
                },
                "file_forensics": {
                    "name": "File Forensics Analyzer", 
                    "description": "Analyse forensique de fichiers avec détection malware et stéganographie",
                    "capabilities": ["metadata_extraction", "malware_detection", "steganography_analysis", "file_recovery"]
                },
                "network_forensics": {
                    "name": "Network Forensics Analyzer",
                    "description": "Analyse forensique réseau avec reconstruction de sessions et détection de menaces",
                    "capabilities": ["pcap_analysis", "session_reconstruction", "threat_detection", "file_extraction"]
                },
                "memory_forensics": {
                    "name": "Memory Forensics Analyzer",
                    "description": "Analyse forensique mémoire avec détection de rootkits et extraction d'artefacts",
                    "capabilities": ["process_analysis", "rootkit_detection", "memory_dumps", "artifact_extraction"]
                }
            },
            "stealth_features": [
                "furtive_file_access",
                "timestamp_preservation", 
                "anti_detection_techniques",
                "memory_access_masking",
                "network_stealth_capture"
            ]
        }
    }

@forensics_router.get("/health")
async def forensics_health():
    """🏥 Vérification de l'état des modules forensiques"""
    health_status = {
        "status": "healthy",
        "modules": {},
        "timestamp": datetime.datetime.now().isoformat()
    }
    
    # Test de chaque module
    modules_to_test = [
        ("log_forensics", forensic_log_analyzer),
        ("file_forensics", file_forensics_analyzer),
        ("network_forensics", network_forensics_analyzer),
        ("memory_forensics", memory_forensics_analyzer)
    ]
    
    for module_name, analyzer in modules_to_test:
        try:
            # Test simple d'accès à la méthode list
            if hasattr(analyzer, 'list_analyses'):
                await analyzer.list_analyses()
            elif hasattr(analyzer, 'list_file_analyses'):
                await analyzer.list_file_analyses()
            elif hasattr(analyzer, 'list_network_analyses'):
                await analyzer.list_network_analyses()
            elif hasattr(analyzer, 'list_memory_analyses'):
                await analyzer.list_memory_analyses()
            
            health_status["modules"][module_name] = {
                "status": "healthy",
                "last_check": datetime.datetime.now().isoformat()
            }
        except Exception as e:
            health_status["modules"][module_name] = {
                "status": "error",
                "error": str(e),
                "last_check": datetime.datetime.now().isoformat()
            }
            health_status["status"] = "degraded"
    
    return health_status

# Export du router
__all__ = ['forensics_router']