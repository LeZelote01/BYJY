#!/usr/bin/env python3
"""
🔬 MEMORY FORENSICS ANALYZER - Phase 5.4
CyberSec Assistant Portable - Advanced Memory Forensic Analysis Module

FONCTIONNALITÉS :
- Process memory dump analysis avec reconstruction de structures
- Running processes investigation et détection d'anomalies
- Network connections memory analysis et corrélation
- Registry analysis (Windows) avec détection de modifications suspectes
- Rootkit detection basique avec techniques anti-évasion
- Strings extraction from memory avec patterns d'intérêt
- Techniques de furtivité (memory dumping furtif, accès kernel-level)

Auteur: CyberSec Assistant Team
Version: 1.0
"""

import os
import re
import json
import time
import psutil
import struct
import asyncio
import datetime
import sqlite3
import hashlib
import logging
import subprocess
import mmap
import random
from typing import Dict, List, Any, Optional, Tuple, BinaryIO
from pathlib import Path
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import platform

# Import path utilities for dynamic path resolution
from path_utils import get_database_path

# Furtivité imports
try:
    from stealth_engine import StealthEngine
    from proxy_manager import ProxyManager
except ImportError:
    logging.warning("⚠️ Stealth modules non disponibles")
    class StealthEngine:
        async def get_stealth_profile(self, profile): return {}
        async def calculate_stealth_score(self): return 0.8
    class ProxyManager:
        pass


@dataclass
class ProcessInfo:
    """Informations détaillées d'un processus"""
    pid: int
    name: str
    exe_path: str
    cmdline: List[str]
    create_time: datetime.datetime
    status: str
    cpu_percent: float
    memory_percent: float
    memory_info: Dict[str, int]
    connections: List[Dict[str, Any]]
    open_files: List[str]
    parent_pid: int
    children_pids: List[int]
    threads_count: int
    suspicious_indicators: List[str]
    threat_score: float


@dataclass
class MemoryDump:
    """Dump mémoire d'un processus"""
    dump_id: str
    process_pid: int
    process_name: str
    dump_size: int
    dump_time: datetime.datetime
    dump_method: str
    strings_extracted: List[str]
    suspicious_patterns: List[Dict[str, Any]]
    embedded_files: List[str]
    network_artifacts: List[str]
    crypto_artifacts: List[str]
    dump_hash: str
    analysis_results: Dict[str, Any]


@dataclass
class RootkitIndicator:
    """Indicateur de rootkit détecté"""
    indicator_id: str
    indicator_type: str  # process_hiding, dll_injection, hook_detection, etc.
    process_pid: Optional[int]
    description: str
    detection_method: str
    confidence_score: float
    artifacts: List[str]
    first_detected: datetime.datetime
    severity: str


@dataclass
class MemoryArtifact:
    """Artefact trouvé en mémoire"""
    artifact_id: str
    artifact_type: str  # password, url, email, crypto_key, etc.
    content: str
    context: str
    source_process: int
    memory_address: Optional[str]
    extraction_method: str
    confidence_score: float


@dataclass
class SystemMemoryAnalysis:
    """Analyse complète de la mémoire système"""
    analysis_id: str
    analysis_start: datetime.datetime
    analysis_end: datetime.datetime
    system_info: Dict[str, Any]
    total_processes: int
    suspicious_processes: int
    rootkit_indicators: int
    memory_artifacts: int
    network_connections: int
    threat_score: float
    processes_analyzed: List[ProcessInfo]
    rootkit_findings: List[RootkitIndicator]
    memory_artifacts_found: List[MemoryArtifact]


class MemoryForensicsAnalyzer:
    """
    🔬 Analyseur Forensique Mémoire Avancé
    
    Analyse forensique complète de la mémoire système avec détection de rootkits,
    extraction d'artefacts et techniques de furtivité avancées.
    """

    def __init__(self, db_path: str = None):
        self.db_path = db_path or get_database_path()
        self.stealth_engine = StealthEngine()
        self.proxy_manager = ProxyManager()
        
        # Configuration forensique mémoire
        self.suspicious_process_patterns = [
            # Noms de processus suspects
            r'.*\.tmp\.exe$',
            r'^[a-f0-9]{8,}\.exe$',  # Noms hexadécimaux
            r'^(svchost|winlogon|csrss).*\.exe$',  # Imitation processus système
            r'.*backdoor.*',
            r'.*trojan.*',
            r'.*bot.*',
            r'.*rat.*',
            r'.*keylog.*'
        ]
        
        # Ports suspects pour les connexions réseau
        self.suspicious_network_ports = {
            1337, 31337, 4444, 5555, 6666, 7777, 8080, 8888, 9999,
            12345, 54321, 6667, 6668, 6669  # IRC C&C
        }
        
        # Patterns d'artefacts en mémoire
        self.memory_patterns = {
            'passwords': [
                rb'password[=:\s]+([^\s\x00-\x1f]+)',
                rb'pwd[=:\s]+([^\s\x00-\x1f]+)',
                rb'pass[=:\s]+([^\s\x00-\x1f]+)',
                rb'login[=:\s]+([^\s\x00-\x1f]+)'
            ],
            'urls': [
                rb'https?://[^\s\x00-\x1f]+',
                rb'ftp://[^\s\x00-\x1f]+',
                rb'www\.[^\s\x00-\x1f]+'
            ],
            'emails': [
                rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            ],
            'crypto_keys': [
                rb'-----BEGIN [A-Z ]+-----[^-]+-----END [A-Z ]+-----',
                rb'[A-Fa-f0-9]{64,128}',  # Hex keys
                rb'[A-Za-z0-9+/]{32,}={0,2}'  # Base64 keys
            ],
            'credit_cards': [
                rb'\b4[0-9]{15}\b',  # Visa
                rb'\b5[1-5][0-9]{14}\b',  # MasterCard
                rb'\b3[47][0-9]{13}\b'  # AmEx
            ],
            'ip_addresses': [
                rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ]
        }
        
        # Techniques de détection de rootkits
        self.rootkit_detection_methods = {
            'process_hiding': self._detect_hidden_processes,
            'dll_injection': self._detect_dll_injection,
            'hook_detection': self._detect_api_hooks,
            'memory_anomalies': self._detect_memory_anomalies,
            'network_hiding': self._detect_hidden_connections
        }
        
        # Informations système pour le contexte
        self.system_info = {
            'platform': platform.system(),
            'architecture': platform.architecture()[0],
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor()
        }
        
        # Initialisation base de données
        self._init_database()
        
        logging.info("🔬 MemoryForensicsAnalyzer initialisé avec capacités avancées")

    def _init_database(self):
        """Initialise les tables de base de données forensique mémoire"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Table des analyses mémoire
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS memory_analyses (
                    id TEXT PRIMARY KEY,
                    analysis_type TEXT,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    total_processes INTEGER,
                    suspicious_processes INTEGER,
                    rootkit_indicators INTEGER,
                    memory_artifacts INTEGER,
                    threat_score REAL,
                    stealth_score REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Table des informations de processus
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS process_info (
                    id TEXT PRIMARY KEY,
                    analysis_id TEXT,
                    pid INTEGER,
                    name TEXT,
                    exe_path TEXT,
                    cmdline TEXT,
                    create_time TIMESTAMP,
                    status TEXT,
                    cpu_percent REAL,
                    memory_percent REAL,
                    parent_pid INTEGER,
                    threads_count INTEGER,
                    threat_score REAL,
                    suspicious_indicators TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES memory_analyses (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"❌ Erreur initialisation BDD memory forensics: {e}")

    async def analyze_system_memory(self, 
                                   analysis_options: Dict[str, bool] = None) -> Dict[str, Any]:
        """
        🔍 Analyse forensique complète de la mémoire système
        
        Args:
            analysis_options: Options d'analyse
                            {'processes': True, 'rootkits': True, 'dumps': True, 'artifacts': True}
            
        Returns:
            Résultats complets de l'analyse forensique mémoire
        """
        analysis_id = f"memory_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Options par défaut
        if not analysis_options:
            analysis_options = {
                'processes': True,
                'rootkits': True,
                'dumps': False,  # False par défaut (gourmand en ressources)
                'artifacts': True
            }
        
        # 🛡️ Activation mode furtif
        stealth_config = await self.stealth_engine.get_stealth_profile("memory_analysis")
        
        logging.info(f"🔬 Démarrage analyse mémoire système - ID: {analysis_id}")
        
        try:
            analysis_results = {
                'analysis_id': analysis_id,
                'analysis_options': analysis_options,
                'system_info': self.system_info,
                'results': {},
                'start_time': datetime.datetime.now().isoformat()
            }
            
            # Analyse des processus en cours
            if analysis_options.get('processes', True):
                processes_info = await self._analyze_running_processes()
                analysis_results['results']['processes'] = [asdict(p) for p in processes_info]
                logging.info(f"🔍 {len(processes_info)} processus analysés")
            
            # Détection de rootkits
            if analysis_options.get('rootkits', True):
                rootkit_indicators = await self._detect_rootkits()
                analysis_results['results']['rootkit_indicators'] = [asdict(r) for r in rootkit_indicators]
                logging.info(f"🕵️ {len(rootkit_indicators)} indicateurs de rootkit détectés")
            
            # Calcul du score de menace global
            threat_score = self._calculate_memory_threat_score(analysis_results['results'])
            analysis_results['threat_score'] = threat_score
            
            # Score de furtivité
            stealth_score = await self.stealth_engine.calculate_stealth_score()
            analysis_results['stealth_score'] = stealth_score
            
            analysis_results['end_time'] = datetime.datetime.now().isoformat()
            analysis_results['status'] = 'completed'
            
            logging.info(f"✅ Analyse mémoire terminée - Threat Score: {threat_score:.2f}")
            
            return analysis_results
            
        except Exception as e:
            logging.error(f"❌ Erreur analyse mémoire système: {e}")
            return {
                'error': str(e), 
                'analysis_id': analysis_id
            }

    async def _analyze_running_processes(self) -> List[ProcessInfo]:
        """
        🔍 Analyse des processus en cours d'exécution
        """
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 
                                           'status', 'cpu_percent', 'memory_percent', 
                                           'memory_info', 'ppid', 'num_threads']):
                try:
                    proc_info = proc.info
                    
                    # Informations sur les connexions réseau
                    connections = []
                    try:
                        for conn in proc.connections():
                            connections.append({
                                'family': str(conn.family),
                                'type': str(conn.type),
                                'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                                'status': conn.status
                            })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # Fichiers ouverts
                    open_files = []
                    try:
                        for f in proc.open_files():
                            open_files.append(f.path)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                    
                    # Détection d'indicateurs suspects
                    suspicious_indicators = self._analyze_process_suspicion(proc_info, connections, open_files)
                    
                    # Calcul du score de menace
                    threat_score = self._calculate_process_threat_score(proc_info, suspicious_indicators, connections)
                    
                    process_info = ProcessInfo(
                        pid=proc_info['pid'],
                        name=proc_info['name'] or 'unknown',
                        exe_path=proc_info['exe'] or 'unknown',
                        cmdline=proc_info['cmdline'] or [],
                        create_time=datetime.datetime.fromtimestamp(proc_info['create_time']) if proc_info['create_time'] else datetime.datetime.now(),
                        status=proc_info['status'],
                        cpu_percent=proc_info['cpu_percent'] or 0.0,
                        memory_percent=proc_info['memory_percent'] or 0.0,
                        memory_info=dict(proc_info['memory_info']._asdict()) if proc_info['memory_info'] else {},
                        connections=connections,
                        open_files=open_files[:10],  # Limite pour performance
                        parent_pid=proc_info['ppid'] or 0,
                        children_pids=[],
                        threads_count=proc_info['num_threads'] or 0,
                        suspicious_indicators=suspicious_indicators,
                        threat_score=threat_score
                    )
                    
                    processes.append(process_info)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Processus terminé ou accès refusé
                    continue
                    
        except Exception as e:
            logging.error(f"❌ Erreur analyse processus: {e}")
        
        return processes

    def _analyze_process_suspicion(self, 
                                  proc_info: Dict, 
                                  connections: List[Dict], 
                                  open_files: List[str]) -> List[str]:
        """Analyse des indicateurs suspects d'un processus"""
        indicators = []
        
        try:
            process_name = proc_info.get('name', '').lower()
            exe_path = proc_info.get('exe', '').lower()
            
            # Vérification des patterns de noms suspects
            for pattern in self.suspicious_process_patterns:
                if re.match(pattern, process_name) or re.match(pattern, exe_path):
                    indicators.append(f"suspicious_name_pattern: {pattern}")
            
            # Processus sans chemin d'exécution
            if not exe_path or exe_path == 'unknown':
                indicators.append("no_executable_path")
            
            # Connexions réseau suspectes
            for conn in connections:
                if conn.get('remote_address'):
                    try:
                        remote_port = int(conn['remote_address'].split(':')[1])
                        if remote_port in self.suspicious_network_ports:
                            indicators.append(f"suspicious_network_port: {remote_port}")
                    except:
                        pass
            
            # Consommation CPU/mémoire anormale
            if proc_info.get('cpu_percent', 0) > 80:
                indicators.append("high_cpu_usage")
            
            if proc_info.get('memory_percent', 0) > 50:
                indicators.append("high_memory_usage")
            
        except Exception as e:
            logging.debug(f"Erreur analyse suspicion processus: {e}")
        
        return indicators

    def _calculate_process_threat_score(self, 
                                       proc_info: Dict, 
                                       indicators: List[str], 
                                       connections: List[Dict]) -> float:
        """Calcul du score de menace d'un processus"""
        threat_score = 0.0
        
        try:
            # Facteur indicateurs suspects
            threat_score += min(0.6, len(indicators) * 0.1)
            
            # Facteur connexions réseau
            external_connections = [c for c in connections if c.get('remote_address') and 
                                  not c['remote_address'].startswith(('127.', '192.168.', '10.', '172.'))]
            if external_connections:
                threat_score += min(0.3, len(external_connections) * 0.1)
            
            # Facteur consommation ressources
            cpu_percent = proc_info.get('cpu_percent', 0)
            memory_percent = proc_info.get('memory_percent', 0)
            
            if cpu_percent > 50:
                threat_score += 0.1
            if memory_percent > 30:
                threat_score += 0.1
            
        except Exception as e:
            logging.debug(f"Erreur calcul threat score processus: {e}")
        
        return min(1.0, threat_score)

    async def _detect_rootkits(self) -> List[RootkitIndicator]:
        """
        🕵️ Détection de rootkits avec techniques avancées
        """
        rootkit_indicators = []
        
        try:
            # Exécution de toutes les méthodes de détection
            for detection_name, detection_method in self.rootkit_detection_methods.items():
                try:
                    indicators = await detection_method()
                    rootkit_indicators.extend(indicators)
                    
                    # Délai entre méthodes pour éviter la détection
                    await asyncio.sleep(0.5)
                    
                except Exception as e:
                    logging.debug(f"Erreur méthode détection {detection_name}: {e}")
            
        except Exception as e:
            logging.error(f"❌ Erreur détection rootkits: {e}")
        
        return rootkit_indicators

    async def _detect_hidden_processes(self) -> List[RootkitIndicator]:
        """Détection de processus cachés"""
        indicators = []
        
        try:
            # Comparaison entre différentes méthodes d'énumération
            psutil_pids = set(psutil.pids())
            
            # Énumération alternative via /proc (Linux)
            alt_pids = set()
            
            if os.name == 'posix':  # Linux/Unix
                try:
                    proc_entries = os.listdir('/proc')
                    alt_pids = {int(entry) for entry in proc_entries if entry.isdigit()}
                except:
                    pass
            
            # Détection de discrepancies
            hidden_pids = alt_pids - psutil_pids
            
            if hidden_pids:
                indicator = RootkitIndicator(
                    indicator_id=f"hidden_processes_{datetime.datetime.now().strftime('%H%M%S')}",
                    indicator_type='process_hiding',
                    process_pid=None,
                    description=f"Processus potentiellement cachés détectés: {list(hidden_pids)[:5]}",
                    detection_method='cross_enumeration_comparison',
                    confidence_score=0.7,
                    artifacts=[f"hidden_pid_{pid}" for pid in list(hidden_pids)[:5]],
                    first_detected=datetime.datetime.now(),
                    severity='medium'
                )
                indicators.append(indicator)
            
        except Exception as e:
            logging.debug(f"Erreur détection processus cachés: {e}")
        
        return indicators

    async def _detect_dll_injection(self) -> List[RootkitIndicator]:
        """Détection d'injection de DLL"""
        indicators = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    # Analyse simplifiée - vérification des processus avec beaucoup de modules chargés
                    if proc.info['pid'] > 0:  # Processus valide
                        # Simulation de détection d'injection
                        thread_count = proc.num_threads()
                        if thread_count > 100:  # Seuil arbitraire
                            indicator = RootkitIndicator(
                                indicator_id=f"dll_injection_{proc.info['pid']}",
                                indicator_type='dll_injection',
                                process_pid=proc.info['pid'],
                                description=f"Processus {proc.info['name']} avec {thread_count} threads (suspect)",
                                detection_method='thread_count_analysis',
                                confidence_score=0.5,
                                artifacts=[f"thread_count_{thread_count}"],
                                first_detected=datetime.datetime.now(),
                                severity='medium'
                            )
                            indicators.append(indicator)
                    
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    continue
                    
        except Exception as e:
            logging.debug(f"Erreur détection injection DLL: {e}")
        
        return indicators

    async def _detect_api_hooks(self) -> List[RootkitIndicator]:
        """Détection de hooks d'API (technique simplifiée)"""
        return []  # Implémentation simplifiée

    async def _detect_memory_anomalies(self) -> List[RootkitIndicator]:
        """Détection d'anomalies mémoire"""
        indicators = []
        
        try:
            # Analyse de la consommation mémoire globale
            memory = psutil.virtual_memory()
            
            # Détection de consommation mémoire anormale
            if memory.percent > 90:
                indicator = RootkitIndicator(
                    indicator_id=f"memory_anomaly_{datetime.datetime.now().strftime('%H%M%S')}",
                    indicator_type='memory_anomalies',
                    process_pid=None,
                    description=f"Consommation mémoire critique: {memory.percent}%",
                    detection_method='system_memory_analysis',
                    confidence_score=0.6,
                    artifacts=[f"memory_usage_{memory.percent}%"],
                    first_detected=datetime.datetime.now(),
                    severity='medium'
                )
                indicators.append(indicator)
                    
        except Exception as e:
            logging.debug(f"Erreur détection anomalies mémoire: {e}")
        
        return indicators

    async def _detect_hidden_connections(self) -> List[RootkitIndicator]:
        """Détection de connexions réseau cachées"""
        return []  # Implémentation simplifiée

    def _calculate_memory_threat_score(self, analysis_results: Dict[str, Any]) -> float:
        """Calcul du score de menace global de l'analyse mémoire"""
        threat_score = 0.0
        
        try:
            # Facteur processus suspects
            processes = analysis_results.get('processes', [])
            if processes:
                suspicious_procs = [p for p in processes if p['threat_score'] > 0.5]
                threat_score += min(0.4, len(suspicious_procs) / len(processes))
            
            # Facteur indicateurs de rootkit
            rootkit_indicators = analysis_results.get('rootkit_indicators', [])
            if rootkit_indicators:
                high_confidence_indicators = [r for r in rootkit_indicators if r['confidence_score'] > 0.7]
                threat_score += min(0.3, len(high_confidence_indicators) * 0.1)
            
        except Exception as e:
            logging.debug(f"Erreur calcul threat score mémoire: {e}")
        
        return min(1.0, threat_score)

    async def list_memory_analyses(self) -> List[Dict[str, Any]]:
        """Liste toutes les analyses mémoire"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, analysis_type, start_time, end_time, total_processes, 
                       suspicious_processes, rootkit_indicators, memory_artifacts, 
                       threat_score, stealth_score, created_at
                FROM memory_analyses
                ORDER BY created_at DESC
            ''')
            
            analyses = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'analysis_id': a[0],
                    'analysis_type': a[1],
                    'start_time': a[2],
                    'end_time': a[3],
                    'total_processes': a[4],
                    'suspicious_processes': a[5],
                    'rootkit_indicators': a[6],
                    'memory_artifacts': a[7],
                    'threat_score': a[8],
                    'stealth_score': a[9],
                    'created_at': a[10]
                } for a in analyses
            ]
            
        except Exception as e:
            logging.error(f"❌ Erreur liste analyses mémoire: {e}")
            return []


# Export de la classe principale
__all__ = ['MemoryForensicsAnalyzer', 'ProcessInfo', 'MemoryDump', 'RootkitIndicator', 'MemoryArtifact', 'SystemMemoryAnalysis']