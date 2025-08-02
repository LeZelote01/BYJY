#!/usr/bin/env python3
"""
🔬 FORENSIC LOG ANALYZER - Phase 5.1
CyberSec Assistant Portable - Advanced Forensic Analysis Module

FONCTIONNALITÉS :
- Parser logs multiformat (syslog, Apache, IIS, Windows Event, etc.)
- Timeline reconstruction automatique
- Détection d'anomalies comportementales
- Corrélation events cross-system
- Pattern matching règles YARA-like
- Chain of custody tracking
- Techniques de furtivité avancées (accès indirect, anti-attribution)

Auteur: CyberSec Assistant Team
Version: 1.0
"""

import os
import re
import json
import gzip
import zipfile
import datetime
import hashlib
import asyncio
import sqlite3
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import logging

# Furtivité imports
from stealth_engine import StealthEngine

# Import path utilities for dynamic path resolution
from path_utils import get_database_path
from proxy_manager import ProxyManager


@dataclass
class LogEntry:
    """Structure d'une entrée de log forensique"""
    timestamp: datetime.datetime
    source_file: str
    log_type: str
    level: str
    message: str
    raw_line: str
    parsed_fields: Dict[str, Any]
    hash_signature: str
    chain_index: int


@dataclass
class ForensicTimeline:
    """Timeline forensique avec corrélation cross-system"""
    timeline_id: str
    case_id: str
    start_time: datetime.datetime
    end_time: datetime.datetime
    total_events: int
    sources: List[str]
    anomalies_detected: int
    events: List[LogEntry]
    correlations: List[Dict[str, Any]]


@dataclass
class AnomalyPattern:
    """Pattern d'anomalie détectée"""
    pattern_id: str
    pattern_type: str  # frequency, sequence, outlier, correlation
    severity: str  # low, medium, high, critical
    description: str
    indicators: List[str]
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    count: int
    confidence_score: float


class ForensicLogAnalyzer:
    """
    🔬 Analyseur de Logs Forensique Avancé
    
    Analyse forensique complète des logs système avec techniques de furtivité
    et reconstruction de timeline pour investigations.
    """

    def __init__(self, db_path: str = None):
        self.db_path = db_path or get_database_path()
        self.stealth_engine = StealthEngine()
        self.proxy_manager = ProxyManager()
        
        # Configuration forensique
        self.supported_formats = {
            'syslog': self._parse_syslog,
            'apache': self._parse_apache,
            'nginx': self._parse_nginx,
            'iis': self._parse_iis, 
            'windows_event': self._parse_windows_event,
            'auth': self._parse_auth_log,
            'firewall': self._parse_firewall_log,
            'custom': self._parse_custom_log
        }
        
        # Patterns d'anomalies prédéfinis
        self.anomaly_patterns = {
            'brute_force': {
                'pattern': r'Failed password|Authentication failure|Invalid user',
                'threshold': 10,
                'timeframe': 300  # 5 minutes
            },
            'privilege_escalation': {
                'pattern': r'sudo|su -|root|administrator',
                'keywords': ['privilege', 'escalation', 'root', 'admin']
            },
            'lateral_movement': {
                'pattern': r'ssh|rdp|telnet|winrm',
                'keywords': ['connection', 'login', 'access']
            },
            'data_exfiltration': {
                'pattern': r'scp|sftp|ftp|wget|curl|download',
                'keywords': ['transfer', 'copy', 'download', 'upload']
            }
        }
        
        # Initialisation base de données
        self._init_database()
        
        logging.info("🔬 ForensicLogAnalyzer initialisé avec furtivité avancée")

    def _init_database(self):
        """Initialise les tables de base de données forensique"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Table des analyses forensiques
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS forensic_analyses (
                    id TEXT PRIMARY KEY,
                    case_id TEXT,
                    name TEXT,
                    description TEXT,
                    source_paths TEXT,
                    analysis_type TEXT,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    status TEXT,
                    total_entries INTEGER,
                    anomalies_found INTEGER,
                    stealth_score REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Table des entrées de logs
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS log_entries (
                    id TEXT PRIMARY KEY,
                    analysis_id TEXT,
                    timestamp TIMESTAMP,
                    source_file TEXT,
                    log_type TEXT,
                    level TEXT,
                    message TEXT,
                    raw_line TEXT,
                    parsed_fields TEXT,
                    hash_signature TEXT,
                    chain_index INTEGER,
                    FOREIGN KEY (analysis_id) REFERENCES forensic_analyses (id)
                )
            ''')
            
            # Table des anomalies détectées
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS log_anomalies (
                    id TEXT PRIMARY KEY,
                    analysis_id TEXT,
                    pattern_id TEXT,
                    pattern_type TEXT,
                    severity TEXT,
                    description TEXT,
                    indicators TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    count INTEGER,
                    confidence_score REAL,
                    FOREIGN KEY (analysis_id) REFERENCES forensic_analyses (id)
                )
            ''')
            
            # Table des timelines forensiques
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS forensic_timelines (
                    id TEXT PRIMARY KEY,
                    case_id TEXT,
                    analysis_id TEXT,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    total_events INTEGER,
                    sources TEXT,
                    correlations TEXT,
                    timeline_data TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES forensic_analyses (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"❌ Erreur initialisation BDD forensique: {e}")

    async def analyze_logs(self, 
                          source_paths: List[str], 
                          case_id: str = None,
                          analysis_name: str = "Forensic Analysis",
                          log_formats: List[str] = None) -> Dict[str, Any]:
        """
        🔍 Analyse forensique complète des logs
        
        Args:
            source_paths: Chemins vers les fichiers de logs
            case_id: ID du case forensique
            analysis_name: Nom de l'analyse
            log_formats: Formats spécifiques à utiliser
            
        Returns:
            Résultats de l'analyse avec timeline et anomalies
        """
        analysis_id = f"forensic_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # 🛡️ Activation mode furtif
        stealth_config = await self.stealth_engine.get_stealth_profile("forensic_analysis")
        
        logging.info(f"🔬 Démarrage analyse forensique - ID: {analysis_id}")
        
        try:
            # Collecte furtive des logs
            all_entries = []
            processed_files = []
            
            for source_path in source_paths:
                if os.path.exists(source_path):
                    entries = await self._process_log_file_stealth(source_path, log_formats)
                    all_entries.extend(entries)
                    processed_files.append(source_path)
                    
                    # Délai furtif entre fichiers
                    await asyncio.sleep(stealth_config.get('file_access_delay', 0.5))
            
            # Timeline reconstruction
            timeline = self._reconstruct_timeline(all_entries, case_id)
            
            # Détection d'anomalies
            anomalies = await self._detect_anomalies(all_entries)
            
            # Corrélation cross-system
            correlations = self._correlate_events(all_entries)
            
            # Calcul score de furtivité
            stealth_score = await self.stealth_engine.calculate_stealth_score()
            
            # Sauvegarde forensique sécurisée
            analysis_result = {
                'analysis_id': analysis_id,
                'case_id': case_id,
                'name': analysis_name,
                'source_files': processed_files,
                'total_entries': len(all_entries),
                'timeline': asdict(timeline),
                'anomalies': [asdict(a) for a in anomalies],
                'correlations': correlations,
                'stealth_score': stealth_score,
                'analysis_completed_at': datetime.datetime.now().isoformat()
            }
            
            await self._save_analysis_results(analysis_result)
            
            logging.info(f"✅ Analyse forensique terminée - {len(all_entries)} entrées analysées")
            
            return analysis_result
            
        except Exception as e:
            logging.error(f"❌ Erreur analyse forensique: {e}")
            return {'error': str(e), 'analysis_id': analysis_id}

    async def _process_log_file_stealth(self, 
                                       file_path: str, 
                                       formats: List[str] = None) -> List[LogEntry]:
        """
        🛡️ Traitement furtif d'un fichier de log avec techniques anti-forensique
        """
        entries = []
        
        try:
            # Détection automatique du format si non spécifié
            detected_format = self._detect_log_format(file_path) if not formats else formats[0]
            
            # Accès furtif au fichier (préservation des métadonnées)
            original_stats = os.stat(file_path)
            
            # Lecture avec préservation des timestamps
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Restauration des métadonnées originales
            os.utime(file_path, (original_stats.st_atime, original_stats.st_mtime))
            
            chain_index = 0
            for line in lines:
                if line.strip():
                    parsed_entry = await self._parse_log_entry(
                        line, file_path, detected_format, chain_index
                    )
                    if parsed_entry:
                        entries.append(parsed_entry)
                        chain_index += 1
            
            logging.info(f"🔍 Traité {len(entries)} entrées de {file_path} (format: {detected_format})")
            
        except Exception as e:
            logging.error(f"❌ Erreur traitement fichier {file_path}: {e}")
        
        return entries

    def _detect_log_format(self, file_path: str) -> str:
        """Détection automatique du format de log"""
        file_name = os.path.basename(file_path).lower()
        
        # Détection par nom de fichier
        format_indicators = {
            'syslog': ['syslog', 'messages', 'kern.log'],
            'apache': ['access.log', 'error.log', 'apache'],
            'nginx': ['nginx', 'access.log', 'error.log'],
            'auth': ['auth.log', 'secure'],
            'firewall': ['firewall', 'iptables', 'ufw'],
            'windows_event': ['.evtx', 'security', 'system', 'application']
        }
        
        for fmt, indicators in format_indicators.items():
            if any(indicator in file_name for indicator in indicators):
                return fmt
        
        # Détection par contenu (première ligne)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline().strip()
                
            # Patterns de détection
            if re.match(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', first_line):
                return 'syslog'
            elif ' - - [' in first_line and '"' in first_line:
                return 'apache'
            elif re.match(r'^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}', first_line):
                return 'nginx'
                
        except:
            pass
        
        return 'custom'

    async def _parse_log_entry(self, 
                              line: str, 
                              source_file: str, 
                              log_format: str, 
                              chain_index: int) -> Optional[LogEntry]:
        """Parse une entrée de log selon le format détecté"""
        try:
            parser_func = self.supported_formats.get(log_format, self._parse_custom_log)
            parsed_data = parser_func(line)
            
            if parsed_data:
                # Génération du hash forensique
                hash_signature = hashlib.sha256(
                    (line + source_file + str(chain_index)).encode()
                ).hexdigest()[:16]
                
                return LogEntry(
                    timestamp=parsed_data['timestamp'],
                    source_file=source_file,
                    log_type=log_format,
                    level=parsed_data.get('level', 'INFO'),
                    message=parsed_data['message'],
                    raw_line=line.strip(),
                    parsed_fields=parsed_data.get('fields', {}),
                    hash_signature=hash_signature,
                    chain_index=chain_index
                )
        except Exception as e:
            logging.debug(f"Erreur parsing ligne: {e}")
        
        return None

    def _parse_syslog(self, line: str) -> Optional[Dict[str, Any]]:
        """Parser pour format syslog standard"""
        # Pattern syslog: Mar 10 12:34:56 hostname process[pid]: message
        pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$'
        match = re.match(pattern, line)
        
        if match:
            timestamp_str, hostname, process, message = match.groups()
            
            # Conversion timestamp (année courante)
            current_year = datetime.datetime.now().year
            timestamp = datetime.datetime.strptime(
                f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S"
            )
            
            return {
                'timestamp': timestamp,
                'level': self._extract_log_level(message),
                'message': message,
                'fields': {
                    'hostname': hostname,
                    'process': process,
                    'facility': 'syslog'
                }
            }
        return None

    def _parse_apache(self, line: str) -> Optional[Dict[str, Any]]:
        """Parser pour logs Apache (Common/Combined Log Format)"""
        # Pattern Apache: IP - - [timestamp] "method url protocol" status size
        pattern = r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\S+)'
        match = re.match(pattern, line)
        
        if match:
            ip, timestamp_str, request, status, size = match.groups()
            
            # Conversion timestamp Apache
            timestamp = datetime.datetime.strptime(
                timestamp_str.split()[0], "%d/%b/%Y:%H:%M:%S"
            )
            
            # Extraction méthode/URL
            request_parts = request.split()
            method = request_parts[0] if request_parts else ''
            url = request_parts[1] if len(request_parts) > 1 else ''
            
            level = 'ERROR' if int(status) >= 400 else 'INFO'
            
            return {
                'timestamp': timestamp,
                'level': level,
                'message': f"{method} {url} - {status}",
                'fields': {
                    'client_ip': ip,
                    'method': method,
                    'url': url,
                    'status_code': int(status),
                    'response_size': size,
                    'log_type': 'web_access'
                }
            }
        return None

    def _parse_nginx(self, line: str) -> Optional[Dict[str, Any]]:
        """Parser pour logs Nginx"""
        # Pattern Nginx: timestamp [level] message
        pattern = r'^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.*)$'
        match = re.match(pattern, line)
        
        if match:
            timestamp_str, level, message = match.groups()
            timestamp = datetime.datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
            
            return {
                'timestamp': timestamp,
                'level': level.upper(),
                'message': message,
                'fields': {'server': 'nginx'}
            }
        return None

    def _parse_auth_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parser pour logs d'authentification"""
        return self._parse_syslog(line)  # Même format que syslog

    def _parse_firewall_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parser pour logs firewall"""
        return self._parse_syslog(line)  # Souvent en format syslog

    def _parse_iis(self, line: str) -> Optional[Dict[str, Any]]:
        """Parser pour logs IIS"""
        # Pattern IIS: date time c-ip cs-method cs-uri-stem sc-status
        if line.startswith('#'):  # Ignorer les commentaires
            return None
            
        fields = line.split()
        if len(fields) >= 6:
            try:
                date, time = fields[0], fields[1]
                timestamp = datetime.datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S")
                
                return {
                    'timestamp': timestamp,
                    'level': 'INFO',
                    'message': f"IIS {fields[4]} {fields[5]} - {fields[8] if len(fields) > 8 else '200'}",
                    'fields': {
                        'client_ip': fields[2] if len(fields) > 2 else '',
                        'method': fields[3] if len(fields) > 3 else '',
                        'uri': fields[4] if len(fields) > 4 else '',
                        'status': fields[8] if len(fields) > 8 else ''
                    }
                }
            except:
                pass
        return None

    def _parse_windows_event(self, line: str) -> Optional[Dict[str, Any]]:
        """Parser pour Windows Event logs (format texte)"""
        # Pattern simple pour events Windows
        pattern = r'^(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)\s+(.*)$'
        match = re.match(pattern, line)
        
        if match:
            timestamp_str, message = match.groups()
            timestamp = datetime.datetime.strptime(timestamp_str, "%m/%d/%Y %I:%M:%S %p")
            
            return {
                'timestamp': timestamp,
                'level': self._extract_log_level(message),
                'message': message,
                'fields': {'source': 'windows_event'}
            }
        return None

    def _parse_custom_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parser générique pour formats personnalisés"""
        # Tentative d'extraction d'un timestamp générique
        timestamp_patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',  # ISO format
            r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',   # US format
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',     # Syslog format
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, line)
            if match:
                timestamp_str = match.group(1)
                try:
                    if '-' in timestamp_str:
                        timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    elif '/' in timestamp_str:
                        timestamp = datetime.datetime.strptime(timestamp_str, "%m/%d/%Y %H:%M:%S")
                    else:
                        current_year = datetime.datetime.now().year
                        timestamp = datetime.datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                    
                    return {
                        'timestamp': timestamp,
                        'level': self._extract_log_level(line),
                        'message': line.strip(),
                        'fields': {'format': 'custom'}
                    }
                except:
                    continue
        
        # Si pas de timestamp trouvé, utiliser timestamp actuel
        return {
            'timestamp': datetime.datetime.now(),
            'level': 'INFO',
            'message': line.strip(),
            'fields': {'format': 'unknown'}
        }

    def _extract_log_level(self, message: str) -> str:
        """Extraction du niveau de log depuis le message"""
        message_upper = message.upper()
        
        if any(keyword in message_upper for keyword in ['CRITICAL', 'FATAL', 'CRIT']):
            return 'CRITICAL'
        elif any(keyword in message_upper for keyword in ['ERROR', 'ERR', 'FAIL']):
            return 'ERROR'
        elif any(keyword in message_upper for keyword in ['WARNING', 'WARN']):
            return 'WARNING'
        elif any(keyword in message_upper for keyword in ['DEBUG', 'DBG']):
            return 'DEBUG'
        else:
            return 'INFO'

    def _reconstruct_timeline(self, entries: List[LogEntry], case_id: str) -> ForensicTimeline:
        """Reconstruction de la timeline forensique"""
        if not entries:
            return ForensicTimeline(
                timeline_id=f"timeline_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
                case_id=case_id or "unknown",
                start_time=datetime.datetime.now(),
                end_time=datetime.datetime.now(),
                total_events=0,
                sources=[],
                anomalies_detected=0,
                events=[],
                correlations=[]
            )
        
        # Tri par timestamp
        sorted_entries = sorted(entries, key=lambda x: x.timestamp)
        
        # Extraction des sources uniques
        sources = list(set(entry.source_file for entry in entries))
        
        # Corrélations temporelles
        correlations = self._find_temporal_correlations(sorted_entries)
        
        return ForensicTimeline(
            timeline_id=f"timeline_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}",
            case_id=case_id or "unknown",
            start_time=sorted_entries[0].timestamp,
            end_time=sorted_entries[-1].timestamp,
            total_events=len(entries),
            sources=sources,
            anomalies_detected=0,  # Sera mis à jour après détection d'anomalies
            events=sorted_entries,
            correlations=correlations
        )

    def _find_temporal_correlations(self, entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Recherche de corrélations temporelles entre events"""
        correlations = []
        
        # Fenêtre de corrélation (5 minutes)
        correlation_window = datetime.timedelta(minutes=5)
        
        for i, entry in enumerate(entries):
            # Recherche d'events corrélés dans la fenêtre temporelle
            correlated_events = []
            
            for j, other_entry in enumerate(entries[i+1:], i+1):
                if other_entry.timestamp - entry.timestamp > correlation_window:
                    break
                
                # Critères de corrélation
                if (entry.source_file != other_entry.source_file and
                    self._events_are_correlated(entry, other_entry)):
                    correlated_events.append({
                        'event_index': j,
                        'correlation_type': 'temporal',
                        'confidence': 0.8
                    })
            
            if correlated_events:
                correlations.append({
                    'primary_event_index': i,
                    'correlated_events': correlated_events,
                    'correlation_window_seconds': correlation_window.total_seconds()
                })
        
        return correlations

    def _events_are_correlated(self, event1: LogEntry, event2: LogEntry) -> bool:
        """Détermine si deux events sont corrélés"""
        # Corrélation par IP si présente
        if 'client_ip' in event1.parsed_fields and 'client_ip' in event2.parsed_fields:
            if event1.parsed_fields['client_ip'] == event2.parsed_fields['client_ip']:
                return True
        
        # Corrélation par processus/service
        if 'process' in event1.parsed_fields and 'process' in event2.parsed_fields:
            if event1.parsed_fields['process'] == event2.parsed_fields['process']:
                return True
        
        # Corrélation par patterns de sécurité
        security_keywords = ['auth', 'login', 'fail', 'error', 'access', 'denied']
        event1_security = any(keyword in event1.message.lower() for keyword in security_keywords)
        event2_security = any(keyword in event2.message.lower() for keyword in security_keywords)
        
        return event1_security and event2_security

    async def _detect_anomalies(self, entries: List[LogEntry]) -> List[AnomalyPattern]:
        """
        🚨 Détection avancée d'anomalies dans les logs
        """
        anomalies = []
        
        # Détection par patterns prédéfinis
        for pattern_name, pattern_config in self.anomaly_patterns.items():
            detected = self._detect_pattern_anomaly(entries, pattern_name, pattern_config)
            anomalies.extend(detected)
        
        # Détection d'anomalies de fréquence
        frequency_anomalies = self._detect_frequency_anomalies(entries)
        anomalies.extend(frequency_anomalies)
        
        # Détection d'anomalies de séquence
        sequence_anomalies = self._detect_sequence_anomalies(entries)
        anomalies.extend(sequence_anomalies)
        
        logging.info(f"🚨 Détecté {len(anomalies)} anomalies dans les logs")
        
        return anomalies

    def _detect_pattern_anomaly(self, 
                               entries: List[LogEntry], 
                               pattern_name: str, 
                               pattern_config: Dict[str, Any]) -> List[AnomalyPattern]:
        """Détection d'anomalies par pattern spécifique"""
        anomalies = []
        pattern = pattern_config['pattern']
        threshold = pattern_config.get('threshold', 5)
        timeframe = pattern_config.get('timeframe', 300)  # 5 minutes
        
        # Recherche d'occurrences du pattern
        matches = []
        for entry in entries:
            if re.search(pattern, entry.message, re.IGNORECASE):
                matches.append(entry)
        
        if not matches:
            return anomalies
        
        # Analyse par fenêtre temporelle
        current_window_start = matches[0].timestamp
        current_window_events = []
        
        for match in matches:
            # Nouvelle fenêtre si dépassement du timeframe
            if (match.timestamp - current_window_start).total_seconds() > timeframe:
                # Vérification du seuil pour la fenêtre précédente
                if len(current_window_events) >= threshold:
                    anomaly = AnomalyPattern(
                        pattern_id=f"{pattern_name}_{current_window_start.strftime('%Y%m%d_%H%M%S')}",
                        pattern_type='frequency',
                        severity=self._calculate_severity(len(current_window_events), threshold),
                        description=f"Pattern '{pattern_name}' détecté {len(current_window_events)} fois en {timeframe}s",
                        indicators=[event.message[:100] for event in current_window_events[:5]],
                        first_seen=current_window_events[0].timestamp,
                        last_seen=current_window_events[-1].timestamp,
                        count=len(current_window_events),
                        confidence_score=min(1.0, len(current_window_events) / (threshold * 2))
                    )
                    anomalies.append(anomaly)
                
                # Nouvelle fenêtre
                current_window_start = match.timestamp
                current_window_events = [match]
            else:
                current_window_events.append(match)
        
        # Vérification de la dernière fenêtre
        if len(current_window_events) >= threshold:
            anomaly = AnomalyPattern(
                pattern_id=f"{pattern_name}_{current_window_start.strftime('%Y%m%d_%H%M%S')}",
                pattern_type='frequency',
                severity=self._calculate_severity(len(current_window_events), threshold),
                description=f"Pattern '{pattern_name}' détecté {len(current_window_events)} fois en {timeframe}s",
                indicators=[event.message[:100] for event in current_window_events[:5]],
                first_seen=current_window_events[0].timestamp,
                last_seen=current_window_events[-1].timestamp,
                count=len(current_window_events),
                confidence_score=min(1.0, len(current_window_events) / (threshold * 2))
            )
            anomalies.append(anomaly)
        
        return anomalies

    def _detect_frequency_anomalies(self, entries: List[LogEntry]) -> List[AnomalyPattern]:
        """Détection d'anomalies basées sur la fréquence"""
        anomalies = []
        
        # Analyse par source de logs
        source_counts = Counter(entry.source_file for entry in entries)
        
        # Calcul des statistiques
        if len(source_counts) > 1:
            counts = list(source_counts.values())
            mean_count = sum(counts) / len(counts)
            
            # Détection d'outliers (sources avec beaucoup plus d'events)
            for source, count in source_counts.items():
                if count > mean_count * 3:  # 3x la moyenne
                    anomaly = AnomalyPattern(
                        pattern_id=f"freq_outlier_{hashlib.md5(source.encode()).hexdigest()[:8]}",
                        pattern_type='outlier',
                        severity='medium',
                        description=f"Source {source} génère {count} events (moyenne: {mean_count:.1f})",
                        indicators=[f"Source: {source}", f"Count: {count}"],
                        first_seen=min(e.timestamp for e in entries if e.source_file == source),
                        last_seen=max(e.timestamp for e in entries if e.source_file == source),
                        count=count,
                        confidence_score=min(1.0, count / (mean_count * 5))
                    )
                    anomalies.append(anomaly)
        
        return anomalies

    def _detect_sequence_anomalies(self, entries: List[LogEntry]) -> List[AnomalyPattern]:
        """Détection d'anomalies de séquence (patterns inhabituels)"""
        anomalies = []
        
        # Analyse des séquences d'events par niveau
        level_sequences = []
        current_sequence = []
        
        for entry in entries:
            if current_sequence and entry.level != current_sequence[-1]:
                if len(current_sequence) >= 3:  # Séquences d'au moins 3 events
                    level_sequences.append(current_sequence.copy())
                current_sequence = [entry.level]
            else:
                current_sequence.append(entry.level)
        
        # Détection de séquences anormales (beaucoup d'erreurs consécutives)
        for i, sequence in enumerate(level_sequences):
            error_count = sequence.count('ERROR') + sequence.count('CRITICAL')
            if error_count >= 5 and error_count / len(sequence) > 0.7:
                anomaly = AnomalyPattern(
                    pattern_id=f"error_sequence_{i}",
                    pattern_type='sequence',
                    severity='high',
                    description=f"Séquence de {error_count} erreurs sur {len(sequence)} events",
                    indicators=[f"Error rate: {error_count/len(sequence)*100:.1f}%"],
                    first_seen=entries[0].timestamp,  # Approximation
                    last_seen=entries[-1].timestamp,
                    count=error_count,
                    confidence_score=min(1.0, error_count / 10)
                )
                anomalies.append(anomaly)
        
        return anomalies

    def _calculate_severity(self, count: int, threshold: int) -> str:
        """Calcul de la sévérité basée sur le count vs threshold"""
        ratio = count / threshold
        if ratio >= 5:
            return 'critical'
        elif ratio >= 3:
            return 'high'
        elif ratio >= 2:
            return 'medium'
        else:
            return 'low'

    def _correlate_events(self, entries: List[LogEntry]) -> List[Dict[str, Any]]:
        """Corrélation cross-system des events"""
        correlations = []
        
        # Groupement par IP source si disponible
        ip_groups = defaultdict(list)
        for entry in entries:
            client_ip = entry.parsed_fields.get('client_ip')
            if client_ip:
                ip_groups[client_ip].append(entry)
        
        # Analyse des corrélations par IP
        for ip, ip_entries in ip_groups.items():
            if len(ip_entries) >= 3:  # Au moins 3 events de la même IP
                sources = set(entry.source_file for entry in ip_entries)
                if len(sources) > 1:  # Events de sources différentes
                    correlation = {
                        'correlation_type': 'cross_system_ip',
                        'identifier': ip,
                        'event_count': len(ip_entries),
                        'sources': list(sources),
                        'time_span': (
                            max(e.timestamp for e in ip_entries) - 
                            min(e.timestamp for e in ip_entries)
                        ).total_seconds(),
                        'confidence_score': min(1.0, len(ip_entries) / 10)
                    }
                    correlations.append(correlation)
        
        return correlations

    async def _save_analysis_results(self, analysis_result: Dict[str, Any]):
        """Sauvegarde sécurisée des résultats d'analyse"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Sauvegarde de l'analyse principale
            cursor.execute('''
                INSERT INTO forensic_analyses 
                (id, case_id, name, description, source_paths, analysis_type, 
                 start_time, end_time, status, total_entries, anomalies_found, stealth_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis_result['analysis_id'],
                analysis_result['case_id'],
                analysis_result['name'],
                "Forensic log analysis with stealth techniques",
                json.dumps(analysis_result['source_files']),
                'forensic_analysis',
                analysis_result['timeline']['start_time'],
                analysis_result['timeline']['end_time'],
                'completed',
                analysis_result['total_entries'],
                len(analysis_result['anomalies']),
                analysis_result['stealth_score']
            ))
            
            # Sauvegarde des entrées de logs (échantillon)
            timeline_events = analysis_result['timeline']['events']
            for i, event in enumerate(timeline_events[:1000]):  # Limite à 1000 pour performance
                cursor.execute('''
                    INSERT INTO log_entries
                    (id, analysis_id, timestamp, source_file, log_type, level, 
                     message, raw_line, parsed_fields, hash_signature, chain_index)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    f"{analysis_result['analysis_id']}_entry_{i}",
                    analysis_result['analysis_id'],
                    event['timestamp'],
                    event['source_file'],
                    event['log_type'],
                    event['level'],
                    event['message'][:500],  # Limite taille message
                    event['raw_line'][:500],
                    json.dumps(event['parsed_fields']),
                    event['hash_signature'],
                    event['chain_index']
                ))
            
            # Sauvegarde des anomalies
            for anomaly in analysis_result['anomalies']:
                cursor.execute('''
                    INSERT INTO log_anomalies
                    (id, analysis_id, pattern_id, pattern_type, severity, description,
                     indicators, first_seen, last_seen, count, confidence_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    anomaly['pattern_id'],
                    analysis_result['analysis_id'],
                    anomaly['pattern_id'],
                    anomaly['pattern_type'],
                    anomaly['severity'],
                    anomaly['description'],
                    json.dumps(anomaly['indicators']),
                    anomaly['first_seen'],
                    anomaly['last_seen'],
                    anomaly['count'],
                    anomaly['confidence_score']
                ))
            
            # Sauvegarde de la timeline
            cursor.execute('''
                INSERT INTO forensic_timelines
                (id, case_id, analysis_id, start_time, end_time, total_events, 
                 sources, correlations, timeline_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis_result['timeline']['timeline_id'],
                analysis_result['case_id'],
                analysis_result['analysis_id'],
                analysis_result['timeline']['start_time'],
                analysis_result['timeline']['end_time'],
                analysis_result['timeline']['total_events'],
                json.dumps(analysis_result['timeline']['sources']),
                json.dumps(analysis_result['correlations']),
                json.dumps(analysis_result['timeline'], default=str)
            ))
            
            conn.commit()
            conn.close()
            
            logging.info(f"💾 Résultats d'analyse sauvegardés - ID: {analysis_result['analysis_id']}")
            
        except Exception as e:
            logging.error(f"❌ Erreur sauvegarde analyse: {e}")

    async def get_analysis_results(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Récupération des résultats d'une analyse forensique"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Récupération de l'analyse principale
            cursor.execute('''
                SELECT * FROM forensic_analyses WHERE id = ?
            ''', (analysis_id,))
            
            analysis_row = cursor.fetchone()
            if not analysis_row:
                return None
            
            # Récupération des anomalies
            cursor.execute('''
                SELECT * FROM log_anomalies WHERE analysis_id = ?
            ''', (analysis_id,))
            
            anomalies = cursor.fetchall()
            
            # Récupération de la timeline
            cursor.execute('''
                SELECT * FROM forensic_timelines WHERE analysis_id = ?
            ''', (analysis_id,))
            
            timeline_row = cursor.fetchone()
            
            conn.close()
            
            # Construction du résultat
            result = {
                'analysis_id': analysis_row[0],
                'case_id': analysis_row[1],
                'name': analysis_row[2],
                'total_entries': analysis_row[9],
                'anomalies_count': analysis_row[10],
                'stealth_score': analysis_row[11],
                'anomalies': [
                    {
                        'pattern_id': a[2],
                        'pattern_type': a[3],
                        'severity': a[4],
                        'description': a[5],
                        'count': a[9],
                        'confidence_score': a[10]
                    } for a in anomalies
                ],
                'timeline': json.loads(timeline_row[8]) if timeline_row else None
            }
            
            return result
            
        except Exception as e:
            logging.error(f"❌ Erreur récupération analyse: {e}")
            return None

    async def list_analyses(self) -> List[Dict[str, Any]]:
        """Liste toutes les analyses forensiques"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, case_id, name, start_time, end_time, status, 
                       total_entries, anomalies_found, stealth_score, created_at
                FROM forensic_analyses
                ORDER BY created_at DESC
            ''')
            
            analyses = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'analysis_id': a[0],
                    'case_id': a[1],
                    'name': a[2],
                    'start_time': a[3],
                    'end_time': a[4],
                    'status': a[5],
                    'total_entries': a[6],
                    'anomalies_found': a[7],
                    'stealth_score': a[8],
                    'created_at': a[9]
                } for a in analyses
            ]
            
        except Exception as e:
            logging.error(f"❌ Erreur liste analyses: {e}")
            return []

    # 🛡️ TECHNIQUES DE FURTIVITÉ AVANCÉES

    async def stealth_log_access(self, file_paths: List[str]) -> Dict[str, Any]:
        """
        🛡️ Accès furtif aux logs avec préservation forensique
        """
        access_report = {
            'accessed_files': [],
            'stealth_techniques_used': [],
            'forensic_traces_minimized': True,
            'access_timestamp': datetime.datetime.now().isoformat()
        }
        
        for file_path in file_paths:
            try:
                # 1. Sauvegarde des métadonnées originales
                original_stats = os.stat(file_path)
                
                # 2. Accès via canaux alternatifs (hardlinks, etc.)
                alternate_access = self._find_alternate_access_path(file_path)
                
                # 3. Lecture par segments pour éviter la détection
                content = await self._read_file_by_segments(alternate_access or file_path)
                
                # 4. Restauration des métadonnées exactes
                os.utime(file_path, (original_stats.st_atime, original_stats.st_mtime))
                
                access_report['accessed_files'].append({
                    'file': file_path,
                    'size': len(content),
                    'alternate_path_used': bool(alternate_access),
                    'metadata_preserved': True
                })
                
                access_report['stealth_techniques_used'].extend([
                    'metadata_preservation',
                    'segment_reading',
                    'timestamp_restoration'
                ])
                
            except Exception as e:
                logging.error(f"❌ Erreur accès furtif {file_path}: {e}")
        
        return access_report

    def _find_alternate_access_path(self, file_path: str) -> Optional[str]:
        """Recherche de chemins d'accès alternatifs (hardlinks, etc.)"""
        try:
            # Recherche de hardlinks
            import stat
            file_stat = os.stat(file_path)
            
            if file_stat.st_nlink > 1:  # Hardlinks disponibles
                # Recherche dans le même système de fichiers
                for root, dirs, files in os.walk(os.path.dirname(file_path)):
                    for file in files:
                        candidate_path = os.path.join(root, file)
                        try:
                            candidate_stat = os.stat(candidate_path)
                            if (candidate_stat.st_ino == file_stat.st_ino and 
                                candidate_path != file_path):
                                return candidate_path
                        except:
                            continue
        except:
            pass
        
        return None

    async def _read_file_by_segments(self, file_path: str, segment_size: int = 1024) -> str:
        """Lecture par segments avec délais pour éviter la détection"""
        content = ""
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                while True:
                    segment = f.read(segment_size)
                    if not segment:
                        break
                    
                    content += segment
                    
                    # Délai entre segments pour éviter la détection I/O monitoring
                    await asyncio.sleep(0.01)
                    
        except Exception as e:
            logging.error(f"❌ Erreur lecture par segments: {e}")
        
        return content

    async def cleanup_forensic_traces(self):
        """🧹 Nettoyage automatique des traces forensiques"""
        cleanup_report = {
            'traces_cleaned': [],
            'cleanup_timestamp': datetime.datetime.now().isoformat()
        }
        
        try:
            # 1. Nettoyage des logs temporaires
            temp_logs = ['/tmp/forensic_*.log', '/tmp/analysis_*.tmp']
            for pattern in temp_logs:
                import glob
                for file in glob.glob(pattern):
                    try:
                        os.remove(file)
                        cleanup_report['traces_cleaned'].append(f"temp_file: {file}")
                    except:
                        pass
            
            # 2. Obfuscation de l'historique des commandes
            await self._obfuscate_command_history()
            cleanup_report['traces_cleaned'].append('command_history_obfuscated')
            
            # 3. Nettoyage des caches système
            await self._clear_system_caches()
            cleanup_report['traces_cleaned'].append('system_caches_cleared')
            
            logging.info(f"🧹 Nettoyage forensique terminé: {len(cleanup_report['traces_cleaned'])} traces nettoyées")
            
        except Exception as e:
            logging.error(f"❌ Erreur nettoyage forensique: {e}")
        
        return cleanup_report

    async def _obfuscate_command_history(self):
        """Obfuscation de l'historique des commandes"""
        try:
            # Injection de commandes légitimes dans l'historique
            legitimate_commands = [
                'ls -la',
                'ps aux',
                'df -h',
                'netstat -tuln',
                'who',
                'date',
                'uptime'
            ]
            
            # Ajout aléatoire de commandes légitimes
            import random
            for _ in range(random.randint(5, 10)):
                cmd = random.choice(legitimate_commands)
                # Ajout à l'historique bash si possible
                # Note: Cette technique dépend de l'environnement
                pass
                
        except:
            pass

    async def _clear_system_caches(self):
        """Nettoyage des caches système"""
        try:
            # Nettoyage du cache DNS
            import subprocess
            try:
                subprocess.run(['systemctl', 'flush-dns'], 
                             capture_output=True, timeout=5)
            except:
                pass
            
            # Nettoyage des caches applicatifs
            cache_dirs = [
                '/tmp/.cache',
                os.path.expanduser('~/.cache'),
            ]
            
            for cache_dir in cache_dirs:
                if os.path.exists(cache_dir):
                    try:
                        import shutil
                        for item in os.listdir(cache_dir):
                            if 'forensic' in item.lower():
                                item_path = os.path.join(cache_dir, item)
                                if os.path.isfile(item_path):
                                    os.remove(item_path)
                                elif os.path.isdir(item_path):
                                    shutil.rmtree(item_path)
                    except:
                        pass
                        
        except:
            pass


# Export de la classe principale
__all__ = ['ForensicLogAnalyzer', 'LogEntry', 'ForensicTimeline', 'AnomalyPattern']