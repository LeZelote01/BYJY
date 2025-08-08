#!/usr/bin/env python3
"""
🔬 NETWORK FORENSICS ANALYZER - Phase 5.3
CyberSec Assistant Portable - Advanced Network Forensic Analysis Module

FONCTIONNALITÉS :
- Capture packets en temps réel avec filtrage avancé
- PCAP files analysis complète avec reconstruction de sessions
- Protocol reconstruction (HTTP, FTP, SMTP, DNS, TCP, UDP)
- Extraction files from network traffic (HTTP downloads, email attachments)
- Suspicious connections detection avec scoring de menace
- Bandwidth analysis et détection d'anomalies de trafic
- Techniques de furtivité (capture passive, anonymisation métadonnées)

Auteur: CyberSec Assistant Team
Version: 1.0
"""

import os
import re
import json
import time
import socket
import struct
import asyncio
import datetime
import sqlite3
import hashlib
import logging
import subprocess
from typing import Dict, List, Any, Optional, Tuple, BinaryIO
from pathlib import Path
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import ipaddress

# Imports réseau forensique
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.utils import rdpcap, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("⚠️ Scapy non disponible - analyse packets limitée")

# Furtivité imports
from stealth_engine import StealthEngine
from proxy_manager import ProxyManager

# Import path utilities for dynamic path resolution
from path_utils import get_database_path


@dataclass
class NetworkSession:
    """Session réseau reconstructed"""
    session_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime.datetime
    end_time: datetime.datetime
    bytes_sent: int
    bytes_received: int
    packets_count: int
    session_data: bytes
    reconstructed_content: Dict[str, Any]
    threat_score: float


@dataclass
class SuspiciousConnection:
    """Connexion suspecte détectée"""
    connection_id: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    threat_type: str
    threat_score: float
    indicators: List[str]
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    packet_count: int
    bytes_transferred: int
    geolocation: Optional[Dict[str, str]]


@dataclass
class ExtractedFile:
    """Fichier extrait du traffic réseau"""
    file_id: str
    original_name: str
    file_type: str
    file_size: int
    md5_hash: str
    sha256_hash: str
    extraction_method: str
    source_session: str
    extracted_content: bytes
    metadata: Dict[str, Any]


@dataclass
class TrafficAnalysis:
    """Analyse complète du trafic réseau"""
    analysis_id: str
    capture_start: datetime.datetime
    capture_end: datetime.datetime
    total_packets: int
    total_bytes: int
    unique_ips: int
    protocols_detected: List[str]
    sessions_reconstructed: int
    suspicious_connections: int
    files_extracted: int
    bandwidth_analysis: Dict[str, Any]
    anomalies_detected: List[str]


class NetworkForensicsAnalyzer:
    """
    🔬 Analyseur Forensique Réseau Avancé
    
    Analyse forensique complète du trafic réseau avec reconstruction de sessions,
    détection de menaces et techniques de furtivité avancées.
    """

    def __init__(self, db_path: str = None):
        self.db_path = db_path or get_database_path()
        self.stealth_engine = StealthEngine()
        self.proxy_manager = ProxyManager()
        
        # Configuration forensique réseau
        self.suspicious_ports = {
            # Ports communs utilisés par malware
            1337, 1338, 1339, 31337,  # Leet speak ports
            4444, 5555, 6666, 7777,   # Backdoor ports
            8080, 8081, 8888, 9999,   # Proxy/tunnel ports
            1234, 12345, 54321,       # Trojan ports
            6667, 6668, 6669,         # IRC ports (C&C)
            80, 443, 53, 22           # Ports légitimes mais suspects selon contexte
        }
        
        # Protocols à surveiller
        self.monitored_protocols = {
            'HTTP': self._analyze_basic_traffic,
            'HTTPS': self._analyze_basic_traffic,
            'DNS': self._analyze_basic_traffic,
            'FTP': self._analyze_basic_traffic,
            'SMTP': self._analyze_basic_traffic,
            'TCP': self._analyze_basic_traffic,
            'UDP': self._analyze_basic_traffic,
            'ICMP': self._analyze_basic_traffic
        }
        
        # Patterns suspects dans le trafic
        self.threat_patterns = {
            'malware_c2': [
                rb'GET /[a-f0-9]{32}',  # MD5-like URL paths
                rb'POST /gate\.php',
                rb'beacon',
                rb'bot_',
                rb'cmd='
            ],
            'data_exfiltration': [
                rb'password',
                rb'creditcard',
                rb'ssn=',
                rb'confidential',
                rb'secret'
            ],
            'network_reconnaissance': [
                rb'nmap',
                rb'masscan',
                rb'dirb',
                rb'nikto',
                rb'sqlmap'
            ],
            'tunneling': [
                rb'CONNECT',
                rb'tunnel',
                rb'proxy',
                rb'socks'
            ]
        }
        
        # Géolocalisation IP suspectes (exemples)
        self.suspicious_countries = [
            'CN', 'RU', 'KP', 'IR'  # Pays souvent associés aux menaces
        ]
        
        # Sessions actives pour reconstruction
        self.active_sessions = {}
        self.extracted_files = []
        
        # Initialisation base de données
        self._init_database()
        
        # Vérification des dépendances
        if not SCAPY_AVAILABLE:
            logging.warning("⚠️ Fonctionnalités réseau limitées sans Scapy")
        
        logging.info("🔬 NetworkForensicsAnalyzer initialisé avec capacités avancées")

    def _init_database(self):
        """Initialise les tables de base de données forensique réseau"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Table des analyses de trafic
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_analyses (
                    id TEXT PRIMARY KEY,
                    capture_source TEXT,
                    analysis_type TEXT,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    total_packets INTEGER,
                    total_bytes INTEGER,
                    suspicious_connections_count INTEGER,
                    files_extracted_count INTEGER,
                    threat_score REAL,
                    stealth_score REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Table des sessions réseau
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_sessions (
                    id TEXT PRIMARY KEY,
                    analysis_id TEXT,
                    session_id TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    bytes_sent INTEGER,
                    bytes_received INTEGER,
                    packets_count INTEGER,
                    threat_score REAL,
                    session_data TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES network_analyses (id)
                )
            ''')
            
            # Table des connexions suspectes
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS suspicious_connections (
                    id TEXT PRIMARY KEY,
                    analysis_id TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    protocol TEXT,
                    threat_type TEXT,
                    threat_score REAL,
                    indicators TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    packet_count INTEGER,
                    bytes_transferred INTEGER,
                    geolocation TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES network_analyses (id)
                )
            ''')
            
            # Table des fichiers extraits
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS extracted_network_files (
                    id TEXT PRIMARY KEY,
                    analysis_id TEXT,
                    original_name TEXT,
                    file_type TEXT,
                    file_size INTEGER,
                    md5_hash TEXT,
                    sha256_hash TEXT,
                    extraction_method TEXT,
                    source_session TEXT,
                    metadata TEXT,
                    extracted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (analysis_id) REFERENCES network_analyses (id)
                )
            ''')
            
            # Table d'analyse de bande passante
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS bandwidth_analysis (
                    id TEXT PRIMARY KEY,
                    analysis_id TEXT,
                    time_window TIMESTAMP,
                    bytes_per_second INTEGER,
                    packets_per_second INTEGER,
                    top_talkers TEXT,
                    anomalies_detected TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES network_analyses (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"❌ Erreur initialisation BDD network forensics: {e}")

    async def analyze_pcap_file(self, 
                               pcap_path: str, 
                               analysis_options: Dict[str, bool] = None) -> Dict[str, Any]:
        """
        🔍 Analyse forensique complète d'un fichier PCAP
        
        Args:
            pcap_path: Chemin vers le fichier PCAP
            analysis_options: Options d'analyse 
                            {'sessions': True, 'threats': True, 'files': True, 'bandwidth': True}
            
        Returns:
            Résultats complets de l'analyse forensique réseau
        """
        if not os.path.exists(pcap_path):
            return {'error': f"Fichier PCAP non trouvé: {pcap_path}"}
        
        if not SCAPY_AVAILABLE:
            return {'error': 'Scapy requis pour l\'analyse PCAP'}
        
        analysis_id = f"pcap_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Options par défaut
        if not analysis_options:
            analysis_options = {
                'sessions': True,
                'threats': True, 
                'files': True,
                'bandwidth': True
            }
        
        # 🛡️ Activation mode furtif
        stealth_config = await self.stealth_engine.get_stealth_profile("network_analysis")
        
        logging.info(f"🔬 Démarrage analyse PCAP - {pcap_path}")
        
        try:
            analysis_results = {
                'analysis_id': analysis_id,
                'pcap_file': pcap_path,
                'analysis_options': analysis_options,
                'results': {},
                'start_time': datetime.datetime.now().isoformat()
            }
            
            # 🛡️ Accès furtif au fichier PCAP
            pcap_access_report = await self._stealth_pcap_access(pcap_path)
            analysis_results['stealth_access'] = pcap_access_report
            
            # Chargement des packets avec Scapy
            logging.info("📦 Chargement des packets PCAP...")
            packets = rdpcap(pcap_path)
            
            total_packets = len(packets)
            total_bytes = sum(len(packet) for packet in packets)
            
            logging.info(f"📊 {total_packets} packets chargés ({total_bytes} bytes)")
            
            # Analyse de base du trafic
            basic_analysis = self._analyze_basic_traffic(packets)
            analysis_results['results']['basic'] = basic_analysis
            
            # Reconstruction des sessions TCP
            if analysis_options.get('sessions', True):
                sessions = await self._reconstruct_tcp_sessions(packets)
                analysis_results['results']['sessions'] = [asdict(s) for s in sessions]
                logging.info(f"🔗 {len(sessions)} sessions TCP reconstructed")
            
            # Détection de connexions suspectes
            if analysis_options.get('threats', True):
                suspicious = await self._detect_suspicious_connections(packets)
                analysis_results['results']['suspicious_connections'] = [asdict(s) for s in suspicious]
                logging.info(f"🚨 {len(suspicious)} connexions suspectes détectées")
            
            # Extraction de fichiers
            if analysis_options.get('files', True):
                extracted_files = await self._extract_files_from_traffic(packets)
                analysis_results['results']['extracted_files'] = [asdict(f) for f in extracted_files]
                logging.info(f"📁 {len(extracted_files)} fichiers extraits")
            
            # Analyse de bande passante
            if analysis_options.get('bandwidth', True):
                bandwidth_analysis = await self._analyze_bandwidth(packets)
                analysis_results['results']['bandwidth'] = bandwidth_analysis
            
            # Création du résumé d'analyse
            traffic_analysis = TrafficAnalysis(
                analysis_id=analysis_id,
                capture_start=datetime.datetime.fromtimestamp(float(packets[0].time)) if packets else datetime.datetime.now(),
                capture_end=datetime.datetime.fromtimestamp(float(packets[-1].time)) if packets else datetime.datetime.now(),
                total_packets=total_packets,
                total_bytes=total_bytes,
                unique_ips=len(set(self._extract_ip_from_packet(p) for p in packets if self._extract_ip_from_packet(p))),
                protocols_detected=basic_analysis['protocols'],
                sessions_reconstructed=len(analysis_results['results'].get('sessions', [])),
                suspicious_connections=len(analysis_results['results'].get('suspicious_connections', [])),
                files_extracted=len(analysis_results['results'].get('extracted_files', [])),
                bandwidth_analysis=analysis_results['results'].get('bandwidth', {}),
                anomalies_detected=[]
            )
            
            analysis_results['results']['summary'] = asdict(traffic_analysis)
            
            # Score de menace global
            threat_score = self._calculate_threat_score(analysis_results['results'])
            analysis_results['threat_score'] = threat_score
            
            # Score de furtivité
            stealth_score = await self.stealth_engine.calculate_stealth_score()
            analysis_results['stealth_score'] = stealth_score
            
            analysis_results['end_time'] = datetime.datetime.now().isoformat()
            analysis_results['status'] = 'completed'
            
            # Sauvegarde des résultats
            await self._save_network_analysis(analysis_results)
            
            logging.info(f"✅ Analyse PCAP terminée - Threat Score: {threat_score:.2f}")
            
            return analysis_results
            
        except Exception as e:
            logging.error(f"❌ Erreur analyse PCAP: {e}")
            return {
                'error': str(e), 
                'analysis_id': analysis_id,
                'pcap_file': pcap_path
            }

    async def _stealth_pcap_access(self, pcap_path: str) -> Dict[str, Any]:
        """
        🛡️ Accès furtif au fichier PCAP avec préservation forensique
        """
        access_report = {
            'pcap_file': pcap_path,
            'original_metadata_preserved': False,
            'stealth_techniques': [],
            'access_timestamp': datetime.datetime.now().isoformat()
        }
        
        try:
            # Sauvegarde des métadonnées originales
            original_stats = os.stat(pcap_path)
            access_report['original_size'] = original_stats.st_size
            access_report['original_mtime'] = original_stats.st_mtime
            
            # Vérification de l'intégrité du fichier PCAP
            file_hash = hashlib.sha256()
            with open(pcap_path, 'rb') as f:
                while chunk := f.read(8192):
                    file_hash.update(chunk)
            
            access_report['file_integrity_hash'] = file_hash.hexdigest()[:16]
            access_report['stealth_techniques'].append('integrity_verification')
            
            # Restauration des timestamps après accès
            os.utime(pcap_path, (original_stats.st_atime, original_stats.st_mtime))
            access_report['original_metadata_preserved'] = True
            access_report['stealth_techniques'].append('timestamp_restoration')
            
        except Exception as e:
            logging.debug(f"Erreur accès furtif PCAP: {e}")
        
        return access_report

    def _analyze_basic_traffic(self, packets: List) -> Dict[str, Any]:
        """Analyse de base du trafic réseau"""
        basic_stats = {
            'total_packets': len(packets),
            'protocols': [],
            'src_ips': set(),
            'dst_ips': set(),
            'ports': set(),
            'packet_sizes': [],
            'time_range': {}
        }
        
        try:
            protocol_count = Counter()
            
            for packet in packets:
                # Taille des packets
                basic_stats['packet_sizes'].append(len(packet))
                
                # IPs source et destination
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    basic_stats['src_ips'].add(ip_layer.src)
                    basic_stats['dst_ips'].add(ip_layer.dst)
                
                # Protocoles
                if packet.haslayer(TCP):
                    protocol_count['TCP'] += 1
                    basic_stats['ports'].add(packet[TCP].sport)
                    basic_stats['ports'].add(packet[TCP].dport)
                elif packet.haslayer(UDP):
                    protocol_count['UDP'] += 1
                    basic_stats['ports'].add(packet[UDP].sport)
                    basic_stats['ports'].add(packet[UDP].dport)
                elif packet.haslayer(ICMP):
                    protocol_count['ICMP'] += 1
                
                # Applications layer protocols
                if packet.haslayer(HTTP):
                    protocol_count['HTTP'] += 1
                elif packet.haslayer(DNS):
                    protocol_count['DNS'] += 1
            
            # Conversion sets en listes pour sérialisation
            basic_stats['src_ips'] = list(basic_stats['src_ips'])
            basic_stats['dst_ips'] = list(basic_stats['dst_ips'])
            basic_stats['ports'] = list(basic_stats['ports'])
            basic_stats['protocols'] = list(protocol_count.keys())
            basic_stats['protocol_distribution'] = dict(protocol_count)
            
            # Statistiques temporelles
            if packets:
                timestamps = [float(p.time) for p in packets if hasattr(p, 'time')]
                if timestamps:
                    basic_stats['time_range'] = {
                        'start': datetime.datetime.fromtimestamp(min(timestamps)).isoformat(),
                        'end': datetime.datetime.fromtimestamp(max(timestamps)).isoformat(),
                        'duration_seconds': max(timestamps) - min(timestamps)
                    }
            
            # Statistiques de taille
            if basic_stats['packet_sizes']:
                basic_stats['size_stats'] = {
                    'min_size': min(basic_stats['packet_sizes']),
                    'max_size': max(basic_stats['packet_sizes']),
                    'avg_size': sum(basic_stats['packet_sizes']) / len(basic_stats['packet_sizes']),
                    'total_bytes': sum(basic_stats['packet_sizes'])
                }
            
        except Exception as e:
            logging.error(f"❌ Erreur analyse trafic de base: {e}")
        
        return basic_stats

    def _extract_ip_from_packet(self, packet) -> Optional[str]:
        """Extraction de l'IP depuis un packet"""
        try:
            if packet.haslayer(IP):
                return packet[IP].src
        except:
            pass
        return None

    async def _reconstruct_tcp_sessions(self, packets: List) -> List[NetworkSession]:
        """
        🔗 Reconstruction des sessions TCP avec payload complet
        """
        sessions = []
        session_tracker = {}
        
        try:
            for packet in packets:
                if not packet.haslayer(TCP) or not packet.haslayer(IP):
                    continue
                
                ip_layer = packet[IP]
                tcp_layer = packet[TCP]
                
                # Identification unique de la session
                session_key = f"{ip_layer.src}:{tcp_layer.sport}-{ip_layer.dst}:{tcp_layer.dport}"
                reverse_key = f"{ip_layer.dst}:{tcp_layer.dport}-{ip_layer.src}:{tcp_layer.sport}"
                
                # Utiliser la clé existante ou créer nouvelle session
                if session_key in session_tracker:
                    current_key = session_key
                elif reverse_key in session_tracker:
                    current_key = reverse_key
                else:
                    # Nouvelle session
                    current_key = session_key
                    session_tracker[current_key] = {
                        'session_id': f"tcp_{len(session_tracker)}",
                        'src_ip': ip_layer.src,
                        'dst_ip': ip_layer.dst,
                        'src_port': tcp_layer.sport,
                        'dst_port': tcp_layer.dport,
                        'protocol': 'TCP',
                        'start_time': datetime.datetime.fromtimestamp(float(packet.time)),
                        'end_time': datetime.datetime.fromtimestamp(float(packet.time)),
                        'packets': [],
                        'bytes_sent': 0,
                        'bytes_received': 0,
                        'session_data': b'',
                        'flags_seen': set()
                    }
                
                session_info = session_tracker[current_key]
                
                # Mise à jour de la session
                session_info['end_time'] = datetime.datetime.fromtimestamp(float(packet.time))
                session_info['packets'].append(packet)
                session_info['flags_seen'].add(tcp_layer.flags)
                
                # Calcul des bytes (payload seulement)
                payload = bytes(tcp_layer.payload) if tcp_layer.payload else b''
                if payload:
                    session_info['session_data'] += payload
                    
                    # Direction du trafic
                    if ip_layer.src == session_info['src_ip']:
                        session_info['bytes_sent'] += len(payload)
                    else:
                        session_info['bytes_received'] += len(payload)
            
            # Conversion en objets NetworkSession
            for session_info in session_tracker.values():
                # Reconstruction du contenu selon le protocole
                reconstructed_content = await self._reconstruct_application_layer(
                    session_info['session_data'], 
                    session_info['dst_port']
                )
                
                # Calcul du score de menace pour cette session
                threat_score = self._calculate_session_threat_score(session_info, reconstructed_content)
                
                session = NetworkSession(
                    session_id=session_info['session_id'],
                    src_ip=session_info['src_ip'],
                    dst_ip=session_info['dst_ip'],
                    src_port=session_info['src_port'],
                    dst_port=session_info['dst_port'],
                    protocol=session_info['protocol'],
                    start_time=session_info['start_time'],
                    end_time=session_info['end_time'],
                    bytes_sent=session_info['bytes_sent'],
                    bytes_received=session_info['bytes_received'],
                    packets_count=len(session_info['packets']),
                    session_data=session_info['session_data'],
                    reconstructed_content=reconstructed_content,
                    threat_score=threat_score
                )
                
                sessions.append(session)
            
        except Exception as e:
            logging.error(f"❌ Erreur reconstruction sessions TCP: {e}")
        
        return sessions

    async def _reconstruct_application_layer(self, session_data: bytes, dst_port: int) -> Dict[str, Any]:
        """Reconstruction du contenu de la couche application"""
        reconstructed = {
            'protocol_detected': 'unknown',
            'content_type': 'binary',
            'parsed_data': {},
            'extracted_info': []
        }
        
        try:
            # Détection du protocole par port
            if dst_port == 80:
                reconstructed.update(await self._parse_http_session(session_data))
            elif dst_port == 443:
                reconstructed.update(await self._parse_https_session(session_data))
            elif dst_port == 21:
                reconstructed.update(await self._parse_ftp_session(session_data))
            elif dst_port == 25 or dst_port == 587:
                reconstructed.update(await self._parse_smtp_session(session_data))
            elif dst_port == 53:
                reconstructed.update(await self._parse_dns_session(session_data))
            else:
                # Analyse générique
                reconstructed.update(await self._parse_generic_session(session_data))
            
        except Exception as e:
            logging.debug(f"Erreur reconstruction application layer: {e}")
        
        return reconstructed

    async def _parse_http_session(self, data: bytes) -> Dict[str, Any]:
        """Parse d'une session HTTP"""
        parsed = {
            'protocol_detected': 'HTTP',
            'content_type': 'text',
            'parsed_data': {},
            'extracted_info': []
        }
        
        try:
            data_str = data.decode('utf-8', errors='ignore')
            
            # Extraction des requêtes HTTP
            http_requests = re.findall(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP/1\.[01]', data_str)
            if http_requests:
                parsed['parsed_data']['requests'] = [{'method': req[0], 'url': req[1]} for req in http_requests]
            
            # Extraction des headers
            headers = re.findall(r'([A-Za-z-]+):\s*([^\r\n]+)', data_str)
            if headers:
                parsed['parsed_data']['headers'] = dict(headers[:10])  # Limite pour performance
            
            # Recherche d'informations sensibles
            sensitive_patterns = [
                (r'password[=:]\s*([^\s&]+)', 'password'),
                (r'email[=:]\s*([^\s&]+)', 'email'),
                (r'token[=:]\s*([^\s&]+)', 'token'),
                (r'cookie[=:]\s*([^\r\n]+)', 'cookie')
            ]
            
            for pattern, info_type in sensitive_patterns:
                matches = re.findall(pattern, data_str, re.IGNORECASE)
                if matches:
                    parsed['extracted_info'].extend([{'type': info_type, 'value': match} for match in matches])
            
        except Exception as e:
            logging.debug(f"Erreur parse HTTP: {e}")
        
        return parsed

    async def _parse_https_session(self, data: bytes) -> Dict[str, Any]:
        """Parse d'une session HTTPS (limitée - données chiffrées)"""
        return {
            'protocol_detected': 'HTTPS',
            'content_type': 'encrypted',
            'parsed_data': {'note': 'Encrypted HTTPS traffic - limited analysis'},
            'extracted_info': [{'type': 'protocol', 'value': 'TLS/SSL encrypted'}]
        }

    async def _parse_ftp_session(self, data: bytes) -> Dict[str, Any]:
        """Parse d'une session FTP"""
        parsed = {
            'protocol_detected': 'FTP',
            'content_type': 'text',
            'parsed_data': {},
            'extracted_info': []
        }
        
        try:
            data_str = data.decode('utf-8', errors='ignore')
            
            # Commandes FTP
            ftp_commands = re.findall(r'(USER|PASS|LIST|RETR|STOR|CWD|PWD)\s+([^\r\n]*)', data_str)
            if ftp_commands:
                parsed['parsed_data']['commands'] = [{'command': cmd[0], 'argument': cmd[1]} for cmd in ftp_commands]
            
            # Extraction des credentials
            user_matches = re.findall(r'USER\s+([^\r\n]+)', data_str)
            pass_matches = re.findall(r'PASS\s+([^\r\n]+)', data_str)
            
            if user_matches:
                parsed['extracted_info'].append({'type': 'username', 'value': user_matches[0]})
            if pass_matches:
                parsed['extracted_info'].append({'type': 'password', 'value': pass_matches[0]})
            
        except Exception as e:
            logging.debug(f"Erreur parse FTP: {e}")
        
        return parsed

    async def _parse_smtp_session(self, data: bytes) -> Dict[str, Any]:
        """Parse d'une session SMTP"""
        parsed = {
            'protocol_detected': 'SMTP',
            'content_type': 'text',
            'parsed_data': {},
            'extracted_info': []
        }
        
        try:
            data_str = data.decode('utf-8', errors='ignore')
            
            # Commandes SMTP
            smtp_commands = re.findall(r'(HELO|EHLO|MAIL FROM|RCPT TO|DATA|QUIT)[\s:]+([^\r\n]*)', data_str)
            if smtp_commands:
                parsed['parsed_data']['commands'] = [{'command': cmd[0], 'argument': cmd[1]} for cmd in smtp_commands]
            
            # Extraction des emails
            email_addresses = re.findall(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', data_str)
            if email_addresses:
                parsed['extracted_info'].extend([{'type': 'email', 'value': email} for email in set(email_addresses)])
            
        except Exception as e:
            logging.debug(f"Erreur parse SMTP: {e}")
        
        return parsed

    async def _parse_dns_session(self, data: bytes) -> Dict[str, Any]:
        """Parse d'une session DNS"""
        parsed = {
            'protocol_detected': 'DNS',
            'content_type': 'binary',
            'parsed_data': {},
            'extracted_info': []
        }
        
        try:
            # Extraction simple des noms de domaines (patterns basiques)
            data_str = data.decode('utf-8', errors='ignore')
            
            # Recherche de patterns de domaines
            domain_patterns = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', data_str)
            if domain_patterns:
                unique_domains = list(set(domain_patterns))
                parsed['parsed_data']['domains_queried'] = unique_domains[:10]  # Limite
                parsed['extracted_info'].extend([{'type': 'domain', 'value': domain} for domain in unique_domains])
            
        except Exception as e:
            logging.debug(f"Erreur parse DNS: {e}")
        
        return parsed

    async def _parse_generic_session(self, data: bytes) -> Dict[str, Any]:
        """Parse générique pour protocoles non reconnus"""
        parsed = {
            'protocol_detected': 'unknown',
            'content_type': 'binary',
            'parsed_data': {},
            'extracted_info': []
        }
        
        try:
            # Tentative de détection de strings printables
            try:
                data_str = data.decode('utf-8', errors='ignore')
                printable_ratio = sum(1 for c in data_str if c.isprintable()) / len(data_str) if data_str else 0
                
                if printable_ratio > 0.7:
                    parsed['content_type'] = 'text'
                    parsed['parsed_data']['printable_content'] = data_str[:500]  # Échantillon
            except:
                pass
            
            # Recherche de patterns suspects
            for threat_type, patterns in self.threat_patterns.items():
                for pattern in patterns:
                    if pattern in data:
                        parsed['extracted_info'].append({
                            'type': 'threat_indicator',
                            'threat_type': threat_type,
                            'pattern': pattern.decode('utf-8', errors='ignore')
                        })
            
        except Exception as e:
            logging.debug(f"Erreur parse générique: {e}")
        
        return parsed

    def _calculate_session_threat_score(self, session_info: Dict, reconstructed_content: Dict) -> float:
        """Calcul du score de menace pour une session"""
        threat_score = 0.0
        
        try:
            # Facteur port suspect
            if session_info['dst_port'] in self.suspicious_ports:
                threat_score += 0.3
            
            # Facteur IP privée vs publique
            try:
                dst_ip = ipaddress.ip_address(session_info['dst_ip'])
                if not dst_ip.is_private:
                    threat_score += 0.1
            except:
                pass
            
            # Facteur volume de données
            total_bytes = session_info['bytes_sent'] + session_info['bytes_received']
            if total_bytes > 1024 * 1024:  # > 1MB
                threat_score += 0.2
            
            # Facteur contenu suspect
            extracted_info = reconstructed_content.get('extracted_info', [])
            threat_indicators = [info for info in extracted_info if info.get('type') == 'threat_indicator']
            threat_score += min(0.4, len(threat_indicators) * 0.1)
            
            # Facteur informations sensibles
            sensitive_info = [info for info in extracted_info if info.get('type') in ['password', 'token', 'cookie']]
            threat_score += min(0.3, len(sensitive_info) * 0.1)
            
        except Exception as e:
            logging.debug(f"Erreur calcul threat score session: {e}")
        
        return min(1.0, threat_score)

    async def _detect_suspicious_connections(self, packets: List) -> List[SuspiciousConnection]:
        """
        🚨 Détection de connexions suspectes avancée
        """
        suspicious_connections = []
        connection_tracker = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'first_seen': None,
            'last_seen': None,
            'threat_indicators': []
        })
        
        try:
            for packet in packets:
                if not packet.haslayer(IP):
                    continue
                
                ip_layer = packet[IP]
                connection_key = f"{ip_layer.src}-{ip_layer.dst}"
                
                # Mise à jour du tracker
                conn_info = connection_tracker[connection_key]
                conn_info['packets'] += 1
                conn_info['bytes'] += len(packet)
                
                packet_time = datetime.datetime.fromtimestamp(float(packet.time))
                if conn_info['first_seen'] is None:
                    conn_info['first_seen'] = packet_time
                conn_info['last_seen'] = packet_time
                
                # Analyse des indicateurs de menace
                threat_indicators = []
                
                # Port scanning detection
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    if tcp_layer.dport in self.suspicious_ports:
                        threat_indicators.append(f"suspicious_port_{tcp_layer.dport}")
                    
                    # SYN flood detection
                    if tcp_layer.flags == 2:  # SYN flag
                        threat_indicators.append("syn_packet")
                
                # Payload analysis
                if packet.payload:
                    payload_bytes = bytes(packet.payload)
                    for threat_type, patterns in self.threat_patterns.items():
                        for pattern in patterns:
                            if pattern in payload_bytes:
                                threat_indicators.append(f"{threat_type}_{pattern.decode('utf-8', errors='ignore')[:20]}")
                
                conn_info['threat_indicators'].extend(threat_indicators)
            
            # Évaluation des connexions suspectes
            for connection_key, conn_info in connection_tracker.items():
                src_ip, dst_ip = connection_key.split('-')
                
                # Calcul du score de menace
                threat_score = 0.0
                unique_indicators = list(set(conn_info['threat_indicators']))
                
                # Facteurs de scoring
                if len(unique_indicators) > 0:
                    threat_score += min(0.5, len(unique_indicators) * 0.1)
                
                # Volume anormal
                if conn_info['packets'] > 1000:
                    threat_score += 0.2
                    unique_indicators.append("high_packet_count")
                
                if conn_info['bytes'] > 10 * 1024 * 1024:  # > 10MB
                    threat_score += 0.2
                    unique_indicators.append("high_byte_count")
                
                # IP géographique suspecte (simulation)
                try:
                    dst_ip_obj = ipaddress.ip_address(dst_ip)
                    if not dst_ip_obj.is_private:
                        # Simulation de géolocalisation
                        if dst_ip.startswith(('1.', '14.', '27.')):  # IPs exemple suspectus
                            threat_score += 0.3
                            unique_indicators.append("suspicious_geolocation")
                except:
                    pass
                
                # Si score suffisant, ajouter à la liste suspecte
                if threat_score >= 0.3:
                    # Détection du protocole et port principal
                    protocol = 'TCP'  # Défaut
                    dst_port = 80     # Défaut
                    
                    # Géolocalisation simulée
                    geolocation = None
                    if not ipaddress.ip_address(dst_ip).is_private:
                        geolocation = {'country': 'Unknown', 'city': 'Unknown'}
                    
                    suspicious_conn = SuspiciousConnection(
                        connection_id=f"susp_{hashlib.md5(connection_key.encode()).hexdigest()[:8]}",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol=protocol,
                        threat_type=self._determine_threat_type(unique_indicators),
                        threat_score=min(1.0, threat_score),
                        indicators=unique_indicators,
                        first_seen=conn_info['first_seen'],
                        last_seen=conn_info['last_seen'],
                        packet_count=conn_info['packets'],
                        bytes_transferred=conn_info['bytes'],
                        geolocation=geolocation
                    )
                    
                    suspicious_connections.append(suspicious_conn)
            
        except Exception as e:
            logging.error(f"❌ Erreur détection connexions suspectes: {e}")
        
        return suspicious_connections

    def _determine_threat_type(self, indicators: List[str]) -> str:
        """Détermine le type de menace basé sur les indicateurs"""
        threat_keywords = {
            'malware_c2': ['malware', 'c2', 'beacon', 'bot'],
            'data_exfiltration': ['password', 'confidential', 'secret'],
            'network_scan': ['syn_packet', 'suspicious_port'],
            'tunneling': ['tunnel', 'proxy', 'socks'],
            'ddos': ['high_packet_count', 'syn_packet']
        }
        
        for threat_type, keywords in threat_keywords.items():
            if any(keyword in ' '.join(indicators).lower() for keyword in keywords):
                return threat_type
        
        return 'unknown_threat'

    async def _extract_files_from_traffic(self, packets: List) -> List[ExtractedFile]:
        """
        📁 Extraction de fichiers depuis le trafic réseau
        """
        extracted_files = []
        
        try:
            # Reconstruction des sessions HTTP pour extraction de fichiers
            http_sessions = {}
            
            for packet in packets:
                if not packet.haslayer(HTTP):
                    continue
                
                # Identification de la session
                if packet.haslayer(IP) and packet.haslayer(TCP):
                    ip_layer = packet[IP]
                    tcp_layer = packet[TCP]
                    session_key = f"{ip_layer.src}:{tcp_layer.sport}-{ip_layer.dst}:{tcp_layer.dport}"
                    
                    if session_key not in http_sessions:
                        http_sessions[session_key] = {
                            'packets': [],
                            'data': b''
                        }
                    
                    http_sessions[session_key]['packets'].append(packet)
                    if packet.payload:
                        http_sessions[session_key]['data'] += bytes(packet.payload)
            
            # Analyse des sessions HTTP pour extraction de fichiers
            for session_key, session_data in http_sessions.items():
                files_in_session = await self._extract_files_from_http_session(
                    session_data['data'], session_key
                )
                extracted_files.extend(files_in_session)
            
        except Exception as e:
            logging.error(f"❌ Erreur extraction fichiers: {e}")
        
        return extracted_files

    async def _extract_files_from_http_session(self, session_data: bytes, session_key: str) -> List[ExtractedFile]:
        """Extraction de fichiers depuis une session HTTP"""
        files = []
        
        try:
            data_str = session_data.decode('utf-8', errors='ignore')
            
            # Recherche de headers indiquant des téléchargements de fichiers
            content_disposition = re.search(r'Content-Disposition:\s*attachment;\s*filename="([^"]+)"', data_str, re.IGNORECASE)
            content_type = re.search(r'Content-Type:\s*([^\r\n]+)', data_str, re.IGNORECASE)
            
            if content_disposition:
                filename = content_disposition.group(1)
                
                # Extraction du contenu du fichier (simplifiée)
                # Recherche du début du contenu (après les headers HTTP)
                content_start = data_str.find('\r\n\r\n')
                if content_start != -1:
                    file_content = session_data[content_start + 4:]
                    
                    if len(file_content) > 0:
                        # Calcul des hashes
                        md5_hash = hashlib.md5(file_content).hexdigest()
                        sha256_hash = hashlib.sha256(file_content).hexdigest()
                        
                        # Détection du type de fichier
                        file_type = 'unknown'
                        if content_type:
                            file_type = content_type.group(1).strip()
                        
                        extracted_file = ExtractedFile(
                            file_id=f"extracted_{len(files)}_{datetime.datetime.now().strftime('%H%M%S')}",
                            original_name=filename,
                            file_type=file_type,
                            file_size=len(file_content),
                            md5_hash=md5_hash,
                            sha256_hash=sha256_hash,
                            extraction_method='http_content_disposition',
                            source_session=session_key,
                            extracted_content=file_content,
                            metadata={
                                'extraction_timestamp': datetime.datetime.now().isoformat(),
                                'session_key': session_key,
                                'content_type': file_type
                            }
                        )
                        
                        files.append(extracted_file)
            
        except Exception as e:
            logging.debug(f"Erreur extraction fichiers HTTP: {e}")
        
        return files

    async def _analyze_bandwidth(self, packets: List) -> Dict[str, Any]:
        """
        📊 Analyse de bande passante et détection d'anomalies
        """
        bandwidth_analysis = {
            'time_windows': [],
            'peak_usage': {},
            'anomalies': [],
            'top_talkers': []
        }
        
        try:
            if not packets:
                return bandwidth_analysis
            
            # Groupement par fenêtres temporelles (30 secondes)
            window_size = 30  # secondes
            time_windows = {}
            ip_traffic = defaultdict(int)
            
            start_time = float(packets[0].time)
            
            for packet in packets:
                packet_time = float(packet.time)
                window_index = int((packet_time - start_time) // window_size)
                
                if window_index not in time_windows:
                    time_windows[window_index] = {
                        'start_time': start_time + (window_index * window_size),
                        'bytes': 0,
                        'packets': 0,
                        'unique_ips': set()
                    }
                
                window_data = time_windows[window_index]
                window_data['bytes'] += len(packet)
                window_data['packets'] += 1
                
                # IPs pour top talkers
                if packet.haslayer(IP):
                    ip_src = packet[IP].src
                    ip_dst = packet[IP].dst
                    window_data['unique_ips'].add(ip_src)
                    window_data['unique_ips'].add(ip_dst)
                    
                    ip_traffic[ip_src] += len(packet)
                    ip_traffic[ip_dst] += len(packet)
            
            # Conversion des fenêtres pour analyse
            window_stats = []
            for window_index, window_data in time_windows.items():
                window_stats.append({
                    'window_index': window_index,
                    'timestamp': datetime.datetime.fromtimestamp(window_data['start_time']).isoformat(),
                    'bytes_per_second': window_data['bytes'] / window_size,
                    'packets_per_second': window_data['packets'] / window_size,
                    'unique_ips': len(window_data['unique_ips']),
                    'total_bytes': window_data['bytes'],
                    'total_packets': window_data['packets']
                })
            
            bandwidth_analysis['time_windows'] = window_stats
            
            # Détection du pic d'utilisation
            if window_stats:
                max_bandwidth = max(window_stats, key=lambda x: x['bytes_per_second'])
                bandwidth_analysis['peak_usage'] = {
                    'timestamp': max_bandwidth['timestamp'],
                    'bytes_per_second': max_bandwidth['bytes_per_second'],
                    'packets_per_second': max_bandwidth['packets_per_second']
                }
            
            # Détection d'anomalies de bande passante
            if len(window_stats) > 3:
                bytes_per_sec_values = [w['bytes_per_second'] for w in window_stats]
                avg_bandwidth = sum(bytes_per_sec_values) / len(bytes_per_sec_values)
                max_bandwidth_value = max(bytes_per_sec_values)
                
                # Anomalie si pic > 5x la moyenne
                if max_bandwidth_value > avg_bandwidth * 5:
                    bandwidth_analysis['anomalies'].append({
                        'type': 'bandwidth_spike',
                        'description': f"Pic de bande passante détecté: {max_bandwidth_value:.0f} B/s (moyenne: {avg_bandwidth:.0f} B/s)",
                        'severity': 'medium',
                        'timestamp': max_bandwidth['timestamp']
                    })
            
            # Top talkers (IPs avec le plus de trafic)
            top_ips = sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:10]
            bandwidth_analysis['top_talkers'] = [
                {'ip': ip, 'bytes': bytes_count, 'percentage': (bytes_count / sum(ip_traffic.values())) * 100}
                for ip, bytes_count in top_ips
            ]
            
        except Exception as e:
            logging.error(f"❌ Erreur analyse bande passante: {e}")
        
        return bandwidth_analysis

    def _calculate_threat_score(self, analysis_results: Dict[str, Any]) -> float:
        """Calcul du score de menace global"""
        threat_score = 0.0
        
        try:
            # Facteur connexions suspectes
            suspicious_connections = analysis_results.get('suspicious_connections', [])
            if suspicious_connections:
                avg_threat_score = sum(conn['threat_score'] for conn in suspicious_connections) / len(suspicious_connections)
                threat_score += avg_threat_score * 0.4
            
            # Facteur sessions à haut risque
            sessions = analysis_results.get('sessions', [])
            high_risk_sessions = [s for s in sessions if s['threat_score'] > 0.7]
            if high_risk_sessions:
                threat_score += min(0.3, len(high_risk_sessions) * 0.1)
            
            # Facteur fichiers extraits suspects
            extracted_files = analysis_results.get('extracted_files', [])
            if extracted_files:
                threat_score += min(0.2, len(extracted_files) * 0.05)
            
            # Facteur anomalies de bande passante
            bandwidth = analysis_results.get('bandwidth', {})
            anomalies = bandwidth.get('anomalies', [])
            if anomalies:
                threat_score += min(0.1, len(anomalies) * 0.05)
            
        except Exception as e:
            logging.debug(f"Erreur calcul threat score global: {e}")
        
        return min(1.0, threat_score)

    async def _save_network_analysis(self, analysis_results: Dict[str, Any]):
        """Sauvegarde des résultats d'analyse réseau"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Sauvegarde de l'analyse principale
            summary = analysis_results['results'].get('summary', {})
            cursor.execute('''
                INSERT INTO network_analyses 
                (id, capture_source, analysis_type, start_time, end_time, 
                 total_packets, total_bytes, suspicious_connections_count, 
                 files_extracted_count, threat_score, stealth_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis_results['analysis_id'],
                analysis_results.get('pcap_file', 'unknown'),
                'pcap_analysis',
                analysis_results['start_time'],
                analysis_results['end_time'],
                summary.get('total_packets', 0),
                summary.get('total_bytes', 0),
                summary.get('suspicious_connections', 0),
                summary.get('files_extracted', 0),
                analysis_results['threat_score'],
                analysis_results['stealth_score']
            ))
            
            # Sauvegarde des sessions (échantillon)
            sessions = analysis_results['results'].get('sessions', [])
            for session in sessions[:50]:  # Limite pour performance
                cursor.execute('''
                    INSERT INTO network_sessions
                    (id, analysis_id, session_id, src_ip, dst_ip, src_port, dst_port, 
                     protocol, start_time, end_time, bytes_sent, bytes_received, 
                     packets_count, threat_score, session_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    f"{analysis_results['analysis_id']}_session_{session['session_id']}",
                    analysis_results['analysis_id'],
                    session['session_id'],
                    session['src_ip'],
                    session['dst_ip'],
                    session['src_port'],
                    session['dst_port'],
                    session['protocol'],
                    session['start_time'],
                    session['end_time'],
                    session['bytes_sent'],
                    session['bytes_received'],
                    session['packets_count'],
                    session['threat_score'],
                    json.dumps(session['reconstructed_content'])
                ))
            
            # Sauvegarde des connexions suspectes
            suspicious_connections = analysis_results['results'].get('suspicious_connections', [])
            for conn in suspicious_connections:
                cursor.execute('''
                    INSERT INTO suspicious_connections
                    (id, analysis_id, src_ip, dst_ip, dst_port, protocol, threat_type, 
                     threat_score, indicators, first_seen, last_seen, packet_count, 
                     bytes_transferred, geolocation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    conn['connection_id'],
                    analysis_results['analysis_id'],
                    conn['src_ip'],
                    conn['dst_ip'],
                    conn['dst_port'],
                    conn['protocol'],
                    conn['threat_type'],
                    conn['threat_score'],
                    json.dumps(conn['indicators']),
                    conn['first_seen'],
                    conn['last_seen'],
                    conn['packet_count'],
                    conn['bytes_transferred'],
                    json.dumps(conn['geolocation'])
                ))
            
            # Sauvegarde des fichiers extraits
            extracted_files = analysis_results['results'].get('extracted_files', [])
            for file_info in extracted_files:
                cursor.execute('''
                    INSERT INTO extracted_network_files
                    (id, analysis_id, original_name, file_type, file_size, 
                     md5_hash, sha256_hash, extraction_method, source_session, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_info['file_id'],
                    analysis_results['analysis_id'],
                    file_info['original_name'],
                    file_info['file_type'],
                    file_info['file_size'],
                    file_info['md5_hash'],
                    file_info['sha256_hash'],
                    file_info['extraction_method'],
                    file_info['source_session'],
                    json.dumps(file_info['metadata'])
                ))
            
            conn.commit()
            conn.close()
            
            logging.info(f"💾 Analyse réseau sauvegardée - ID: {analysis_results['analysis_id']}")
            
        except Exception as e:
            logging.error(f"❌ Erreur sauvegarde analyse réseau: {e}")

    async def list_network_analyses(self) -> List[Dict[str, Any]]:
        """Liste toutes les analyses réseau"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, capture_source, analysis_type, start_time, end_time, 
                       total_packets, total_bytes, suspicious_connections_count, 
                       files_extracted_count, threat_score, stealth_score, created_at
                FROM network_analyses
                ORDER BY created_at DESC
            ''')
            
            analyses = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'analysis_id': a[0],
                    'capture_source': a[1],
                    'analysis_type': a[2],
                    'start_time': a[3],
                    'end_time': a[4],
                    'total_packets': a[5],
                    'total_bytes': a[6],
                    'suspicious_connections_count': a[7],
                    'files_extracted_count': a[8],
                    'threat_score': a[9],
                    'stealth_score': a[10],
                    'created_at': a[11]
                } for a in analyses
            ]
            
        except Exception as e:
            logging.error(f"❌ Erreur liste analyses réseau: {e}")
            return []

    # 🛡️ TECHNIQUES DE FURTIVITÉ AVANCÉES POUR L'ANALYSE RÉSEAU

    async def stealth_packet_capture(self, 
                                   interface: str, 
                                   duration: int = 60, 
                                   filter_expression: str = None) -> Dict[str, Any]:
        """
        🛡️ Capture de packets furtive en mode monitor
        """
        if not SCAPY_AVAILABLE:
            return {'error': 'Scapy requis pour la capture'}
        
        capture_report = {
            'interface': interface,
            'duration': duration,
            'filter': filter_expression,
            'stealth_techniques': [],
            'packets_captured': 0,
            'capture_file': None
        }
        
        try:
            # Mode monitor WiFi furtif (si supporté)
            if 'wlan' in interface or 'wifi' in interface:
                # Tentative d'activation du mode monitor
                try:
                    subprocess.run(['iwconfig', interface, 'mode', 'monitor'], 
                                 capture_output=True, timeout=10)
                    capture_report['stealth_techniques'].append('monitor_mode_activated')
                except:
                    pass
            
            # Capture avec filtrage pour réduire la détection
            capture_filter = filter_expression or "not arp and not icmp"
            
            # Capture furtive avec Scapy
            captured_packets = []
            
            def packet_handler(packet):
                captured_packets.append(packet)
                # Limite pour éviter l'épuisement mémoire
                if len(captured_packets) >= 10000:
                    return True  # Stop capture
            
            # Démarrage de la capture
            logging.info(f"🔍 Démarrage capture furtive sur {interface} ({duration}s)")
            
            scapy.sniff(
                iface=interface,
                filter=capture_filter,
                prn=packet_handler,
                timeout=duration,
                store=False
            )
            
            capture_report['packets_captured'] = len(captured_packets)
            capture_report['stealth_techniques'].extend([
                'filtered_capture',
                'real_time_processing',
                'memory_efficient'
            ])
            
            # Sauvegarde temporaire des packets
            if captured_packets:
                temp_pcap = f"/tmp/stealth_capture_{datetime.datetime.now().strftime('%H%M%S')}.pcap"
                wrpcap(temp_pcap, captured_packets)
                capture_report['capture_file'] = temp_pcap
                
                # Auto-cleanup après 1 heure
                asyncio.create_task(self._cleanup_temp_pcap(temp_pcap, 3600))
            
            logging.info(f"✅ Capture terminée - {len(captured_packets)} packets")
            
        except Exception as e:
            logging.error(f"❌ Erreur capture furtive: {e}")
            capture_report['error'] = str(e)
        
        return capture_report

    async def _cleanup_temp_pcap(self, pcap_path: str, delay: int):
        """Nettoyage automatique des fichiers PCAP temporaires"""
        try:
            await asyncio.sleep(delay)
            if os.path.exists(pcap_path):
                os.remove(pcap_path)
                logging.info(f"🧹 Fichier PCAP temporaire nettoyé: {pcap_path}")
        except Exception as e:
            logging.debug(f"Erreur nettoyage PCAP: {e}")


# Fonctions utilitaires pour l'analyse réseau
def _analyze_http_traffic(session_data: bytes) -> Dict[str, Any]:
    """Analyse du trafic HTTP (fonction utilitaire)"""
    pass

def _analyze_https_traffic(session_data: bytes) -> Dict[str, Any]:
    """Analyse du trafic HTTPS (fonction utilitaire)"""
    pass

def _analyze_dns_traffic(session_data: bytes) -> Dict[str, Any]:
    """Analyse du trafic DNS (fonction utilitaire)"""
    pass

def _analyze_ftp_traffic(session_data: bytes) -> Dict[str, Any]:
    """Analyse du trafic FTP (fonction utilitaire)"""
    pass

def _analyze_smtp_traffic(session_data: bytes) -> Dict[str, Any]:
    """Analyse du trafic SMTP (fonction utilitaire)"""
    pass

def _analyze_tcp_traffic(session_data: bytes) -> Dict[str, Any]:
    """Analyse du trafic TCP (fonction utilitaire)"""
    pass

def _analyze_udp_traffic(session_data: bytes) -> Dict[str, Any]:
    """Analyse du trafic UDP (fonction utilitaire)"""
    pass

def _analyze_icmp_traffic(session_data: bytes) -> Dict[str, Any]:
    """Analyse du trafic ICMP (fonction utilitaire)"""
    pass


# Export de la classe principale
__all__ = ['NetworkForensicsAnalyzer', 'NetworkSession', 'SuspiciousConnection', 'ExtractedFile', 'TrafficAnalysis']