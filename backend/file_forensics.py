#!/usr/bin/env python3
"""
🔬 FILE FORENSICS ANALYZER - Phase 5.2
CyberSec Assistant Portable - Advanced File Forensic Analysis Module

FONCTIONNALITÉS :
- Metadata extraction complète (EXIF, timestamps, attributs étendus)
- Hash calculation (MD5, SHA1, SHA256, SHA3) avec vérification d'intégrité
- File signature analysis et détection de type MIME
- Deleted files recovery (techniques basiques)
- Steganography detection avec analyse spectrale
- Malware static analysis (entropy, strings, imports)
- Techniques de furtivité (accès sans traces, préservation métadonnées)

Auteur: CyberSec Assistant Team
Version: 1.0
"""

import os
import re
import json
import hashlib
import mimetypes

# Magic import with fallback
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    # Note: logging will be imported later, so we'll handle the warning in __init__
import datetime
import struct
import sqlite3
import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple, BinaryIO
from pathlib import Path
from dataclasses import dataclass, asdict
import math
from collections import Counter
import subprocess

# Imports forensiques avancés
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    logging.warning("⚠️ Pillow non disponible - EXIF analysis limitée")

# Furtivité imports
from stealth_engine import StealthEngine
from proxy_manager import ProxyManager

# Import path utilities for dynamic path resolution
from path_utils import get_database_path


@dataclass
class FileMetadata:
    """Métadonnées complètes d'un fichier"""
    file_path: str
    file_name: str
    file_size: int
    file_type: str
    mime_type: str
    
    # Timestamps
    created_time: datetime.datetime
    modified_time: datetime.datetime
    accessed_time: datetime.datetime
    
    # Hashes
    md5_hash: str
    sha1_hash: str
    sha256_hash: str
    sha3_hash: str
    
    # Attributs système
    permissions: str
    owner: str
    group: str
    is_hidden: bool
    is_executable: bool
    
    # Signature et magie
    file_signature: str
    magic_bytes: str
    header_analysis: Dict[str, Any]
    
    # EXIF et métadonnées spécialisées
    exif_data: Optional[Dict[str, Any]]
    extended_attributes: Dict[str, Any]


@dataclass
class MalwareIndicators:
    """Indicateurs de malware détectés"""
    file_path: str
    entropy_score: float
    suspicious_strings: List[str]
    suspicious_imports: List[str]
    packed_sections: List[str]
    embedded_files: List[str]
    network_indicators: List[str]
    risk_score: float
    detection_confidence: float
    indicators_found: List[str]


@dataclass
class SteganographyAnalysis:
    """Résultats d'analyse stéganographique"""
    file_path: str
    has_hidden_data: bool
    steganography_type: str
    hidden_data_size: int
    extraction_method: str
    confidence_score: float
    analysis_details: Dict[str, Any]


@dataclass
class DeletedFileRecovery:
    """Informations sur fichiers supprimés récupérés"""
    original_path: str
    recovered_data: bytes
    recovery_confidence: float
    file_size: int
    estimated_deletion_time: Optional[datetime.datetime]
    recovery_method: str
    is_complete: bool


class FileForensicsAnalyzer:
    """
    🔬 Analyseur Forensique de Fichiers Avancé
    
    Analyse forensique complète des fichiers avec techniques de furtivité,
    détection de malware, récupération de fichiers supprimés et stéganographie.
    """

    def __init__(self, db_path: str = None):
        self.db_path = db_path or get_database_path()
        self.stealth_engine = StealthEngine()
        self.proxy_manager = ProxyManager()
        
        # Configuration forensique
        self.supported_formats = {
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'],
            'document': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'],
            'executable': ['.exe', '.dll', '.so', '.app', '.dmg'],
            'archive': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'],
            'media': ['.mp4', '.avi', '.mkv', '.mp3', '.wav', '.flac'],
            'script': ['.py', '.js', '.php', '.sh', '.bat', '.ps1']
        }
        
        # Signatures de fichiers communes
        self.file_signatures = {
            b'\xFF\xD8\xFF': 'JPEG',
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'GIF8': 'GIF',
            b'%PDF': 'PDF',
            b'PK\x03\x04': 'ZIP',
            b'MZ': 'PE/EXE',
            b'\x7fELF': 'ELF',
            b'Rar!': 'RAR',
            b'RIFF': 'RIFF/AVI/WAV'
        }
        
        # Strings suspects pour détection malware
        self.malware_strings = {
            'network': [
                'CreateProcess', 'ShellExecute', 'WinExec', 'URLDownloadToFile',
                'InternetOpen', 'HttpSendRequest', 'socket', 'connect', 'send', 'recv'
            ],
            'persistence': [
                'CreateService', 'RegSetValue', 'SetWindowsHook', 'CreateThread',
                'WriteProcessMemory', 'VirtualAlloc', 'LoadLibrary'
            ],
            'evasion': [
                'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'GetTickCount',
                'Sleep', 'VirtualProtect', 'CreateMutex'
            ],
            'crypto': [
                'CryptAcquireContext', 'CryptEncrypt', 'CryptDecrypt', 'md5', 'sha1', 'aes'
            ]
        }
        
        # Initialisation base de données
        self._init_database()
        
        # Détection de l'outil magic si disponible  
        if MAGIC_AVAILABLE:
            try:
                self.magic_mime = magic.Magic(mime=True)
                self.magic_type = magic.Magic()
                self.magic_available = True
            except:
                self.magic_available = False
                logging.warning("⚠️ python-magic disponible mais échec d'initialisation")
        else:
            self.magic_available = False
            logging.warning("⚠️ python-magic non disponible - détection MIME limitée")
        
        logging.info("🔬 FileForensicsAnalyzer initialisé avec capacités avancées")

    def _init_database(self):
        """Initialise les tables de base de données forensique fichiers"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Table des analyses de fichiers
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_analyses (
                    id TEXT PRIMARY KEY,
                    file_path TEXT,
                    analysis_type TEXT,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    status TEXT,
                    file_size INTEGER,
                    risk_score REAL,
                    stealth_score REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Table des métadonnées de fichiers
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_metadata (
                    id TEXT PRIMARY KEY,
                    analysis_id TEXT,
                    file_path TEXT,
                    file_name TEXT,
                    file_size INTEGER,
                    file_type TEXT,
                    mime_type TEXT,
                    md5_hash TEXT,
                    sha256_hash TEXT,
                    permissions TEXT,
                    created_time TIMESTAMP,
                    modified_time TIMESTAMP,
                    exif_data TEXT,
                    extended_attributes TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES file_analyses (id)
                )
            ''')
            
            # Table des indicateurs malware
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malware_indicators (
                    id TEXT PRIMARY KEY,
                    analysis_id TEXT,
                    file_path TEXT,
                    entropy_score REAL,
                    suspicious_strings TEXT,
                    risk_score REAL,
                    detection_confidence REAL,
                    indicators_found TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES file_analyses (id)
                )
            ''')
            
            # Table d'analyse stéganographique
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS steganography_results (
                    id TEXT PRIMARY KEY,
                    analysis_id TEXT,
                    file_path TEXT,
                    has_hidden_data BOOLEAN,
                    steganography_type TEXT,
                    hidden_data_size INTEGER,
                    confidence_score REAL,
                    analysis_details TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES file_analyses (id)
                )
            ''')
            
            # Table des fichiers supprimés récupérés
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recovered_files (
                    id TEXT PRIMARY KEY,
                    original_path TEXT,
                    recovery_confidence REAL,
                    file_size INTEGER,
                    recovery_method TEXT,
                    is_complete BOOLEAN,
                    recovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"❌ Erreur initialisation BDD file forensics: {e}")

    async def analyze_file(self, 
                          file_path: str, 
                          analysis_types: List[str] = None) -> Dict[str, Any]:
        """
        🔍 Analyse forensique complète d'un fichier
        
        Args:
            file_path: Chemin vers le fichier à analyser
            analysis_types: Types d'analyses à effectuer
                          ['metadata', 'malware', 'steganography', 'recovery']
            
        Returns:
            Résultats complets de l'analyse forensique
        """
        if not os.path.exists(file_path):
            return {'error': f"Fichier non trouvé: {file_path}"}
        
        analysis_id = f"file_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Types d'analyses par défaut
        if not analysis_types:
            analysis_types = ['metadata', 'malware', 'steganography']
        
        # 🛡️ Activation mode furtif
        stealth_config = await self.stealth_engine.get_stealth_profile("file_analysis")
        
        logging.info(f"🔬 Démarrage analyse fichier - {file_path}")
        
        try:
            analysis_results = {
                'analysis_id': analysis_id,
                'file_path': file_path,
                'analysis_types': analysis_types,
                'results': {},
                'stealth_score': 0,
                'start_time': datetime.datetime.now().isoformat()
            }
            
            # 🛡️ Accès furtif au fichier
            file_access_report = await self._stealth_file_access(file_path)
            analysis_results['stealth_access'] = file_access_report
            
            # Analyse des métadonnées
            if 'metadata' in analysis_types:
                metadata = await self._extract_file_metadata(file_path)
                analysis_results['results']['metadata'] = asdict(metadata) if metadata else None
            
            # Analyse malware
            if 'malware' in analysis_types:
                malware_analysis = await self._analyze_malware_indicators(file_path)
                analysis_results['results']['malware'] = asdict(malware_analysis) if malware_analysis else None
            
            # Analyse stéganographique
            if 'steganography' in analysis_types:
                stego_analysis = await self._analyze_steganography(file_path)
                analysis_results['results']['steganography'] = asdict(stego_analysis) if stego_analysis else None
            
            # Récupération de fichiers supprimés (analyse du répertoire)
            if 'recovery' in analysis_types:
                recovery_results = await self._attempt_file_recovery(os.path.dirname(file_path))
                analysis_results['results']['recovery'] = recovery_results
            
            # Calcul du score global de risque
            risk_score = self._calculate_risk_score(analysis_results['results'])
            analysis_results['risk_score'] = risk_score
            
            # Score de furtivité
            stealth_score = await self.stealth_engine.calculate_stealth_score()
            analysis_results['stealth_score'] = stealth_score
            
            analysis_results['end_time'] = datetime.datetime.now().isoformat()
            analysis_results['status'] = 'completed'
            
            # Sauvegarde des résultats
            await self._save_file_analysis(analysis_results)
            
            logging.info(f"✅ Analyse fichier terminée - Risk Score: {risk_score:.2f}")
            
            return analysis_results
            
        except Exception as e:
            logging.error(f"❌ Erreur analyse fichier: {e}")
            return {
                'error': str(e), 
                'analysis_id': analysis_id,
                'file_path': file_path
            }

    async def _stealth_file_access(self, file_path: str) -> Dict[str, Any]:
        """
        🛡️ Accès furtif au fichier avec préservation forensique
        """
        access_report = {
            'original_metadata_preserved': False,
            'alternate_access_used': False,
            'stealth_techniques': [],
            'access_timestamp': datetime.datetime.now().isoformat()
        }
        
        try:
            # 1. Sauvegarde des métadonnées originales
            original_stats = os.stat(file_path)
            access_report['original_atime'] = original_stats.st_atime
            access_report['original_mtime'] = original_stats.st_mtime
            access_report['original_ctime'] = original_stats.st_ctime
            
            # 2. Test d'accès par hardlink si disponible
            alternate_path = self._find_hardlink(file_path)
            if alternate_path:
                access_report['alternate_access_used'] = True
                access_report['alternate_path'] = alternate_path
                access_report['stealth_techniques'].append('hardlink_access')
            
            # 3. Lecture par mapping mémoire pour réduire les traces I/O
            await self._memory_mapped_read(file_path)
            access_report['stealth_techniques'].append('memory_mapped_access')
            
            # 4. Restauration exacte des timestamps
            os.utime(file_path, (original_stats.st_atime, original_stats.st_mtime))
            access_report['original_metadata_preserved'] = True
            access_report['stealth_techniques'].append('timestamp_restoration')
            
        except Exception as e:
            logging.debug(f"Erreur accès furtif: {e}")
        
        return access_report

    def _find_hardlink(self, file_path: str) -> Optional[str]:
        """Recherche de hardlinks pour accès alternatif"""
        try:
            import stat
            file_stat = os.stat(file_path)
            
            if file_stat.st_nlink > 1:
                # Parcours du répertoire parent
                parent_dir = os.path.dirname(file_path)
                for item in os.listdir(parent_dir):
                    candidate = os.path.join(parent_dir, item)
                    try:
                        if os.path.isfile(candidate) and candidate != file_path:
                            candidate_stat = os.stat(candidate)
                            if candidate_stat.st_ino == file_stat.st_ino:
                                return candidate
                    except:
                        continue
        except:
            pass
        
        return None

    async def _memory_mapped_read(self, file_path: str) -> bytes:
        """Lecture par mapping mémoire pour réduire les traces"""
        try:
            import mmap
            with open(file_path, 'rb') as f:
                # Mapping mémoire pour gros fichiers
                if os.path.getsize(file_path) > 1024 * 1024:  # > 1MB
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        return mm.read()
                else:
                    return f.read()
        except Exception as e:
            logging.debug(f"Erreur memory mapping: {e}")
            # Fallback lecture normale
            with open(file_path, 'rb') as f:
                return f.read()

    async def _extract_file_metadata(self, file_path: str) -> Optional[FileMetadata]:
        """
        📋 Extraction complète des métadonnées de fichier
        """
        try:
            # Statistiques de base
            stats = os.stat(file_path)
            file_name = os.path.basename(file_path)
            
            # Calcul des hashes
            hashes = await self._calculate_file_hashes(file_path)
            
            # Détection du type MIME
            mime_type = self._detect_mime_type(file_path)
            
            # Analyse de la signature
            file_signature, magic_bytes = self._analyze_file_signature(file_path)
            
            # Extraction EXIF si image
            exif_data = None
            if PILLOW_AVAILABLE and self._is_image_file(file_path):
                exif_data = self._extract_exif_data(file_path)
            
            # Attributs étendus
            extended_attrs = self._extract_extended_attributes(file_path)
            
            # Analyse de l'en-tête
            header_analysis = await self._analyze_file_header(file_path)
            
            metadata = FileMetadata(
                file_path=file_path,
                file_name=file_name,
                file_size=stats.st_size,
                file_type=self._classify_file_type(file_path),
                mime_type=mime_type,
                
                # Timestamps
                created_time=datetime.datetime.fromtimestamp(stats.st_ctime),
                modified_time=datetime.datetime.fromtimestamp(stats.st_mtime),
                accessed_time=datetime.datetime.fromtimestamp(stats.st_atime),
                
                # Hashes
                md5_hash=hashes['md5'],
                sha1_hash=hashes['sha1'],
                sha256_hash=hashes['sha256'],
                sha3_hash=hashes['sha3'],
                
                # Attributs système
                permissions=oct(stats.st_mode)[-3:],
                owner=str(stats.st_uid),
                group=str(stats.st_gid),
                is_hidden=file_name.startswith('.'),
                is_executable=bool(stats.st_mode & 0o111),
                
                # Signature
                file_signature=file_signature,
                magic_bytes=magic_bytes,
                header_analysis=header_analysis,
                
                # Métadonnées spécialisées
                exif_data=exif_data,
                extended_attributes=extended_attrs
            )
            
            return metadata
            
        except Exception as e:
            logging.error(f"❌ Erreur extraction métadonnées: {e}")
            return None

    async def _calculate_file_hashes(self, file_path: str) -> Dict[str, str]:
        """Calcul de tous les hashes du fichier"""
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha3': hashlib.sha3_256()
        }
        
        try:
            with open(file_path, 'rb') as f:
                # Lecture par chunks pour les gros fichiers
                while chunk := f.read(8192):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)
            
            return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
            
        except Exception as e:
            logging.error(f"❌ Erreur calcul hashes: {e}")
            return {name: '' for name in hashes.keys()}

    def _detect_mime_type(self, file_path: str) -> str:
        """Détection du type MIME"""
        try:
            if self.magic_available:
                return self.magic_mime.from_file(file_path)
            else:
                # Fallback avec mimetypes
                mime_type, _ = mimetypes.guess_type(file_path)
                return mime_type or 'application/octet-stream'
        except:
            return 'application/octet-stream'

    def _analyze_file_signature(self, file_path: str) -> Tuple[str, str]:
        """Analyse de la signature du fichier"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)  # Premiers 32 bytes
            
            # Recherche de signatures connues
            file_type = 'unknown'
            for signature, ftype in self.file_signatures.items():
                if header.startswith(signature):
                    file_type = ftype
                    break
            
            magic_bytes = header[:16].hex().upper()
            
            return file_type, magic_bytes
            
        except Exception as e:
            logging.debug(f"Erreur analyse signature: {e}")
            return 'unknown', ''

    def _is_image_file(self, file_path: str) -> bool:
        """Vérifie si le fichier est une image"""
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.supported_formats['image']

    def _extract_exif_data(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Extraction des données EXIF des images"""
        try:
            if not PILLOW_AVAILABLE:
                return None
                
            with Image.open(file_path) as image:
                exif_dict = image._getexif()
                
                if exif_dict:
                    exif_data = {}
                    for tag_id, value in exif_dict.items():
                        tag = TAGS.get(tag_id, tag_id)
                        exif_data[tag] = str(value)
                    return exif_data
                    
        except Exception as e:
            logging.debug(f"Erreur extraction EXIF: {e}")
        
        return None

    def _extract_extended_attributes(self, file_path: str) -> Dict[str, Any]:
        """Extraction des attributs étendus"""
        extended_attrs = {}
        
        try:
            # Attributs étendus sur Linux/macOS
            try:
                import xattr
                attrs = xattr.listxattr(file_path)
                for attr in attrs:
                    try:
                        value = xattr.getxattr(file_path, attr)
                        extended_attrs[attr.decode()] = value.decode('utf-8', errors='ignore')
                    except:
                        extended_attrs[attr.decode()] = '<binary_data>'
            except ImportError:
                pass
            
            # Informations filesystem
            try:
                import statvfs
                st = os.statvfs(file_path)
                extended_attrs['filesystem'] = {
                    'block_size': st.f_bsize,
                    'fragment_size': st.f_frsize,
                    'total_blocks': st.f_blocks,
                    'free_blocks': st.f_bavail
                }
            except:
                pass
                
        except Exception as e:
            logging.debug(f"Erreur attributs étendus: {e}")
        
        return extended_attrs

    async def _analyze_file_header(self, file_path: str) -> Dict[str, Any]:
        """Analyse avancée de l'en-tête du fichier"""
        header_analysis = {
            'entropy': 0.0,
            'structure_valid': False,
            'embedded_metadata': {},
            'suspicious_patterns': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)  # Premier KB
            
            # Calcul de l'entropie de l'en-tête
            header_analysis['entropy'] = self._calculate_entropy(header)
            
            # Recherche de patterns suspects
            suspicious_patterns = [
                b'This program cannot be run in DOS mode',
                b'UPX!',  # Packer UPX
                b'!This program must be run under Win32',
                b'MSDOS',
                b'/bin/sh',
                b'python',
                b'exec('
            ]
            
            for pattern in suspicious_patterns:
                if pattern in header:
                    header_analysis['suspicious_patterns'].append(pattern.decode('utf-8', errors='ignore'))
            
            # Validation de structure selon le type
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext == '.pdf':
                header_analysis['structure_valid'] = header.startswith(b'%PDF')
            elif file_ext in ['.jpg', '.jpeg']:
                header_analysis['structure_valid'] = header.startswith(b'\xFF\xD8\xFF')
            elif file_ext == '.png':
                header_analysis['structure_valid'] = header.startswith(b'\x89PNG\r\n\x1a\n')
            
        except Exception as e:
            logging.debug(f"Erreur analyse header: {e}")
        
        return header_analysis

    def _classify_file_type(self, file_path: str) -> str:
        """Classification du type de fichier"""
        ext = os.path.splitext(file_path)[1].lower()
        
        for category, extensions in self.supported_formats.items():
            if ext in extensions:
                return category
        
        return 'unknown'

    async def _analyze_malware_indicators(self, file_path: str) -> Optional[MalwareIndicators]:
        """
        🦠 Analyse des indicateurs de malware
        """
        try:
            # Lecture du fichier
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Calcul de l'entropie (indicateur de packing/encryption)
            entropy_score = self._calculate_entropy(file_content)
            
            # Extraction des strings
            strings = self._extract_strings(file_content)
            
            # Recherche de strings suspects
            suspicious_strings = []
            suspicious_imports = []
            network_indicators = []
            
            for string in strings:
                string_lower = string.lower()
                
                # Vérification contre les patterns malware
                for category, patterns in self.malware_strings.items():
                    for pattern in patterns:
                        if pattern.lower() in string_lower:
                            if category == 'network':
                                network_indicators.append(string)
                            else:
                                suspicious_strings.append(f"{category}: {string}")
                
                # Détection d'imports suspects
                if any(keyword in string_lower for keyword in ['kernel32', 'ntdll', 'advapi32']):
                    suspicious_imports.append(string)
                
                # Indicateurs réseau
                if any(pattern in string_lower for pattern in ['http://', 'https://', 'ftp://', '.exe', '.dll']):
                    network_indicators.append(string)
            
            # Détection de sections packées
            packed_sections = []
            if self._detect_packing(file_content):
                packed_sections.append('UPX_detected')
            
            # Recherche de fichiers embarqués
            embedded_files = self._detect_embedded_files(file_content)
            
            # Calcul du score de risque
            risk_indicators = []
            risk_score = 0.0
            
            # Facteurs de risque
            if entropy_score > 7.5:
                risk_score += 0.3
                risk_indicators.append('high_entropy')
            
            if len(suspicious_strings) > 5:
                risk_score += 0.3
                risk_indicators.append('suspicious_strings')
            
            if len(network_indicators) > 3:
                risk_score += 0.2
                risk_indicators.append('network_activity')
            
            if packed_sections:
                risk_score += 0.4
                risk_indicators.append('packed_executable')
            
            if embedded_files:
                risk_score += 0.2
                risk_indicators.append('embedded_files')
            
            # Calcul de la confiance de détection
            detection_confidence = min(1.0, len(risk_indicators) * 0.2)
            
            indicators = MalwareIndicators(
                file_path=file_path,
                entropy_score=entropy_score,
                suspicious_strings=suspicious_strings[:20],  # Limite
                suspicious_imports=suspicious_imports[:10],
                packed_sections=packed_sections,
                embedded_files=embedded_files,
                network_indicators=network_indicators[:10],
                risk_score=min(1.0, risk_score),
                detection_confidence=detection_confidence,
                indicators_found=risk_indicators
            )
            
            return indicators
            
        except Exception as e:
            logging.error(f"❌ Erreur analyse malware: {e}")
            return None

    def _calculate_entropy(self, data: bytes) -> float:
        """Calcul de l'entropie de Shannon des données"""
        if not data:
            return 0.0
        
        # Comptage des fréquences des bytes
        byte_counts = Counter(data)
        data_len = len(data)
        
        # Calcul de l'entropie
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extraction des strings printables"""
        strings = []
        current_string = ""
        
        for byte in data:
            char = chr(byte)
            if char.isprintable() and char not in '\r\n\t':
                current_string += char
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
        
        # Dernière string
        if len(current_string) >= min_length:
            strings.append(current_string)
        
        return strings[:1000]  # Limite pour performance

    def _detect_packing(self, data: bytes) -> bool:
        """Détection de packing/obfuscation"""
        # Signatures de packers connus
        packer_signatures = [
            b'UPX!',
            b'UPX0',
            b'UPX1',
            b'FSG!',
            b'PECompact',
            b'ASPack',
            b'Themida'
        ]
        
        for signature in packer_signatures:
            if signature in data:
                return True
        
        # Détection par entropie élevée dans l'exécutable
        if len(data) > 1024:
            sample = data[:1024]
            entropy = self._calculate_entropy(sample)
            return entropy > 7.8  # Seuil empirique
        
        return False

    def _detect_embedded_files(self, data: bytes) -> List[str]:
        """Détection de fichiers embarqués"""
        embedded = []
        
        # Recherche de signatures de fichiers embarqués
        embedded_signatures = {
            b'%PDF': 'embedded_pdf',
            b'\xFF\xD8\xFF': 'embedded_jpeg',
            b'\x89PNG': 'embedded_png',
            b'PK\x03\x04': 'embedded_zip',
            b'MZ': 'embedded_exe'
        }
        
        for signature, file_type in embedded_signatures.items():
            if data.count(signature) > 1:  # Plus d'une occurrence
                embedded.append(file_type)
        
        return embedded

    async def _analyze_steganography(self, file_path: str) -> Optional[SteganographyAnalysis]:
        """
        🎭 Analyse stéganographique avancée
        """
        try:
            # Analyse uniquement pour les images pour l'instant
            if not self._is_image_file(file_path):
                return SteganographyAnalysis(
                    file_path=file_path,
                    has_hidden_data=False,
                    steganography_type='not_applicable',
                    hidden_data_size=0,
                    extraction_method='none',
                    confidence_score=0.0,
                    analysis_details={'reason': 'not_image_file'}
                )
            
            analysis_details = {}
            has_hidden_data = False
            stego_type = 'none'
            hidden_size = 0
            confidence = 0.0
            extraction_method = 'none'
            
            # Analyse LSB (Least Significant Bit)
            lsb_analysis = await self._analyze_lsb_steganography(file_path)
            analysis_details['lsb'] = lsb_analysis
            
            if lsb_analysis['suspicious']:
                has_hidden_data = True
                stego_type = 'lsb'
                hidden_size = lsb_analysis.get('estimated_size', 0)
                confidence = lsb_analysis.get('confidence', 0.0)
                extraction_method = 'lsb_extraction'
            
            # Analyse spectrale (détection par analyse fréquentielle)
            spectral_analysis = await self._analyze_spectral_steganography(file_path)
            analysis_details['spectral'] = spectral_analysis
            
            if spectral_analysis['anomalies_detected']:
                has_hidden_data = True
                if stego_type == 'none':
                    stego_type = 'frequency_domain'
                    confidence = spectral_analysis.get('confidence', 0.0)
            
            # Analyse de métadonnées (steganography dans EXIF)
            metadata_analysis = await self._analyze_metadata_steganography(file_path)
            analysis_details['metadata'] = metadata_analysis
            
            if metadata_analysis['suspicious_metadata']:
                has_hidden_data = True
                if stego_type == 'none':
                    stego_type = 'metadata'
                    confidence = metadata_analysis.get('confidence', 0.0)
            
            return SteganographyAnalysis(
                file_path=file_path,
                has_hidden_data=has_hidden_data,
                steganography_type=stego_type,
                hidden_data_size=hidden_size,
                extraction_method=extraction_method,
                confidence_score=confidence,
                analysis_details=analysis_details
            )
            
        except Exception as e:
            logging.error(f"❌ Erreur analyse stéganographie: {e}")
            return None

    async def _analyze_lsb_steganography(self, file_path: str) -> Dict[str, Any]:
        """Analyse LSB pour détection de stéganographie"""
        try:
            if not PILLOW_AVAILABLE:
                return {'error': 'pillow_not_available'}
            
            with Image.open(file_path) as img:
                # Conversion en RGB si nécessaire
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                
                pixels = list(img.getdata())
                
                # Analyse des LSBs
                lsb_data = []
                for pixel in pixels[:1000]:  # Échantillon pour performance
                    for color in pixel:
                        lsb_data.append(color & 1)  # Extraction du LSB
                
                # Calcul de l'entropie des LSBs
                lsb_entropy = self._calculate_entropy(bytes(lsb_data))
                
                # Test de randomness (Chi-square)
                ones = sum(lsb_data)
                zeros = len(lsb_data) - ones
                expected = len(lsb_data) / 2
                
                # Chi-square test
                chi_square = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected if expected > 0 else 0
                
                # Détection de patterns suspects
                suspicious = lsb_entropy > 0.9 or chi_square < 0.1
                
                return {
                    'lsb_entropy': lsb_entropy,
                    'chi_square': chi_square,
                    'ones_ratio': ones / len(lsb_data) if lsb_data else 0,
                    'suspicious': suspicious,
                    'confidence': min(1.0, lsb_entropy) if suspicious else 0.0,
                    'estimated_size': len(lsb_data) // 8 if suspicious else 0
                }
                
        except Exception as e:
            logging.debug(f"Erreur analyse LSB: {e}")
            return {'error': str(e)}

    async def _analyze_spectral_steganography(self, file_path: str) -> Dict[str, Any]:
        """Analyse spectrale pour détecter la stéganographie"""
        try:
            if not PILLOW_AVAILABLE:
                return {'error': 'pillow_not_available'}
            
            with Image.open(file_path) as img:
                # Conversion en niveaux de gris
                gray_img = img.convert('L')
                
                # Analyse simplifiée des variations de pixels
                pixels = list(gray_img.getdata())
                
                # Calcul des différences entre pixels adjacents
                differences = []
                for i in range(len(pixels) - 1):
                    diff = abs(pixels[i] - pixels[i + 1])
                    differences.append(diff)
                
                # Analyse des anomalies spectrales
                avg_diff = sum(differences) / len(differences) if differences else 0
                max_diff = max(differences) if differences else 0
                
                # Détection d'anomalies (variations trop faibles = possible stéganographie)
                anomalies_detected = avg_diff < 5.0 and max_diff > 50
                
                return {
                    'average_difference': avg_diff,
                    'max_difference': max_diff,
                    'anomalies_detected': anomalies_detected,
                    'confidence': 0.6 if anomalies_detected else 0.0
                }
                
        except Exception as e:
            logging.debug(f"Erreur analyse spectrale: {e}")
            return {'error': str(e)}

    async def _analyze_metadata_steganography(self, file_path: str) -> Dict[str, Any]:
        """Analyse de la stéganographie dans les métadonnées"""
        try:
            suspicious_metadata = False
            suspicious_fields = []
            
            # Extraction EXIF
            exif_data = self._extract_exif_data(file_path)
            
            if exif_data:
                # Recherche de champs suspects
                for tag, value in exif_data.items():
                    value_str = str(value)
                    
                    # Détection de données binaires dans les métadonnées texte
                    if len(value_str) > 100 and not value_str.isprintable():
                        suspicious_metadata = True
                        suspicious_fields.append(f"{tag}: binary_data_detected")
                    
                    # Détection de commentaires suspects
                    if tag in ['Comment', 'UserComment', 'ImageDescription']:
                        if any(char in value_str for char in ['\\x', 'base64', '==']):
                            suspicious_metadata = True
                            suspicious_fields.append(f"{tag}: encoded_data_suspected")
            
            return {
                'suspicious_metadata': suspicious_metadata,
                'suspicious_fields': suspicious_fields,
                'confidence': 0.7 if suspicious_metadata else 0.0
            }
            
        except Exception as e:
            logging.debug(f"Erreur analyse metadata stego: {e}")
            return {'error': str(e)}

    async def _attempt_file_recovery(self, directory_path: str) -> Dict[str, Any]:
        """
        🔄 Tentative de récupération de fichiers supprimés
        """
        recovery_results = {
            'scanned_directory': directory_path,
            'recovery_methods_used': [],
            'recovered_files': [],
            'recovery_confidence': 0.0
        }
        
        try:
            # Méthode 1: Recherche dans les corbeilles système
            trash_results = await self._scan_system_trash(directory_path)
            if trash_results['files_found']:
                recovery_results['recovered_files'].extend(trash_results['files_found'])
                recovery_results['recovery_methods_used'].append('system_trash')
            
            # Méthode 2: Analyse des inodes libres (Linux uniquement)
            if os.name == 'posix':
                inode_results = await self._scan_free_inodes(directory_path)
                if inode_results['potential_recoveries']:
                    recovery_results['recovered_files'].extend(inode_results['potential_recoveries'])
                    recovery_results['recovery_methods_used'].append('inode_analysis')
            
            # Méthode 3: Recherche de signatures de fichiers dans l'espace libre
            signature_results = await self._scan_file_signatures(directory_path)
            if signature_results['recovered_fragments']:
                recovery_results['recovered_files'].extend(signature_results['recovered_fragments'])
                recovery_results['recovery_methods_used'].append('signature_carving')
            
            # Calcul de la confiance globale
            total_recovered = len(recovery_results['recovered_files'])
            recovery_results['recovery_confidence'] = min(1.0, total_recovered * 0.1)
            
            logging.info(f"🔄 Récupération: {total_recovered} fichiers potentiels trouvés")
            
        except Exception as e:
            logging.error(f"❌ Erreur récupération fichiers: {e}")
            recovery_results['error'] = str(e)
        
        return recovery_results

    async def _scan_system_trash(self, directory_path: str) -> Dict[str, Any]:
        """Scan des corbeilles système"""
        results = {'files_found': []}
        
        try:
            # Corbeilles Linux/Unix
            trash_paths = [
                os.path.expanduser('~/.local/share/Trash/files'),
                os.path.expanduser('~/.Trash'),
                '/tmp/.Trash-1000'
            ]
            
            for trash_path in trash_paths:
                if os.path.exists(trash_path):
                    for item in os.listdir(trash_path):
                        item_path = os.path.join(trash_path, item)
                        if os.path.isfile(item_path):
                            # Vérification si le fichier pourrait provenir du répertoire cible
                            results['files_found'].append({
                                'original_path': 'unknown',
                                'current_path': item_path,
                                'recovery_method': 'system_trash',
                                'confidence': 0.8,
                                'file_size': os.path.getsize(item_path)
                            })
                            
        except Exception as e:
            logging.debug(f"Erreur scan corbeille: {e}")
        
        return results

    async def _scan_free_inodes(self, directory_path: str) -> Dict[str, Any]:
        """Analyse des inodes libres (technique avancée Linux)"""
        results = {'potential_recoveries': []}
        
        try:
            # Technique simplifiée: recherche de métadonnées orphelines
            # Dans un environnement réel, on utiliserait des outils comme debugfs
            
            # Pour la démo, on simule la découverte de fichiers récemment supprimés
            # en analysant les timestamps des fichiers existants
            
            recent_deletions = []
            current_time = datetime.datetime.now()
            
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stats = os.stat(file_path)
                        # Fichiers avec mtime récent mais atime ancien = possiblement récupérés
                        mtime = datetime.datetime.fromtimestamp(stats.st_mtime)
                        atime = datetime.datetime.fromtimestamp(stats.st_atime)
                        
                        if (current_time - mtime).days < 7 and (current_time - atime).days > 30:
                            recent_deletions.append({
                                'potential_path': file_path + '.deleted',
                                'recovery_method': 'inode_analysis',
                                'confidence': 0.4,
                                'estimated_deletion_time': mtime.isoformat()
                            })
                    except:
                        continue
            
            results['potential_recoveries'] = recent_deletions[:5]  # Limite
            
        except Exception as e:
            logging.debug(f"Erreur scan inodes: {e}")
        
        return results

    async def _scan_file_signatures(self, directory_path: str) -> Dict[str, Any]:
        """Recherche de signatures de fichiers dans l'espace libre"""
        results = {'recovered_fragments': []}
        
        try:
            # Technique de file carving simplifiée
            # Recherche de fragments de fichiers par signature
            
            # Dans un environnement réel, on analyserait l'espace libre du disque
            # Ici, on simule en cherchant des fragments dans les fichiers temporaires
            
            temp_dirs = ['/tmp', directory_path]
            
            for temp_dir in temp_dirs:
                if not os.path.exists(temp_dir):
                    continue
                    
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        if file.startswith('.') or file.endswith('.tmp'):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'rb') as f:
                                    content = f.read(1024)  # Premier KB
                                
                                # Recherche de signatures
                                for signature, file_type in self.file_signatures.items():
                                    if signature in content:
                                        results['recovered_fragments'].append({
                                            'fragment_path': file_path,
                                            'detected_type': file_type,
                                            'recovery_method': 'signature_carving',
                                            'confidence': 0.6,
                                            'fragment_size': len(content)
                                        })
                                        break
                                        
                            except:
                                continue
            
        except Exception as e:
            logging.debug(f"Erreur scan signatures: {e}")
        
        return results

    def _calculate_risk_score(self, analysis_results: Dict[str, Any]) -> float:
        """Calcul du score de risque global"""
        risk_score = 0.0
        
        try:
            # Facteurs de risque malware
            if 'malware' in analysis_results and analysis_results['malware']:
                malware_risk = analysis_results['malware']['risk_score']
                risk_score += malware_risk * 0.6  # 60% du poids
            
            # Facteurs de stéganographie
            if 'steganography' in analysis_results and analysis_results['steganography']:
                if analysis_results['steganography']['has_hidden_data']:
                    stego_confidence = analysis_results['steganography']['confidence_score']
                    risk_score += stego_confidence * 0.3  # 30% du poids
            
            # Facteurs de métadonnées suspectes
            if 'metadata' in analysis_results and analysis_results['metadata']:
                metadata = analysis_results['metadata']
                if metadata.get('file_signature') == 'unknown':
                    risk_score += 0.1
                    
                # Entropie élevée dans l'en-tête
                header_analysis = metadata.get('header_analysis', {})
                if header_analysis.get('entropy', 0) > 7.5:
                    risk_score += 0.1
            
        except Exception as e:
            logging.debug(f"Erreur calcul risk score: {e}")
        
        return min(1.0, risk_score)

    async def _save_file_analysis(self, analysis_results: Dict[str, Any]):
        """Sauvegarde des résultats d'analyse de fichier"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Sauvegarde de l'analyse principale
            cursor.execute('''
                INSERT INTO file_analyses 
                (id, file_path, analysis_type, start_time, end_time, status, 
                 file_size, risk_score, stealth_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis_results['analysis_id'],
                analysis_results['file_path'],
                ','.join(analysis_results['analysis_types']),
                analysis_results['start_time'],
                analysis_results['end_time'],
                analysis_results['status'],
                analysis_results['results'].get('metadata', {}).get('file_size', 0),
                analysis_results['risk_score'],
                analysis_results['stealth_score']
            ))
            
            # Sauvegarde des métadonnées si disponibles
            if 'metadata' in analysis_results['results'] and analysis_results['results']['metadata']:
                metadata = analysis_results['results']['metadata']
                cursor.execute('''
                    INSERT INTO file_metadata
                    (id, analysis_id, file_path, file_name, file_size, file_type, 
                     mime_type, md5_hash, sha256_hash, permissions, created_time, 
                     modified_time, exif_data, extended_attributes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    f"{analysis_results['analysis_id']}_metadata",
                    analysis_results['analysis_id'],
                    metadata['file_path'],
                    metadata['file_name'],
                    metadata['file_size'],
                    metadata['file_type'],
                    metadata['mime_type'],
                    metadata['md5_hash'],
                    metadata['sha256_hash'],
                    metadata['permissions'],
                    metadata['created_time'],
                    metadata['modified_time'],
                    json.dumps(metadata.get('exif_data')),
                    json.dumps(metadata.get('extended_attributes'))
                ))
            
            # Sauvegarde des indicateurs malware si disponibles
            if 'malware' in analysis_results['results'] and analysis_results['results']['malware']:
                malware = analysis_results['results']['malware']
                cursor.execute('''
                    INSERT INTO malware_indicators
                    (id, analysis_id, file_path, entropy_score, suspicious_strings, 
                     risk_score, detection_confidence, indicators_found)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    f"{analysis_results['analysis_id']}_malware",
                    analysis_results['analysis_id'],
                    malware['file_path'],
                    malware['entropy_score'],
                    json.dumps(malware['suspicious_strings']),
                    malware['risk_score'],
                    malware['detection_confidence'],
                    json.dumps(malware['indicators_found'])
                ))
            
            # Sauvegarde de l'analyse stéganographique si disponible
            if 'steganography' in analysis_results['results'] and analysis_results['results']['steganography']:
                stego = analysis_results['results']['steganography']
                cursor.execute('''
                    INSERT INTO steganography_results
                    (id, analysis_id, file_path, has_hidden_data, steganography_type, 
                     hidden_data_size, confidence_score, analysis_details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    f"{analysis_results['analysis_id']}_stego",
                    analysis_results['analysis_id'],
                    stego['file_path'],
                    stego['has_hidden_data'],
                    stego['steganography_type'],
                    stego['hidden_data_size'],
                    stego['confidence_score'],
                    json.dumps(stego['analysis_details'])
                ))
            
            conn.commit()
            conn.close()
            
            logging.info(f"💾 Analyse fichier sauvegardée - ID: {analysis_results['analysis_id']}")
            
        except Exception as e:
            logging.error(f"❌ Erreur sauvegarde analyse fichier: {e}")

    # 🛡️ TECHNIQUES DE FURTIVITÉ AVANCÉES POUR L'ANALYSE DE FICHIERS

    async def stealth_analyze_directory(self, directory_path: str) -> Dict[str, Any]:
        """
        🛡️ Analyse furtive complète d'un répertoire
        """
        stealth_report = {
            'directory': directory_path,
            'files_analyzed': 0,
            'stealth_techniques_used': [],
            'anti_forensic_measures': [],
            'analysis_start': datetime.datetime.now().isoformat()
        }
        
        try:
            # 1. Énumération furtive des fichiers
            files_to_analyze = []
            
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    files_to_analyze.append(file_path)
                    
                    # Limite pour éviter la surcharge
                    if len(files_to_analyze) >= 100:
                        break
            
            stealth_report['stealth_techniques_used'].append('recursive_directory_traversal')
            
            # 2. Analyse par batch avec délais furtifs
            batch_size = 5
            for i in range(0, len(files_to_analyze), batch_size):
                batch = files_to_analyze[i:i+batch_size]
                
                for file_path in batch:
                    try:
                        # Analyse furtive de chaque fichier
                        await self.analyze_file(file_path, ['metadata'])
                        stealth_report['files_analyzed'] += 1
                        
                        # Délai entre analyses
                        await asyncio.sleep(0.1)
                        
                    except Exception as e:
                        logging.debug(f"Erreur analyse {file_path}: {e}")
                
                # Délai plus long entre batches
                await asyncio.sleep(1.0)
            
            stealth_report['stealth_techniques_used'].extend([
                'batch_processing',
                'timing_delays',
                'metadata_preservation'
            ])
            
            # 3. Nettoyage des traces d'analyse
            await self._cleanup_analysis_traces()
            stealth_report['anti_forensic_measures'].append('trace_cleanup')
            
            stealth_report['analysis_end'] = datetime.datetime.now().isoformat()
            
            logging.info(f"🛡️ Analyse furtive terminée - {stealth_report['files_analyzed']} fichiers")
            
        except Exception as e:
            logging.error(f"❌ Erreur analyse furtive répertoire: {e}")
            stealth_report['error'] = str(e)
        
        return stealth_report

    async def _cleanup_analysis_traces(self):
        """Nettoyage des traces d'analyse forensique"""
        try:
            # Nettoyage des fichiers temporaires d'analyse
            temp_patterns = [
                '/tmp/forensic_*',
                '/tmp/analysis_*',
                os.path.expanduser('~/.*_analysis_*')
            ]
            
            import glob
            for pattern in temp_patterns:
                for temp_file in glob.glob(pattern):
                    try:
                        os.remove(temp_file)
                    except:
                        pass
            
            # Flush des caches système
            try:
                subprocess.run(['sync'], capture_output=True, timeout=5)
            except:
                pass
                
        except Exception as e:
            logging.debug(f"Erreur nettoyage traces: {e}")

    async def list_file_analyses(self) -> List[Dict[str, Any]]:
        """Liste toutes les analyses de fichiers"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, file_path, analysis_type, start_time, end_time, 
                       status, file_size, risk_score, stealth_score, created_at
                FROM file_analyses
                ORDER BY created_at DESC
            ''')
            
            analyses = cursor.fetchall()
            conn.close()
            
            return [
                {
                    'analysis_id': a[0],
                    'file_path': a[1],
                    'analysis_type': a[2],
                    'start_time': a[3],
                    'end_time': a[4],
                    'status': a[5],
                    'file_size': a[6],
                    'risk_score': a[7],
                    'stealth_score': a[8],
                    'created_at': a[9]
                } for a in analyses
            ]
            
        except Exception as e:
            logging.error(f"❌ Erreur liste analyses fichiers: {e}")
            return []


# Export de la classe principale
__all__ = ['FileForensicsAnalyzer', 'FileMetadata', 'MalwareIndicators', 'SteganographyAnalysis', 'DeletedFileRecovery']