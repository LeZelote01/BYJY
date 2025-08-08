#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Stealth OSINT Collector V1.0
Collecteur d'informations OSINT furtif avec techniques d'évasion
Features: Subdomain Enumeration, Email Harvesting, Certificate Analysis, Social Media Intel
"""

import os
import sys
import json
import time
import random
import asyncio
import threading
import dns.resolver
import ssl
import socket
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import logging
import requests
import re
from urllib.parse import urlparse, urljoin
import base64
from dataclasses import dataclass
import concurrent.futures

from stealth_engine import get_global_stealth_engine
from proxy_manager import get_global_proxy_manager

logger = logging.getLogger(__name__)

@dataclass
class OSINTTarget:
    """Cible pour collecte OSINT"""
    domain: str
    collect_subdomains: bool = True
    collect_emails: bool = True
    collect_social_media: bool = False
    collect_certificates: bool = True
    collect_technologies: bool = True
    stealth_level: int = 8

@dataclass
class OSINTResult:
    """Résultat de collecte OSINT"""
    collection_id: str
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "running"
    subdomains: Set[str] = None
    emails: Set[str] = None
    social_media: Dict[str, List[str]] = None
    certificates: List[Dict] = None
    technologies: Dict[str, Any] = None
    dns_records: Dict[str, List[str]] = None
    whois_info: Dict[str, Any] = None
    stealth_score: float = 100.0
    
    def __post_init__(self):
        if self.subdomains is None:
            self.subdomains = set()
        if self.emails is None:
            self.emails = set()
        if self.social_media is None:
            self.social_media = {}
        if self.certificates is None:
            self.certificates = []
        if self.technologies is None:
            self.technologies = {}
        if self.dns_records is None:
            self.dns_records = {}

class StealthOSINTCollector:
    """
    Collecteur OSINT furtif avec techniques d'évasion avancées
    """
    
    def __init__(self):
        self.stealth_engine = get_global_stealth_engine()
        self.proxy_manager = get_global_proxy_manager()
        self.active_collections = {}
        self.collection_history = []
        
        # Wordlists pour énumération de sous-domaines
        self.subdomain_wordlist = [
            "www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
            "blog", "shop", "store", "news", "forum", "support", "help",
            "secure", "login", "dashboard", "panel", "cpanel", "webmail",
            "mx", "ns1", "ns2", "dns", "smtp", "pop", "imap", "exchange",
            "vpn", "remote", "access", "portal", "gateway", "proxy",
            "cdn", "static", "assets", "img", "images", "video", "media",
            "download", "files", "backup", "old", "new", "beta", "alpha",
            "mobile", "m", "wap", "app", "apps", "service", "services"
        ]
        
        # Sources OSINT publiques
        self.osint_sources = {
            "certificate_transparency": [
                "https://crt.sh/?q=",
                "https://certspotter.com/api/v0/certs?domain="
            ],
            "dns_databases": [
                "https://dns.bufferover.run/dns?q=",
                "https://tls.bufferover.run/dns?q="
            ],
            "search_engines": [
                "https://www.google.com/search?q=site:",
                "https://duckduckgo.com/?q=site:",
                "https://www.bing.com/search?q=site:"
            ]
        }
        
        # Patterns d'extraction
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.subdomain_pattern = re.compile(r'[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+')
        
        logger.info("✅ Stealth OSINT Collector initialized")
    
    def start_collection(
        self, 
        target: str, 
        collect_subdomains: bool = True,
        collect_emails: bool = True, 
        collect_social_media: bool = False,
        collect_certificates: bool = True,
        stealth_level: int = 8
    ) -> str:
        """Démarrer une collecte OSINT furtive"""
        
        collection_id = f"osint_{int(time.time())}_{random.randint(1000, 9999)}"
        
        osint_target = OSINTTarget(
            domain=target,
            collect_subdomains=collect_subdomains,
            collect_emails=collect_emails,
            collect_social_media=collect_social_media,
            collect_certificates=collect_certificates,
            stealth_level=stealth_level
        )
        
        collection_result = OSINTResult(
            collection_id=collection_id,
            target=target,
            start_time=datetime.now()
        )
        
        self.active_collections[collection_id] = collection_result
        
        # Démarrer la collecte en arrière-plan
        collection_thread = threading.Thread(
            target=self._execute_osint_collection,
            args=(collection_id, osint_target),
            daemon=True
        )
        collection_thread.start()
        
        logger.info(f"🕵️ OSINT collection initiated: {collection_id} -> {target}")
        return collection_id
    
    def _execute_osint_collection(self, collection_id: str, target: OSINTTarget):
        """Exécuter la collecte OSINT"""
        collection_result = self.active_collections[collection_id]
        
        try:
            # Collecte DNS de base
            collection_result.dns_records = self._collect_dns_records(target.domain)
            
            # Collecte WHOIS
            collection_result.whois_info = self._collect_whois_info(target.domain)
            
            # Énumération de sous-domaines
            if target.collect_subdomains:
                collection_result.subdomains = self._enumerate_subdomains(target)
            
            # Collecte d'emails
            if target.collect_emails:
                collection_result.emails = self._harvest_emails(target)
            
            # Analyse des certificats
            if target.collect_certificates:
                collection_result.certificates = self._analyze_certificates(target)
            
            # Détection de technologies
            if target.collect_technologies:
                collection_result.technologies = self._detect_technologies(target)
            
            # Réseaux sociaux (si activé)
            if target.collect_social_media:
                collection_result.social_media = self._collect_social_media(target)
            
            # Calculer le score de furtivité
            collection_result.stealth_score = self._calculate_collection_stealth_score(target)
            
            collection_result.status = "completed"
            collection_result.end_time = datetime.now()
            
            logger.info(f"✅ OSINT collection completed: {collection_id}")
            
        except Exception as e:
            logger.error(f"❌ OSINT collection failed: {collection_id} - {e}")
            collection_result.status = "failed"
            collection_result.end_time = datetime.now()
        
        # Nettoyer les traces
        self.stealth_engine.cleanup_forensics()
    
    def _collect_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Collecte des enregistrements DNS"""
        dns_records = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        try:
            for record_type in record_types:
                try:
                    # Appliquer délai de furtivité
                    self.stealth_engine.apply_stealth_timing(1.0)
                    
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(answer) for answer in answers]
                    
                    logger.debug(f"🔍 DNS {record_type} records found for {domain}: {len(answers)}")
                    
                except dns.resolver.NXDOMAIN:
                    dns_records[record_type] = []
                except dns.resolver.NoAnswer:
                    dns_records[record_type] = []
                except Exception as e:
                    logger.debug(f"DNS query failed for {record_type}: {e}")
                    dns_records[record_type] = []
        
        except Exception as e:
            logger.error(f"❌ DNS collection failed: {e}")
        
        return dns_records
    
    def _collect_whois_info(self, domain: str) -> Dict[str, Any]:
        """Collecte d'informations WHOIS"""
        try:
            # Utiliser whois command line si disponible
            try:
                result = subprocess.run(['whois', domain], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    whois_data = result.stdout
                    
                    # Parser les informations importantes
                    whois_info = {
                        "raw_data": whois_data,
                        "registrar": self._extract_whois_field(whois_data, "Registrar"),
                        "creation_date": self._extract_whois_field(whois_data, "Creation Date"),
                        "expiry_date": self._extract_whois_field(whois_data, "Registry Expiry Date"),
                        "name_servers": self._extract_whois_nameservers(whois_data)
                    }
                    
                    logger.debug(f"🔍 WHOIS info collected for {domain}")
                    return whois_info
                    
            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("WHOIS command not available or timed out")
        
        except Exception as e:
            logger.error(f"❌ WHOIS collection failed: {e}")
        
        return {"error": "WHOIS data not available"}
    
    def _extract_whois_field(self, whois_data: str, field_name: str) -> Optional[str]:
        """Extraire un champ spécifique du WHOIS"""
        pattern = rf"{field_name}:\s*(.+)"
        match = re.search(pattern, whois_data, re.IGNORECASE)
        return match.group(1).strip() if match else None
    
    def _extract_whois_nameservers(self, whois_data: str) -> List[str]:
        """Extraire les serveurs de noms du WHOIS"""
        pattern = r"Name Server:\s*(.+)"
        matches = re.findall(pattern, whois_data, re.IGNORECASE)
        return [ns.strip() for ns in matches]
    
    def _enumerate_subdomains(self, target: OSINTTarget) -> Set[str]:
        """Énumération de sous-domaines avec techniques furtives"""
        subdomains = set()
        
        # 1. Brute force avec wordlist
        subdomains.update(self._bruteforce_subdomains(target))
        
        # 2. Certificate Transparency
        subdomains.update(self._certificate_transparency_search(target))
        
        # 3. DNS Zone Transfer (si possible)
        subdomains.update(self._attempt_zone_transfer(target))
        
        # 4. Search Engine Dorking
        if target.stealth_level <= 7:  # Plus risqué
            subdomains.update(self._search_engine_dorking(target))
        
        # 5. Passive DNS databases
        subdomains.update(self._passive_dns_lookup(target))
        
        logger.info(f"🔍 Found {len(subdomains)} subdomains for {target.domain}")
        return subdomains
    
    def _bruteforce_subdomains(self, target: OSINTTarget) -> Set[str]:
        """Brute force de sous-domaines avec délais furtifs"""
        subdomains = set()
        domain = target.domain
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            try:
                # Appliquer délai de furtivité
                delay = self.stealth_engine.apply_stealth_timing(0.5)
                
                # Test de résolution DNS
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    return full_domain
            except:
                pass
            return None
        
        # Utiliser ThreadPool pour paralléliser avec contrôle du taux
        max_workers = min(10, len(self.subdomain_wordlist))
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_subdomain = {
                executor.submit(check_subdomain, sub): sub 
                for sub in self.subdomain_wordlist
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    subdomains.add(result)
                    logger.debug(f"✅ Subdomain found: {result}")
        
        return subdomains
    
    def _certificate_transparency_search(self, target: OSINTTarget) -> Set[str]:
        """Recherche dans les logs Certificate Transparency"""
        subdomains = set()
        domain = target.domain
        
        # Utiliser crt.sh
        try:
            session = self.stealth_engine.create_stealth_session()
            
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            response = session.get(url, timeout=30)
            
            if response.status_code == 200:
                certificates = response.json()
                
                for cert in certificates:
                    name_value = cert.get('name_value', '')
                    # Extraire tous les domaines du certificat
                    cert_domains = name_value.split('\n')
                    
                    for cert_domain in cert_domains:
                        cert_domain = cert_domain.strip()
                        if cert_domain.endswith(f'.{domain}'):
                            subdomains.add(cert_domain)
                
                logger.debug(f"🔍 Certificate Transparency: {len(subdomains)} subdomains found")
        
        except Exception as e:
            logger.warning(f"⚠️ Certificate Transparency search failed: {e}")
        
        return subdomains
    
    def _attempt_zone_transfer(self, target: OSINTTarget) -> Set[str]:
        """Tentative de transfert de zone DNS"""
        subdomains = set()
        domain = target.domain
        
        try:
            # Obtenir les serveurs de noms
            ns_answers = dns.resolver.resolve(domain, 'NS')
            
            for ns in ns_answers:
                try:
                    # Tentative de transfert de zone
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    
                    for name in zone.nodes.keys():
                        subdomain = str(name) + '.' + domain
                        if subdomain != domain:
                            subdomains.add(subdomain)
                    
                    logger.info(f"✅ Zone transfer successful from {ns}")
                    break  # Si ça marche avec un NS, pas besoin d'essayer les autres
                    
                except Exception as e:
                    logger.debug(f"Zone transfer failed from {ns}: {e}")
                    continue
        
        except Exception as e:
            logger.debug(f"Zone transfer enumeration failed: {e}")
        
        return subdomains
    
    def _search_engine_dorking(self, target: OSINTTarget) -> Set[str]:
        """Recherche de sous-domaines via moteurs de recherche"""
        subdomains = set()
        domain = target.domain
        
        # Google dorking (avec prudence)
        try:
            session = self.stealth_engine.create_stealth_session()
            
            query = f"site:{domain}"
            url = f"https://www.google.com/search?q={query}&num=50"
            
            # Délai important pour éviter la détection
            self.stealth_engine.apply_stealth_timing(5.0)
            
            response = session.get(url)
            
            if response.status_code == 200:
                # Extraire les sous-domaines des résultats
                found_domains = self.subdomain_pattern.findall(response.text)
                
                for found_domain in found_domains:
                    if found_domain.endswith(f'.{domain}') or found_domain == domain:
                        subdomains.add(found_domain)
                
                logger.debug(f"🔍 Search engine dorking: {len(subdomains)} subdomains found")
        
        except Exception as e:
            logger.warning(f"⚠️ Search engine dorking failed: {e}")
        
        return subdomains
    
    def _passive_dns_lookup(self, target: OSINTTarget) -> Set[str]:
        """Recherche dans les bases de données DNS passives"""
        subdomains = set()
        domain = target.domain
        
        # Utiliser DNS databases publiques
        sources = [
            f"https://dns.bufferover.run/dns?q=.{domain}",
            f"https://tls.bufferover.run/dns?q=.{domain}"
        ]
        
        for source_url in sources:
            try:
                session = self.stealth_engine.create_stealth_session()
                
                # Délai entre les requêtes
                self.stealth_engine.apply_stealth_timing(2.0)
                
                response = session.get(source_url, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # Parser selon le format de la source
                    if 'FDNS_A' in data:
                        for record in data['FDNS_A']:
                            parts = record.split(',')
                            if len(parts) >= 2:
                                subdomain = parts[1]
                                if subdomain.endswith(f'.{domain}'):
                                    subdomains.add(subdomain)
            
            except Exception as e:
                logger.debug(f"Passive DNS lookup failed for {source_url}: {e}")
                continue
        
        return subdomains
    
    def _harvest_emails(self, target: OSINTTarget) -> Set[str]:
        """Collecte d'adresses email"""
        emails = set()
        domain = target.domain
        
        # 1. Recherche sur les sous-domaines connus
        subdomains_to_check = list(self.active_collections[target.domain].subdomains) if target.domain in self.active_collections else [domain]
        
        for subdomain in subdomains_to_check[:10]:  # Limiter pour la furtivité
            try:
                session = self.stealth_engine.create_stealth_session()
                
                # Délai entre les requêtes
                self.stealth_engine.apply_stealth_timing(1.0)
                
                response = session.get(f"http://{subdomain}", timeout=10)
                
                if response.status_code == 200:
                    # Extraire les emails du contenu
                    found_emails = self.email_pattern.findall(response.text)
                    
                    for email in found_emails:
                        if domain in email:
                            emails.add(email)
            
            except Exception as e:
                logger.debug(f"Email harvest failed for {subdomain}: {e}")
                continue
        
        # 2. Recherche sur les moteurs de recherche
        if target.stealth_level <= 6:
            emails.update(self._search_engines_email_harvest(domain))
        
        logger.info(f"📧 Found {len(emails)} email addresses for {domain}")
        return emails
    
    def _search_engines_email_harvest(self, domain: str) -> Set[str]:
        """Collecte d'emails via moteurs de recherche"""
        emails = set()
        
        try:
            session = self.stealth_engine.create_stealth_session()
            
            # Query pour chercher des emails
            query = f'"{domain}" email OR contact OR @{domain}'
            url = f"https://www.google.com/search?q={query}&num=20"
            
            # Délai important
            self.stealth_engine.apply_stealth_timing(8.0)
            
            response = session.get(url)
            
            if response.status_code == 200:
                found_emails = self.email_pattern.findall(response.text)
                
                for email in found_emails:
                    if domain in email:
                        emails.add(email)
        
        except Exception as e:
            logger.warning(f"⚠️ Search engine email harvest failed: {e}")
        
        return emails
    
    def _analyze_certificates(self, target: OSINTTarget) -> List[Dict]:
        """Analyse des certificats SSL/TLS"""
        certificates = []
        domain = target.domain
        
        try:
            # Analyser le certificat du domaine principal
            cert_info = self._get_ssl_certificate(domain, 443)
            if cert_info:
                certificates.append(cert_info)
            
            # Analyser quelques sous-domaines si trouvés
            if hasattr(self.active_collections.get(domain), 'subdomains'):
                subdomains = list(self.active_collections[domain].subdomains)[:5]  # Limiter pour la furtivité
                
                for subdomain in subdomains:
                    try:
                        cert_info = self._get_ssl_certificate(subdomain, 443)
                        if cert_info:
                            certificates.append(cert_info)
                        
                        # Délai entre les analyses
                        self.stealth_engine.apply_stealth_timing(1.0)
                    
                    except Exception as e:
                        logger.debug(f"Certificate analysis failed for {subdomain}: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"❌ Certificate analysis failed: {e}")
        
        logger.info(f"🔒 Analyzed {len(certificates)} certificates for {domain}")
        return certificates
    
    def _get_ssl_certificate(self, hostname: str, port: int = 443) -> Optional[Dict]:
        """Obtenir les informations du certificat SSL"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    cert_info = {
                        "hostname": hostname,
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "signature_algorithm": cert.get('signatureAlgorithm'),
                        "subject_alt_names": [x[1] for x in cert.get('subjectAltName', []) if x[0] == 'DNS']
                    }
                    
                    return cert_info
        
        except Exception as e:
            logger.debug(f"SSL certificate retrieval failed for {hostname}: {e}")
            return None
    
    def _detect_technologies(self, target: OSINTTarget) -> Dict[str, Any]:
        """Détection des technologies utilisées"""
        technologies = {}
        domain = target.domain
        
        try:
            session = self.stealth_engine.create_stealth_session()
            
            # Analyser les headers HTTP
            response = session.get(f"http://{domain}", timeout=10)
            
            tech_info = {
                "http_status": response.status_code,
                "server": response.headers.get('Server', 'Unknown'),
                "powered_by": response.headers.get('X-Powered-By', 'Unknown'),
                "framework": self._detect_framework(response),
                "cms": self._detect_cms(response),
                "javascript_libraries": self._detect_js_libraries(response.text),
                "security_headers": self._analyze_security_headers(response.headers)
            }
            
            technologies.update(tech_info)
            
            # Tenter HTTPS aussi
            try:
                https_response = session.get(f"https://{domain}", timeout=10)
                technologies["https_available"] = True
                technologies["https_redirect"] = response.status_code in [301, 302]
            except:
                technologies["https_available"] = False
        
        except Exception as e:
            logger.debug(f"Technology detection failed: {e}")
            technologies = {"error": str(e)}
        
        return technologies
    
    def _detect_framework(self, response) -> str:
        """Détecter le framework web"""
        headers = response.headers
        content = response.text.lower()
        
        # Headers spécifiques
        if 'django' in headers.get('Server', '').lower():
            return "Django"
        elif 'flask' in headers.get('Server', '').lower():
            return "Flask"
        elif 'express' in headers.get('X-Powered-By', '').lower():
            return "Express.js"
        
        # Contenu spécifique
        if 'wp-content' in content or 'wordpress' in content:
            return "WordPress"
        elif 'drupal' in content:
            return "Drupal"
        elif 'joomla' in content:
            return "Joomla"
        
        return "Unknown"
    
    def _detect_cms(self, response) -> str:
        """Détecter le CMS utilisé"""
        content = response.text.lower()
        
        cms_patterns = {
            'wordpress': ['wp-content', 'wp-includes', 'wp-json'],
            'drupal': ['drupal', 'sites/default'],
            'joomla': ['joomla', 'option=com_'],
            'magento': ['magento', 'mage/'],
            'shopify': ['shopify', 'cdn.shopify']
        }
        
        for cms, patterns in cms_patterns.items():
            if any(pattern in content for pattern in patterns):
                return cms.title()
        
        return "Unknown"
    
    def _detect_js_libraries(self, content: str) -> List[str]:
        """Détecter les bibliothèques JavaScript"""
        libraries = []
        content_lower = content.lower()
        
        js_patterns = {
            'jQuery': ['jquery', 'jquery.min.js'],
            'React': ['react', '_reactinternals'],
            'Angular': ['angular', 'ng-app'],
            'Vue.js': ['vue', 'vue.js'],
            'Bootstrap': ['bootstrap', 'bootstrap.min'],
            'D3.js': ['d3.js', 'd3.min.js']
        }
        
        for lib, patterns in js_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                libraries.append(lib)
        
        return libraries
    
    def _analyze_security_headers(self, headers) -> Dict[str, bool]:
        """Analyser les headers de sécurité"""
        security_headers = {
            'Content-Security-Policy': 'content-security-policy' in headers,
            'X-Frame-Options': 'x-frame-options' in headers,
            'X-XSS-Protection': 'x-xss-protection' in headers,
            'X-Content-Type-Options': 'x-content-type-options' in headers,
            'Strict-Transport-Security': 'strict-transport-security' in headers,
            'Referrer-Policy': 'referrer-policy' in headers
        }
        
        return security_headers
    
    def _collect_social_media(self, target: OSINTTarget) -> Dict[str, List[str]]:
        """Collecte d'informations sur les réseaux sociaux"""
        social_media = {
            "facebook": [],
            "twitter": [],
            "linkedin": [],
            "instagram": [],
            "youtube": []
        }
        
        domain = target.domain
        
        # Patterns de recherche pour les réseaux sociaux
        social_patterns = {
            "facebook": [f"facebook.com/{domain}", f"fb.me/{domain}"],
            "twitter": [f"twitter.com/{domain}", f"@{domain}"],
            "linkedin": [f"linkedin.com/company/{domain}"],
            "instagram": [f"instagram.com/{domain}"],
            "youtube": [f"youtube.com/c/{domain}", f"youtube.com/user/{domain}"]
        }
        
        try:
            session = self.stealth_engine.create_stealth_session()
            
            for platform, patterns in social_patterns.items():
                for pattern in patterns:
                    try:
                        # Délai important pour éviter la détection
                        self.stealth_engine.apply_stealth_timing(3.0)
                        
                        search_query = f"site:{platform.split('.')[0]}.com {domain}"
                        search_url = f"https://www.google.com/search?q={search_query}"
                        
                        response = session.get(search_url)
                        
                        if response.status_code == 200:
                            # Extraire les liens vers les profils sociaux
                            links = re.findall(r'https?://[^\s<>"\']+', response.text)
                            
                            for link in links:
                                if platform.split('.')[0] in link and domain in link:
                                    social_media[platform].append(link)
                    
                    except Exception as e:
                        logger.debug(f"Social media search failed for {platform}: {e}")
                        continue
        
        except Exception as e:
            logger.error(f"❌ Social media collection failed: {e}")
        
        return social_media
    
    def _calculate_collection_stealth_score(self, target: OSINTTarget) -> float:
        """Calculer le score de furtivité de la collecte"""
        base_score = 100.0
        
        # Pénalités selon les techniques utilisées
        if target.collect_social_media:
            base_score -= 15  # Plus risqué
        
        if target.stealth_level < 5:
            base_score -= 25
        elif target.stealth_level < 7:
            base_score -= 15
        
        # Bonus pour utilisation de proxies
        if self.proxy_manager.get_current_proxy():
            base_score += 10
        
        return max(0, min(100, base_score))
    
    def get_collection_status(self, collection_id: str) -> Optional[Dict[str, Any]]:
        """Obtenir le statut d'une collecte"""
        if collection_id not in self.active_collections:
            return None
        
        collection = self.active_collections[collection_id]
        
        return {
            "collection_id": collection_id,
            "target": collection.target,
            "status": collection.status,
            "start_time": collection.start_time.isoformat(),
            "end_time": collection.end_time.isoformat() if collection.end_time else None,
            "subdomains_count": len(collection.subdomains),
            "emails_count": len(collection.emails),
            "certificates_count": len(collection.certificates),
            "stealth_score": collection.stealth_score,
            "progress": 100 if collection.status == "completed" else 50 if collection.status == "running" else 0
        }
    
    def get_collection_results(self, collection_id: str) -> Optional[Dict[str, Any]]:
        """Obtenir les résultats complets d'une collecte"""
        if collection_id not in self.active_collections:
            return None
        
        collection = self.active_collections[collection_id]
        
        return {
            "collection_id": collection_id,
            "target": collection.target,
            "status": collection.status,
            "start_time": collection.start_time.isoformat(),
            "end_time": collection.end_time.isoformat() if collection.end_time else None,
            "subdomains": list(collection.subdomains),
            "emails": list(collection.emails),
            "social_media": collection.social_media,
            "certificates": collection.certificates,
            "technologies": collection.technologies,
            "dns_records": collection.dns_records,
            "whois_info": collection.whois_info,
            "stealth_score": collection.stealth_score,
            "summary": {
                "total_subdomains": len(collection.subdomains),
                "total_emails": len(collection.emails),
                "total_certificates": len(collection.certificates),
                "technologies_detected": len([k for k, v in collection.technologies.items() if v and v != "Unknown"]) if collection.technologies else 0
            }
        }
    
    def get_collector_statistics(self) -> Dict[str, Any]:
        """Obtenir les statistiques du collecteur"""
        total_collections = len(self.active_collections)
        completed_collections = len([c for c in self.active_collections.values() if c.status == "completed"])
        running_collections = len([c for c in self.active_collections.values() if c.status == "running"])
        
        avg_stealth_score = 0
        if completed_collections > 0:
            total_score = sum(c.stealth_score for c in self.active_collections.values() if c.status == "completed")
            avg_stealth_score = total_score / completed_collections
        
        return {
            "total_collections": total_collections,
            "completed_collections": completed_collections,
            "running_collections": running_collections,
            "success_rate": (completed_collections / total_collections * 100) if total_collections > 0 else 0,
            "average_stealth_score": avg_stealth_score,
            "osint_techniques": [
                "DNS enumeration",
                "Certificate transparency",
                "Subdomain brute force",
                "Email harvesting",
                "Technology detection",
                "Social media intel"
            ],
            "stealth_features": [
                "Proxy rotation",
                "Request timing randomization",
                "User-agent rotation", 
                "Anti-forensics cleanup"
            ]
        }

# Factory functions
def get_osint_collector() -> StealthOSINTCollector:
    """Obtenir une instance du collecteur OSINT"""
    return StealthOSINTCollector()

# Global instance
_osint_collector = None

def get_global_osint_collector() -> StealthOSINTCollector:
    """Obtenir l'instance globale du collecteur OSINT"""
    global _osint_collector
    if _osint_collector is None:
        _osint_collector = get_osint_collector()
    return _osint_collector