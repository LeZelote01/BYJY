#!/usr/bin/env python3
"""
Brute Force API - CyberSec Assistant
API endpoints pour les fonctionnalités de brute force
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from typing import Dict, List, Optional, Any
from pydantic import BaseModel
import uuid
import time
import logging

from bruteforce_engine import BruteForceEngine, BruteForceTarget, BruteForceType
from wordlist_generator import WordlistGenerator, WordlistConfig

# Configuration Pydantic pour requêtes
class BruteForceRequest(BaseModel):
    target_type: str
    host: str
    port: Optional[int] = None
    service: Optional[str] = None
    username_list: Optional[List[str]] = None
    password_list: Optional[List[str]] = None
    hash_target: Optional[str] = None
    form_data: Optional[Dict[str, Any]] = None
    headers: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    stealth_level: int = 5
    max_threads: int = 10
    delay_min: float = 0.1
    delay_max: float = 2.0
    timeout: int = 10
    stop_on_success: bool = True

class WordlistGenerationRequest(BaseModel):
    generation_type: str = "smart"  # "smart", "common", "targeted", "brute_force", "rule_based"
    target_info: Optional[Dict[str, Any]] = None
    config: Optional[Dict[str, Any]] = None
    custom_words: Optional[List[str]] = None
    limit: int = 10000

class HashCrackRequest(BaseModel):
    hash_value: str
    hash_type: str
    wordlist_name: Optional[str] = None
    custom_wordlist: Optional[List[str]] = None
    stealth_level: int = 5
    max_attempts: int = 100000

router = APIRouter(prefix="/api/bruteforce", tags=["bruteforce"])

# Instance globale des engines
brute_engine = None
wordlist_gen = None

def get_brute_engine():
    """Récupère l'instance du moteur de brute force"""
    global brute_engine
    if brute_engine is None:
        brute_engine = BruteForceEngine()
    return brute_engine

def get_wordlist_generator():
    """Récupère l'instance du générateur de wordlists"""
    global wordlist_gen
    if wordlist_gen is None:
        wordlist_gen = WordlistGenerator()
        # Créer wordlists par défaut
        wordlist_gen.create_default_wordlists()
    return wordlist_gen

@router.get("/health")
async def health_check():
    """Vérification de santé du module brute force"""
    return {
        "status": "healthy",
        "module": "bruteforce",
        "version": "1.0",
        "timestamp": time.time(),
        "features": {
            "network_attacks": ["ssh", "ftp", "http_basic", "http_form", "telnet"],
            "hash_cracking": ["md5", "sha1", "sha256", "ntlm"],
            "wordlist_generation": ["smart", "common", "targeted", "rule_based"]
        }
    }

@router.get("/supported_protocols")
async def get_supported_protocols():
    """Retourne les protocoles supportés pour le brute force"""
    protocols = {
        "network": {
            "ssh": {
                "name": "SSH",
                "default_port": 22,
                "description": "Secure Shell brute force attack",
                "required_fields": ["host", "username_list", "password_list"]
            },
            "ftp": {
                "name": "FTP",
                "default_port": 21,
                "description": "File Transfer Protocol brute force",
                "required_fields": ["host", "username_list", "password_list"]
            },
            "telnet": {
                "name": "Telnet",
                "default_port": 23,
                "description": "Telnet protocol brute force",
                "required_fields": ["host", "username_list", "password_list"]
            },
            "http_basic": {
                "name": "HTTP Basic Auth",
                "default_port": 80,
                "description": "HTTP Basic Authentication brute force",
                "required_fields": ["host", "service", "username_list", "password_list"]
            },
            "http_form": {
                "name": "HTTP Form Auth",
                "default_port": 80,
                "description": "HTTP Form-based authentication brute force",
                "required_fields": ["host", "service", "form_data", "username_list", "password_list"]
            }
        },
        "hashing": {
            "hash_md5": {
                "name": "MD5 Hash",
                "description": "MD5 hash cracking",
                "required_fields": ["hash_target", "password_list"]
            },
            "hash_sha1": {
                "name": "SHA1 Hash",
                "description": "SHA1 hash cracking",
                "required_fields": ["hash_target", "password_list"]
            },
            "hash_sha256": {
                "name": "SHA256 Hash",
                "description": "SHA256 hash cracking",
                "required_fields": ["hash_target", "password_list"]
            },
            "hash_ntlm": {
                "name": "NTLM Hash",
                "description": "Windows NTLM hash cracking",
                "required_fields": ["hash_target", "password_list"]
            }
        }
    }
    return protocols

@router.post("/start")
async def start_brute_force_attack(request: BruteForceRequest, background_tasks: BackgroundTasks):
    """Démarre une attaque de brute force"""
    try:
        engine = get_brute_engine()
        
        # Validation du type d'attaque
        try:
            attack_type = BruteForceType(request.target_type)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported attack type: {request.target_type}"
            )
        
        # Création de la cible
        target = BruteForceTarget(
            target_type=attack_type,
            host=request.host,
            port=request.port,
            service=request.service,
            username_list=request.username_list,
            password_list=request.password_list,
            hash_target=request.hash_target,
            form_data=request.form_data,
            headers=request.headers,
            cookies=request.cookies,
            stealth_level=request.stealth_level,
            max_threads=request.max_threads,
            delay_min=request.delay_min,
            delay_max=request.delay_max,
            timeout=request.timeout,
            stop_on_success=request.stop_on_success
        )
        
        # Générer un ID unique pour l'attaque
        attack_id = str(uuid.uuid4())
        
        # Démarrer l'attaque
        await engine.start_brute_force(target, attack_id)
        
        return {
            "status": "started",
            "attack_id": attack_id,
            "target_host": request.host,
            "target_type": request.target_type,
            "estimated_combinations": len(target.username_list or []) * len(target.password_list or []) if target.username_list and target.password_list else len(target.password_list or []),
            "stealth_level": request.stealth_level,
            "timestamp": time.time()
        }
        
    except Exception as e:
        logging.error(f"Failed to start brute force attack: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/attacks")
async def list_active_attacks():
    """Liste toutes les attaques actives"""
    engine = get_brute_engine()
    attacks = engine.list_active_attacks()
    
    return {
        "active_attacks": attacks,
        "total_count": len(attacks),
        "timestamp": time.time()
    }

@router.get("/attacks/{attack_id}")
async def get_attack_status(attack_id: str):
    """Récupère le statut détaillé d'une attaque"""
    engine = get_brute_engine()
    attack_data = engine.get_attack_status(attack_id)
    
    if not attack_data:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    # Calculer statistiques supplémentaires
    results = attack_data['results']
    successful_results = [r for r in results if r.success]
    
    return {
        "attack_id": attack_id,
        "status": attack_data['status'],
        "progress": attack_data['progress'],
        "start_time": attack_data['start_time'],
        "elapsed_time": time.time() - attack_data['start_time'],
        "target": {
            "host": attack_data['target'].host,
            "type": attack_data['target'].target_type.value,
            "port": attack_data['target'].port,
            "stealth_level": attack_data['target'].stealth_level
        },
        "statistics": {
            "total_results": len(results),
            "successful_attempts": len(successful_results),
            "failed_attempts": len(results) - len(successful_results)
        },
        "successful_credentials": [
            {
                "username": r.username,
                "password": r.password,
                "response_time": r.response_time,
                "timestamp": r.timestamp
            } for r in successful_results
        ]
    }

@router.post("/attacks/{attack_id}/stop")
async def stop_attack(attack_id: str):
    """Arrête une attaque en cours"""
    engine = get_brute_engine()
    success = engine.stop_attack(attack_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    return {
        "status": "stopped",
        "attack_id": attack_id,
        "timestamp": time.time()
    }

@router.get("/attacks/{attack_id}/results")
async def get_attack_results(attack_id: str, limit: Optional[int] = 100):
    """Récupère les résultats d'une attaque"""
    engine = get_brute_engine()
    results = engine.get_results(attack_id)
    
    if results is None:
        raise HTTPException(status_code=404, detail="Attack not found")
    
    # Limiter et formater les résultats
    limited_results = results[:limit] if limit else results
    
    formatted_results = []
    for result in limited_results:
        formatted_results.append({
            "success": result.success,
            "username": result.username,
            "password": result.password,
            "hash_value": result.hash_value,
            "response_time": result.response_time,
            "response_data": result.response_data[:500] if result.response_data else None,
            "error_message": result.error_message,
            "timestamp": result.timestamp
        })
    
    return {
        "attack_id": attack_id,
        "results": formatted_results,
        "total_results": len(results),
        "returned_count": len(formatted_results),
        "timestamp": time.time()
    }

@router.get("/statistics")
async def get_brute_force_statistics():
    """Récupère les statistiques globales de brute force"""
    engine = get_brute_engine()
    stats = engine.get_statistics()
    
    return {
        "statistics": stats,
        "timestamp": time.time()
    }

@router.post("/wordlists/generate")
async def generate_wordlist(request: WordlistGenerationRequest):
    """Génère une wordlist personnalisée"""
    try:
        generator = get_wordlist_generator()
        
        if request.generation_type == "common":
            wordlist = generator.generate_common_passwords(request.limit)
        
        elif request.generation_type == "targeted":
            if not request.target_info:
                raise HTTPException(status_code=400, detail="target_info required for targeted generation")
            wordlist = generator.generate_targeted_passwords(request.target_info, request.limit)
        
        elif request.generation_type == "smart":
            config = WordlistConfig(**(request.config or {}))
            if request.custom_words:
                config.custom_words = request.custom_words
            wordlist = generator.generate_smart_wordlist(request.target_info or {}, config)
        
        elif request.generation_type == "rule_based":
            if not request.custom_words:
                raise HTTPException(status_code=400, detail="custom_words required for rule_based generation")
            config = WordlistConfig(**(request.config or {}))
            wordlist = generator.generate_rule_based_passwords(request.custom_words, config)
        
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported generation type: {request.generation_type}")
        
        return {
            "generation_type": request.generation_type,
            "wordlist": wordlist,
            "count": len(wordlist),
            "timestamp": time.time()
        }
        
    except Exception as e:
        logging.error(f"Wordlist generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/wordlists")
async def list_available_wordlists():
    """Liste les wordlists disponibles"""
    generator = get_wordlist_generator()
    wordlists = generator.get_available_wordlists()
    
    return {
        "wordlists": wordlists,
        "total_count": len(wordlists),
        "timestamp": time.time()
    }

@router.get("/wordlists/{filename}")
async def get_wordlist_content(filename: str, limit: Optional[int] = 1000):
    """Récupère le contenu d'une wordlist"""
    generator = get_wordlist_generator()
    words = generator.load_wordlist_from_file(filename)
    
    if not words:
        raise HTTPException(status_code=404, detail="Wordlist not found or empty")
    
    limited_words = words[:limit] if limit else words
    
    return {
        "filename": filename,
        "words": limited_words,
        "total_count": len(words),
        "returned_count": len(limited_words),
        "timestamp": time.time()
    }

@router.post("/wordlists/{filename}")
async def save_custom_wordlist(filename: str, wordlist: List[str]):
    """Sauvegarde une wordlist personnalisée"""
    generator = get_wordlist_generator()
    success = generator.save_wordlist_to_file(wordlist, filename)
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save wordlist")
    
    return {
        "status": "saved",
        "filename": filename,
        "word_count": len(wordlist),
        "timestamp": time.time()
    }

@router.post("/hash/crack")
async def crack_hash(request: HashCrackRequest, background_tasks: BackgroundTasks):
    """Démarre un crackage de hash"""
    try:
        engine = get_brute_engine()
        generator = get_wordlist_generator()
        
        # Préparer la wordlist
        if request.custom_wordlist:
            password_list = request.custom_wordlist
        elif request.wordlist_name:
            password_list = generator.load_wordlist_from_file(request.wordlist_name)
            if not password_list:
                raise HTTPException(status_code=404, detail="Wordlist not found")
        else:
            # Utiliser wordlist commune par défaut
            password_list = generator.generate_common_passwords(request.max_attempts)
        
        # Limiter le nombre de tentatives
        password_list = password_list[:request.max_attempts]
        
        # Créer la cible de hash
        try:
            hash_type = BruteForceType(f"hash_{request.hash_type.lower()}")
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unsupported hash type: {request.hash_type}")
        
        target = BruteForceTarget(
            target_type=hash_type,
            host="localhost",  # Pas utilisé pour les hash
            hash_target=request.hash_value,
            password_list=password_list,
            stealth_level=request.stealth_level,
            max_threads=1,  # Hash cracking séquentiel pour simplicité
            delay_min=0.001,
            delay_max=0.01,
            stop_on_success=True
        )
        
        # Générer ID et démarrer
        attack_id = str(uuid.uuid4())
        await engine.start_brute_force(target, attack_id)
        
        return {
            "status": "started",
            "attack_id": attack_id,
            "hash_type": request.hash_type,
            "hash_value": request.hash_value[:10] + "..." if len(request.hash_value) > 10 else request.hash_value,
            "wordlist_size": len(password_list),
            "timestamp": time.time()
        }
        
    except Exception as e:
        logging.error(f"Hash cracking failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/cleanup")
async def cleanup_old_attacks(max_age_hours: int = 24):
    """Nettoie les attaques anciennes terminées"""
    engine = get_brute_engine()
    removed_count = engine.cleanup_completed_attacks(max_age_hours)
    
    return {
        "status": "cleaned",
        "removed_attacks": removed_count,
        "max_age_hours": max_age_hours,
        "timestamp": time.time()
    }

@router.get("/profiles")
async def get_brute_force_profiles():
    """Retourne les profils prédéfinis de brute force"""
    profiles = {
        "quick_network": {
            "name": "Quick Network Scan",
            "description": "Fast network service brute force",
            "config": {
                "stealth_level": 3,
                "max_threads": 20,
                "delay_min": 0.05,
                "delay_max": 0.5,
                "timeout": 5,
                "stop_on_success": True
            },
            "suitable_for": ["ssh", "ftp", "telnet", "http_basic"]
        },
        "stealth_network": {
            "name": "Stealth Network Scan",
            "description": "Slow and stealthy network brute force",
            "config": {
                "stealth_level": 9,
                "max_threads": 2,
                "delay_min": 2.0,
                "delay_max": 10.0,
                "timeout": 30,
                "stop_on_success": True
            },
            "suitable_for": ["ssh", "ftp", "http_basic", "http_form"]
        },
        "hash_cracking": {
            "name": "Hash Cracking",
            "description": "Optimized for hash cracking",
            "config": {
                "stealth_level": 1,
                "max_threads": 1,
                "delay_min": 0.001,
                "delay_max": 0.01,
                "timeout": 1,
                "stop_on_success": True
            },
            "suitable_for": ["hash_md5", "hash_sha1", "hash_sha256", "hash_ntlm"]
        },
        "web_application": {
            "name": "Web Application",
            "description": "Optimized for web form brute force",
            "config": {
                "stealth_level": 6,
                "max_threads": 5,
                "delay_min": 1.0,
                "delay_max": 3.0,
                "timeout": 15,
                "stop_on_success": True
            },
            "suitable_for": ["http_form", "http_basic"]
        }
    }
    
    return {
        "profiles": profiles,
        "total_profiles": len(profiles),
        "timestamp": time.time()
    }