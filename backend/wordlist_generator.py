#!/usr/bin/env python3
"""
Wordlist Generator - CyberSec Assistant
Générateur intelligent de dictionnaires et wordlists
"""

import os
import random
import string
import itertools
import re
from typing import List, Dict, Set, Optional, Generator
from dataclasses import dataclass
import json
import logging
from pathlib import Path

# Import path utilities for dynamic path resolution
from path_utils import get_data_dir

@dataclass
class WordlistConfig:
    """Configuration pour génération de wordlists"""
    min_length: int = 1
    max_length: int = 12
    include_numbers: bool = True
    include_symbols: bool = True
    include_uppercase: bool = True
    include_lowercase: bool = True
    common_patterns: bool = True
    year_variations: bool = True
    leet_speak: bool = True
    keyboard_patterns: bool = True
    custom_words: List[str] = None
    output_limit: int = 100000

class WordlistGenerator:
    """Générateur intelligent de wordlists pour brute force"""
    
    def __init__(self, data_dir: str = None):
        self.data_dir = Path(data_dir) if data_dir else get_data_dir()
        self.wordlists_dir = self.data_dir / "wordlists"
        self.wordlists_dir.mkdir(exist_ok=True)
        
        self.logger = logging.getLogger(__name__)
        
        # Patterns de clavier communs
        self.keyboard_patterns = [
            "qwerty", "azerty", "qwertz", "123456", "password",
            "admin", "12345", "123456789", "qwerty123", "password123"
        ]
        
        # Mots courants
        self.common_words = [
            "password", "admin", "user", "guest", "test", "root", "default",
            "login", "pass", "secret", "master", "shadow", "welcome", "letmein",
            "monkey", "dragon", "computer", "system", "server", "database"
        ]
        
        # Suffixes/préfixes courants
        self.common_suffixes = [
            "123", "1234", "12345", "01", "2023", "2024", "2025",
            "!", "@", "#", "$", ".", "_", "-"
        ]
        
        self.common_prefixes = [
            "admin", "root", "user", "test", "demo", "guest"
        ]
        
        # Substitutions leet speak
        self.leet_substitutions = {
            'a': ['@', '4'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'],
            's': ['5', '$'], 't': ['7'], 'l': ['1'], 'g': ['9'],
            'b': ['6'], 'z': ['2']
        }
    
    def generate_common_passwords(self, limit: int = 10000) -> List[str]:
        """Génère une liste de mots de passe communs"""
        passwords = set()
        
        # Top passwords basiques
        basic_passwords = [
            "123456", "password", "123456789", "12345678", "12345",
            "1234567", "1234567890", "qwerty", "abc123", "111111",
            "dragon", "master", "monkey", "letmein", "login",
            "princess", "qwertyuiop", "solo", "passw0rd", "starwars"
        ]
        passwords.update(basic_passwords)
        
        # Variations avec années
        current_year = 2025
        for word in self.common_words:
            for year in range(current_year-10, current_year+1):
                passwords.add(f"{word}{year}")
                passwords.add(f"{word}{str(year)[-2:]}")
        
        # Variations avec suffixes
        for word in self.common_words:
            for suffix in self.common_suffixes:
                passwords.add(f"{word}{suffix}")
                passwords.add(f"{suffix}{word}")
        
        # Combinaisons de mots
        for word1, word2 in itertools.combinations(self.common_words[:10], 2):
            passwords.add(f"{word1}{word2}")
            passwords.add(f"{word1}_{word2}")
        
        return list(passwords)[:limit]
    
    def generate_targeted_passwords(self, target_info: Dict, limit: int = 5000) -> List[str]:
        """Génère des mots de passe ciblés basés sur les informations de la cible"""
        passwords = set()
        
        # Informations de base
        company_name = target_info.get('company', '')
        domain = target_info.get('domain', '')
        keywords = target_info.get('keywords', [])
        
        base_words = []
        if company_name:
            base_words.extend([company_name, company_name.lower(), company_name.upper()])
        if domain:
            domain_parts = domain.replace('.', '').replace('-', '').replace('_', '')
            base_words.append(domain_parts)
        base_words.extend(keywords)
        
        # Générer variations
        current_year = 2025
        for word in base_words:
            if not word:
                continue
                
            # Mot de base
            passwords.add(word)
            
            # Avec années
            for year in range(current_year-5, current_year+1):
                passwords.add(f"{word}{year}")
                passwords.add(f"{word}{str(year)[-2:]}")
            
            # Avec suffixes courants
            for suffix in ["123", "!", "@", "#", "01", "admin", "user"]:
                passwords.add(f"{word}{suffix}")
            
            # Variations de casse
            passwords.add(word.lower())
            passwords.add(word.upper())
            passwords.add(word.capitalize())
            
            # Leet speak
            if len(word) > 2:
                leet_word = self._apply_leet_speak(word)
                passwords.add(leet_word)
                passwords.add(f"{leet_word}123")
        
        return list(passwords)[:limit]
    
    def generate_rule_based_passwords(self, base_words: List[str], config: WordlistConfig) -> List[str]:
        """Génère des mots de passe basés sur des règles"""
        passwords = set()
        
        for word in base_words:
            if len(word) < config.min_length:
                continue
            
            # Mot de base
            if len(word) <= config.max_length:
                passwords.add(word)
            
            # Variations de casse
            if config.include_uppercase and config.include_lowercase:
                passwords.add(word.capitalize())
                passwords.add(word.upper())
                passwords.add(word.lower())
            
            # Ajout de chiffres
            if config.include_numbers:
                for i in range(100):
                    candidate = f"{word}{i:02d}"
                    if len(candidate) <= config.max_length:
                        passwords.add(candidate)
                
                for year in range(2020, 2026):
                    candidate = f"{word}{year}"
                    if len(candidate) <= config.max_length:
                        passwords.add(candidate)
            
            # Ajout de symboles
            if config.include_symbols:
                symbols = "!@#$%^&*()_+-=[]{}|;':\",./<>?"
                for symbol in symbols[:5]:  # Limiter pour éviter explosion
                    candidate = f"{word}{symbol}"
                    if len(candidate) <= config.max_length:
                        passwords.add(candidate)
            
            # Leet speak
            if config.leet_speak:
                leet_word = self._apply_leet_speak(word)
                if leet_word != word and len(leet_word) <= config.max_length:
                    passwords.add(leet_word)
            
            # Patterns clavier
            if config.keyboard_patterns:
                keyboard_word = self._apply_keyboard_pattern(word)
                if keyboard_word != word and len(keyboard_word) <= config.max_length:
                    passwords.add(keyboard_word)
        
        # Ajouter mots personnalisés
        if config.custom_words:
            for word in config.custom_words:
                if config.min_length <= len(word) <= config.max_length:
                    passwords.add(word)
        
        return list(passwords)[:config.output_limit]
    
    def generate_brute_force_wordlist(self, charset: str, min_len: int, max_len: int, 
                                    limit: int = 100000) -> Generator[str, None, None]:
        """Générateur pour brute force exhaustif"""
        count = 0
        
        for length in range(min_len, max_len + 1):
            if count >= limit:
                break
            
            for combination in itertools.product(charset, repeat=length):
                if count >= limit:
                    break
                yield ''.join(combination)
                count += 1
    
    def generate_hybrid_wordlist(self, base_list: List[str], config: WordlistConfig) -> List[str]:
        """Génère une wordlist hybride combinant plusieurs techniques"""
        passwords = set()
        
        # Ajouter mots de base
        passwords.update(base_list)
        
        # Générer variations règles
        rule_based = self.generate_rule_based_passwords(base_list, config)
        passwords.update(rule_based)
        
        # Ajouter patterns courants
        if config.common_patterns:
            common = self.generate_common_passwords(1000)
            passwords.update(common)
        
        # Mutations de mots existants
        mutations = self._generate_mutations(list(passwords)[:1000], config)
        passwords.update(mutations)
        
        return list(passwords)[:config.output_limit]
    
    def _apply_leet_speak(self, word: str) -> str:
        """Applique les substitutions leet speak"""
        leet_word = word.lower()
        
        for char, substitutions in self.leet_substitutions.items():
            if char in leet_word:
                # Prendre la première substitution
                leet_word = leet_word.replace(char, substitutions[0])
        
        return leet_word
    
    def _apply_keyboard_pattern(self, word: str) -> str:
        """Applique des patterns de clavier"""
        # Mapping simple de proximité clavier
        keyboard_map = {
            'q': 'w', 'w': 'e', 'e': 'r', 'r': 't', 't': 'y',
            'a': 's', 's': 'd', 'd': 'f', 'f': 'g', 'g': 'h',
            'z': 'x', 'x': 'c', 'c': 'v', 'v': 'b', 'b': 'n'
        }
        
        result = ""
        for char in word.lower():
            result += keyboard_map.get(char, char)
        
        return result
    
    def _generate_mutations(self, words: List[str], config: WordlistConfig) -> Set[str]:
        """Génère des mutations de mots existants"""
        mutations = set()
        
        for word in words:
            if len(word) > config.max_length:
                continue
            
            # Inversion
            mutations.add(word[::-1])
            
            # Doublement
            if len(word * 2) <= config.max_length:
                mutations.add(word * 2)
            
            # Suppression de caractères
            if len(word) > config.min_length:
                for i in range(len(word)):
                    mutated = word[:i] + word[i+1:]
                    if config.min_length <= len(mutated) <= config.max_length:
                        mutations.add(mutated)
            
            # Insertion de caractères
            chars_to_insert = string.ascii_lowercase + string.digits
            for i in range(len(word) + 1):
                for char in chars_to_insert[:5]:  # Limiter
                    mutated = word[:i] + char + word[i:]
                    if len(mutated) <= config.max_length:
                        mutations.add(mutated)
                        break  # Limiter les variations
        
        return mutations
    
    def load_wordlist_from_file(self, filename: str) -> List[str]:
        """Charge une wordlist depuis un fichier"""
        filepath = self.wordlists_dir / filename
        
        if not filepath.exists():
            self.logger.warning(f"Wordlist file not found: {filepath}")
            return []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                words = [line.strip() for line in f if line.strip()]
            
            self.logger.info(f"Loaded {len(words)} words from {filename}")
            return words
        
        except Exception as e:
            self.logger.error(f"Failed to load wordlist {filename}: {e}")
            return []
    
    def save_wordlist_to_file(self, wordlist: List[str], filename: str) -> bool:
        """Sauvegarde une wordlist dans un fichier"""
        filepath = self.wordlists_dir / filename
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for word in wordlist:
                    f.write(f"{word}\n")
            
            self.logger.info(f"Saved {len(wordlist)} words to {filename}")
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to save wordlist {filename}: {e}")
            return False
    
    def get_available_wordlists(self) -> List[Dict[str, any]]:
        """Retourne la liste des wordlists disponibles"""
        wordlists = []
        
        for filepath in self.wordlists_dir.glob("*.txt"):
            try:
                size = filepath.stat().st_size
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    line_count = sum(1 for line in f if line.strip())
                
                wordlists.append({
                    'filename': filepath.name,
                    'path': str(filepath),
                    'size_bytes': size,
                    'line_count': line_count,
                    'type': self._detect_wordlist_type(filepath.name)
                })
            
            except Exception as e:
                self.logger.warning(f"Error reading wordlist {filepath}: {e}")
        
        return wordlists
    
    def _detect_wordlist_type(self, filename: str) -> str:
        """Détecte le type de wordlist basé sur le nom de fichier"""
        filename_lower = filename.lower()
        
        if 'password' in filename_lower:
            return 'passwords'
        elif 'username' in filename_lower or 'user' in filename_lower:
            return 'usernames'
        elif 'common' in filename_lower:
            return 'common'
        elif 'dictionary' in filename_lower or 'dict' in filename_lower:
            return 'dictionary'
        elif any(x in filename_lower for x in ['rockyou', 'darkweb', 'leaked']):
            return 'breached'
        else:
            return 'custom'
    
    def create_default_wordlists(self):
        """Crée les wordlists par défaut si elles n'existent pas"""
        # Common passwords
        if not (self.wordlists_dir / "common_passwords.txt").exists():
            common_passwords = self.generate_common_passwords(10000)
            self.save_wordlist_to_file(common_passwords, "common_passwords.txt")
        
        # Common usernames
        if not (self.wordlists_dir / "common_usernames.txt").exists():
            common_usernames = [
                'admin', 'administrator', 'root', 'user', 'guest', 'test',
                'oracle', 'postgres', 'mysql', 'sa', 'backup', 'service',
                'demo', 'anonymous', 'ftp', 'web', 'www', 'mail', 'email',
                'support', 'manager', 'operator', 'supervisor', 'developer',
                'system', 'server', 'network', 'security', 'audit',
                'monitor', 'student', 'teacher', 'admin1', 'user1'
            ]
            self.save_wordlist_to_file(common_usernames, "common_usernames.txt")
        
        # Numeric patterns
        if not (self.wordlists_dir / "numeric_patterns.txt").exists():
            numeric_patterns = []
            
            # Years
            for year in range(1950, 2030):
                numeric_patterns.append(str(year))
            
            # Common numeric patterns
            for i in range(1, 10000):
                if i < 100:
                    numeric_patterns.append(f"{i:02d}")
                if i < 1000:
                    numeric_patterns.append(f"{i:03d}")
                if i < 10000:
                    numeric_patterns.append(f"{i:04d}")
            
            self.save_wordlist_to_file(numeric_patterns, "numeric_patterns.txt")
    
    def generate_smart_wordlist(self, target_info: Dict, config: WordlistConfig) -> List[str]:
        """Génère une wordlist intelligente basée sur le contexte"""
        all_passwords = set()
        
        # Mots de passe ciblés
        targeted = self.generate_targeted_passwords(target_info, 2000)
        all_passwords.update(targeted)
        
        # Mots de passe communs
        common = self.generate_common_passwords(3000)
        all_passwords.update(common)
        
        # Si on a des mots personnalisés, générer des variations
        if config.custom_words:
            custom_variations = self.generate_rule_based_passwords(config.custom_words, config)
            all_passwords.update(custom_variations)
        
        # Wordlists existantes
        for wordlist_info in self.get_available_wordlists():
            if wordlist_info['type'] in ['passwords', 'common']:
                existing_words = self.load_wordlist_from_file(wordlist_info['filename'])
                all_passwords.update(existing_words[:1000])  # Limiter pour performance
        
        # Filtrer selon la configuration
        filtered_passwords = []
        for password in all_passwords:
            if config.min_length <= len(password) <= config.max_length:
                filtered_passwords.append(password)
        
        return filtered_passwords[:config.output_limit]