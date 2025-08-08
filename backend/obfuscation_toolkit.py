#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Advanced Obfuscation Toolkit V1.0
Suite complète d'obfuscation et de masquage pour l'évasion
Features: Code Obfuscation, String Encryption, Binary Packing, Anti-Detection
"""

import os
import sys
import ast
import base64
import random
import string
import zlib
import hashlib
import marshal
import types
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Callable
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import keyword

logger = logging.getLogger(__name__)

class AdvancedObfuscator:
    """
    Système d'obfuscation avancé pour scripts et données
    """
    
    def __init__(self, obfuscation_level: int = 10):
        self.obfuscation_level = obfuscation_level  # 1-10, 10 = maximum
        self.variable_mapping = {}  # Mapping des variables obfusquées
        self.function_mapping = {}  # Mapping des fonctions obfusquées
        self.string_mapping = {}   # Mapping des chaînes obfusquées
        
        # Générateurs de noms obfusqués
        self.name_generators = [
            self._generate_misleading_name,
            self._generate_random_name,
            self._generate_hex_name,
            self._generate_unicode_name
        ]
        
        logger.info(f"✅ Advanced Obfuscator initialized (level {obfuscation_level})")
    
    def obfuscate_python_code(self, source_code: str) -> str:
        """Obfusquer du code Python"""
        try:
            # Parser le code en AST
            tree = ast.parse(source_code)
            
            # Appliquer les transformations d'obfuscation
            if self.obfuscation_level >= 3:
                tree = self._rename_identifiers(tree)
            
            if self.obfuscation_level >= 5:
                tree = self._obfuscate_strings(tree)
                tree = self._add_dead_code(tree)
            
            if self.obfuscation_level >= 7:
                tree = self._transform_control_flow(tree)
                tree = self._add_anti_debug(tree)
            
            if self.obfuscation_level >= 9:
                tree = self._advanced_transformations(tree)
            
            # Reconvertir en code
            import astor
            obfuscated_code = astor.to_source(tree)
            
            if self.obfuscation_level >= 8:
                # Chiffrement final du code
                obfuscated_code = self._encrypt_and_wrap_code(obfuscated_code)
            
            logger.info("✅ Python code obfuscated successfully")
            return obfuscated_code
            
        except Exception as e:
            logger.error(f"❌ Code obfuscation failed: {e}")
            return source_code  # Retourner le code original en cas d'erreur
    
    def _rename_identifiers(self, tree: ast.AST) -> ast.AST:
        """Renommer tous les identifiants (variables, fonctions)"""
        class IdentifierRenamer(ast.NodeTransformer):
            def __init__(self, obfuscator):
                self.obfuscator = obfuscator
                self.scope_stack = [{}]  # Stack des scopes
            
            def visit_FunctionDef(self, node):
                # Renommer la fonction
                if node.name not in keyword.kwlist:
                    new_name = self.obfuscator._generate_obfuscated_name(node.name, "function")
                    self.obfuscator.function_mapping[node.name] = new_name
                    node.name = new_name
                
                # Renommer les arguments
                for arg in node.args.args:
                    if arg.arg not in keyword.kwlist:
                        new_name = self.obfuscator._generate_obfuscated_name(arg.arg, "variable")
                        self.obfuscator.variable_mapping[arg.arg] = new_name
                        arg.arg = new_name
                
                self.generic_visit(node)
                return node
            
            def visit_Name(self, node):
                # Renommer les variables
                if isinstance(node.ctx, ast.Store) and node.id not in keyword.kwlist:
                    if node.id not in self.obfuscator.variable_mapping:
                        new_name = self.obfuscator._generate_obfuscated_name(node.id, "variable")
                        self.obfuscator.variable_mapping[node.id] = new_name
                    node.id = self.obfuscator.variable_mapping[node.id]
                elif isinstance(node.ctx, ast.Load) and node.id in self.obfuscator.variable_mapping:
                    node.id = self.obfuscator.variable_mapping[node.id]
                
                return node
        
        transformer = IdentifierRenamer(self)
        return transformer.visit(tree)
    
    def _obfuscate_strings(self, tree: ast.AST) -> ast.AST:
        """Obfusquer toutes les chaînes de caractères"""
        class StringObfuscator(ast.NodeTransformer):
            def __init__(self, obfuscator):
                self.obfuscator = obfuscator
            
            def visit_Str(self, node):
                if len(node.s) > 2:  # Obfusquer seulement les chaînes significatives
                    encrypted = self.obfuscator._encrypt_string(node.s)
                    
                    # Créer un appel de fonction pour décrypter
                    decrypt_call = ast.Call(
                        func=ast.Name(id='_decrypt_str', ctx=ast.Load()),
                        args=[ast.Str(s=encrypted)],
                        keywords=[]
                    )
                    return decrypt_call
                return node
        
        # Ajouter la fonction de décryptage au début du code
        decrypt_func = self._create_decrypt_function()
        if isinstance(tree, ast.Module):
            tree.body.insert(0, decrypt_func)
        
        transformer = StringObfuscator(self)
        return transformer.visit(tree)
    
    def _add_dead_code(self, tree: ast.AST) -> ast.AST:
        """Ajouter du code mort pour confusion"""
        class DeadCodeInjector(ast.NodeTransformer):
            def __init__(self, obfuscator):
                self.obfuscator = obfuscator
            
            def visit_Module(self, node):
                new_body = []
                
                for stmt in node.body:
                    new_body.append(stmt)
                    
                    # Ajouter du code mort aléatoirement
                    if random.random() < 0.3:  # 30% de chance
                        dead_code = self.obfuscator._generate_dead_code()
                        new_body.extend(dead_code)
                
                node.body = new_body
                return node
        
        transformer = DeadCodeInjector(self)
        return transformer.visit(tree)
    
    def _transform_control_flow(self, tree: ast.AST) -> ast.AST:
        """Transformer le flux de contrôle (if/while/for)"""
        class ControlFlowTransformer(ast.NodeTransformer):
            def visit_If(self, node):
                # Transformer if simple en if imbriqué avec confusion
                if random.random() < 0.4:  # 40% de chance
                    # Créer une condition toujours vraie mais complexe
                    always_true = ast.Compare(
                        left=ast.Num(n=1),
                        ops=[ast.Eq()],
                        comparators=[ast.Num(n=1)]
                    )
                    
                    # Imbriquer la condition originale
                    nested_if = ast.If(
                        test=node.test,
                        body=node.body,
                        orelse=node.orelse
                    )
                    
                    node.test = always_true
                    node.body = [nested_if]
                    node.orelse = []
                
                self.generic_visit(node)
                return node
        
        transformer = ControlFlowTransformer()
        return transformer.visit(tree)
    
    def _add_anti_debug(self, tree: ast.AST) -> ast.AST:
        """Ajouter des techniques anti-debug"""
        anti_debug_code = '''
import sys
import os
import time

def _check_debugger():
    """Vérifier la présence d'un debugger"""
    if hasattr(sys, 'gettrace') and sys.gettrace():
        os._exit(1)
    
    # Vérifier les variables d'environnement suspectes
    debug_vars = ['PYTHONBREAKPOINT', 'PDBDEBUG', 'PYDEVD']
    for var in debug_vars:
        if os.environ.get(var):
            os._exit(1)
    
    # Timing check (détection de breakpoints)
    start = time.time()
    time.sleep(0.01)
    if time.time() - start > 0.1:
        os._exit(1)

# Appeler la vérification
_check_debugger()
'''
        
        # Parser et ajouter le code anti-debug
        anti_debug_ast = ast.parse(anti_debug_code)
        if isinstance(tree, ast.Module):
            tree.body = anti_debug_ast.body + tree.body
        
        return tree
    
    def _advanced_transformations(self, tree: ast.AST) -> ast.AST:
        """Transformations avancées (niveau 9-10)"""
        # Transformation des opérateurs
        class OperatorTransformer(ast.NodeTransformer):
            def visit_BinOp(self, node):
                # Transformer les opérations simples en fonctions
                if isinstance(node.op, ast.Add):
                    return ast.Call(
                        func=ast.Name(id='_add_op', ctx=ast.Load()),
                        args=[node.left, node.right],
                        keywords=[]
                    )
                return node
        
        # Ajouter les fonctions d'opérateurs
        operator_funcs = '''
def _add_op(a, b):
    return a + b

def _sub_op(a, b):
    return a - b
'''
        operator_ast = ast.parse(operator_funcs)
        if isinstance(tree, ast.Module):
            tree.body = operator_ast.body + tree.body
        
        transformer = OperatorTransformer()
        return transformer.visit(tree)
    
    def _generate_obfuscated_name(self, original: str, name_type: str) -> str:
        """Générer un nom obfusqué"""
        generator = random.choice(self.name_generators)
        return generator(original, name_type)
    
    def _generate_misleading_name(self, original: str, name_type: str) -> str:
        """Générer un nom trompeur mais crédible"""
        misleading_prefixes = {
            "variable": ["config", "data", "value", "temp", "buffer", "cache"],
            "function": ["process", "handle", "execute", "validate", "parse", "format"]
        }
        
        prefixes = misleading_prefixes.get(name_type, ["item"])
        prefix = random.choice(prefixes)
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
        
        return f"{prefix}_{suffix}"
    
    def _generate_random_name(self, original: str, name_type: str) -> str:
        """Générer un nom complètement aléatoire"""
        length = random.randint(6, 12)
        return ''.join(random.choices(string.ascii_letters, k=length))
    
    def _generate_hex_name(self, original: str, name_type: str) -> str:
        """Générer un nom basé sur le hash hex"""
        hash_obj = hashlib.md5(original.encode())
        hex_hash = hash_obj.hexdigest()[:8]
        return f"_{hex_hash}"
    
    def _generate_unicode_name(self, original: str, name_type: str) -> str:
        """Générer un nom avec des caractères Unicode similaires"""
        # Utiliser des caractères Unicode qui ressemblent aux ASCII
        unicode_map = {
            'a': 'а', 'e': 'е', 'o': 'о', 'p': 'р', 'c': 'с',
            'x': 'х', 'y': 'у', 'B': 'В', 'H': 'Н', 'K': 'К'
        }
        
        result = ""
        for char in original[:6]:  # Limiter la longueur
            result += unicode_map.get(char, char)
        
        return result + ''.join(random.choices(string.ascii_lowercase, k=3))
    
    def _encrypt_string(self, text: str) -> str:
        """Chiffrer une chaîne de caractères"""
        if self.obfuscation_level >= 8:
            # Chiffrement AES avec Fernet
            key = Fernet.generate_key()
            f = Fernet(key)
            encrypted = f.encrypt(text.encode())
            # Stocker la clé avec le texte chiffré (pas sécure mais fonctionnel pour l'obfuscation)
            combined = key + b"||" + encrypted
            return base64.b64encode(combined).decode()
        
        elif self.obfuscation_level >= 5:
            # XOR avec clé fixe
            key = 0x42  # Clé simple pour l'exemple
            encrypted = ''.join(chr(ord(c) ^ key) for c in text)
            return base64.b64encode(encrypted.encode()).decode()
        
        else:
            # Base64 simple
            return base64.b64encode(text.encode()).decode()
    
    def _create_decrypt_function(self) -> ast.FunctionDef:
        """Créer la fonction de décryptage pour les chaînes"""
        decrypt_code = '''
def _decrypt_str(encrypted_text):
    import base64
    from cryptography.fernet import Fernet
    
    try:
        # Décryptage AES
        decoded = base64.b64decode(encrypted_text.encode())
        if b"||" in decoded:
            key, encrypted = decoded.split(b"||", 1)
            f = Fernet(key)
            return f.decrypt(encrypted).decode()
    except:
        pass
    
    try:
        # Décryptage XOR
        decoded = base64.b64decode(encrypted_text.encode()).decode()
        return ''.join(chr(ord(c) ^ 0x42) for c in decoded)
    except:
        pass
    
    try:
        # Base64 simple
        return base64.b64decode(encrypted_text.encode()).decode()
    except:
        return encrypted_text
'''
        
        return ast.parse(decrypt_code).body[0]
    
    def _generate_dead_code(self) -> List[ast.stmt]:
        """Générer du code mort crédible"""
        dead_code_templates = [
            # Variables inutiles
            "temp_var = random.randint(1, 100)",
            "dummy_list = [i for i in range(10)]",
            "config_value = 'placeholder'",
            
            # Fonctions inutiles
            """
def dummy_function():
    x = 1 + 1
    return x * 2
""",
            
            # Boucles inutiles
            """
for i in range(5):
    temp = i * 2
    if temp > 10:
        break
""",
            
            # Conditions inutiles
            """
if True:
    dummy_var = 'test'
else:
    dummy_var = 'other'
"""
        ]
        
        selected = random.choice(dead_code_templates)
        return ast.parse(selected).body
    
    def _encrypt_and_wrap_code(self, code: str) -> str:
        """Chiffrer et encapsuler le code final"""
        # Compresser le code
        compressed = zlib.compress(code.encode())
        
        # Chiffrer
        key = Fernet.generate_key()
        f = Fernet(key)
        encrypted = f.encrypt(compressed)
        
        # Créer le wrapper de déchiffrement
        wrapper_template = f'''
import base64
import zlib
from cryptography.fernet import Fernet

# Code chiffré et compressé
_encrypted_code = {base64.b64encode(encrypted).decode()!r}
_key = {base64.b64encode(key).decode()!r}

def _execute_encrypted():
    try:
        key = base64.b64decode(_key.encode())
        encrypted_data = base64.b64decode(_encrypted_code.encode())
        
        f = Fernet(key)
        compressed_code = f.decrypt(encrypted_data)
        original_code = zlib.decompress(compressed_code).decode()
        
        exec(original_code, globals())
    except Exception as e:
        print(f"Execution error: {{e}}")
        exit(1)

if __name__ == "__main__":
    _execute_encrypted()
'''
        
        return wrapper_template
    
    def obfuscate_script_file(self, input_file: str, output_file: str = None) -> str:
        """Obfusquer un fichier script Python"""
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        if not output_file:
            output_file = input_path.with_suffix('.obfuscated.py')
        
        # Lire le code source
        with open(input_path, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        # Obfusquer
        obfuscated_code = self.obfuscate_python_code(source_code)
        
        # Sauvegarder
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(obfuscated_code)
        
        logger.info(f"✅ Script obfuscated: {input_file} -> {output_file}")
        return str(output_file)
    
    def create_packed_executable(self, script_file: str, output_file: str = None) -> str:
        """Créer un exécutable packed à partir d'un script"""
        try:
            import PyInstaller.__main__
            
            script_path = Path(script_file)
            if not output_file:
                output_file = script_path.with_suffix('.exe')
            
            # Obfusquer d'abord le script
            obfuscated_script = self.obfuscate_script_file(script_file)
            
            # Arguments PyInstaller pour maximum stealth
            pyinstaller_args = [
                '--onefile',
                '--noconsole',
                '--clean',
                '--strip',
                f'--distpath={script_path.parent}',
                f'--name={output_file.stem}',
                '--add-data', f'{obfuscated_script};.',
                obfuscated_script
            ]
            
            # Exécuter PyInstaller
            PyInstaller.__main__.run(pyinstaller_args)
            
            logger.info(f"✅ Packed executable created: {output_file}")
            return str(output_file)
            
        except ImportError:
            logger.error("❌ PyInstaller not available for packing")
            return script_file
        except Exception as e:
            logger.error(f"❌ Packing failed: {e}")
            return script_file
    
    def get_obfuscation_stats(self) -> Dict[str, Any]:
        """Obtenir les statistiques d'obfuscation"""
        return {
            "obfuscation_level": self.obfuscation_level,
            "variables_renamed": len(self.variable_mapping),
            "functions_renamed": len(self.function_mapping), 
            "strings_encrypted": len(self.string_mapping),
            "techniques_applied": self._get_applied_techniques(),
            "estimated_detection_reduction": f"{self.obfuscation_level * 10}%"
        }
    
    def _get_applied_techniques(self) -> List[str]:
        """Obtenir la liste des techniques appliquées"""
        techniques = []
        
        if self.obfuscation_level >= 3:
            techniques.append("Identifier renaming")
        
        if self.obfuscation_level >= 5:
            techniques.extend(["String encryption", "Dead code injection"])
        
        if self.obfuscation_level >= 7:
            techniques.extend(["Control flow transformation", "Anti-debug"])
        
        if self.obfuscation_level >= 8:
            techniques.extend(["Code encryption", "Compression"])
        
        if self.obfuscation_level >= 9:
            techniques.extend(["Advanced transformations", "Operator obfuscation"])
        
        return techniques

# Utility functions
def obfuscate_python_file(input_file: str, output_file: str = None, level: int = 8) -> str:
    """Fonction helper pour obfusquer un fichier Python"""
    obfuscator = AdvancedObfuscator(level)
    return obfuscator.obfuscate_script_file(input_file, output_file)

def create_stealth_executable(script_file: str, output_file: str = None, level: int = 9) -> str:
    """Fonction helper pour créer un exécutable furtif"""
    obfuscator = AdvancedObfuscator(level)
    return obfuscator.create_packed_executable(script_file, output_file)

def quick_string_obfuscation(text: str, level: int = 5) -> str:
    """Obfuscation rapide d'une chaîne"""
    obfuscator = AdvancedObfuscator(level)
    return obfuscator._encrypt_string(text)

# Factory function
def get_obfuscator(level: int = 8) -> AdvancedObfuscator:
    """Obtenir une instance de l'obfuscateur"""
    return AdvancedObfuscator(level)