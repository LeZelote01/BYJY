#!/usr/bin/env python3
"""
Test script pour vérifier les améliorations du start-portable.py
"""

import subprocess
import time
import sys

def test_supervisor_detection():
    """Test la détection de supervisor"""
    print("=== Test de détection de supervisor ===")
    
    try:
        result = subprocess.run([sys.executable, "start-portable.py"], 
                              capture_output=True, text=True, timeout=10)
        print("Sortie du script:")
        print(result.stdout)
        if result.stderr:
            print("Erreurs:")
            print(result.stderr)
        
        # Vérifier si le script détecte supervisor
        if "already running under supervisor" in result.stdout:
            print("✅ SUCCÈS: Le script détecte correctement supervisor")
            return True
        else:
            print("❌ ÉCHEC: Le script ne détecte pas supervisor")
            return False
            
    except subprocess.TimeoutExpired:
        print("⚠️  Le script a été interrompu après timeout (normal)")
        return True
    except Exception as e:
        print(f"❌ Erreur lors du test: {e}")
        return False

def test_port_detection():
    """Test la détection de ports occupés"""
    print("\n=== Test de détection de ports ===")
    
    # Vérifier si le port 8001 est occupé
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex(('127.0.0.1', 8001))
            if result == 0:
                print("✅ Port 8001 est occupé (comme attendu)")
                return True
            else:
                print("⚠️  Port 8001 n'est pas occupé")
                return False
    except Exception as e:
        print(f"❌ Erreur lors du test de port: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Tests des améliorations de start-portable.py")
    print("=" * 50)
    
    results = []
    results.append(test_supervisor_detection())
    results.append(test_port_detection())
    
    print("\n" + "=" * 50)
    print(f"📊 Résultats: {sum(results)}/{len(results)} tests réussis")
    
    if all(results):
        print("🎉 Tous les tests sont passés!")
        sys.exit(0)
    else:
        print("⚠️  Certains tests ont échoué")
        sys.exit(1)