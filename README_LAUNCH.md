# 🛡️ CyberSec Assistant - Guide de Lancement

## Scripts de Lancement Disponibles

L'ancien script `start-portable.py` a été remplacé par de nouveaux scripts plus robustes :

### 1. Script Python Principal : `launch.py`
**Script principal recommandé avec gestion avancée des erreurs**

```bash
cd /app
python3 launch.py
```

**Fonctionnalités :**
- ✅ Vérifications système complètes
- ✅ Installation automatique des dépendances
- ✅ Gestion robuste des processus
- ✅ Logs détaillés dans `/app/logs/`
- ✅ Nettoyage automatique en cas d'arrêt
- ✅ Détection automatique de Node.js/Yarn

### 2. Script Bash Alternatif : `launch.sh`
**Alternative simple en bash**

```bash
cd /app
./launch.sh
```

**Fonctionnalités :**
- ✅ Lancement rapide et simple
- ✅ Gestion des signaux d'arrêt
- ✅ Logs séparés pour debug
- ✅ Compatible avec les systèmes sans Python complexe

## 🚀 Lancement Rapide

Pour lancer l'application immédiatement :

```bash
cd /app
python3 launch.py
```

L'application sera disponible sur :
- **Backend API** : http://localhost:8001
- **Frontend UI** : http://localhost:3000

## 📝 Logs et Debug

Les logs sont automatiquement sauvegardés dans `/app/logs/` :

- `backend_stdout.log` - Sortie standard du backend
- `backend_stderr.log` - Erreurs du backend  
- `frontend_stdout.log` - Sortie standard du frontend
- `frontend_stderr.log` - Erreurs du frontend

Pour surveiller les logs en temps réel :
```bash
tail -f /app/logs/backend_stdout.log
tail -f /app/logs/frontend_stdout.log
```

## 🛑 Arrêt de l'Application

- **Méthode recommandée** : `Ctrl+C` dans le terminal où le script tourne
- **Méthode alternative** : `pkill -f launch.py`

## ⚠️ Résolution de Problèmes

### Backend ne démarre pas
1. Vérifier les logs : `cat /app/logs/backend_stderr.log`
2. Vérifier que le port 8001 est libre : `lsof -i :8001`
3. Réinstaller les dépendances : `cd /app/backend && pip install -r requirements.txt`

### Frontend ne démarre pas
1. Vérifier Node.js : `node --version`
2. Vérifier les logs : `cat /app/logs/frontend_stderr.log`
3. Réinstaller les dépendances : `cd /app/frontend && yarn install`

### Problèmes de ports
Si les ports sont déjà utilisés, modifier les ports dans `launch.py` :
```python
self.backend_port = 8002  # Au lieu de 8001
self.frontend_port = 3001  # Au lieu de 3000
```

## 🔧 Configuration Avancée

Pour personnaliser le lancement, modifier les variables dans `launch.py` :

```python
# Configuration des ports
self.backend_port = 8001
self.frontend_port = 3000
self.backend_host = "127.0.0.1"
```

## 📋 Vérification de Santé

Test rapide pour vérifier que l'application fonctionne :

```bash
# Test backend
curl http://localhost:8001/api/health

# Test frontend
curl -I http://localhost:3000
```

## 🎯 Différences avec l'Ancien Script

| Fonctionnalité | Ancien `start-portable.py` | Nouveau `launch.py` |
|----------------|---------------------------|-------------------|
| Gestion des processus | ❌ Problématique | ✅ Robuste |
| Timeout backend | ❌ Frequent | ✅ Résolu |
| Logs détaillés | ❌ Limités | ✅ Complets |
| Nettoyage automatique | ❌ Incomplet | ✅ Complet |
| Gestion d'erreurs | ❌ Basique | ✅ Avancée |

---

**✅ Le problème "Backend failed to start within timeout" est maintenant résolu !**