#!/bin/bash
# Script de lancement alternatif pour CyberSec Assistant

echo "🛡️  CYBERSEC ASSISTANT - LANCEUR BASH"
echo "======================================"

# Variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
LOGS_DIR="$SCRIPT_DIR/logs"

# Créer le dossier logs
mkdir -p "$LOGS_DIR"

# Fonction de nettoyage
cleanup() {
    echo ""
    echo "🛑 Arrêt de l'application..."
    
    # Tuer les processus backend et frontend
    pkill -f "python.*server.py" 2>/dev/null
    pkill -f "yarn start" 2>/dev/null
    pkill -f "npm start" 2>/dev/null
    
    echo "✅ Nettoyage terminé"
    exit 0
}

# Gestionnaire de signal
trap cleanup SIGINT SIGTERM

# Nettoyage initial
echo "🧹 Nettoyage initial..."
cleanup > /dev/null 2>&1
sleep 2

# Vérification Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 n'est pas installé"
    exit 1
fi
echo "✅ Python3 trouvé: $(python3 --version)"

# Vérification Node.js
NODE_AVAILABLE=false
if command -v node &> /dev/null; then
    echo "✅ Node.js trouvé: $(node --version)"
    NODE_AVAILABLE=true
else
    echo "⚠️  Node.js non trouvé, seul le backend sera lancé"
fi

# Installation des dépendances backend
echo "📦 Installation des dépendances backend..."
cd "$BACKEND_DIR"
python3 -m pip install -r requirements.txt > "$LOGS_DIR/pip_install.log" 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Dépendances backend installées"
else
    echo "❌ Erreur lors de l'installation des dépendances backend"
    exit 1
fi

# Installation des dépendances frontend si Node.js disponible
if [ "$NODE_AVAILABLE" = true ] && [ -f "$FRONTEND_DIR/package.json" ]; then
    echo "📦 Installation des dépendances frontend..."
    cd "$FRONTEND_DIR"
    
    if command -v yarn &> /dev/null; then
        yarn install > "$LOGS_DIR/yarn_install.log" 2>&1
    else
        npm install > "$LOGS_DIR/npm_install.log" 2>&1
    fi
    
    if [ $? -eq 0 ]; then
        echo "✅ Dépendances frontend installées"
    else
        echo "⚠️  Problème avec les dépendances frontend"
    fi
fi

# Lancement du backend
echo "🚀 Lancement du backend..."
cd "$BACKEND_DIR"
export PYTHONPATH="$BACKEND_DIR"
export PORT=8001
export HOST=127.0.0.1

python3 server.py > "$LOGS_DIR/backend.log" 2>&1 &
BACKEND_PID=$!

# Attendre que le backend démarre
echo "⏳ Attente du démarrage du backend..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:8001/api/health > /dev/null 2>&1; then
        echo "✅ Backend démarré avec succès!"
        break
    fi
    
    # Vérifier si le processus backend est toujours en vie
    if ! kill -0 $BACKEND_PID 2>/dev/null; then
        echo "❌ Le processus backend s'est arrêté"
        exit 1
    fi
    
    echo "[$i/30] Attente..."
    sleep 1
done

# Vérifier une dernière fois le backend
if ! curl -s http://127.0.0.1:8001/api/health > /dev/null 2>&1; then
    echo "❌ Le backend ne répond pas après 30 secondes"
    exit 1
fi

# Lancement du frontend si disponible
if [ "$NODE_AVAILABLE" = true ] && [ -f "$FRONTEND_DIR/package.json" ]; then
    echo "🌐 Lancement du frontend..."
    cd "$FRONTEND_DIR"
    
    if command -v yarn &> /dev/null; then
        yarn start > "$LOGS_DIR/frontend.log" 2>&1 &
    else
        npm start > "$LOGS_DIR/frontend.log" 2>&1 &
    fi
    FRONTEND_PID=$!
    
    echo "✅ Frontend en cours de démarrage..."
fi

# Application lancée
echo ""
echo "======================================"
echo "🎉 CyberSec Assistant lancé!"
echo "📋 Backend API: http://localhost:8001"
if [ "$NODE_AVAILABLE" = true ]; then
    echo "🌐 Frontend UI: http://localhost:3000"
fi
echo "📝 Logs disponibles dans: $LOGS_DIR"
echo "⌨️  Appuyez sur Ctrl+C pour arrêter"
echo "======================================"

# Garder le script en vie
while true; do
    sleep 1
    
    # Vérifier que le backend est toujours en vie
    if ! kill -0 $BACKEND_PID 2>/dev/null; then
        echo "❌ Le backend s'est arrêté de façon inattendue"
        cleanup
        exit 1
    fi
done