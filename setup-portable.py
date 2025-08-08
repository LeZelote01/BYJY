#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Configuration Setup
Ensures portable configuration for localhost use
"""

import os
from pathlib import Path

def setup_portable_config():
    """Setup portable configuration for local use"""
    
    script_dir = Path(__file__).parent.absolute()
    frontend_env = script_dir / "frontend" / ".env"
    
    # Ensure frontend uses localhost configuration
    env_content = """REACT_APP_BACKEND_URL=http://localhost:8001
WDS_SOCKET_PORT=443
"""
    
    print("🔧 Configuring portable environment...")
    
    # Write frontend .env file
    with open(frontend_env, 'w') as f:
        f.write(env_content)
    
    print("✅ Portable configuration complete")
    print("   - Frontend configured for localhost:8001")
    print("   - Ready for portable deployment")

if __name__ == "__main__":
    setup_portable_config()