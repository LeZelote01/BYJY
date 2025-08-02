#!/usr/bin/env python3
"""
CyberSec Assistant Portable - Path Utils
Utilities for dynamic path resolution to ensure portability
"""

import os
from pathlib import Path
from typing import Union


def get_project_root() -> Path:
    """
    Get the root directory of the BYJY project dynamically.
    
    This function works regardless of where the project is moved
    by finding the parent directory that contains both 'backend' and 'data' folders.
    
    Returns:
        Path: The absolute path to the project root directory
    """
    # Start from the current file's directory
    current_dir = Path(__file__).resolve().parent
    
    # Go up the directory tree to find the project root
    # Look for the directory that contains both 'backend' and 'data' folders
    while current_dir != current_dir.parent:  # Stop at filesystem root
        if (current_dir / 'backend').exists() and (current_dir / 'data').exists():
            return current_dir
        current_dir = current_dir.parent
    
    # Fallback: assume we're in backend/ and parent is project root
    backend_dir = Path(__file__).resolve().parent
    project_root = backend_dir.parent
    
    # Ensure data directory exists
    data_dir = project_root / 'data'
    data_dir.mkdir(exist_ok=True)
    
    return project_root


def get_data_dir() -> Path:
    """
    Get the data directory path dynamically.
    
    Returns:
        Path: The absolute path to the data directory
    """
    data_dir = get_project_root() / 'data'
    data_dir.mkdir(exist_ok=True)
    return data_dir


def get_backend_dir() -> Path:
    """
    Get the backend directory path dynamically.
    
    Returns:
        Path: The absolute path to the backend directory
    """
    return get_project_root() / 'backend'


def get_frontend_dir() -> Path:
    """
    Get the frontend directory path dynamically.
    
    Returns:
        Path: The absolute path to the frontend directory
    """
    return get_project_root() / 'frontend'


def get_logs_dir() -> Path:
    """
    Get the logs directory path dynamically.
    
    Returns:
        Path: The absolute path to the logs directory
    """
    logs_dir = get_project_root() / 'logs'
    logs_dir.mkdir(exist_ok=True)
    return logs_dir


def get_database_path() -> str:
    """
    Get the default database path dynamically.
    
    Returns:
        str: The absolute path to the cybersec.db database file
    """
    return str(get_data_dir() / 'cybersec.db')


def resolve_path(relative_path: Union[str, Path], base_dir: str = None) -> Path:
    """
    Resolve a relative path to an absolute path based on project structure.
    
    Args:
        relative_path: The relative path to resolve
        base_dir: Base directory ('data', 'backend', 'frontend', 'logs', or None for project root)
    
    Returns:
        Path: The resolved absolute path
    """
    project_root = get_project_root()
    
    if base_dir == 'data':
        base = get_data_dir()
    elif base_dir == 'backend':
        base = get_backend_dir()
    elif base_dir == 'frontend':
        base = get_frontend_dir()
    elif base_dir == 'logs':
        base = get_logs_dir()
    else:
        base = project_root
    
    return base / relative_path


# Environment variable for database path (for compatibility)
def set_database_env_var():
    """Set the DATABASE_PATH environment variable if not already set."""
    if not os.environ.get('DATABASE_PATH'):
        os.environ['DATABASE_PATH'] = get_database_path()


# Initialize environment variable on import
set_database_env_var()


# Export commonly used functions
__all__ = [
    'get_project_root',
    'get_data_dir', 
    'get_backend_dir',
    'get_frontend_dir',
    'get_logs_dir',
    'get_database_path',
    'resolve_path'
]