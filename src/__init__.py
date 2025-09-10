"""
Crypto Wallet Discovery & Analysis Toolkit

A comprehensive Python toolkit for discovering, analyzing, and monitoring 
cryptocurrency wallet addresses across multiple blockchains.
"""

__version__ = "1.0.0"
__author__ = "Crypto Discovery Team"
__email__ = "support@cryptodiscovery.com"

# Import main classes for easy access
from .core.discoverer import EnhancedWalletDiscoverer
from .core.validator import DataValidator
from .core.database import DatabaseManager
from .config.settings import ConfigManager

__all__ = [
    'EnhancedWalletDiscoverer',
    'DataValidator', 
    'DatabaseManager',
    'ConfigManager'
]
