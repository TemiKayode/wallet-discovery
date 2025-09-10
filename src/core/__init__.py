"""
Core module for the Crypto Wallet Discovery & Analysis Toolkit.

This module contains the core functionality including the main discoverer,
data validation, database management, and technical enhancement modules.
"""

from .discoverer import EnhancedWalletDiscoverer
from .validator import DataValidator
from .database import DatabaseManager
from .stream_processor import StreamManager, BlockchainStreamProcessor, DataPipeline
from .data_lake import DataLakeManager, S3DataLake, BigQueryDataLake, LocalDataLake
from .etl_processor import ETLProcessor, DataTransformer, DataExtractor, DataLoader
from .data_quality import DataQualityValidator, ValidationResult, ValidationSeverity
from .backfill_processor import HistoricalDataProcessor, BackfillJob

__all__ = [
    'EnhancedWalletDiscoverer',
    'DataValidator', 
    'DatabaseManager',
    'StreamManager',
    'BlockchainStreamProcessor',
    'DataPipeline',
    'DataLakeManager',
    'S3DataLake',
    'BigQueryDataLake',
    'LocalDataLake',
    'ETLProcessor',
    'DataTransformer',
    'DataExtractor',
    'DataLoader',
    'DataQualityValidator',
    'ValidationResult',
    'ValidationSeverity',
    'HistoricalDataProcessor',
    'BackfillJob'
]
