"""
ETL (Extract, Transform, Load) Processor Module

This module provides automated data transformation capabilities for blockchain data,
including data cleaning, enrichment, and structured loading into various destinations.
"""

import logging
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any, Callable, Union
from datetime import datetime, timedelta
import json
import hashlib
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio

logger = logging.getLogger(__name__)


@dataclass
class ETLJob:
    """Represents an ETL job configuration"""
    job_id: str
    name: str
    description: str
    source_type: str  # 'database', 'file', 'api', 'stream'
    source_config: Dict[str, Any]
    transformations: List[Dict[str, Any]]
    destination_type: str  # 'database', 'file', 'data_lake'
    destination_config: Dict[str, Any]
    schedule: Optional[str] = None  # cron expression
    enabled: bool = True
    created_at: datetime = None
    last_run: Optional[datetime] = None
    status: str = 'pending'  # pending, running, completed, failed
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()


class DataTransformer:
    """Handles data transformation operations"""
    
    def __init__(self):
        self.transformation_registry = self._register_transformations()
        
    def _register_transformations(self) -> Dict[str, Callable]:
        """Register all available transformations"""
        return {
            'clean_addresses': self.clean_addresses,
            'normalize_timestamps': self.normalize_timestamps,
            'calculate_balances': self.calculate_balances,
            'enrich_wallet_info': self.enrich_wallet_info,
            'aggregate_transactions': self.aggregate_transactions,
            'detect_patterns': self.detect_patterns,
            'validate_data': self.validate_data,
            'deduplicate': self.deduplicate,
            'format_output': self.format_output
        }
        
    def transform_data(self, data: pd.DataFrame, transformations: List[Dict[str, Any]]) -> pd.DataFrame:
        """Apply a series of transformations to the data"""
        result = data.copy()
        
        for transform_config in transformations:
            transform_name = transform_config['name']
            transform_params = transform_config.get('parameters', {})
            
            if transform_name in self.transformation_registry:
                try:
                    logger.info(f"Applying transformation: {transform_name}")
                    result = self.transformation_registry[transform_name](result, **transform_params)
                except Exception as e:
                    logger.error(f"Transformation {transform_name} failed: {e}")
                    continue
            else:
                logger.warning(f"Unknown transformation: {transform_name}")
                
        return result
        
    def clean_addresses(self, df: pd.DataFrame, address_columns: List[str] = None) -> pd.DataFrame:
        """Clean and validate wallet addresses"""
        if address_columns is None:
            address_columns = [col for col in df.columns if 'address' in col.lower()]
            
        for col in address_columns:
            if col in df.columns:
                # Remove whitespace and convert to lowercase
                df[col] = df[col].astype(str).str.strip().str.lower()
                
                # Remove invalid addresses (basic validation)
                df = df[df[col].str.match(r'^0x[a-fA-F0-9]{40}$|^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$')]
                
        return df
        
    def normalize_timestamps(self, df: pd.DataFrame, timestamp_columns: List[str] = None) -> pd.DataFrame:
        """Normalize timestamp columns to UTC"""
        if timestamp_columns is None:
            timestamp_columns = [col for col in df.columns if 'time' in col.lower() or 'date' in col.lower()]
            
        for col in timestamp_columns:
            if col in df.columns:
                try:
                    df[col] = pd.to_datetime(df[col], utc=True)
                except Exception as e:
                    logger.warning(f"Could not normalize timestamp column {col}: {e}")
                    
        return df
        
    def calculate_balances(self, df: pd.DataFrame, amount_column: str = 'amount', 
                          address_column: str = 'address') -> pd.DataFrame:
        """Calculate running balances for addresses"""
        if amount_column in df.columns and address_column in df.columns:
            # Sort by timestamp if available
            if 'timestamp' in df.columns:
                df = df.sort_values('timestamp')
                
            # Calculate running balance
            df['running_balance'] = df.groupby(address_column)[amount_column].cumsum()
            
        return df
        
    def enrich_wallet_info(self, df: pd.DataFrame, 
                          address_column: str = 'address') -> pd.DataFrame:
        """Enrich wallet information with additional metadata"""
        if address_column in df.columns:
            # Add address type classification
            df['address_type'] = df[address_column].apply(self._classify_address_type)
            
            # Add address length
            df['address_length'] = df[address_column].str.len()
            
            # Add checksum validation
            df['is_valid_checksum'] = df[address_column].apply(self._validate_checksum)
            
        return df
        
    def _classify_address_type(self, address: str) -> str:
        """Classify address type based on format"""
        if address.startswith('0x'):
            return 'ethereum'
        elif address.startswith('1') or address.startswith('3'):
            return 'bitcoin'
        else:
            return 'unknown'
            
    def _validate_checksum(self, address: str) -> bool:
        """Basic checksum validation"""
        try:
            if address.startswith('0x'):
                # Ethereum address validation
                return len(address) == 42 and all(c in '0123456789abcdef' for c in address[2:])
            else:
                # Bitcoin address validation (simplified)
                return len(address) >= 26 and len(address) <= 35
        except:
            return False
            
    def aggregate_transactions(self, df: pd.DataFrame, 
                             group_by: List[str] = None,
                             agg_rules: Dict[str, List[str]] = None) -> pd.DataFrame:
        """Aggregate transaction data"""
        if group_by is None:
            group_by = ['address']
            
        if agg_rules is None:
            agg_rules = {
                'amount': ['sum', 'count', 'mean'],
                'timestamp': ['min', 'max'],
                'gas_price': ['mean'],
                'gas_used': ['sum']
            }
            
        # Filter columns that exist in the dataframe
        existing_agg_rules = {}
        for col, agg_funcs in agg_rules.items():
            if col in df.columns:
                existing_agg_rules[col] = agg_funcs
                
        if existing_agg_rules:
            return df.groupby(group_by).agg(existing_agg_rules).reset_index()
        
        return df
        
    def detect_patterns(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detect transaction patterns"""
        if 'amount' in df.columns and 'address' in df.columns:
            # Detect large transactions
            df['is_large_tx'] = df['amount'] > df['amount'].quantile(0.95)
            
            # Detect frequent senders
            address_counts = df['address'].value_counts()
            df['tx_frequency'] = df['address'].map(address_counts)
            
            # Detect unusual patterns
            df['is_unusual'] = (df['is_large_tx'] & (df['tx_frequency'] == 1))
            
        return df
        
    def validate_data(self, df: pd.DataFrame, validation_rules: Dict[str, Any] = None) -> pd.DataFrame:
        """Validate data according to rules"""
        if validation_rules is None:
            validation_rules = {
                'amount': {'min': 0, 'max': 1e12},
                'gas_price': {'min': 0, 'max': 1e12},
                'gas_used': {'min': 0, 'max': 1e8}
            }
            
        for column, rules in validation_rules.items():
            if column in df.columns:
                if 'min' in rules:
                    df = df[df[column] >= rules['min']]
                if 'max' in rules:
                    df = df[df[column] <= rules['max']]
                    
        return df
        
    def deduplicate(self, df: pd.DataFrame, 
                   subset: List[str] = None, 
                   keep: str = 'first') -> pd.DataFrame:
        """Remove duplicate records"""
        if subset is None:
            subset = ['address', 'amount', 'timestamp']
            
        # Filter to columns that exist
        existing_subset = [col for col in subset if col in df.columns]
        
        if existing_subset:
            return df.drop_duplicates(subset=existing_subset, keep=keep)
        
        return df
        
    def format_output(self, df: pd.DataFrame, 
                     output_format: str = 'standard',
                     include_metadata: bool = True) -> pd.DataFrame:
        """Format output according to specifications"""
        if output_format == 'standard':
            # Ensure standard column order
            standard_columns = ['address', 'amount', 'timestamp', 'chain', 'tx_hash']
            existing_columns = [col for col in standard_columns if col in df.columns]
            other_columns = [col for col in df.columns if col not in standard_columns]
            
            if existing_columns:
                df = df[existing_columns + other_columns]
                
        if include_metadata:
            df['etl_processed_at'] = datetime.utcnow()
            df['etl_job_id'] = hashlib.md5(
                f"{datetime.utcnow()}".encode()
            ).hexdigest()[:8]
            
        return df


class DataExtractor:
    """Handles data extraction from various sources"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        
    def extract_from_database(self, config: Dict[str, Any]) -> pd.DataFrame:
        """Extract data from database"""
        try:
            db_path = config.get('database_path', 'wallet_data.db')
            query = config.get('query', 'SELECT * FROM wallets')
            
            conn = sqlite3.connect(db_path)
            df = pd.read_sql_query(query, conn)
            conn.close()
            
            logger.info(f"Extracted {len(df)} records from database")
            return df
            
        except Exception as e:
            logger.error(f"Database extraction failed: {e}")
            return pd.DataFrame()
            
    def extract_from_file(self, config: Dict[str, Any]) -> pd.DataFrame:
        """Extract data from file"""
        try:
            file_path = config.get('file_path', '')
            file_type = config.get('file_type', 'csv')
            
            if file_type == 'csv':
                df = pd.read_csv(file_path)
            elif file_type == 'json':
                df = pd.read_json(file_path)
            elif file_type == 'excel':
                df = pd.read_excel(file_path)
            else:
                logger.error(f"Unsupported file type: {file_type}")
                return pd.DataFrame()
                
            logger.info(f"Extracted {len(df)} records from file: {file_path}")
            return df
            
        except Exception as e:
            logger.error(f"File extraction failed: {e}")
            return pd.DataFrame()
            
    def extract_from_api(self, config: Dict[str, Any]) -> pd.DataFrame:
        """Extract data from API"""
        try:
            # This would integrate with the existing API infrastructure
            # For now, return empty DataFrame
            logger.info("API extraction not yet implemented")
            return pd.DataFrame()
            
        except Exception as e:
            logger.error(f"API extraction failed: {e}")
            return pd.DataFrame()


class DataLoader:
    """Handles data loading to various destinations"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        
    def load_to_database(self, df: pd.DataFrame, config: Dict[str, Any]) -> bool:
        """Load data to database"""
        try:
            db_path = config.get('database_path', 'wallet_data.db')
            table_name = config.get('table_name', 'etl_results')
            
            conn = sqlite3.connect(db_path)
            df.to_sql(table_name, conn, if_exists='replace', index=False)
            conn.close()
            
            logger.info(f"Loaded {len(df)} records to database table: {table_name}")
            return True
            
        except Exception as e:
            logger.error(f"Database loading failed: {e}")
            return False
            
    def load_to_file(self, df: pd.DataFrame, config: Dict[str, Any]) -> bool:
        """Load data to file"""
        try:
            file_path = config.get('file_path', 'etl_output.csv')
            file_type = config.get('file_type', 'csv')
            
            if file_type == 'csv':
                df.to_csv(file_path, index=False)
            elif file_type == 'json':
                df.to_json(file_path, orient='records', indent=2)
            elif file_type == 'excel':
                df.to_excel(file_path, index=False)
            else:
                logger.error(f"Unsupported output file type: {file_type}")
                return False
                
            logger.info(f"Loaded {len(df)} records to file: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"File loading failed: {e}")
            return False


class ETLProcessor:
    """Main ETL processor orchestrating the entire process"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.transformer = DataTransformer()
        self.extractor = DataExtractor(config_manager)
        self.loader = DataLoader(config_manager)
        self.jobs: Dict[str, ETLJob] = {}
        self.job_history: List[Dict[str, Any]] = []
        
    def create_job(self, job_config: Dict[str, Any]) -> str:
        """Create a new ETL job"""
        job_id = hashlib.md5(
            f"{job_config.get('name', '')}{datetime.utcnow()}".encode()
        ).hexdigest()[:8]
        
        job = ETLJob(
            job_id=job_id,
            **job_config
        )
        
        self.jobs[job_id] = job
        logger.info(f"Created ETL job: {job_id} - {job.name}")
        
        return job_id
        
    def run_job(self, job_id: str) -> bool:
        """Run a specific ETL job"""
        if job_id not in self.jobs:
            logger.error(f"Job not found: {job_id}")
            return False
            
        job = self.jobs[job_id]
        job.status = 'running'
        job.last_run = datetime.utcnow()
        
        start_time = datetime.utcnow()
        
        try:
            # Extract
            logger.info(f"Starting extraction for job: {job.name}")
            data = self._extract_data(job.source_type, job.source_config)
            
            if data.empty:
                logger.warning(f"No data extracted for job: {job.name}")
                job.status = 'failed'
                return False
                
            # Transform
            logger.info(f"Starting transformation for job: {job.name}")
            transformed_data = self.transformer.transform_data(data, job.transformations)
            
            if transformed_data.empty:
                logger.warning(f"No data after transformation for job: {job.name}")
                job.status = 'failed'
                return False
                
            # Load
            logger.info(f"Starting loading for job: {job.name}")
            load_success = self._load_data(transformed_data, job.destination_type, job.destination_config)
            
            if not load_success:
                job.status = 'failed'
                return False
                
            # Success
            job.status = 'completed'
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Record job history
            self.job_history.append({
                'job_id': job_id,
                'status': 'completed',
                'start_time': start_time,
                'end_time': datetime.utcnow(),
                'duration_seconds': duration,
                'records_processed': len(transformed_data)
            })
            
            logger.info(f"ETL job completed successfully: {job.name} in {duration:.2f}s")
            return True
            
        except Exception as e:
            job.status = 'failed'
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Record failure
            self.job_history.append({
                'job_id': job_id,
                'status': 'failed',
                'start_time': start_time,
                'end_time': datetime.utcnow(),
                'duration_seconds': duration,
                'error': str(e)
            })
            
            logger.error(f"ETL job failed: {job.name} - {e}")
            return False
            
    def _extract_data(self, source_type: str, source_config: Dict[str, Any]) -> pd.DataFrame:
        """Extract data based on source type"""
        if source_type == 'database':
            return self.extractor.extract_from_database(source_config)
        elif source_type == 'file':
            return self.extractor.extract_from_file(source_config)
        elif source_type == 'api':
            return self.extractor.extract_from_api(source_config)
        else:
            logger.error(f"Unknown source type: {source_type}")
            return pd.DataFrame()
            
    def _load_data(self, data: pd.DataFrame, destination_type: str, 
                   destination_config: Dict[str, Any]) -> bool:
        """Load data based on destination type"""
        if destination_type == 'database':
            return self.loader.load_to_database(data, destination_config)
        elif destination_type == 'file':
            return self.loader.load_to_file(data, destination_config)
        else:
            logger.error(f"Unknown destination type: {destination_type}")
            return False
            
    def run_all_jobs(self) -> Dict[str, bool]:
        """Run all enabled ETL jobs"""
        results = {}
        
        for job_id, job in self.jobs.items():
            if job.enabled:
                results[job_id] = self.run_job(job_id)
                
        return results
        
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific job"""
        if job_id not in self.jobs:
            return None
            
        job = self.jobs[job_id]
        return {
            'job_id': job.job_id,
            'name': job.name,
            'status': job.status,
            'last_run': job.last_run,
            'created_at': job.created_at
        }
        
    def get_job_history(self, job_id: str = None) -> List[Dict[str, Any]]:
        """Get job execution history"""
        if job_id:
            return [h for h in self.job_history if h['job_id'] == job_id]
        return self.job_history
