"""
Data Lake Integration Module

This module provides integration with cloud data lakes including AWS S3, Google BigQuery,
and other cloud storage solutions for scalable data storage and retrieval.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import pandas as pd
from pathlib import Path
import tempfile
import gzip
import pickle

logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    logger.warning("boto3 not available. S3 functionality will be disabled.")

try:
    from google.cloud import bigquery
    from google.cloud import storage
    from google.oauth2 import service_account
    BIGQUERY_AVAILABLE = True
except ImportError:
    BIGQUERY_AVAILABLE = False
    logger.warning("google-cloud-bigquery not available. BigQuery functionality will be disabled.")


class DataLakeInterface:
    """Abstract interface for data lake operations"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.connection_status = {}
        
    def test_connection(self) -> bool:
        """Test connection to the data lake"""
        raise NotImplementedError
        
    def upload_data(self, data: Any, path: str, **kwargs) -> bool:
        """Upload data to the data lake"""
        raise NotImplementedError
        
    def download_data(self, path: str, **kwargs) -> Any:
        """Download data from the data lake"""
        raise NotImplementedError
        
    def list_objects(self, prefix: str = "") -> List[str]:
        """List objects in the data lake"""
        raise NotImplementedError
        
    def delete_object(self, path: str) -> bool:
        """Delete an object from the data lake"""
        raise NotImplementedError


class S3DataLake(DataLakeInterface):
    """AWS S3 Data Lake Integration"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.s3_client = None
        self.bucket_name = self.config.get_setting('s3_bucket_name', '')
        self.region = self.config.get_setting('s3_region', 'us-east-1')
        
        if BOTO3_AVAILABLE:
            self._initialize_s3_client()
            
    def _initialize_s3_client(self):
        """Initialize S3 client with credentials"""
        try:
            # Try to get credentials from config or environment
            aws_access_key = self.config.get_setting('aws_access_key_id', '')
            aws_secret_key = self.config.get_setting('aws_secret_access_key', '')
            
            if aws_access_key and aws_secret_key:
                self.s3_client = boto3.client(
                    's3',
                    aws_access_key_id=aws_access_key,
                    aws_secret_access_key=aws_secret_key,
                    region_name=self.region
                )
            else:
                # Use default credential chain
                self.s3_client = boto3.client('s3', region_name=self.region)
                
            self.connection_status['s3'] = True
            logger.info("S3 client initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize S3 client: {e}")
            self.connection_status['s3'] = False
            
    def test_connection(self) -> bool:
        """Test S3 connection"""
        if not self.s3_client:
            return False
            
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            return True
        except (ClientError, NoCredentialsError) as e:
            logger.error(f"S3 connection test failed: {e}")
            return False
            
    def upload_data(self, data: Any, path: str, **kwargs) -> bool:
        """Upload data to S3"""
        if not self.s3_client:
            logger.error("S3 client not initialized")
            return False
            
        try:
            # Handle different data types
            if isinstance(data, pd.DataFrame):
                # Convert DataFrame to CSV
                with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp_file:
                    data.to_csv(tmp_file.name, index=False)
                    tmp_file_path = tmp_file.name
                
                try:
                    self.s3_client.upload_file(
                        tmp_file_path, 
                        self.bucket_name, 
                        path,
                        ExtraArgs={'ContentType': 'text/csv'}
                    )
                finally:
                    os.unlink(tmp_file_path)
                    
            elif isinstance(data, dict):
                # Convert dict to JSON
                json_data = json.dumps(data, default=str)
                self.s3_client.put_object(
                    Bucket=self.bucket_name,
                    Key=path,
                    Body=json_data,
                    ContentType='application/json'
                )
                
            elif isinstance(data, (str, bytes)):
                # Upload raw data
                self.s3_client.put_object(
                    Bucket=self.bucket_name,
                    Key=path,
                    Body=data
                )
                
            else:
                # Try to pickle the data
                pickle_data = pickle.dumps(data)
                self.s3_client.put_object(
                    Bucket=self.bucket_name,
                    Key=path,
                    Body=pickle_data
                )
                
            logger.info(f"Successfully uploaded data to S3: {path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to upload data to S3: {e}")
            return False
            
    def download_data(self, path: str, **kwargs) -> Any:
        """Download data from S3"""
        if not self.s3_client:
            logger.error("S3 client not initialized")
            return None
            
        try:
            response = self.s3_client.get_object(Bucket=self.bucket_name, Key=path)
            
            # Determine data type based on file extension
            if path.endswith('.csv'):
                return pd.read_csv(response['Body'])
            elif path.endswith('.json'):
                return json.loads(response['Body'].read().decode('utf-8'))
            elif path.endswith('.pkl'):
                return pickle.loads(response['Body'].read())
            else:
                # Return raw bytes
                return response['Body'].read()
                
        except Exception as e:
            logger.error(f"Failed to download data from S3: {e}")
            return None
            
    def list_objects(self, prefix: str = "") -> List[str]:
        """List objects in S3 bucket"""
        if not self.s3_client:
            return []
            
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix
            )
            
            if 'Contents' in response:
                return [obj['Key'] for obj in response['Contents']]
            return []
            
        except Exception as e:
            logger.error(f"Failed to list S3 objects: {e}")
            return []
            
    def delete_object(self, path: str) -> bool:
        """Delete object from S3"""
        if not self.s3_client:
            return False
            
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=path)
            logger.info(f"Successfully deleted S3 object: {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete S3 object: {e}")
            return False


class BigQueryDataLake(DataLakeInterface):
    """Google BigQuery Data Lake Integration"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.bq_client = None
        self.storage_client = None
        self.project_id = self.config.get_setting('bigquery_project_id', '')
        self.dataset_id = self.config.get_setting('bigquery_dataset_id', 'wallet_data')
        
        if BIGQUERY_AVAILABLE:
            self._initialize_bigquery_client()
            
    def _initialize_bigquery_client(self):
        """Initialize BigQuery client with credentials"""
        try:
            # Try to get service account key from config
            service_account_key = self.config.get_setting('bigquery_service_account_key', '')
            
            if service_account_key and os.path.exists(service_account_key):
                credentials = service_account.Credentials.from_service_account_file(
                    service_account_key
                )
                self.bq_client = bigquery.Client(
                    credentials=credentials,
                    project=self.project_id
                )
                self.storage_client = storage.Client(
                    credentials=credentials,
                    project=self.project_id
                )
            else:
                # Use default credentials
                self.bq_client = bigquery.Client(project=self.project_id)
                self.storage_client = storage.Client(project=self.project_id)
                
            self.connection_status['bigquery'] = True
            logger.info("BigQuery client initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize BigQuery client: {e}")
            self.connection_status['bigquery'] = False
            
    def test_connection(self) -> bool:
        """Test BigQuery connection"""
        if not self.bq_client:
            return False
            
        try:
            # Try to list datasets
            datasets = list(self.bq_client.list_datasets())
            return True
        except Exception as e:
            logger.error(f"BigQuery connection test failed: {e}")
            return False
            
    def upload_data(self, data: Any, path: str, **kwargs) -> bool:
        """Upload data to BigQuery"""
        if not self.bq_client:
            logger.error("BigQuery client not initialized")
            return False
            
        try:
            table_id = f"{self.project_id}.{self.dataset_id}.{path}"
            
            if isinstance(data, pd.DataFrame):
                # Upload DataFrame to BigQuery
                job_config = bigquery.LoadJobConfig(
                    write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE,
                    autodetect=True
                )
                
                job = self.bq_client.load_table_from_dataframe(
                    data, table_id, job_config=job_config
                )
                job.result()  # Wait for the job to complete
                
                logger.info(f"Successfully uploaded DataFrame to BigQuery: {table_id}")
                return True
                
            else:
                logger.error("BigQuery upload only supports DataFrames")
                return False
                
        except Exception as e:
            logger.error(f"Failed to upload data to BigQuery: {e}")
            return False
            
    def download_data(self, path: str, **kwargs) -> Any:
        """Download data from BigQuery"""
        if not self.bq_client:
            logger.error("BigQuery client not initialized")
            return None
            
        try:
            table_id = f"{self.project_id}.{self.dataset_id}.{path}"
            
            # Execute query to get data
            query = f"SELECT * FROM `{table_id}`"
            if 'limit' in kwargs:
                query += f" LIMIT {kwargs['limit']}"
                
            df = self.bq_client.query(query).to_dataframe()
            return df
            
        except Exception as e:
            logger.error(f"Failed to download data from BigQuery: {e}")
            return None
            
    def list_objects(self, prefix: str = "") -> List[str]:
        """List tables in BigQuery dataset"""
        if not self.bq_client:
            return []
            
        try:
            dataset_ref = self.bq_client.dataset(self.dataset_id)
            tables = list(self.bq_client.list_tables(dataset_ref))
            return [table.table_id for table in tables if table.table_id.startswith(prefix)]
        except Exception as e:
            logger.error(f"Failed to list BigQuery tables: {e}")
            return []
            
    def delete_object(self, path: str) -> bool:
        """Delete table from BigQuery"""
        if not self.bq_client:
            return False
            
        try:
            table_id = f"{self.project_id}.{self.dataset_id}.{path}"
            self.bq_client.delete_table(table_id, not_found_ok=True)
            logger.info(f"Successfully deleted BigQuery table: {table_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete BigQuery table: {e}")
            return False


class LocalDataLake(DataLakeInterface):
    """Local file system data lake for development and testing"""
    
    def __init__(self, config_manager):
        super().__init__(config_manager)
        self.base_path = Path(self.config.get_setting('local_data_path', './data_lake'))
        self.base_path.mkdir(exist_ok=True)
        self.connection_status['local'] = True
        
    def test_connection(self) -> bool:
        """Test local file system access"""
        try:
            test_file = self.base_path / 'test.txt'
            test_file.write_text('test')
            test_file.unlink()
            return True
        except Exception as e:
            logger.error(f"Local file system test failed: {e}")
            return False
            
    def upload_data(self, data: Any, path: str, **kwargs) -> bool:
        """Upload data to local file system"""
        try:
            file_path = self.base_path / path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            if isinstance(data, pd.DataFrame):
                data.to_csv(file_path, index=False)
            elif isinstance(data, dict):
                with open(file_path, 'w') as f:
                    json.dump(data, f, default=str, indent=2)
            elif isinstance(data, str):
                file_path.write_text(data)
            else:
                # Try to pickle
                with open(file_path, 'wb') as f:
                    pickle.dump(data, f)
                    
            logger.info(f"Successfully uploaded data locally: {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to upload data locally: {e}")
            return False
            
    def download_data(self, path: str, **kwargs) -> Any:
        """Download data from local file system"""
        try:
            file_path = self.base_path / path
            
            if not file_path.exists():
                logger.error(f"File not found: {file_path}")
                return None
                
            if path.endswith('.csv'):
                return pd.read_csv(file_path)
            elif path.endswith('.json'):
                with open(file_path, 'r') as f:
                    return json.load(f)
            elif path.endswith('.pkl'):
                with open(file_path, 'rb') as f:
                    return pickle.load(f)
            else:
                return file_path.read_text()
                
        except Exception as e:
            logger.error(f"Failed to download data locally: {e}")
            return None
            
    def list_objects(self, prefix: str = "") -> List[str]:
        """List files in local directory"""
        try:
            files = []
            for file_path in self.base_path.rglob('*'):
                if file_path.is_file() and str(file_path.relative_to(self.base_path)).startswith(prefix):
                    files.append(str(file_path.relative_to(self.base_path)))
            return files
        except Exception as e:
            logger.error(f"Failed to list local files: {e}")
            return []
            
    def delete_object(self, path: str) -> bool:
        """Delete file from local file system"""
        try:
            file_path = self.base_path / path
            if file_path.exists():
                file_path.unlink()
                logger.info(f"Successfully deleted local file: {file_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete local file: {e}")
            return False


class DataLakeManager:
    """Manages multiple data lake connections"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.data_lakes: Dict[str, DataLakeInterface] = {}
        self._initialize_data_lakes()
        
    def _initialize_data_lakes(self):
        """Initialize available data lakes"""
        # Initialize S3 if available
        if BOTO3_AVAILABLE:
            self.data_lakes['s3'] = S3DataLake(self.config)
            
        # Initialize BigQuery if available
        if BIGQUERY_AVAILABLE:
            self.data_lakes['bigquery'] = BigQueryDataLake(self.config)
            
        # Always initialize local data lake
        self.data_lakes['local'] = LocalDataLake(self.config)
        
    def get_data_lake(self, name: str) -> Optional[DataLakeInterface]:
        """Get a specific data lake by name"""
        return self.data_lakes.get(name)
        
    def test_all_connections(self) -> Dict[str, bool]:
        """Test connections to all data lakes"""
        results = {}
        for name, data_lake in self.data_lakes.items():
            results[name] = data_lake.test_connection()
        return results
        
    def upload_to_all(self, data: Any, path: str, **kwargs) -> Dict[str, bool]:
        """Upload data to all available data lakes"""
        results = {}
        for name, data_lake in self.data_lakes.items():
            if data_lake.test_connection():
                results[name] = data_lake.upload_data(data, path, **kwargs)
            else:
                results[name] = False
        return results
        
    def get_connection_status(self) -> Dict[str, bool]:
        """Get connection status for all data lakes"""
        return {name: dl.connection_status.get(name, False) for name, dl in self.data_lakes.items()}
