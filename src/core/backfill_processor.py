"""
Backfill Processor Module for Historical Data Processing

This module provides capabilities for processing and analyzing historical blockchain data,
including batch processing, incremental updates, and data reconstruction.
"""

import logging
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio
import time

logger = logging.getLogger(__name__)


@dataclass
class BackfillJob:
    """Represents a backfill job configuration"""
    job_id: str
    name: str
    description: str
    start_date: datetime
    end_date: datetime
    chain: str
    data_types: List[str]  # 'transactions', 'blocks', 'wallets', 'events'
    batch_size: int = 1000
    parallel_workers: int = 4
    enabled: bool = True
    created_at: datetime = None
    last_run: Optional[datetime] = None
    status: str = 'pending'  # pending, running, completed, failed, paused
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()


class HistoricalDataProcessor:
    """Processes historical blockchain data"""
    
    def __init__(self, config_manager):
        self.config = config_manager
        self.db = None
        self._initialize_database()
        
    def _initialize_database(self):
        """Initialize database connection"""
        try:
            db_path = self.config.get_setting('database_path', 'wallet_data.db')
            self.db = sqlite3.connect(db_path)
            self._create_backfill_tables()
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            
    def _create_backfill_tables(self):
        """Create tables for backfill operations"""
        try:
            cursor = self.db.cursor()
            
            # Backfill jobs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS backfill_jobs (
                    job_id TEXT PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    start_date TEXT,
                    end_date TEXT,
                    chain TEXT,
                    data_types TEXT,
                    batch_size INTEGER,
                    parallel_workers INTEGER,
                    enabled BOOLEAN,
                    created_at TEXT,
                    last_run TEXT,
                    status TEXT
                )
            """)
            
            # Backfill progress table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS backfill_progress (
                    job_id TEXT,
                    date TEXT,
                    records_processed INTEGER,
                    status TEXT,
                    error_message TEXT,
                    processed_at TEXT,
                    PRIMARY KEY (job_id, date)
                )
            """)
            
            # Historical data table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS historical_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT,
                    date TEXT,
                    chain TEXT,
                    data_type TEXT,
                    data_hash TEXT,
                    data_content TEXT,
                    processed_at TEXT
                )
            """)
            
            self.db.commit()
            logger.info("Backfill tables created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create backfill tables: {e}")
            
    def create_backfill_job(self, job_config: Dict[str, Any]) -> str:
        """Create a new backfill job"""
        job_id = hashlib.md5(
            f"{job_config.get('name', '')}{datetime.utcnow()}".encode()
        ).hexdigest()[:8]
        
        job = BackfillJob(
            job_id=job_id,
            **job_config
        )
        
        # Save to database
        self._save_job_to_db(job)
        
        logger.info(f"Created backfill job: {job_id} - {job.name}")
        return job_id
        
    def _save_job_to_db(self, job: BackfillJob):
        """Save job to database"""
        try:
            cursor = self.db.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO backfill_jobs 
                (job_id, name, description, start_date, end_date, chain, data_types, 
                 batch_size, parallel_workers, enabled, created_at, last_run, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                job.job_id, job.name, job.description, 
                job.start_date.isoformat(), job.end_date.isoformat(),
                job.chain, json.dumps(job.data_types), job.batch_size,
                job.parallel_workers, job.enabled, job.created_at.isoformat(),
                job.last_run.isoformat() if job.last_run else None, job.status
            ))
            self.db.commit()
        except Exception as e:
            logger.error(f"Failed to save job to database: {e}")
            
    def run_backfill_job(self, job_id: str) -> bool:
        """Run a specific backfill job"""
        job = self._get_job_from_db(job_id)
        if not job:
            logger.error(f"Job not found: {job_id}")
            return False
            
        job.status = 'running'
        job.last_run = datetime.utcnow()
        self._save_job_to_db(job)
        
        try:
            # Generate date range for processing
            date_range = self._generate_date_range(job.start_date, job.end_date)
            
            # Process data in parallel batches
            with ThreadPoolExecutor(max_workers=job.parallel_workers) as executor:
                # Submit batch processing tasks
                future_to_date = {
                    executor.submit(self._process_date_batch, job, date): date
                    for date in date_range
                }
                
                # Process completed tasks
                for future in as_completed(future_to_date):
                    date = future_to_date[future]
                    try:
                        result = future.result()
                        self._update_progress(job_id, date, result)
                    except Exception as e:
                        logger.error(f"Batch processing failed for date {date}: {e}")
                        self._update_progress(job_id, date, {'status': 'failed', 'error': str(e)})
                        
            job.status = 'completed'
            self._save_job_to_db(job)
            logger.info(f"Backfill job completed: {job.name}")
            return True
            
        except Exception as e:
            job.status = 'failed'
            self._save_job_to_db(job)
            logger.error(f"Backfill job failed: {job.name} - {e}")
            return False
            
    def _generate_date_range(self, start_date: datetime, end_date: datetime) -> List[datetime]:
        """Generate list of dates to process"""
        dates = []
        current_date = start_date.date()
        end_date_obj = end_date.date()
        
        while current_date <= end_date_obj:
            dates.append(current_date)
            current_date += timedelta(days=1)
            
        return dates
        
    def _process_date_batch(self, job: BackfillJob, date: datetime) -> Dict[str, Any]:
        """Process a single date batch"""
        try:
            logger.info(f"Processing date: {date} for job: {job.name}")
            
            # Simulate data processing for different data types
            total_records = 0
            processed_data = {}
            
            for data_type in job.data_types:
                if data_type == 'transactions':
                    records = self._fetch_historical_transactions(job.chain, date)
                    processed_data[data_type] = records
                    total_records += len(records)
                elif data_type == 'blocks':
                    records = self._fetch_historical_blocks(job.chain, date)
                    processed_data[data_type] = records
                    total_records += len(records)
                elif data_type == 'wallets':
                    records = self._fetch_historical_wallets(job.chain, date)
                    processed_data[data_type] = records
                    total_records += len(records)
                    
            # Store processed data
            self._store_historical_data(job.job_id, date, job.chain, processed_data)
            
            return {
                'status': 'completed',
                'records_processed': total_records,
                'data_types': list(processed_data.keys())
            }
            
        except Exception as e:
            logger.error(f"Date batch processing failed: {e}")
            return {
                'status': 'failed',
                'error': str(e),
                'records_processed': 0
            }
            
    def _fetch_historical_transactions(self, chain: str, date: datetime) -> List[Dict[str, Any]]:
        """Fetch historical transactions for a specific date"""
        # This is a placeholder implementation
        # In practice, you would integrate with blockchain APIs or databases
        logger.info(f"Fetching historical transactions for {chain} on {date}")
        
        # Simulate some sample data
        sample_transactions = [
            {
                'tx_hash': f"0x{hashlib.md5(f'{chain}{date}{i}'.encode()).hexdigest()[:64]}",
                'from_address': f"0x{hashlib.md5(f'from{i}'.encode()).hexdigest()[:40]}",
                'to_address': f"0x{hashlib.md5(f'to{i}'.encode()).hexdigest()[:40]}",
                'amount': 1000 + i * 100,
                'timestamp': date.isoformat(),
                'chain': chain
            }
            for i in range(10)  # Generate 10 sample transactions
        ]
        
        return sample_transactions
        
    def _fetch_historical_blocks(self, chain: str, date: datetime) -> List[Dict[str, Any]]:
        """Fetch historical blocks for a specific date"""
        logger.info(f"Fetching historical blocks for {chain} on {date}")
        
        # Simulate sample block data
        sample_blocks = [
            {
                'block_number': 1000000 + i,
                'block_hash': f"0x{hashlib.md5(f'block{i}'.encode()).hexdigest()[:64]}",
                'timestamp': date.isoformat(),
                'chain': chain,
                'transaction_count': 100 + i * 10
            }
            for i in range(5)  # Generate 5 sample blocks
        ]
        
        return sample_blocks
        
    def _fetch_historical_wallets(self, chain: str, date: datetime) -> List[Dict[str, Any]]:
        """Fetch historical wallet data for a specific date"""
        logger.info(f"Fetching historical wallets for {chain} on {date}")
        
        # Simulate sample wallet data
        sample_wallets = [
            {
                'address': f"0x{hashlib.md5(f'wallet{i}'.encode()).hexdigest()[:40]}",
                'balance': 10000 + i * 1000,
                'transaction_count': 50 + i * 5,
                'first_seen': date.isoformat(),
                'chain': chain
            }
            for i in range(20)  # Generate 20 sample wallets
        ]
        
        return sample_wallets
        
    def _store_historical_data(self, job_id: str, date: datetime, chain: str, 
                              data: Dict[str, Any]):
        """Store processed historical data"""
        try:
            cursor = self.db.cursor()
            
            for data_type, records in data.items():
                for record in records:
                    data_hash = hashlib.md5(
                        json.dumps(record, sort_keys=True).encode()
                    ).hexdigest()
                    
                    cursor.execute("""
                        INSERT OR REPLACE INTO historical_data 
                        (job_id, date, chain, data_type, data_hash, data_content, processed_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        job_id, date.isoformat(), chain, data_type, data_hash,
                        json.dumps(record), datetime.utcnow().isoformat()
                    ))
                    
            self.db.commit()
            logger.info(f"Stored historical data for {date} - {len(data)} data types")
            
        except Exception as e:
            logger.error(f"Failed to store historical data: {e}")
            
    def _update_progress(self, job_id: str, date: datetime, result: Dict[str, Any]):
        """Update backfill progress"""
        try:
            cursor = self.db.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO backfill_progress 
                (job_id, date, records_processed, status, error_message, processed_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                job_id, date.isoformat(), result.get('records_processed', 0),
                result.get('status', 'unknown'), result.get('error', None),
                datetime.utcnow().isoformat()
            ))
            self.db.commit()
        except Exception as e:
            logger.error(f"Failed to update progress: {e}")
            
    def _get_job_from_db(self, job_id: str) -> Optional[BackfillJob]:
        """Retrieve job from database"""
        try:
            cursor = self.db.cursor()
            cursor.execute("SELECT * FROM backfill_jobs WHERE job_id = ?", (job_id,))
            row = cursor.fetchone()
            
            if row:
                return BackfillJob(
                    job_id=row[0], name=row[1], description=row[2],
                    start_date=datetime.fromisoformat(row[3]),
                    end_date=datetime.fromisoformat(row[4]),
                    chain=row[5], data_types=json.loads(row[6]),
                    batch_size=row[7], parallel_workers=row[8],
                    enabled=bool(row[9]), created_at=datetime.fromisoformat(row[10]),
                    last_run=datetime.fromisoformat(row[11]) if row[11] else None,
                    status=row[12]
                )
        except Exception as e:
            logger.error(f"Failed to retrieve job: {e}")
            
        return None
        
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a backfill job"""
        job = self._get_job_from_db(job_id)
        if not job:
            return None
            
        # Get progress information
        try:
            cursor = self.db.cursor()
            cursor.execute("""
                SELECT COUNT(*) as total_dates, 
                       SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_dates,
                       SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_dates
                FROM backfill_progress 
                WHERE job_id = ?
            """, (job_id,))
            
            progress_row = cursor.fetchone()
            if progress_row:
                total_dates, completed_dates, failed_dates = progress_row
                progress_percentage = (completed_dates / total_dates * 100) if total_dates > 0 else 0
            else:
                progress_percentage = 0
                completed_dates = failed_dates = 0
                
        except Exception as e:
            logger.error(f"Failed to get progress: {e}")
            progress_percentage = 0
            completed_dates = failed_dates = 0
            
        return {
            'job_id': job.job_id,
            'name': job.name,
            'status': job.status,
            'progress_percentage': progress_percentage,
            'completed_dates': completed_dates,
            'failed_dates': failed_dates,
            'start_date': job.start_date.isoformat(),
            'end_date': job.end_date.isoformat(),
            'chain': job.chain,
            'last_run': job.last_run.isoformat() if job.last_run else None
        }
        
    def get_all_jobs(self) -> List[Dict[str, Any]]:
        """Get all backfill jobs"""
        try:
            cursor = self.db.cursor()
            cursor.execute("SELECT job_id FROM backfill_jobs ORDER BY created_at DESC")
            job_ids = [row[0] for row in cursor.fetchall()]
            
            return [self.get_job_status(job_id) for job_id in job_ids]
            
        except Exception as e:
            logger.error(f"Failed to get jobs: {e}")
            return []
            
    def pause_job(self, job_id: str) -> bool:
        """Pause a running backfill job"""
        try:
            job = self._get_job_from_db(job_id)
            if job and job.status == 'running':
                job.status = 'paused'
                self._save_job_to_db(job)
                logger.info(f"Job paused: {job_id}")
                return True
        except Exception as e:
            logger.error(f"Failed to pause job: {e}")
            
        return False
        
    def resume_job(self, job_id: str) -> bool:
        """Resume a paused backfill job"""
        try:
            job = self._get_job_from_db(job_id)
            if job and job.status == 'paused':
                job.status = 'pending'
                self._save_job_to_db(job)
                logger.info(f"Job resumed: {job_id}")
                return True
        except Exception as e:
            logger.error(f"Failed to resume job: {e}")
            
        return False
        
    def delete_job(self, job_id: str) -> bool:
        """Delete a backfill job and its data"""
        try:
            cursor = self.db.cursor()
            
            # Delete related data
            cursor.execute("DELETE FROM backfill_progress WHERE job_id = ?", (job_id,))
            cursor.execute("DELETE FROM historical_data WHERE job_id = ?", (job_id,))
            cursor.execute("DELETE FROM backfill_jobs WHERE job_id = ?", (job_id,))
            
            self.db.commit()
            logger.info(f"Job deleted: {job_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete job: {e}")
            return False
            
    def export_historical_data(self, job_id: str, output_format: str = 'csv') -> str:
        """Export historical data for a specific job"""
        try:
            cursor = self.db.cursor()
            cursor.execute("""
                SELECT data_content FROM historical_data 
                WHERE job_id = ? ORDER BY date, data_type
            """, (job_id,))
            
            rows = cursor.fetchall()
            if not rows:
                logger.warning(f"No data found for job: {job_id}")
                return ""
                
            # Parse JSON data
            data_records = []
            for row in rows:
                try:
                    record = json.loads(row[0])
                    data_records.append(record)
                except json.JSONDecodeError:
                    continue
                    
            # Convert to DataFrame
            df = pd.DataFrame(data_records)
            
            # Export based on format
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            
            if output_format == 'csv':
                filename = f"historical_data_{job_id}_{timestamp}.csv"
                df.to_csv(filename, index=False)
            elif output_format == 'json':
                filename = f"historical_data_{job_id}_{timestamp}.json"
                df.to_json(filename, orient='records', indent=2)
            else:
                raise ValueError(f"Unsupported export format: {output_format}")
                
            logger.info(f"Historical data exported to: {filename}")
            return filename
            
        except Exception as e:
            logger.error(f"Failed to export historical data: {e}")
            return ""
