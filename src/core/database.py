"""
Database management module for the Crypto Wallet Discovery & Analysis Toolkit.
Handles SQLite database operations for storing wallet data and discovery logs.
"""

import sqlite3
import logging
from typing import List, Dict, Optional
from datetime import datetime
import json


class DatabaseManager:
    """SQLite database manager for storing wallet data and discovery logs."""
    
    def __init__(self, db_path: str = 'wallet_data.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create wallets table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS wallets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    address TEXT UNIQUE NOT NULL,
                    chain TEXT,
                    discovery_method TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    transaction_count INTEGER DEFAULT 0,
                    total_value REAL DEFAULT 0,
                    usd_value REAL DEFAULT 0,
                    status TEXT DEFAULT 'active',
                    metadata TEXT
                )
            ''')
            
            # Create discovery_log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS discovery_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    method TEXT,
                    wallets_found INTEGER,
                    duration REAL,
                    status TEXT,
                    error_message TEXT
                )
            ''')
            
            # Create transactions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    wallet_address TEXT,
                    tx_hash TEXT UNIQUE,
                    from_address TEXT,
                    to_address TEXT,
                    value REAL,
                    block_number INTEGER,
                    timestamp TIMESTAMP,
                    chain TEXT,
                    FOREIGN KEY (wallet_address) REFERENCES wallets (address)
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_wallets_address ON wallets (address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_wallets_chain ON wallets (chain)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_wallets_method ON wallets (discovery_method)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_transactions_wallet ON transactions (wallet_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_transactions_hash ON transactions (tx_hash)')
            
            conn.commit()
            conn.close()
            
            logging.info(f"Database initialized: {self.db_path}")
            
        except Exception as e:
            logging.error(f"Database initialization failed: {e}")
            raise
    
    def save_wallets_batch(self, wallets: List[Dict]):
        """Save multiple wallets to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for wallet in wallets:
                try:
                    # Prepare metadata
                    metadata = {
                        'discovery_method': wallet.get('discovery_method', 'unknown'),
                        'timestamp': wallet.get('timestamp', ''),
                        'status': wallet.get('status', 'active')
                    }
                    
                    cursor.execute('''
                        INSERT OR REPLACE INTO wallets 
                        (address, chain, discovery_method, last_updated, 
                         transaction_count, total_value, usd_value, status, metadata)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?)
                    ''', (
                        wallet.get('address'),
                        wallet.get('chain', 'unknown'),
                        wallet.get('discovery_method', 'unknown'),
                        wallet.get('transaction_count', 0),
                        wallet.get('total_value', 0.0),
                        wallet.get('usd_value', 0.0),
                        wallet.get('status', 'active'),
                        json.dumps(metadata)
                    ))
                    
                except Exception as e:
                    logging.error(f"Error saving wallet {wallet.get('address', 'unknown')}: {e}")
                    continue
            
            conn.commit()
            conn.close()
            
            logging.info(f"Saved {len(wallets)} wallets to database")
            
        except Exception as e:
            logging.error(f"Failed to save wallets to database: {e}")
            raise
    
    def save_wallet(self, wallet: Dict):
        """Save a single wallet to database"""
        self.save_wallets_batch([wallet])
    
    def get_wallet_count(self) -> int:
        """Get total number of wallets in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM wallets')
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception as e:
            logging.error(f"Failed to get wallet count: {e}")
            return 0
    
    def get_wallets_by_chain(self, chain: str, limit: int = 100) -> List[Dict]:
        """Get wallets by blockchain"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT address, chain, discovery_method, first_seen, 
                       last_updated, transaction_count, total_value, usd_value, status
                FROM wallets 
                WHERE chain = ? 
                ORDER BY last_updated DESC 
                LIMIT ?
            ''', (chain, limit))
            
            wallets = []
            for row in cursor.fetchall():
                wallets.append({
                    'address': row[0],
                    'chain': row[1],
                    'discovery_method': row[2],
                    'first_seen': row[3],
                    'last_updated': row[4],
                    'transaction_count': row[5],
                    'total_value': row[6],
                    'usd_value': row[7],
                    'status': row[8]
                })
            
            conn.close()
            return wallets
            
        except Exception as e:
            logging.error(f"Failed to get wallets by chain: {e}")
            return []
    
    def get_wallets_by_method(self, method: str, limit: int = 100) -> List[Dict]:
        """Get wallets by discovery method"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT address, chain, discovery_method, first_seen, 
                       last_updated, transaction_count, total_value, usd_value, status
                FROM wallets 
                WHERE discovery_method = ? 
                ORDER BY last_updated DESC 
                LIMIT ?
            ''', (method, limit))
            
            wallets = []
            for row in cursor.fetchall():
                wallets.append({
                    'address': row[0],
                    'chain': row[1],
                    'discovery_method': row[2],
                    'first_seen': row[3],
                    'last_updated': row[4],
                    'transaction_count': row[5],
                    'total_value': row[6],
                    'usd_value': row[7],
                    'status': row[8]
                })
            
            conn.close()
            return wallets
            
        except Exception as e:
            logging.error(f"Failed to get wallets by method: {e}")
            return []
    
    def search_wallets(self, query: str, limit: int = 50) -> List[Dict]:
        """Search wallets by address or other criteria"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT address, chain, discovery_method, first_seen, 
                       last_updated, transaction_count, total_value, usd_value, status
                FROM wallets 
                WHERE address LIKE ? OR chain LIKE ? OR discovery_method LIKE ?
                ORDER BY last_updated DESC 
                LIMIT ?
            ''', (f'%{query}%', f'%{query}%', f'%{query}%', limit))
            
            wallets = []
            for row in cursor.fetchall():
                wallets.append({
                    'address': row[0],
                    'chain': row[1],
                    'discovery_method': row[2],
                    'first_seen': row[3],
                    'last_updated': row[4],
                    'transaction_count': row[5],
                    'total_value': row[6],
                    'usd_value': row[7],
                    'status': row[8]
                })
            
            conn.close()
            return wallets
            
        except Exception as e:
            logging.error(f"Failed to search wallets: {e}")
            return []
    
    def log_discovery(self, method: str, wallets_found: int, duration: float, 
                     status: str = 'success', error_message: str = None):
        """Log discovery operation"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO discovery_log 
                (method, wallets_found, duration, status, error_message)
                VALUES (?, ?, ?, ?, ?)
            ''', (method, wallets_found, duration, status, error_message))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Failed to log discovery: {e}")
    
    def get_discovery_stats(self, days: int = 7) -> Dict:
        """Get discovery statistics for the last N days"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    method,
                    COUNT(*) as discovery_count,
                    SUM(wallets_found) as total_wallets,
                    AVG(duration) as avg_duration,
                    COUNT(CASE WHEN status = 'success' THEN 1 END) as success_count,
                    COUNT(CASE WHEN status = 'error' THEN 1 END) as error_count
                FROM discovery_log 
                WHERE timestamp >= datetime('now', '-{} days')
                GROUP BY method
            '''.format(days))
            
            stats = {}
            for row in cursor.fetchall():
                stats[row[0]] = {
                    'discovery_count': row[1],
                    'total_wallets': row[2],
                    'avg_duration': row[3],
                    'success_count': row[4],
                    'error_count': row[5]
                }
            
            conn.close()
            return stats
            
        except Exception as e:
            logging.error(f"Failed to get discovery stats: {e}")
            return {}
    
    def save_transaction(self, tx_data: Dict):
        """Save transaction data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO transactions 
                (wallet_address, tx_hash, from_address, to_address, 
                 value, block_number, timestamp, chain)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                tx_data.get('wallet_address'),
                tx_data.get('tx_hash'),
                tx_data.get('from_address'),
                tx_data.get('to_address'),
                tx_data.get('value', 0.0),
                tx_data.get('block_number'),
                tx_data.get('timestamp'),
                tx_data.get('chain', 'eth')
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Failed to save transaction: {e}")
    
    def get_wallet_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get transactions for a specific wallet"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT tx_hash, from_address, to_address, value, 
                       block_number, timestamp, chain
                FROM transactions 
                WHERE wallet_address = ? 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (address, limit))
            
            transactions = []
            for row in cursor.fetchall():
                transactions.append({
                    'tx_hash': row[0],
                    'from_address': row[1],
                    'to_address': row[2],
                    'value': row[3],
                    'block_number': row[4],
                    'timestamp': row[5],
                    'chain': row[6]
                })
            
            conn.close()
            return transactions
            
        except Exception as e:
            logging.error(f"Failed to get wallet transactions: {e}")
            return []
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old discovery logs"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM discovery_log 
                WHERE timestamp < datetime('now', '-{} days')
            '''.format(days))
            
            deleted_count = cursor.rowcount
            conn.commit()
            conn.close()
            
            logging.info(f"Cleaned up {deleted_count} old discovery logs")
            
        except Exception as e:
            logging.error(f"Failed to cleanup old data: {e}")
    
    def export_to_csv(self, filename: str, table: str = 'wallets'):
        """Export table data to CSV"""
        try:
            import csv
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(f'SELECT * FROM {table}')
            rows = cursor.fetchall()
            
            if rows:
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    # Write header
                    writer.writerow([description[0] for description in cursor.description])
                    # Write data
                    writer.writerows(rows)
                
                logging.info(f"Exported {len(rows)} rows to {filename}")
            
            conn.close()
            
        except Exception as e:
            logging.error(f"Failed to export to CSV: {e}")
