"""
Blockchain explorers module for the Crypto Wallet Discovery & Analysis Toolkit.
Handles multi-chain transaction analysis and blockchain data retrieval.
"""

import requests
import logging
from typing import List, Dict, Optional
from datetime import datetime


class BlockchainExplorer:
    """Multi-chain blockchain explorer for transaction analysis."""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
        })
        
        # API endpoints for different blockchains
        self.explorers = {
            'eth': {
                'base_url': 'https://api.etherscan.io/api',
                'api_key_param': 'apikey'
            },
            'btc': {
                'base_url': 'https://blockchain.info/rawblock/',
                'api_key_param': None
            },
            'bsc': {
                'base_url': 'https://api.bscscan.com/api',
                'api_key_param': 'apikey'
            },
            'matic': {
                'base_url': 'https://api.polygonscan.com/api',
                'api_key_param': 'apikey'
            }
        }
        
    def get_block_transactions(self, chain: str, block_number: int) -> List[Dict]:
        """Get all transactions from a specific block"""
        if chain not in self.explorers:
            logging.error(f"Unsupported chain: {chain}")
            return []
        
        try:
            if chain == 'eth':
                return self._get_ethereum_block_transactions(block_number)
            elif chain == 'btc':
                return self._get_bitcoin_block_transactions(block_number)
            elif chain == 'bsc':
                return self._get_bsc_block_transactions(block_number)
            elif chain == 'matic':
                return self._get_polygon_block_transactions(block_number)
            else:
                return []
                
        except Exception as e:
            logging.error(f"Error getting block {block_number} from {chain}: {e}")
            return []
    
    def _get_ethereum_block_transactions(self, block_number: int) -> List[Dict]:
        """Get Ethereum block transactions"""
        try:
            params = {
                'module': 'proxy',
                'action': 'eth_getBlockByNumber',
                'tag': hex(block_number),
                'boolean': 'true',
                'apikey': 'YourApiKey'  # Should come from config
            }
            
            response = self.session.get(
                self.explorers['eth']['base_url'], 
                params=params, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('result'):
                    return data['result'].get('transactions', [])
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting Ethereum block transactions: {e}")
            return []
    
    def _get_bitcoin_block_transactions(self, block_number: int) -> List[Dict]:
        """Get Bitcoin block transactions"""
        try:
            url = f"{self.explorers['btc']['base_url']}{block_number}"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('tx', [])
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting Bitcoin block transactions: {e}")
            return []
    
    def _get_bsc_block_transactions(self, block_number: int) -> List[Dict]:
        """Get BSC block transactions"""
        try:
            params = {
                'module': 'proxy',
                'action': 'eth_getBlockByNumber',
                'tag': hex(block_number),
                'boolean': 'true',
                'apikey': 'YourApiKey'  # Should come from config
            }
            
            response = self.session.get(
                self.explorers['bsc']['base_url'], 
                params=params, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('result'):
                    return data['result'].get('transactions', [])
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting BSC block transactions: {e}")
            return []
    
    def _get_polygon_block_transactions(self, block_number: int) -> List[Dict]:
        """Get Polygon block transactions"""
        try:
            params = {
                'module': 'proxy',
                'action': 'eth_getBlockByNumber',
                'tag': hex(block_number),
                'boolean': 'true',
                'apikey': 'YourApiKey'  # Should come from config
            }
            
            response = self.session.get(
                self.explorers['matic']['base_url'], 
                params=params, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('result'):
                    return data['result'].get('transactions', [])
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting Polygon block transactions: {e}")
            return []
    
    def get_wallet_transactions(self, address: str, chain: str = 'eth', 
                              start_block: int = 0, end_block: int = 99999999) -> List[Dict]:
        """Get transactions for a specific wallet address"""
        if chain not in self.explorers:
            logging.error(f"Unsupported chain: {chain}")
            return []
        
        try:
            if chain == 'eth':
                return self._get_ethereum_wallet_transactions(address, start_block, end_block)
            elif chain == 'bsc':
                return self._get_bsc_wallet_transactions(address, start_block, end_block)
            elif chain == 'matic':
                return self._get_polygon_wallet_transactions(address, start_block, end_block)
            else:
                return []
                
        except Exception as e:
            logging.error(f"Error getting wallet transactions for {address} on {chain}: {e}")
            return []
    
    def _get_ethereum_wallet_transactions(self, address: str, start_block: int, end_block: int) -> List[Dict]:
        """Get Ethereum wallet transactions"""
        try:
            params = {
                'module': 'account',
                'action': 'txlist',
                'address': address,
                'startblock': start_block,
                'endblock': end_block,
                'sort': 'desc',
                'apikey': 'YourApiKey'  # Should come from config
            }
            
            response = self.session.get(
                self.explorers['eth']['base_url'], 
                params=params, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == '1':
                    return data.get('result', [])
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting Ethereum wallet transactions: {e}")
            return []
    
    def _get_bsc_wallet_transactions(self, address: str, start_block: int, end_block: int) -> List[Dict]:
        """Get BSC wallet transactions"""
        try:
            params = {
                'module': 'account',
                'action': 'txlist',
                'address': address,
                'startblock': start_block,
                'endblock': end_block,
                'sort': 'desc',
                'apikey': 'YourApiKey'  # Should come from config
            }
            
            response = self.session.get(
                self.explorers['bsc']['base_url'], 
                params=params, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == '1':
                    return data.get('result', [])
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting BSC wallet transactions: {e}")
            return []
    
    def _get_polygon_wallet_transactions(self, address: str, start_block: int, end_block: int) -> List[Dict]:
        """Get Polygon wallet transactions"""
        try:
            params = {
                'module': 'account',
                'action': 'txlist',
                'address': address,
                'startblock': start_block,
                'endblock': end_block,
                'sort': 'desc',
                'apikey': 'YourApiKey'  # Should come from config
            }
            
            response = self.session.get(
                self.explorers['matic']['base_url'], 
                params=params, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == '1':
                    return data.get('result', [])
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting Polygon wallet transactions: {e}")
            return []
    
    def get_latest_block_number(self, chain: str) -> Optional[int]:
        """Get the latest block number for a chain"""
        if chain not in self.explorers:
            logging.error(f"Unsupported chain: {chain}")
            return None
        
        try:
            if chain == 'eth':
                return self._get_ethereum_latest_block()
            elif chain == 'btc':
                return self._get_bitcoin_latest_block()
            elif chain == 'bsc':
                return self._get_bsc_latest_block()
            elif chain == 'matic':
                return self._get_polygon_latest_block()
            else:
                return None
                
        except Exception as e:
            logging.error(f"Error getting latest block number for {chain}: {e}")
            return None
    
    def _get_ethereum_latest_block(self) -> Optional[int]:
        """Get Ethereum latest block number"""
        try:
            params = {
                'module': 'proxy',
                'action': 'eth_blockNumber',
                'apikey': 'YourApiKey'  # Should come from config
            }
            
            response = self.session.get(
                self.explorers['eth']['base_url'], 
                params=params, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('result'):
                    return int(data['result'], 16)
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting Ethereum latest block: {e}")
            return None
    
    def _get_bitcoin_latest_block(self) -> Optional[int]:
        """Get Bitcoin latest block number"""
        try:
            url = 'https://blockchain.info/latestblock'
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('height')
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting Bitcoin latest block: {e}")
            return None
    
    def _get_bsc_latest_block(self) -> Optional[int]:
        """Get BSC latest block number"""
        try:
            params = {
                'module': 'proxy',
                'action': 'eth_blockNumber',
                'apikey': 'YourApiKey'  # Should come from config
            }
            
            response = self.session.get(
                self.explorers['bsc']['base_url'], 
                params=params, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('result'):
                    return int(data['result'], 16)
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting BSC latest block: {e}")
            return None
    
    def _get_polygon_latest_block(self) -> Optional[int]:
        """Get Polygon latest block number"""
        try:
            params = {
                'module': 'proxy',
                'action': 'eth_blockNumber',
                'apikey': 'YourApiKey'  # Should come from config
            }
            
            response = self.session.get(
                self.explorers['matic']['base_url'], 
                params=params, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('result'):
                    return int(data['result'], 16)
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting Polygon latest block: {e}")
            return None
    
    def get_transaction_details(self, tx_hash: str, chain: str = 'eth') -> Optional[Dict]:
        """Get detailed transaction information"""
        if chain not in self.explorers:
            logging.error(f"Unsupported chain: {chain}")
            return None
        
        try:
            if chain == 'eth':
                return self._get_ethereum_transaction_details(tx_hash)
            elif chain == 'btc':
                return self._get_bitcoin_transaction_details(tx_hash)
            elif chain == 'bsc':
                return self._get_bsc_transaction_details(tx_hash)
            elif chain == 'matic':
                return self._get_polygon_transaction_details(tx_hash)
            else:
                return None
                
        except Exception as e:
            logging.error(f"Error getting transaction details for {tx_hash} on {chain}: {e}")
            return None
    
    def _get_ethereum_transaction_details(self, tx_hash: str) -> Optional[Dict]:
        """Get Ethereum transaction details"""
        try:
            params = {
                'module': 'proxy',
                'action': 'eth_getTransactionByHash',
                'txhash': tx_hash,
                'apikey': 'YourApiKey'  # Should come from config
            }
            
            response = self.session.get(
                self.explorers['eth']['base_url'], 
                params=params, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('result')
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting Ethereum transaction details: {e}")
            return None
    
    def _get_bitcoin_transaction_details(self, tx_hash: str) -> Optional[Dict]:
        """Get Bitcoin transaction details"""
        try:
            url = f'https://blockchain.info/rawtx/{tx_hash}'
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting Bitcoin transaction details: {e}")
            return None
    
    def _get_bsc_transaction_details(self, tx_hash: str) -> Optional[Dict]:
        """Get BSC transaction details"""
        try:
            params = {
                'module': 'proxy',
                'action': 'eth_getTransactionByHash',
                'txhash': tx_hash,
                'apikey': 'YourApiKey'  # Should come from config
            }
            
            response = self.session.get(
                self.explorers['bsc']['base_url'], 
                params=params, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('result')
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting BSC transaction details: {e}")
            return None
    
    def _get_polygon_transaction_details(self, tx_hash: str) -> Optional[Dict]:
        """Get Polygon transaction details"""
        try:
            params = {
                'module': 'proxy',
                'action': 'eth_getTransactionByHash',
                'txhash': tx_hash,
                'apikey': 'YourApiKey'  # Should come from config
            }
            
            response = self.session.get(
                self.explorers['matic']['base_url'], 
                params=params, 
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('result')
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting Polygon transaction details: {e}")
            return None
