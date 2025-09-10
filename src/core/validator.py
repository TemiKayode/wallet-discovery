"""
Data validation module for the Crypto Wallet Discovery & Analysis Toolkit.
Handles address validation, data sanitization, and format verification.
"""

import re
import logging
from typing import List, Dict
from web3 import Web3


class DataValidator:
    """Comprehensive data validation for wallet addresses and transaction data."""
    
    def __init__(self):
        self.w3 = Web3()
        
        # Regex patterns for different address formats
        self.address_patterns = {
            'eth': r'^0x[a-fA-F0-9]{40}$',
            'btc_legacy': r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',
            'btc_segwit': r'^bc1[a-zA-HJ-NP-Z0-9]{25,90}$',
            'btc_bech32': r'^bc1[a-zA-HJ-NP-Z0-9]{25,90}$',
            'bsc': r'^0x[a-fA-F0-9]{40}$',
            'matic': r'^0x[a-fA-F0-9]{40}$'
        }
        
    def validate_eth_address(self, address: str) -> bool:
        """Validate Ethereum address format and checksum"""
        try:
            if not re.match(self.address_patterns['eth'], address):
                return False
            
            # Check checksum if mixed case
            if any(c.isupper() for c in address[2:]):
                checksum_address = self.w3.to_checksum_address(address)
                return checksum_address == address
            
            return True
        except Exception as e:
            logging.debug(f"Ethereum address validation failed: {e}")
            return False
    
    def validate_btc_address(self, address: str) -> bool:
        """Validate Bitcoin address using multiple methods"""
        try:
            # Check legacy format
            if re.match(self.address_patterns['btc_legacy'], address):
                return True
            
            # Check SegWit format
            if re.match(self.address_patterns['btc_segwit'], address):
                return True
            
            # Check Bech32 format
            if re.match(self.address_patterns['btc_bech32'], address):
                return True
            
            return False
        except Exception as e:
            logging.debug(f"Bitcoin address validation failed: {e}")
            return False
    
    def validate_address(self, address: str, chain: str = 'eth') -> bool:
        """Validate address for specific blockchain"""
        try:
            if chain.lower() in ['eth', 'ethereum']:
                return self.validate_eth_address(address)
            elif chain.lower() in ['btc', 'bitcoin']:
                return self.validate_btc_address(address)
            elif chain.lower() in ['bsc', 'binance']:
                return self.validate_eth_address(address)  # BSC uses same format as ETH
            elif chain.lower() in ['matic', 'polygon']:
                return self.validate_eth_address(address)  # Polygon uses same format as ETH
            else:
                # Try all validation methods
                return (self.validate_eth_address(address) or 
                       self.validate_btc_address(address))
        except Exception as e:
            logging.debug(f"Address validation failed for {chain}: {e}")
            return False
    
    def sanitize_wallet_data(self, wallets: List[Dict]) -> List[Dict]:
        """Clean and validate wallet data"""
        valid_wallets = []
        seen_addresses = set()
        
        for wallet in wallets:
            try:
                address = wallet.get('address', '').strip()
                chain = wallet.get('chain', 'eth').lower()
                
                # Skip if no address
                if not address:
                    continue
                
                # Validate address
                if not self.validate_address(address, chain):
                    logging.debug(f"Invalid address: {address}")
                    continue
                
                # Normalize address format
                if chain in ['eth', 'bsc', 'matic']:
                    address = address.lower()
                
                # Skip duplicates
                if address in seen_addresses:
                    continue
                
                seen_addresses.add(address)
                
                # Clean and standardize wallet data
                clean_wallet = {
                    'address': address,
                    'chain': chain,
                    'discovery_method': wallet.get('discovery_method', 'unknown'),
                    'timestamp': wallet.get('timestamp', ''),
                    'amount': self._clean_amount(wallet.get('amount', 0)),
                    'usd_value': self._clean_amount(wallet.get('usd_value', 0)),
                    'transaction_count': self._clean_integer(wallet.get('transaction_count', 0)),
                    'status': wallet.get('status', 'active')
                }
                
                valid_wallets.append(clean_wallet)
                
            except Exception as e:
                logging.error(f"Error sanitizing wallet data: {e}")
                continue
        
        return valid_wallets
    
    def _clean_amount(self, amount) -> float:
        """Clean and validate amount values"""
        try:
            if isinstance(amount, str):
                # Remove currency symbols and commas
                amount = re.sub(r'[$,€£¥]', '', amount)
                amount = amount.replace(',', '')
            
            amount = float(amount) if amount else 0.0
            
            # Ensure non-negative
            return max(0.0, amount)
        except (ValueError, TypeError):
            return 0.0
    
    def _clean_integer(self, value) -> int:
        """Clean and validate integer values"""
        try:
            value = int(value) if value else 0
            return max(0, value)
        except (ValueError, TypeError):
            return 0
    
    def validate_transaction_data(self, tx_data: Dict) -> bool:
        """Validate transaction data structure"""
        required_fields = ['hash', 'from', 'to', 'value']
        
        try:
            for field in required_fields:
                if field not in tx_data:
                    return False
                
                if not tx_data[field]:
                    return False
            
            # Validate addresses
            if not self.validate_eth_address(tx_data['from']):
                return False
            
            if not self.validate_eth_address(tx_data['to']):
                return False
            
            # Validate hash format
            if not re.match(r'^0x[a-fA-F0-9]{64}$', tx_data['hash']):
                return False
            
            return True
            
        except Exception as e:
            logging.debug(f"Transaction validation failed: {e}")
            return False
    
    def validate_api_response(self, response_data: Dict, expected_fields: List[str]) -> bool:
        """Validate API response structure"""
        try:
            for field in expected_fields:
                if field not in response_data:
                    logging.warning(f"Missing field in API response: {field}")
                    return False
            
            return True
        except Exception as e:
            logging.error(f"API response validation failed: {e}")
            return False
    
    def sanitize_url(self, url: str) -> str:
        """Sanitize and validate URLs"""
        try:
            # Basic URL validation
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Remove any potentially dangerous characters
            url = re.sub(r'[<>"\']', '', url)
            
            return url.strip()
        except Exception as e:
            logging.error(f"URL sanitization failed: {e}")
            return ""
    
    def validate_config(self, config_data: Dict) -> bool:
        """Validate configuration data"""
        required_configs = ['API_KEYS', 'SETTINGS']
        
        try:
            for section in required_configs:
                if section not in config_data:
                    logging.error(f"Missing configuration section: {section}")
                    return False
            
            # Validate API keys section
            api_keys = config_data.get('API_KEYS', {})
            if not isinstance(api_keys, dict):
                logging.error("API_KEYS section must be a dictionary")
                return False
            
            # Validate settings section
            settings = config_data.get('SETTINGS', {})
            if not isinstance(settings, dict):
                logging.error("SETTINGS section must be a dictionary")
                return False
            
            return True
            
        except Exception as e:
            logging.error(f"Configuration validation failed: {e}")
            return False
