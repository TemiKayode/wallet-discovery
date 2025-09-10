"""
Configuration settings module for the Crypto Wallet Discovery & Analysis Toolkit.
Provides centralized configuration management and API key handling.
"""

import configparser
import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path


class ConfigManager:
    """Centralized configuration manager for the wallet discovery toolkit."""
    
    def __init__(self, config_file: str = 'config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        if not os.path.exists(self.config_file):
            self.create_default_config()
        
        self.config.read(self.config_file)
        logging.info(f"Configuration loaded from {self.config_file}")
    
    def create_default_config(self):
        """Create default configuration file"""
        self.config['API_KEYS'] = {
            'etherscan': 'YOUR_ETHERSCAN_API_KEY',
            'bscscan': 'YOUR_BSCSCAN_API_KEY',
            'polygonscan': 'YOUR_POLYGONSCAN_API_KEY',
            'infura': 'YOUR_INFURA_PROJECT_ID',
            'alchemy': 'YOUR_ALCHEMY_API_KEY',
            'opensea': 'YOUR_OPENSEA_API_KEY',
            'twitter_bearer_token': 'YOUR_TWITTER_BEARER_TOKEN',
            'reddit_client_id': 'YOUR_REDDIT_CLIENT_ID',
            'reddit_client_secret': 'YOUR_REDDIT_CLIENT_SECRET'
        }
        
        self.config['SETTINGS'] = {
            'max_retries': '5',
            'request_timeout': '30',
            'rate_limit_delay': '1.0',
            'proxy_enabled': 'false',
            'database_path': 'wallet_data.db',
            'log_level': 'INFO',
            'log_file': 'wallet_discovery.log',
            'max_concurrent_requests': '4',
            'discovery_interval_minutes': '60',
            'max_wallets_per_discovery': '1000'
        }
        
        self.config['MONITORING'] = {
            'email_alerts': 'false',
            'alert_email': 'your_email@example.com',
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': '587',
            'smtp_username': 'your_email@gmail.com',
            'smtp_password': 'your_app_password',
            'alert_threshold_error_rate': '0.1',
            'alert_threshold_failure_rate': '0.2'
        }
        
        self.config['BLOCKCHAIN'] = {
            'ethereum_rpc': 'https://mainnet.infura.io/v3/YOUR_PROJECT_ID',
            'bsc_rpc': 'https://bsc-dataseed.binance.org/',
            'polygon_rpc': 'https://polygon-rpc.com/',
            'bitcoin_rpc': 'https://blockchain.info/',
            'supported_chains': 'eth,btc,bsc,matic'
        }
        
        self.config['DISCOVERY'] = {
            'blockchain_enabled': 'true',
            'defi_enabled': 'true',
            'social_media_enabled': 'true',
            'exchange_enabled': 'true',
            'nft_enabled': 'true',
            'airdrop_enabled': 'true',
            'min_transaction_amount': '1000',
            'max_blocks_to_scan': '100',
            'discovery_methods': 'blockchain,defi,social_media,exchange,nft,airdrop'
        }
        
        self.config['SECURITY'] = {
            'encrypt_database': 'false',
            'encryption_key': '',
            'enable_audit_log': 'true',
            'max_failed_attempts': '3',
            'lockout_duration_minutes': '30'
        }
        
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)
        
        logging.info(f"Default configuration created: {self.config_file}")
    
    def get_api_key(self, service: str) -> str:
        """Get API key for specific service"""
        return self.config.get('API_KEYS', service, fallback='')
    
    def set_api_key(self, service: str, key: str):
        """Set API key for specific service"""
        if not self.config.has_section('API_KEYS'):
            self.config.add_section('API_KEYS')
        
        self.config.set('API_KEYS', service, key)
        self.save_config()
        logging.info(f"API key set for {service}")
    
    def get_setting(self, setting: str, default: str = '') -> str:
        """Get setting value"""
        for section in self.config.sections():
            if self.config.has_option(section, setting):
                return self.config.get(section, setting)
        return default
    
    def set_setting(self, section: str, setting: str, value: str):
        """Set setting value"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        
        self.config.set(section, setting, value)
        self.save_config()
        logging.info(f"Setting {section}.{setting} = {value}")
    
    def get_int_setting(self, setting: str, default: int = 0) -> int:
        """Get integer setting value"""
        try:
            return int(self.get_setting(setting, str(default)))
        except ValueError:
            return default
    
    def get_float_setting(self, setting: str, default: float = 0.0) -> float:
        """Get float setting value"""
        try:
            return float(self.get_setting(setting, str(default)))
        except ValueError:
            return default
    
    def get_bool_setting(self, setting: str, default: bool = False) -> bool:
        """Get boolean setting value"""
        value = self.get_setting(setting, str(default)).lower()
        return value in ['true', '1', 'yes', 'on']
    
    def get_list_setting(self, setting: str, default: list = None) -> list:
        """Get list setting value (comma-separated)"""
        if default is None:
            default = []
        
        value = self.get_setting(setting, '')
        if value:
            return [item.strip() for item in value.split(',') if item.strip()]
        return default
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)
        logging.debug(f"Configuration saved to {self.config_file}")
    
    def reload_config(self):
        """Reload configuration from file"""
        self.load_config()
        logging.info("Configuration reloaded")
    
    def validate_config(self) -> bool:
        """Validate configuration"""
        errors = []
        
        # Check required API keys
        required_apis = ['etherscan', 'infura']
        for api in required_apis:
            if not self.get_api_key(api) or self.get_api_key(api) == f'YOUR_{api.upper()}_API_KEY':
                errors.append(f"Missing or invalid API key for {api}")
        
        # Check required settings
        required_settings = [
            ('SETTINGS', 'database_path'),
            ('SETTINGS', 'log_level'),
            ('BLOCKCHAIN', 'ethereum_rpc')
        ]
        
        for section, setting in required_settings:
            if not self.config.has_option(section, setting):
                errors.append(f"Missing required setting: {section}.{setting}")
        
        if errors:
            logging.error("Configuration validation failed:")
            for error in errors:
                logging.error(f"  - {error}")
            return False
        
        logging.info("Configuration validation passed")
        return True
    
    def get_all_settings(self) -> Dict[str, Dict[str, str]]:
        """Get all configuration settings"""
        settings = {}
        for section in self.config.sections():
            settings[section] = dict(self.config.items(section))
        return settings
    
    def export_config(self, filename: str):
        """Export configuration to file"""
        try:
            with open(filename, 'w') as f:
                self.config.write(f)
            logging.info(f"Configuration exported to {filename}")
        except Exception as e:
            logging.error(f"Failed to export configuration: {e}")
    
    def import_config(self, filename: str):
        """Import configuration from file"""
        try:
            if os.path.exists(filename):
                self.config.read(filename)
                self.save_config()
                logging.info(f"Configuration imported from {filename}")
            else:
                logging.error(f"Configuration file not found: {filename}")
        except Exception as e:
            logging.error(f"Failed to import configuration: {e}")
    
    def get_database_path(self) -> str:
        """Get database file path"""
        db_path = self.get_setting('database_path', 'wallet_data.db')
        return os.path.abspath(db_path)
    
    def get_log_config(self) -> Dict[str, str]:
        """Get logging configuration"""
        return {
            'level': self.get_setting('log_level', 'INFO'),
            'file': self.get_setting('log_file', 'wallet_discovery.log'),
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        }
    
    def get_discovery_config(self) -> Dict[str, Any]:
        """Get discovery configuration"""
        return {
            'blockchain_enabled': self.get_bool_setting('blockchain_enabled', True),
            'defi_enabled': self.get_bool_setting('defi_enabled', True),
            'social_media_enabled': self.get_bool_setting('social_media_enabled', True),
            'exchange_enabled': self.get_bool_setting('exchange_enabled', True),
            'nft_enabled': self.get_bool_setting('nft_enabled', True),
            'airdrop_enabled': self.get_bool_setting('airdrop_enabled', True),
            'min_transaction_amount': self.get_float_setting('min_transaction_amount', 1000.0),
            'max_blocks_to_scan': self.get_int_setting('max_blocks_to_scan', 100),
            'discovery_methods': self.get_list_setting('discovery_methods', [
                'blockchain', 'defi', 'social_media', 'exchange', 'nft', 'airdrop'
            ])
        }
    
    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration"""
        return {
            'email_alerts': self.get_bool_setting('email_alerts', False),
            'alert_email': self.get_setting('alert_email', ''),
            'smtp_server': self.get_setting('smtp_server', 'smtp.gmail.com'),
            'smtp_port': self.get_int_setting('smtp_port', 587),
            'smtp_username': self.get_setting('smtp_username', ''),
            'smtp_password': self.get_setting('smtp_password', ''),
            'alert_threshold_error_rate': self.get_float_setting('alert_threshold_error_rate', 0.1),
            'alert_threshold_failure_rate': self.get_float_setting('alert_threshold_failure_rate', 0.2)
        }
    
    def get_blockchain_config(self) -> Dict[str, str]:
        """Get blockchain configuration"""
        return {
            'ethereum_rpc': self.get_setting('ethereum_rpc', ''),
            'bsc_rpc': self.get_setting('bsc_rpc', ''),
            'polygon_rpc': self.get_setting('polygon_rpc', ''),
            'bitcoin_rpc': self.get_setting('bitcoin_rpc', ''),
            'supported_chains': self.get_setting('supported_chains', 'eth,btc,bsc,matic')
        }
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        # Save configuration on exit
        self.save_config()
