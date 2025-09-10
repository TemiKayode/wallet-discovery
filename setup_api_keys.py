#!/usr/bin/env python3
"""
API Keys Setup Script for Crypto Wallet Discovery & Analysis Toolkit

This script helps you configure your API keys interactively.
"""

import os
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.config.settings import ConfigManager


def print_header():
    """Print setup header"""
    print("🔑 Crypto Wallet Discovery & Analysis Toolkit - API Keys Setup")
    print("=" * 70)
    print("This script will help you configure your API keys for optimal results.")
    print("=" * 70)


def get_api_key(service_name, description, url, required=False):
    """Get API key from user input"""
    print(f"\n📋 {service_name}")
    print(f"   Description: {description}")
    print(f"   Get it here: {url}")
    
    if required:
        print("   ⭐ REQUIRED for basic functionality")
    else:
        print("   💡 Optional but recommended for better results")
    
    current_key = config.get_api_key(service_name.lower().replace(' ', '_'))
    
    if current_key and current_key != f'YOUR_{service_name.upper().replace(" ", "_")}_API_KEY':
        print(f"   Current key: {current_key[:8]}...{current_key[-4:]}")
        update = input("   Update this key? (y/N): ").lower().strip()
        if update != 'y':
            return current_key
    
    new_key = input(f"   Enter your {service_name} API key: ").strip()
    
    if new_key:
        config.set_api_key(service_name.lower().replace(' ', '_'), new_key)
        print(f"   ✅ {service_name} API key saved!")
        return new_key
    elif required:
        print(f"   ⚠️  Warning: {service_name} is required for basic functionality")
        return None
    else:
        print(f"   ⏭️  Skipping {service_name} (optional)")
        return None


def setup_essential_keys():
    """Setup essential API keys"""
    print("\n🎯 ESSENTIAL API KEYS (Required for Basic Functionality)")
    print("-" * 60)
    
    # Etherscan
    get_api_key(
        "Etherscan",
        "Ethereum blockchain data, transaction history, wallet analysis",
        "https://etherscan.io/apis",
        required=True
    )
    
    # Infura
    get_api_key(
        "Infura",
        "Ethereum RPC access, real-time blockchain data",
        "https://infura.io/",
        required=True
    )


def setup_high_value_keys():
    """Setup high-value API keys"""
    print("\n🚀 HIGH-VALUE API KEYS (For Excellent Results)")
    print("-" * 60)
    
    # BSCscan
    get_api_key(
        "BSCscan",
        "Binance Smart Chain data, BSC wallet analysis",
        "https://bscscan.com/apis"
    )
    
    # Polygonscan
    get_api_key(
        "Polygonscan",
        "Polygon blockchain data, MATIC transactions",
        "https://polygonscan.com/apis"
    )
    
    # Alchemy
    get_api_key(
        "Alchemy",
        "Enhanced blockchain infrastructure, Web3 development",
        "https://www.alchemy.com/"
    )


def setup_specialized_keys():
    """Setup specialized API keys"""
    print("\n🎨 SPECIALIZED API KEYS (For Advanced Features)")
    print("-" * 60)
    
    # OpenSea
    get_api_key(
        "OpenSea",
        "NFT market data, collection analysis, trading patterns",
        "https://docs.opensea.io/reference/api-overview"
    )
    
    # Twitter
    get_api_key(
        "Twitter Bearer Token",
        "Social media wallet mentions, sentiment analysis",
        "https://developer.twitter.com/en/portal/dashboard"
    )
    
    # Reddit
    get_api_key(
        "Reddit Client ID",
        "Reddit wallet mentions, community sentiment",
        "https://www.reddit.com/prefs/apps"
    )
    
    get_api_key(
        "Reddit Client Secret",
        "Reddit API authentication",
        "https://www.reddit.com/prefs/apps"
    )


def update_rpc_endpoints():
    """Update RPC endpoints with Infura project ID"""
    infura_key = config.get_api_key('infura')
    
    if infura_key and infura_key != 'YOUR_INFURA_PROJECT_ID':
        ethereum_rpc = f"https://mainnet.infura.io/v3/{infura_key}"
        config.set_setting('BLOCKCHAIN', 'ethereum_rpc', ethereum_rpc)
        print(f"\n✅ Updated Ethereum RPC endpoint with Infura project ID")


def validate_setup():
    """Validate the API keys setup"""
    print("\n🔍 VALIDATING SETUP")
    print("-" * 30)
    
    if config.validate_config():
        print("✅ Configuration validation passed!")
        
        # Count configured API keys
        api_keys = config.get_all_settings().get('API_KEYS', {})
        configured_keys = sum(1 for key, value in api_keys.items() 
                            if value and not value.startswith('YOUR_'))
        
        print(f"📊 Configured API keys: {configured_keys}/{len(api_keys)}")
        
        if configured_keys >= 2:
            print("🎉 You're ready to run the toolkit!")
        else:
            print("⚠️  Consider adding more API keys for better results")
            
    else:
        print("❌ Configuration validation failed!")
        print("   Please check the error messages above and fix the issues.")


def show_next_steps():
    """Show next steps after setup"""
    print("\n🚀 NEXT STEPS")
    print("-" * 20)
    print("1. Test your setup:")
    print("   python examples/technical_enhancements_demo.py")
    print()
    print("2. Run the main application:")
    print("   python main.py")
    print()
    print("3. For continuous monitoring:")
    print("   python main.py --continuous")
    print()
    print("4. Check the logs:")
    print("   tail -f wallet_discovery.log")
    print()
    print("📚 For more information, see:")
    print("   - API_KEYS_GUIDE.md")
    print("   - README.md")


def main():
    """Main setup function"""
    global config
    
    print_header()
    
    # Initialize config manager
    config = ConfigManager()
    
    try:
        # Setup API keys in order of importance
        setup_essential_keys()
        setup_high_value_keys()
        setup_specialized_keys()
        
        # Update RPC endpoints
        update_rpc_endpoints()
        
        # Validate setup
        validate_setup()
        
        # Show next steps
        show_next_steps()
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Setup interrupted by user")
        print("   Your configuration has been saved.")
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        print("   Please check your configuration and try again.")


if __name__ == "__main__":
    main()
