#!/usr/bin/env python3
"""
Main entry point for the Crypto Wallet Discovery & Analysis Toolkit.
"""

import sys
import logging
import logging.config
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.core.discoverer import EnhancedWalletDiscoverer
from src.config.settings import ConfigManager


def setup_logging():
    """Configure comprehensive logging"""
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'detailed': {
                'format': '%(asctime)s %(name)-15s %(levelname)-8s %(message)s'
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'INFO',
                'formatter': 'detailed'
            },
            'file': {
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': 'wallet_discovery.log',
                'maxBytes': 10485760,  # 10MB
                'backupCount': 5,
                'formatter': 'detailed',
                'level': 'DEBUG'
            }
        },
        'root': {
            'handlers': ['console', 'file'],
            'level': 'INFO'
        }
    })


class EthicalGuidelines:
    """Ethical guidelines for tool usage."""
    
    @staticmethod
    def display_guidelines():
        """Display ethical guidelines and require user acknowledgment."""
        guidelines = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    ETHICAL GUIDELINES & RESPONSIBLE USE                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This tool is designed for RESEARCH and EDUCATIONAL purposes only.          ║
║                                                                              ║
║  BEFORE PROCEEDING, you must agree to:                                      ║
║                                                                              ║
║  ✅ Use only for legitimate research and analysis                           ║
║  ✅ Respect privacy and terms of service of all platforms                   ║
║  ✅ Comply with all applicable laws and regulations                         ║
║  ✅ Not engage in malicious activities or unauthorized access               ║
║  ✅ Use data ethically and responsibly                                      ║
║  ✅ Only analyze publicly available blockchain data                         ║
║                                                                              ║
║  The developers are not responsible for misuse of this tool.                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        
        print(guidelines)
        
        while True:
            response = input("Do you agree to use this tool ethically and responsibly? (yes/no): ").lower().strip()
            if response in ['yes', 'y']:
                print("✅ Thank you for your commitment to ethical use!")
                return True
            elif response in ['no', 'n']:
                print("❌ You must agree to ethical guidelines to use this tool.")
                sys.exit(1)
            else:
                print("Please answer 'yes' or 'no'.")


def main():
    """Main application entry point."""
    # Setup logging
    setup_logging()
    
    # Display ethical guidelines
    EthicalGuidelines.display_guidelines()
    
    try:
        # Initialize enhanced discoverer
        discoverer = EnhancedWalletDiscoverer()
        
        # Parse command line arguments
        if len(sys.argv) > 1:
            if sys.argv[1] == '--continuous':
                interval = int(sys.argv[2]) if len(sys.argv) > 2 else 60
                print(f"🚀 Starting continuous wallet discovery (interval: {interval} minutes)...")
                print("Press Ctrl+C to stop")
                discoverer.run_continuous_discovery(interval_minutes=interval)
            elif sys.argv[1] == '--help':
                print_help()
            else:
                print(f"❌ Unknown argument: {sys.argv[1]}")
                print_help()
        else:
            # Run single discovery
            print("🚀 Starting wallet discovery...")
            wallets = discoverer.discover_wallets_comprehensive()
            
            print(f"\n✅ Discovery completed successfully!")
            print(f"📊 Total wallets found: {len(wallets)}")
            print(f"💾 Results saved to database: {discoverer.config.get_setting('database_path')}")
            
            # Show database statistics
            total_in_db = discoverer.db.get_wallet_count()
            print(f"🗄️  Total wallets in database: {total_in_db}")
            
            # Show metrics
            metrics = discoverer.monitor.get_performance_summary()
            print(f"📈 Performance metrics:")
            print(f"   • API calls: {metrics['total_api_calls']}")
            print(f"   • Error rate: {metrics['error_rate']:.2%}")
            print(f"   • Success rate: {metrics['success_rate']:.2%}")
            
            # Show sample results
            if wallets:
                print(f"\n📋 Sample wallets discovered:")
                for i, wallet in enumerate(wallets[:5]):
                    print(f"   {i+1}. {wallet['address']} ({wallet.get('chain', 'unknown')})")
            
            print(f"\n🎯 Next Steps:")
            print(f"   • Check the database for detailed results")
            print(f"   • Use --continuous for ongoing monitoring")
            print(f"   • Review logs for detailed information")
    
    except KeyboardInterrupt:
        print("\n⏹️  Operation cancelled by user")
    except Exception as e:
        logging.error(f"Critical error: {e}")
        print(f"❌ Error occurred: {e}")
        print(f"\n🔧 Troubleshooting:")
        print(f"   • Check your API keys in config.ini")
        print(f"   • Verify internet connection")
        print(f"   • Review logs for detailed error information")


def print_help():
    """Print help information."""
    help_text = """
🚀 Crypto Wallet Discovery & Analysis Toolkit

Usage:
  python main.py                    # Run single discovery
  python main.py --continuous       # Run continuous discovery (60 min interval)
  python main.py --continuous 30    # Run continuous discovery (30 min interval)
  python main.py --help            # Show this help

Examples:
  python main.py
  python main.py --continuous
  python main.py --continuous 120

Configuration:
  Edit config.ini to set API keys and other settings
  See README.md for detailed configuration instructions

For more information, visit: https://github.com/yourusername/crypto-wallet-discovery
    """
    print(help_text)


if __name__ == "__main__":
    main()
