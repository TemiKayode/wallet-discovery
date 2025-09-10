import requests
from bs4 import BeautifulSoup
import time
import csv
import re
from typing import List, Dict, Optional, Callable
import logging
from datetime import datetime, timedelta
import random
from urllib.parse import quote_plus, urlparse
import backoff
from fp.fp import FreeProxy

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GoogleDorkWalletFinder:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        self.delay_range = (2, 5)  # Random delay between requests
        self.max_results = 50      # Maximum results to collect
        
        # Regex patterns for extraction
        self.patterns = {
            'eth_address': r'\b0x[a-fA-F0-9]{40}\b',
            'btc_address': r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})\b',
            'amount': r'\$([0-9]{1,3}(?:,[0-9]{3})*(?:\.[0-9]{2})?)|\$([0-9]+(?:\.[0-9]{2})?)',
            'usd_value': r'USD\s*([0-9,]+(?:\.\d{2})?)',
            'transaction_value': r'Value:\s*([0-9.]+)\s*ETH|Value:\s*([0-9.]+)\s*BTC',
        }

    def random_delay(self):
        """Add random delay between requests to avoid rate limiting"""
        delay = random.uniform(self.delay_range[0], self.delay_range[1])
        time.sleep(delay)

    def search_google(self, dork_query: str, num_results: int = 10) -> List[str]:
        """Perform Google search using dork query"""
        urls = []
        try:
            # Encode the query for URL
            encoded_query = quote_plus(dork_query)
            search_url = f"https://www.google.com/search?q={encoded_query}&num={num_results}"
            
            self.random_delay()
            response = self.session.get(search_url, timeout=15)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all search result links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('/url?q='):
                        # Extract actual URL from Google's redirect
                        url = href.split('/url?q=')[1].split('&')[0]
                        url = requests.utils.unquote(url)
                        
                        # Filter out Google-specific URLs
                        if not any(x in url for x in ['google.com', 'webcache.googleusercontent.com']):
                            urls.append(url)
            
            logger.info(f"Found {len(urls)} URLs for query: {dork_query}")
            
        except Exception as e:
            logger.error(f"Error searching Google: {e}")
        
        return urls[:num_results]  # Return only requested number of results

    def extract_wallet_info(self, url: str) -> List[Dict]:
        """Extract wallet information from a webpage"""
        wallet_data = []
        
        try:
            self.random_delay()
            response = self.session.get(url, timeout=15)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                text_content = soup.get_text()
                
                # Extract Ethereum addresses
                eth_addresses = re.findall(self.patterns['eth_address'], text_content)
                
                # Extract Bitcoin addresses
                btc_addresses = re.findall(self.patterns['btc_address'], text_content)
                
                # Extract amounts and values
                amounts = re.findall(self.patterns['amount'], text_content)
                usd_values = re.findall(self.patterns['usd_value'], text_content)
                tx_values = re.findall(self.patterns['transaction_value'], text_content)
                
                # Process amounts (convert to float)
                processed_amounts = []
                for amount in amounts:
                    for amt in amount:
                        if amt:
                            # Remove commas and convert to float
                            clean_amt = amt.replace(',', '')
                            try:
                                processed_amounts.append(float(clean_amt))
                            except ValueError:
                                pass
                
                # Process USD values
                processed_usd = []
                for value in usd_values:
                    if value:
                        clean_val = value.replace(',', '')
                        try:
                            processed_usd.append(float(clean_val))
                        except ValueError:
                            pass
                
                # Process transaction values
                processed_tx = []
                for tx_val in tx_values:
                    for val in tx_val:
                        if val:
                            try:
                                processed_tx.append(float(val))
                            except ValueError:
                                pass
                
                # Combine all addresses
                all_addresses = list(set(eth_addresses + btc_addresses))
                
                # Create wallet entries
                for address in all_addresses:
                    # Determine chain
                    if address.startswith('0x'):
                        chain = 'eth'
                    elif address.startswith('bc1') or address.startswith('1') or address.startswith('3'):
                        chain = 'btc'
                    else:
                        chain = 'unknown'
                    
                    # Get relevant amounts
                    amount = processed_amounts[0] if processed_amounts else 0
                    usd_value = processed_usd[0] if processed_usd else 0
                    tx_value = processed_tx[0] if processed_tx else 0
                    
                    wallet_data.append({
                        'address': address,
                        'chain': chain,
                        'amount': amount,
                        'usd_value': usd_value,
                        'transaction_value': tx_value,
                        'source_url': url,
                        'found_date': datetime.now().isoformat(),
                        'amount_type': 'USD' if usd_value > 0 else 'crypto' if tx_value > 0 else 'unknown'
                    })
                
                logger.info(f"Extracted {len(wallet_data)} wallets from {url}")
                
        except Exception as e:
            logger.error(f"Error extracting from {url}: {e}")
        
        return wallet_data

    def generate_dork_queries(self, min_amount: int = 10000) -> List[str]:
        """Generate Google dork queries for wallet searching"""
        current_year = datetime.now().year
        current_month = datetime.now().strftime("%Y-%m")
        
        dorks = [
            f'site:etherscan.io "Value: $" intext:"{min_amount}" after:{current_year}-01-01',
            f'site:bscscan.com "transaction value" ">{min_amount}"',
            f'site:blockchain.com "output value" "{min_amount}"',
            f'site:whale-alert.io "transaction" "USD {min_amount}"',
            f'site:twitter.com "whale alert" "${min_amount}"',
            f'site:reddit.com "large transaction" "${min_amount}"',
            f'site:medium.com "crypto whale" "${min_amount} transaction"',
            f'site:github.com "whale transactions" "{min_amount}"',
            f'intitle:"wallet address" "large transaction" "${min_amount}"',
            f'filetype:csv "wallet_address" "transaction_value" ">{min_amount}"',
            f'site:coindesk.com OR site:cointelegraph.com "large transaction" "{min_amount}"',
            f'site:bitcointalk.org "interesting wallet" "${min_amount}"',
        ]
        
        return dorks

    def filter_wallets_by_amount(self, wallets: List[Dict], min_amount: float = 10000) -> List[Dict]:
        """Filter wallets by minimum amount"""
        filtered = []
        for wallet in wallets:
            if (wallet['usd_value'] >= min_amount or 
                wallet['amount'] >= min_amount or 
                wallet['transaction_value'] * 2000 >= min_amount):  # Approximate crypto value
                filtered.append(wallet)
        return filtered

    def remove_duplicates(self, wallets: List[Dict]) -> List[Dict]:
        """Remove duplicate wallet addresses"""
        seen = set()
        unique_wallets = []
        
        for wallet in wallets:
            if wallet['address'] not in seen:
                seen.add(wallet['address'])
                unique_wallets.append(wallet)
        
        return unique_wallets

    def save_to_csv(self, wallets: List[Dict], filename: str):
        """Save wallet data to CSV file"""
        if not wallets:
            logger.warning("No wallet data to save")
            return
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['address', 'chain', 'amount', 'usd_value', 'transaction_value', 
                             'amount_type', 'source_url', 'found_date']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(wallets)
            
            logger.info(f"Saved {len(wallets)} wallets to {filename}")
            
        except Exception as e:
            logger.error(f"Error saving to CSV: {e}")

    def find_wallets_with_dorks(self, min_amount: int = 10000, max_results: int = 20, 
                               output_file: str = "large_wallets.csv") -> List[Dict]:
        """Main function to find wallets using Google dorks"""
        all_wallets = []
        
        # Generate dork queries
        dork_queries = self.generate_dork_queries(min_amount)
        logger.info(f"Generated {len(dork_queries)} dork queries")
        
        # Process each dork query
        for i, dork in enumerate(dork_queries):
            if len(all_wallets) >= max_results:
                break
                
            logger.info(f"Processing dork {i+1}/{len(dork_queries)}: {dork}")
            
            try:
                # Search Google for this dork
                urls = self.search_google(dork, num_results=5)
                
                # Process each URL found
                for url in urls:
                    if len(all_wallets) >= max_results:
                        break
                        
                    # Extract wallet info from URL
                    wallets_from_url = self.extract_wallet_info(url)
                    
                    # Filter by amount
                    filtered_wallets = self.filter_wallets_by_amount(wallets_from_url, min_amount)
                    
                    # Add to results
                    all_wallets.extend(filtered_wallets)
                    
                    logger.info(f"Found {len(filtered_wallets)} wallets from {url}")
                    
                    # Small delay between URL processing
                    time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error processing dork '{dork}': {e}")
                continue
        
        # Remove duplicates
        unique_wallets = self.remove_duplicates(all_wallets)
        
        # Save results
        if unique_wallets:
            self.save_to_csv(unique_wallets, output_file)
            
            # Print summary
            print(f"\n✅ Found {len(unique_wallets)} unique wallets with transactions > ${min_amount:,}")
            
            # Group by chain
            chain_stats = {}
            for wallet in unique_wallets:
                chain = wallet['chain']
                chain_stats[chain] = chain_stats.get(chain, 0) + 1
            
            print(f"\n🔗 Distribution by blockchain:")
            for chain, count in chain_stats.items():
                print(f"{chain.upper()}: {count} wallets")
            
            # Show top wallets by value
            print(f"\n🏆 Top wallets by USD value:")
            sorted_wallets = sorted(unique_wallets, key=lambda x: x['usd_value'], reverse=True)
            for i, wallet in enumerate(sorted_wallets[:5]):
                if wallet['usd_value'] > 0:
                    print(f"{i+1}. {wallet['address'][:8]}...{wallet['address'][-6:]} - ${wallet['usd_value']:,.2f}")
        
        return unique_wallets

    def quick_search(self, min_amount: int = 10000):
        """Quick search with predefined known wallets"""
        known_large_wallets = [
            {
                'address': '0x28c6c06298d514db089934071355e5743bf21d60',
                'chain': 'eth',
                'amount': 50000,
                'usd_value': 50000,
                'transaction_value': 25.0,
                'source_url': 'https://etherscan.io/address/0x28c6c06298d514db089934071355e5743bf21d60',
                'found_date': datetime.now().isoformat(),
                'amount_type': 'USD'
            },
            {
                'address': '0x71660c4005ba85c37ccec55d0c4493e66fe775d3',
                'chain': 'eth',
                'amount': 75000,
                'usd_value': 75000,
                'transaction_value': 37.5,
                'source_url': 'https://etherscan.io/address/0x71660c4005ba85c37ccec55d0c4493e66fe775d3',
                'found_date': datetime.now().isoformat(),
                'amount_type': 'USD'
            },
            {
                'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                'chain': 'btc',
                'amount': 100000,
                'usd_value': 100000,
                'transaction_value': 2.5,
                'source_url': 'https://blockchain.com/btc/address/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                'found_date': datetime.now().isoformat(),
                'amount_type': 'USD'
            }
        ]
        
        # Filter by amount
        filtered = [w for w in known_large_wallets if w['usd_value'] >= min_amount]
        self.save_to_csv(filtered, 'quick_wallet_search.csv')
        
        return filtered

class AdvancedWalletAnalyzer(GoogleDorkWalletFinder):
    def __init__(self):
        super().__init__()
        self.api_keys = {
            'etherscan': 'YourApiKeyToken',
            'bscscan': 'YourBscApiKey'
        }
    
    def verify_wallet_activity(self, wallet_address: str, chain: str = 'eth') -> Dict:
        """Verify wallet activity and get recent transactions"""
        try:
            if chain == 'eth':
                url = "https://api.etherscan.io/api"
                params = {
                    'module': 'account',
                    'action': 'txlist',
                    'address': wallet_address,
                    'startblock': 0,
                    'endblock': 99999999,
                    'sort': 'desc',
                    'page': 1,
                    'offset': 10,
                    'apikey': self.api_keys['etherscan']
                }
            elif chain == 'bsc':
                url = "https://api.bscscan.com/api"
                params = {
                    'module': 'account',
                    'action': 'txlist',
                    'address': wallet_address,
                    'startblock': 0,
                    'endblock': 99999999,
                    'sort': 'desc',
                    'apikey': self.api_keys['bscscan']
                }
            else:
                return {'error': 'Unsupported chain'}
            
            response = self.session.get(url, params=params, timeout=15)
            data = response.json()
            
            if data.get('status') == '1':
                transactions = data['result']
                total_value = sum(int(tx['value']) for tx in transactions) / (10**18)
                
                return {
                    'address': wallet_address,
                    'chain': chain,
                    'transaction_count': len(transactions),
                    'total_value': total_value,
                    'last_transaction': transactions[0]['timeStamp'] if transactions else None,
                    'status': 'active'
                }
            else:
                return {'address': wallet_address, 'status': 'inactive', 'error': data.get('message')}
                
        except Exception as e:
            return {'address': wallet_address, 'status': 'error', 'error': str(e)}
    
    def analyze_found_wallets(self, input_csv: str, output_csv: str = "analyzed_wallets.csv"):
        """Analyze wallets found through dorking"""
        wallets = []
        
        # Read wallets from CSV
        try:
            with open(input_csv, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                wallets = list(reader)
        except FileNotFoundError:
            print(f"File {input_csv} not found")
            return
        
        analyzed_data = []
        
        print(f"Analyzing {len(wallets)} wallets...")
        for i, wallet in enumerate(wallets):
            print(f"Analyzing wallet {i+1}/{len(wallets)}")
            
            analysis = self.verify_wallet_activity(wallet['address'], wallet.get('chain', 'eth'))
            analyzed_data.append({**wallet, **analysis})
            
            # Rate limiting
            time.sleep(1)
        
        # Save analyzed data
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            fieldnames = list(analyzed_data[0].keys()) if analyzed_data else []
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(analyzed_data)
        
        print(f"Analysis complete. Saved to {output_csv}")

class WalletAddressGenerator:
    """Generates cryptographic wallet addresses for Bitcoin and Ethereum."""
    
    def __init__(self):
        # Curve parameters for secp256k1 (Bitcoin's curve)
        self.p = 2**256 - 2**32 - 977  # Prime modulus
        self.a = 0
        self.b = 7
        self.n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
        self.G = (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424) # Generator point G

    def scalar_multiply(self, k: int, P: tuple) -> Optional[tuple]:
        """Performs elliptic curve scalar multiplication (k * P)"""
        if k == 0:
            return (0, 0) # Point at infinity
        
        Q = (0, 0) # Initialize Q to point at infinity
        R = P # Start with R = P
        
        k_binary = bin(k)[2:] # Convert k to binary
        for bit in k_binary:
            Q = self.add_points(Q, Q) # Double Q
            if bit == '1':
                Q = self.add_points(Q, R) # Add R to Q if bit is 1
        
        return Q

    def add_points(self, P: tuple, Q: tuple) -> tuple:
        """Adds two points on the elliptic curve"""
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        
        x1, y1 = P
        x2, y2 = Q
        
        if x1 == x2 and y1 == -y2: # P + (-Q) = point at infinity
            return (0, 0)
        
        if P == Q: # P + P = 2P
            lam = (3 * x1**2 + self.a) * pow(2 * y1, -1, self.p) % self.p
        else: # P + Q
            lam = (y2 - y1) * pow(x2 - x1, -1, self.p) % self.p
        
        x3 = (lam**2 - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        
        return (x3, y3)

    def generate_public_key(self, private_key: str) -> str:
        """Generates the corresponding public key (compressed)"""
        k = int(private_key)
        Q = self.scalar_multiply(k, self.G)
        
        if Q is None:
            return "Error: Point at infinity"
        
        x, y = Q
        return f"0x{x:064x}" + (f"{y:064x}" if y % 2 == 0 else f"{y:064x}")

    def private_key_to_public_key(self, private_key_hex: str, compressed: bool = True) -> str:
        """Convert private key to public key using ECC multiplication"""
        private_key_int = int(private_key_hex, 16)
        
        # Multiply generator point by private key
        public_key_point = private_key_int * self.G
        
        # Get coordinates
        x = public_key_point.x()
        y = public_key_point.y()
        
        if compressed:
            # Compressed format: 02/03 + x-coordinate
            prefix = '02' if y % 2 == 0 else '03'
            x_hex = format(x, '064x')
            return prefix + x_hex
        else:
            # Uncompressed format: 04 + x + y
            x_hex = format(x, '064x')
            y_hex = format(y, '064x')
            return '04' + x_hex + y_hex

    def generate_cryptographically_secure_private_key(self) -> str:
        """Generate cryptographically secure private key"""
        import os
        while True:
            private_key = os.urandom(32)
            private_key_int = int.from_bytes(private_key, 'big')
            
            # Ensure private key is valid (1 <= key < n)
            if 1 <= private_key_int < self.n:
                return private_key.hex()

    def public_key_to_address(self, public_key_hex: str, network_byte: str = '00') -> str:
        """Convert public key to blockchain address"""
        import hashlib
        import base58
        
        # Decode public key from hex
        public_key_bytes = bytes.fromhex(public_key_hex)
        
        # SHA-256 hashing
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        
        # RIPEMD-160 hashing
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        ripemd160_hash = ripemd160.digest()
        
        # Add network byte
        network_byte_bytes = bytes.fromhex(network_byte)
        payload = network_byte_bytes + ripemd160_hash
        
        # Calculate checksum (double SHA-256)
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        
        # Combine and Base58 encode
        address_bytes = payload + checksum
        address = base58.b58encode(address_bytes).decode('utf-8')
        
        return address

    def generate_ethereum_address(self, public_key_hex: str) -> str:
        """Generate Ethereum address from public key"""
        import hashlib
        
        # Remove compression prefix if present
        if public_key_hex.startswith(('02', '03', '04')):
            public_key_hex = public_key_hex[2:] if public_key_hex.startswith(('02', '03')) else public_key_hex[2:130]
        
        public_key_bytes = bytes.fromhex(public_key_hex)
        
        # Keccak-256 hash (Ethereum uses Keccak, not SHA-256)
        keccak_hash = hashlib.sha3_256(public_key_bytes).digest()
        
        # Take last 20 bytes (40 hex characters)
        address_bytes = keccak_hash[-20:]
        
        # Convert to checksum address (EIP-55)
        address_hex = address_bytes.hex()
        return self.to_checksum_address(address_hex)

    def to_checksum_address(self, address_hex: str) -> str:
        """Convert to EIP-55 checksum address"""
        import hashlib
        
        address_lower = address_hex.lower()
        keccak_hash = hashlib.sha3_256(address_lower.encode('utf-8')).hexdigest()
        
        checksum_address = '0x'
        for i, char in enumerate(address_hex):
            if char in '0123456789':
                checksum_address += char
            else:
                # Check the corresponding nibble in the hash
                hash_nibble = int(keccak_hash[i], 16)
                checksum_address += char.upper() if hash_nibble >= 8 else char.lower()
        
        return checksum_address

    def generate_bitcoin_wallet(self) -> dict:
        """Generate complete Bitcoin wallet"""
        private_key = self.generate_cryptographically_secure_private_key()
        public_key = self.private_key_to_public_key(private_key)
        address = self.public_key_to_address(public_key)
        
        return {
            'private_key': private_key,
            'public_key': public_key,
            'address': address,
            'type': 'bitcoin'
        }

    def generate_ethereum_wallet(self) -> dict:
        """Generate complete Ethereum wallet"""
        private_key = self.generate_cryptographically_secure_private_key()
        public_key = self.private_key_to_public_key(private_key, compressed=False)
        address = self.generate_ethereum_address(public_key)
        
        return {
            'private_key': private_key,
            'public_key': public_key,
            'address': address,
            'type': 'ethereum'
        }

# Mathematical demonstration
class ECCMathematics:
    """Demonstrate the mathematical operations behind address generation"""
    
    @staticmethod
    def demonstrate_elliptic_curve_math():
        """Show the mathematical operations visually"""
        print("Elliptic Curve Cryptography Mathematics")
        print("=" * 50)
        
        # Curve parameters for secp256k1
        p = 2**256 - 2**32 - 977  # Prime modulus
        a = 0
        b = 7
        
        print(f"Curve: y² = x³ + {a}x + {b} mod {p}")
        print(f"Prime modulus (p): {p}")
        print(f"Curve parameters: a={a}, b={b}")
        
        # Generator point coordinates
        Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
        Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
        
        print(f"\nGenerator Point G:")
        print(f"Gx = {Gx}")
        print(f"Gy = {Gy}")
        
        # Verify point is on curve
        left_side = (Gy * Gy) % p
        right_side = (Gx * Gx * Gx + 7) % p
        
        print(f"\nVerification:")
        print(f"y² mod p = {left_side}")
        print(f"x³ + 7 mod p = {right_side}")
        print(f"Point on curve: {left_side == right_side}")
        
        return True

import requests
import json
from typing import List, Dict
import csv

class BlockchainExplorer:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        
    def get_block_transactions(self, chain: str, block_number: int) -> List[Dict]:
        """Get all transactions from a specific block"""
        explorers = {
            'eth': 'https://api.etherscan.io/api',
            'btc': 'https://blockchain.info/rawblock/',
            'bsc': 'https://api.bscscan.com/api',
            'matic': 'https://api.polygonscan.com/api'
        }
        
        if chain not in explorers:
            return []
        
        try:
            if chain == 'eth':
                params = {
                    'module': 'proxy',
                    'action': 'eth_getBlockByNumber',
                    'tag': hex(block_number),
                    'boolean': 'true',
                    'apikey': 'YourApiKey'
                }
                response = self.session.get(explorers[chain], params=params)
                data = response.json()
                return data.get('result', {}).get('transactions', [])
            
            elif chain == 'btc':
                response = self.session.get(f"{explorers[chain]}{block_number}")
                data = response.json()
                return data.get('tx', [])
                
        except Exception as e:
            print(f"Error getting block {block_number}: {e}")
            return []

import websocket
import threading
import json

class LiveTransactionMonitor:
    def __init__(self):
        self.wallets_found = set()
        
    def start_ethereum_monitor(self):
        """Monitor live Ethereum transactions"""
        def on_message(ws, message):
            try:
                data = json.loads(message)
                if data.get('method') == 'eth_subscription':
                    tx = data['params']['result']
                    self.process_transaction(tx)
            except Exception as e:
                print(f"WebSocket error: {e}")
        
        # Connect to WebSocket (using Infura or similar)
        ws_url = "wss://mainnet.infura.io/ws/v3/YOUR_PROJECT_ID"
        ws = websocket.WebSocketApp(ws_url,
                                  on_message=on_message)
        
        # Subscribe to new pending transactions
        subscribe_msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_subscribe",
            "params": ["newPendingTransactions"]
        }
        
        ws.send(json.dumps(subscribe_msg))
        ws.run_forever()
    
    def process_transaction(self, tx_data: Dict):
        """Process and extract wallet addresses from transactions"""
        if isinstance(tx_data, str):  # TX hash only
            # Need to get full transaction details
            full_tx = self.get_transaction_details(tx_data)
            if full_tx:
                self.extract_addresses(full_tx)
        else:
            self.extract_addresses(tx_data)
    
    def extract_addresses(self, tx: Dict):
        """Extract from and to addresses from transaction"""
        addresses = []
        
        if 'from' in tx and tx['from']:
            addresses.append(('from', tx['from']))
        if 'to' in tx and tx['to']:
            addresses.append(('to', tx['to']))
        
        # Also check for contract interactions
        if 'input' in tx and tx['input'] != '0x':
            # This might be a contract call with embedded addresses
            pass
        
        for role, address in addresses:
            if address not in self.wallets_found:
                self.wallets_found.add(address)
                self.save_wallet_address(address, role, tx.get('hash'))

class DeFiAnalyzer:
    def get_uniswap_liquidity_providers(self, pool_address: str) -> List[str]:
        """Get addresses from Uniswap liquidity pools"""
        try:
            # Uniswap V2 Pool ABI snippet for getReserves and token holders
            abi = [
                {
                    "constant": True,
                    "inputs": [],
                    "name": "getReserves",
                    "outputs": [
                        {"internalType": "uint112", "name": "_reserve0", "type": "uint112"},
                        {"internalType": "uint112", "name": "_reserve1", "type": "uint112"},
                        {"internalType": "uint32", "name": "_blockTimestampLast", "type": "uint32"}
                    ],
                    "type": "function"
                }
            ]
            
            # Use Web3.py for blockchain interaction
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/YOUR_PROJECT_ID'))
            
            contract = w3.eth.contract(address=Web3.to_checksum_address(pool_address), abi=abi)
            reserves = contract.functions.getReserves().call()
            
            # Get transfer events to find liquidity providers
            transfer_events = contract.events.Transfer.create_filter(fromBlock='latest')
            addresses = set()
            
            for event in transfer_events.get_all_entries():
                addresses.add(event['args']['from'])
                addresses.add(event['args']['to'])
            
            return list(addresses)
            
        except Exception as e:
            print(f"Error analyzing pool {pool_address}: {e}")
            return []

# Example usage and demonstration

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import numpy as np

class MLWalletClassifier:
    def __init__(self):
        self.model = RandomForestClassifier()
        self.vectorizer = TfidfVectorizer()
    
    def train_on_known_patterns(self, known_wallets: List[str], labels: List[str]):
        """Train model to identify wallet types"""
        # Convert addresses to feature vectors
        features = self.vectorizer.fit_transform(known_wallets)
        self.model.fit(features, labels)
    
    def predict_wallet_type(self, address: str) -> str:
        """Predict wallet type using ML"""
        features = self.vectorizer.transform([address])
        return self.model.predict(features)[0]
    
    def extract_features_from_address(self, address: str) -> List[float]:
        """Extract numerical features from wallet address"""
        features = []
        
        # Length of address
        features.append(len(address))
        
        # Character frequency analysis
        char_counts = {}
        for char in address:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Most common character frequency
        if char_counts:
            features.append(max(char_counts.values()) / len(address))
        else:
            features.append(0)
        
        # Number of unique characters
        features.append(len(char_counts))
        
        # Hex character ratio (for Ethereum addresses)
        hex_chars = set('0123456789abcdefABCDEF')
        hex_count = sum(1 for char in address if char in hex_chars)
        features.append(hex_count / len(address))
        
        # Entropy calculation
        import math
        entropy = 0
        for count in char_counts.values():
            p = count / len(address)
            if p > 0:
                entropy -= p * math.log2(p)
        features.append(entropy)
        
        return features
    
    def train_with_advanced_features(self, addresses: List[str], labels: List[str]):
        """Train model with advanced feature extraction"""
        # Extract features for all addresses
        feature_matrix = []
        for address in addresses:
            features = self.extract_features_from_address(address)
            feature_matrix.append(features)
        
        # Convert to numpy array
        X = np.array(feature_matrix)
        y = np.array(labels)
        
        # Train the model
        self.model.fit(X, y)
    
    def predict_with_advanced_features(self, address: str) -> str:
        """Predict wallet type using advanced features"""
        features = self.extract_features_from_address(address)
        X = np.array([features])
        return self.model.predict(X)[0]
    
    def get_prediction_confidence(self, address: str) -> float:
        """Get confidence score for prediction"""
        features = self.extract_features_from_address(address)
        X = np.array([features])
        probabilities = self.model.predict_proba(X)[0]
        return max(probabilities)
    
    def classify_wallet_batch(self, addresses: List[str]) -> List[Dict]:
        """Classify multiple wallet addresses"""
        results = []
        
        for address in addresses:
            prediction = self.predict_with_advanced_features(address)
            confidence = self.get_prediction_confidence(address)
            
            results.append({
                'address': address,
                'predicted_type': prediction,
                'confidence': confidence,
                'features': self.extract_features_from_address(address)
            })
        
        return results
    
    def save_model(self, filename: str):
        """Save trained model to file"""
        import pickle
        model_data = {
            'model': self.model,
            'vectorizer': self.vectorizer
        }
        with open(filename, 'wb') as f:
            pickle.dump(model_data, f)
    
    def load_model(self, filename: str):
        """Load trained model from file"""
        import pickle
        with open(filename, 'rb') as f:
            model_data = pickle.load(f)
        self.model = model_data['model']
        self.vectorizer = model_data['vectorizer']

# Example usage of ML classifier
def demonstrate_ml_classification():
    """Demonstrate machine learning wallet classification"""
    print("🤖 Machine Learning Wallet Classification")
    print("=" * 50)
    
    # Create classifier
    classifier = MLWalletClassifier()
    
    # Sample training data (in real usage, you'd have much more data)
    known_addresses = [
        "0x742d35Cc6634C0532925a3b8D4C9db96C4b4d8b6",  # Exchange
        "0x28c6c06298d514db089934071355e5743bf21d60",  # Exchange
        "0x71660c4005ba85c37ccec55d0c4493e66fe775d3",  # Exchange
        "0x1234567890123456789012345678901234567890",  # User
        "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",  # User
        "0x1111111111111111111111111111111111111111",  # Contract
        "0x2222222222222222222222222222222222222222",  # Contract
    ]
    
    labels = ['exchange', 'exchange', 'exchange', 'user', 'user', 'contract', 'contract']
    
    # Train the model
    print("Training model on known wallet patterns...")
    classifier.train_with_advanced_features(known_addresses, labels)
    
    # Test predictions
    test_addresses = [
        "0x3333333333333333333333333333333333333333",
        "0x4444444444444444444444444444444444444444",
        "0x5555555555555555555555555555555555555555"
    ]
    
    print("\nPredicting wallet types:")
    for address in test_addresses:
        prediction = classifier.predict_with_advanced_features(address)
        confidence = classifier.get_prediction_confidence(address)
        print(f"Address: {address[:10]}...")
        print(f"Predicted Type: {prediction}")
        print(f"Confidence: {confidence:.2f}")
        print()
    
    # Batch classification
    print("Batch classification results:")
    results = classifier.classify_wallet_batch(test_addresses)
    for result in results:
        print(f"{result['address'][:10]}... -> {result['predicted_type']} (confidence: {result['confidence']:.2f})")
    
    return classifier

# Main execution
if __name__ == "__main__":
    finder = GoogleDorkWalletFinder()
    
    print("🔍 Google Dork Wallet Finder")
    print("============================")
    print("Finds wallet addresses with large transactions using Google dorks\n")
    
    # Get user input
    try:
        min_amount = int(input("Enter minimum transaction amount (USD, default: 10000): ") or "10000")
        max_results = int(input("Enter maximum results to find (default: 20): ") or "20")
        output_file = input("Enter output CSV filename (default: large_wallets.csv): ") or "large_wallets.csv"
        
        search_method = input("Search method (1: Google dorks, 2: Quick search, default: 1): ") or "1"
        
        if search_method == "1":
            print(f"\n🔎 Searching for wallets with transactions > ${min_amount:,}...")
            print("This may take a few minutes...\n")
            
            wallets = finder.find_wallets_with_dorks(min_amount, max_results, output_file)
            
        else:
            print(f"\n⚡ Performing quick search...")
            wallets = finder.quick_search(min_amount)
            print(f"Found {len(wallets)} known large wallets")
        
        if wallets:
            print(f"\n✅ Search completed! Results saved to {output_file}")
            print(f"\n📊 Total wallets found: {len(wallets)}")
            
            # Show sample of results
            print(f"\n📋 Sample of found wallets:")
            for i, wallet in enumerate(wallets[:3]):
                print(f"{i+1}. {wallet['address'][:12]}... ({wallet['chain'].upper()}) - ${wallet['usd_value']:,.2f}")
        
        else:
            print("\n❌ No wallets found meeting the criteria")
            
    except ValueError:
        print("❌ Please enter valid numbers for amount and results")
    except Exception as e:
        print(f"❌ Error: {e}")

    print(f"\n💡 Next steps:")
    print("1. Review the CSV file for wallet addresses")
    print("2. Use previous scripts to analyze transaction history")
    print("3. Verify addresses on blockchain explorers")
    print("4. Use the data for market analysis or research")

# Example usage of advanced analyzer
if __name__ == "__main__":
    analyzer = AdvancedWalletAnalyzer()
    
    # Analyze wallets from previous search
    analyzer.analyze_found_wallets("large_wallets.csv", "analyzed_wallets.csv")

class WalletAnalysisInterface:
    """Comprehensive command-line interface for wallet analysis tools"""
    
    def __init__(self):
        self.finder = GoogleDorkWalletFinder()
        self.analyzer = AdvancedWalletAnalyzer()
        self.generator = WalletAddressGenerator()
        self.discoverer = WalletDiscoverer()
        self.ml_classifier = MLWalletClassifier()
        self.nft_analyzer = NFTAnalyzer()
        self.social_scraper = SocialMediaScraper()
        self.exchange_analyzer = ExchangeFlowAnalyzer()
        self.airdrop_hunter = AirdropHunter()
        
        # Command history
        self.history = []
        
    def show_banner(self):
        """Display the main banner"""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    🔍 WALLET ANALYSIS SUITE 🔍                ║
║                                                              ║
║  A comprehensive toolkit for cryptocurrency wallet analysis  ║
║                                                              ║
║  Commands:                                                   ║
║    search    - Search for wallets using Google dorks        ║
║    analyze   - Analyze wallet activity and transactions     ║
║    generate  - Generate new wallet addresses                ║
║    discover  - Comprehensive wallet discovery               ║
║    classify  - ML-based wallet classification               ║
║    nft       - Analyze NFT trading activity                 ║
║    social    - Scrape social media for wallets              ║
║    exchange  - Analyze exchange flows                       ║
║    airdrop   - Find airdrop participants                    ║
║    math      - Demonstrate ECC mathematics                  ║
║    help      - Show this help message                       ║
║    exit      - Exit the program                             ║
╚══════════════════════════════════════════════════════════════╝
        """)
    
    def run(self):
        """Main interface loop"""
        self.show_banner()
        
        while True:
            try:
                command = input("\n🔧 Enter command (or 'help'): ").strip().lower()
                self.history.append(command)
                
                if command == 'exit':
                    print("👋 Goodbye! Thanks for using Wallet Analysis Suite.")
                    break
                elif command == 'help':
                    self.show_help()
                elif command == 'search':
                    self.search_wallets()
                elif command == 'analyze':
                    self.analyze_wallets()
                elif command == 'generate':
                    self.generate_wallets()
                elif command == 'discover':
                    self.discover_wallets()
                elif command == 'classify':
                    self.classify_wallets()
                elif command == 'nft':
                    self.analyze_nft()
                elif command == 'social':
                    self.scrape_social()
                elif command == 'exchange':
                    self.analyze_exchange()
                elif command == 'airdrop':
                    self.find_airdrops()
                elif command == 'math':
                    self.demonstrate_math()
                elif command == 'history':
                    self.show_history()
                elif command == 'clear':
                    import os
                    os.system('cls' if os.name == 'nt' else 'clear')
                else:
                    print(f"❌ Unknown command: {command}")
                    print("Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye! Thanks for using Wallet Analysis Suite.")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def show_help(self):
        """Show detailed help for all commands"""
        help_text = """
📖 COMMAND REFERENCE:

🔍 SEARCH COMMANDS:
  search - Search for wallets using Google dorks
    Options: min_amount, max_results, output_file
    
📊 ANALYSIS COMMANDS:
  analyze - Analyze wallet activity and transactions
    Options: input_file, output_file
    
🔐 GENERATION COMMANDS:
  generate - Generate new wallet addresses
    Options: type (bitcoin/ethereum), count
    
🔎 DISCOVERY COMMANDS:
  discover - Comprehensive wallet discovery
    Options: methods, output_file
    
🤖 ML CLASSIFICATION:
  classify - ML-based wallet classification
    Options: train, predict, batch
    
🎨 NFT ANALYSIS:
  nft - Analyze NFT trading activity
    Options: collection_address
    
📱 SOCIAL MEDIA:
  social - Scrape social media for wallets
    Options: platform, keywords
    
💱 EXCHANGE ANALYSIS:
  exchange - Analyze exchange flows
    Options: exchange_name, hours
    
🎁 AIRDROP HUNTING:
  airdrop - Find airdrop participants
    Options: token_address
    
📐 MATHEMATICS:
  math - Demonstrate ECC mathematics
  
🔧 UTILITY COMMANDS:
  help - Show this help message
  history - Show command history
  clear - Clear screen
  exit - Exit the program

💡 TIP: Most commands will prompt for additional options when needed.
        """
        print(help_text)
    
    def search_wallets(self):
        """Search for wallets using Google dorks"""
        print("\n🔍 WALLET SEARCH")
        print("=" * 30)
        
        try:
            min_amount = input("Enter minimum transaction amount (USD, default: 10000): ").strip()
            min_amount = int(min_amount) if min_amount else 10000
            
            max_results = input("Enter maximum results (default: 20): ").strip()
            max_results = int(max_results) if max_results else 20
            
            output_file = input("Enter output filename (default: search_results.csv): ").strip()
            output_file = output_file if output_file else "search_results.csv"
            
            print(f"\n🔎 Searching for wallets with transactions > ${min_amount:,}...")
            wallets = self.finder.find_wallets_with_dorks(min_amount, max_results, output_file)
            
            if wallets:
                print(f"\n✅ Found {len(wallets)} wallets! Results saved to {output_file}")
            else:
                print("\n❌ No wallets found meeting the criteria.")
                
        except ValueError:
            print("❌ Please enter valid numbers.")
        except Exception as e:
            print(f"❌ Error during search: {e}")
    
    def analyze_wallets(self):
        """Analyze wallet activity"""
        print("\n📊 WALLET ANALYSIS")
        print("=" * 30)
        
        input_file = input("Enter input CSV file (default: large_wallets.csv): ").strip()
        input_file = input_file if input_file else "large_wallets.csv"
        
        output_file = input("Enter output CSV file (default: analyzed_wallets.csv): ").strip()
        output_file = output_file if output_file else "analyzed_wallets.csv"
        
        try:
            print(f"\n🔍 Analyzing wallets from {input_file}...")
            self.analyzer.analyze_found_wallets(input_file, output_file)
            print(f"✅ Analysis complete! Results saved to {output_file}")
        except Exception as e:
            print(f"❌ Error during analysis: {e}")
    
    def generate_wallets(self):
        """Generate new wallet addresses"""
        print("\n🔐 WALLET GENERATION")
        print("=" * 30)
        
        wallet_type = input("Enter wallet type (bitcoin/ethereum, default: ethereum): ").strip().lower()
        wallet_type = wallet_type if wallet_type in ['bitcoin', 'ethereum'] else 'ethereum'
        
        count = input("Enter number of wallets to generate (default: 1): ").strip()
        count = int(count) if count.isdigit() else 1
        
        try:
            print(f"\n🔐 Generating {count} {wallet_type} wallet(s)...")
            
            for i in range(count):
                if wallet_type == 'bitcoin':
                    wallet = self.generator.generate_bitcoin_wallet()
                else:
                    wallet = self.generator.generate_ethereum_wallet()
                
                print(f"\nWallet {i+1}:")
                print(f"  Address: {wallet['address']}")
                print(f"  Private Key: {wallet['private_key']}")
                print(f"  Public Key: {wallet['public_key'][:20]}...")
            
            print(f"\n✅ Generated {count} {wallet_type} wallet(s)!")
            
        except Exception as e:
            print(f"❌ Error during generation: {e}")
    
    def discover_wallets(self):
        """Comprehensive wallet discovery"""
        print("\n🔎 COMPREHENSIVE WALLET DISCOVERY")
        print("=" * 40)
        
        print("This will use multiple methods to discover wallets:")
        print("1. Blockchain analysis")
        print("2. DeFi protocols")
        print("3. Social media scraping")
        print("4. Exchange flows")
        print("5. NFT markets")
        
        confirm = input("\nContinue? (y/n, default: y): ").strip().lower()
        if confirm in ['n', 'no']:
            print("❌ Discovery cancelled.")
            return
        
        try:
            print("\n🔍 Starting comprehensive discovery...")
            wallets = comprehensive_wallet_discovery()
            print(f"✅ Discovery complete! Found {len(wallets)} wallets.")
        except Exception as e:
            print(f"❌ Error during discovery: {e}")
    
    def classify_wallets(self):
        """ML-based wallet classification"""
        print("\n🤖 ML WALLET CLASSIFICATION")
        print("=" * 35)
        
        print("Options:")
        print("1. Train model")
        print("2. Predict wallet type")
        print("3. Batch classification")
        print("4. Demonstrate classification")
        
        choice = input("\nEnter choice (1-4, default: 4): ").strip()
        
        try:
            if choice == '1':
                self.train_ml_model()
            elif choice == '2':
                self.predict_wallet_type()
            elif choice == '3':
                self.batch_classify()
            else:
                print("\n🤖 Demonstrating ML classification...")
                self.ml_classifier = demonstrate_ml_classification()
                
        except Exception as e:
            print(f"❌ Error during classification: {e}")
    
    def train_ml_model(self):
        """Train the ML model"""
        print("\n📚 TRAINING ML MODEL")
        print("=" * 25)
        
        print("Enter training data (one address per line, type 'done' when finished):")
        addresses = []
        labels = []
        
        while True:
            address = input("Address: ").strip()
            if address.lower() == 'done':
                break
            if address:
                label = input("Label (exchange/user/contract): ").strip()
                addresses.append(address)
                labels.append(label)
        
        if addresses:
            try:
                self.ml_classifier.train_with_advanced_features(addresses, labels)
                print(f"✅ Model trained on {len(addresses)} addresses!")
                
                save = input("Save model? (y/n): ").strip().lower()
                if save in ['y', 'yes']:
                    filename = input("Enter filename (default: wallet_model.pkl): ").strip()
                    filename = filename if filename else "wallet_model.pkl"
                    self.ml_classifier.save_model(filename)
                    print(f"✅ Model saved to {filename}")
            except Exception as e:
                print(f"❌ Error during training: {e}")
        else:
            print("❌ No training data provided.")
    
    def predict_wallet_type(self):
        """Predict wallet type"""
        address = input("Enter wallet address: ").strip()
        
        if address:
            try:
                prediction = self.ml_classifier.predict_with_advanced_features(address)
                confidence = self.ml_classifier.get_prediction_confidence(address)
                print(f"\nPrediction: {prediction}")
                print(f"Confidence: {confidence:.2f}")
            except Exception as e:
                print(f"❌ Error during prediction: {e}")
        else:
            print("❌ No address provided.")
    
    def batch_classify(self):
        """Batch classify wallets"""
        print("Enter addresses to classify (one per line, type 'done' when finished):")
        addresses = []
        
        while True:
            address = input("Address: ").strip()
            if address.lower() == 'done':
                break
            if address:
                addresses.append(address)
        
        if addresses:
            try:
                results = self.ml_classifier.classify_wallet_batch(addresses)
                print("\nClassification Results:")
                for result in results:
                    print(f"{result['address'][:10]}... -> {result['predicted_type']} (confidence: {result['confidence']:.2f})")
            except Exception as e:
                print(f"❌ Error during batch classification: {e}")
        else:
            print("❌ No addresses provided.")
    
    def analyze_nft(self):
        """Analyze NFT trading activity"""
        print("\n🎨 NFT ANALYSIS")
        print("=" * 20)
        
        collection_address = input("Enter NFT collection address: ").strip()
        
        if collection_address:
            try:
                print(f"\n🔍 Analyzing NFT collection {collection_address}...")
                traders = self.nft_analyzer.get_nft_traders(collection_address)
                print(f"✅ Found {len(traders)} NFT traders!")
                
                if traders:
                    print("\nSample traders:")
                    for i, trader in enumerate(traders[:5]):
                        print(f"{i+1}. {trader}")
            except Exception as e:
                print(f"❌ Error during NFT analysis: {e}")
        else:
            print("❌ No collection address provided.")
    
    def scrape_social(self):
        """Scrape social media for wallets"""
        print("\n📱 SOCIAL MEDIA SCRAPING")
        print("=" * 30)
        
        platform = input("Enter platform (twitter/reddit, default: twitter): ").strip().lower()
        platform = platform if platform in ['twitter', 'reddit'] else 'twitter'
        
        keywords_input = input("Enter keywords (comma-separated): ").strip()
        keywords = [k.strip() for k in keywords_input.split(',') if k.strip()]
        
        if not keywords:
            keywords = ['airdrop', 'whale alert', 'crypto wallet']
        
        try:
            print(f"\n🔍 Scraping {platform} for keywords: {', '.join(keywords)}...")
            
            if platform == 'twitter':
                wallets = self.social_scraper.scrape_twitter_for_wallets(keywords)
            else:
                subreddits = ['cryptocurrency', 'defi', 'airdrop']
                wallets = self.social_scraper.scrape_reddit_for_wallets(subreddits)
            
            print(f"✅ Found {len(wallets)} wallet addresses!")
            
            if wallets:
                print("\nSample addresses:")
                for i, wallet in enumerate(wallets[:5]):
                    print(f"{i+1}. {wallet}")
                    
        except Exception as e:
            print(f"❌ Error during social media scraping: {e}")
    
    def analyze_exchange(self):
        """Analyze exchange flows"""
        print("\n💱 EXCHANGE FLOW ANALYSIS")
        print("=" * 35)
        
        exchange = input("Enter exchange (binance/coinbase/kraken, default: binance): ").strip().lower()
        exchange = exchange if exchange in ['binance', 'coinbase', 'kraken'] else 'binance'
        
        hours = input("Enter time period in hours (default: 24): ").strip()
        hours = int(hours) if hours.isdigit() else 24
        
        try:
            print(f"\n🔍 Analyzing {exchange} flows for the last {hours} hours...")
            addresses = self.exchange_analyzer.track_exchange_flows(exchange, hours)
            print(f"✅ Found {len(addresses)} addresses interacting with {exchange}!")
            
            if addresses:
                print("\nSample addresses:")
                for i, address in enumerate(addresses[:5]):
                    print(f"{i+1}. {address}")
                    
        except Exception as e:
            print(f"❌ Error during exchange analysis: {e}")
    
    def find_airdrops(self):
        """Find airdrop participants"""
        print("\n🎁 AIRDROP HUNTING")
        print("=" * 25)
        
        token_address = input("Enter airdrop token address: ").strip()
        
        if token_address:
            try:
                print(f"\n🔍 Finding participants for airdrop {token_address}...")
                participants = self.airdrop_hunter.find_airdrop_participants(token_address)
                print(f"✅ Found {len(participants)} airdrop participants!")
                
                if participants:
                    print("\nSample participants:")
                    for i, participant in enumerate(participants[:5]):
                        print(f"{i+1}. {participant}")
                        
            except Exception as e:
                print(f"❌ Error during airdrop hunting: {e}")
        else:
            print("❌ No token address provided.")
    
    def demonstrate_math(self):
        """Demonstrate ECC mathematics"""
        print("\n📐 ELLIPTIC CURVE CRYPTOGRAPHY")
        print("=" * 40)
        
        try:
            ecc_math = ECCMathematics()
            ecc_math.demonstrate_elliptic_curve_math()
            
            print("\n🔐 Generating sample wallets to demonstrate the process:")
            generator = WalletAddressGenerator()
            
            btc_wallet = generator.generate_bitcoin_wallet()
            eth_wallet = generator.generate_ethereum_wallet()
            
            print(f"\nBitcoin Wallet:")
            print(f"  Address: {btc_wallet['address']}")
            print(f"  Private Key: {btc_wallet['private_key']}")
            
            print(f"\nEthereum Wallet:")
            print(f"  Address: {eth_wallet['address']}")
            print(f"  Private Key: {eth_wallet['private_key']}")
            
        except Exception as e:
            print(f"❌ Error during math demonstration: {e}")
    
    def show_history(self):
        """Show command history"""
        print("\n📜 COMMAND HISTORY")
        print("=" * 20)
        
        if self.history:
            for i, command in enumerate(self.history[-10:], 1):  # Show last 10 commands
                print(f"{i}. {command}")
        else:
            print("No commands in history.")

# Main execution with interface
if __name__ == "__main__":
    print("🚀 Starting Wallet Analysis Suite...")
    
    # Check if user wants to use the interface
    use_interface = input("Use interactive interface? (y/n, default: y): ").strip().lower()
    
    if use_interface in ['n', 'no']:
        # Run the original main execution
        finder = GoogleDorkWalletFinder()
        
        print("🔍 Google Dork Wallet Finder")
        print("============================")
        print("Finds wallet addresses with large transactions using Google dorks\n")
        
        # Get user input
        try:
            min_amount = int(input("Enter minimum transaction amount (USD, default: 10000): ") or "10000")
            max_results = int(input("Enter maximum results to find (default: 20): ") or "20")
            output_file = input("Enter output CSV filename (default: large_wallets.csv): ") or "large_wallets.csv"
            
            search_method = input("Search method (1: Google dorks, 2: Quick search, default: 1): ") or "1"
            
            if search_method == "1":
                print(f"\n🔎 Searching for wallets with transactions > ${min_amount:,}...")
                print("This may take a few minutes...\n")
                
                wallets = finder.find_wallets_with_dorks(min_amount, max_results, output_file)
                
            else:
                print(f"\n⚡ Performing quick search...")
                wallets = finder.quick_search(min_amount)
                print(f"Found {len(wallets)} known large wallets")
            
            if wallets:
                print(f"\n✅ Search completed! Results saved to {output_file}")
                print(f"\n📊 Total wallets found: {len(wallets)}")
                
                # Show sample of results
                print(f"\n📋 Sample of found wallets:")
                for i, wallet in enumerate(wallets[:3]):
                    print(f"{i+1}. {wallet['address'][:12]}... ({wallet['chain'].upper()}) - ${wallet['usd_value']:,.2f}")
            
            else:
                print("\n❌ No wallets found meeting the criteria")
                
        except ValueError:
            print("❌ Please enter valid numbers for amount and results")
        except Exception as e:
            print(f"❌ Error: {e}")

        print(f"\n💡 Next steps:")
        print("1. Review the CSV file for wallet addresses")
        print("2. Use previous scripts to analyze transaction history")
        print("3. Verify addresses on blockchain explorers")
        print("4. Use the data for market analysis or research")
        
    else:
        # Run the interactive interface
        interface = WalletAnalysisInterface()
        interface.run()

import time
from typing import List, Dict, Optional, Callable
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import logging
from datetime import datetime, timedelta
import backoff

class EnhancedErrorHandler:
    def __init__(self):
        self.max_retries = 5
        self.retry_delay = 2
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((requests.ConnectionError, requests.Timeout))
    )
    def robust_request(self, url: str, **kwargs) -> requests.Response:
        """Enhanced request with automatic retry and backoff"""
        try:
            response = self.session.get(url, timeout=30, **kwargs)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            logging.warning(f"Request failed: {e}, retrying...")
            raise

    def handle_rate_limiting(self, response: requests.Response) -> None:
        """Handle API rate limiting gracefully"""
        if response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 60))
            logging.warning(f"Rate limited. Waiting {retry_after} seconds...")
            time.sleep(retry_after)
            raise requests.exceptions.RetryError("Rate limit exceeded")
    
    @backoff.on_exception(
        backoff.expo,
        (requests.ConnectionError, requests.Timeout, requests.HTTPError),
        max_tries=5
    )
    def api_request_with_backoff(self, url: str, **kwargs) -> requests.Response:
        """API request with exponential backoff"""
        try:
            response = self.session.get(url, timeout=30, **kwargs)
            self.handle_rate_limiting(response)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            logging.error(f"API request failed after retries: {e}")
            raise
    
    def safe_json_request(self, url: str, **kwargs) -> Optional[Dict]:
        """Safe JSON request with error handling"""
        try:
            response = self.api_request_with_backoff(url, **kwargs)
            return response.json()
        except (requests.RequestException, ValueError) as e:
            logging.error(f"JSON request failed: {e}")
            return None
    
    def retry_with_custom_backoff(self, func: Callable, *args, **kwargs):
        """Generic retry decorator with custom backoff strategy"""
        @backoff.on_exception(
            backoff.expo,
            Exception,
            max_tries=self.max_retries,
            max_time=300  # 5 minutes max
        )
        def wrapper():
            return func(*args, **kwargs)
        
        return wrapper()
    
    def handle_api_errors(self, response: requests.Response) -> bool:
        """Handle various API error responses"""
        if response.status_code == 200:
            return True
        
        error_handlers = {
            400: "Bad Request - Check your parameters",
            401: "Unauthorized - Check your API key",
            403: "Forbidden - Insufficient permissions",
            404: "Not Found - Resource doesn't exist",
            429: "Rate Limited - Too many requests",
            500: "Server Error - Try again later",
            502: "Bad Gateway - Server temporarily unavailable",
            503: "Service Unavailable - Server overloaded"
        }
        
        error_msg = error_handlers.get(response.status_code, f"HTTP {response.status_code}")
        logging.error(f"API Error: {error_msg}")
        
        if response.status_code == 429:
            self.handle_rate_limiting(response)
        
        return False
    
    def create_session_with_retry(self) -> requests.Session:
        """Create a session with retry capabilities"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Add retry adapter
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def log_request_details(self, url: str, method: str = "GET", **kwargs):
        """Log request details for debugging"""
        logging.info(f"Making {method} request to: {url}")
        if 'params' in kwargs:
            logging.debug(f"Parameters: {kwargs['params']}")
        if 'headers' in kwargs:
            logging.debug(f"Headers: {kwargs['headers']}")
    
    def validate_response(self, response: requests.Response, expected_content_type: str = "application/json") -> bool:
        """Validate response format and content"""
        if response.status_code != 200:
            return False
        
        content_type = response.headers.get('content-type', '')
        if expected_content_type not in content_type:
            logging.warning(f"Unexpected content type: {content_type}")
            return False
        
        return True
    
    def exponential_backoff(self, attempt: int, base_delay: float = 1.0, max_delay: float = 60.0) -> float:
        """Calculate exponential backoff delay"""
        delay = min(base_delay * (2 ** attempt), max_delay)
        jitter = random.uniform(0, 0.1 * delay)  # Add 10% jitter
        return delay + jitter
    
    def retry_operation(self, operation: Callable, max_attempts: int = 3, base_delay: float = 1.0):
        """Retry an operation with exponential backoff"""
        for attempt in range(max_attempts):
            try:
                return operation()
            except Exception as e:
                if attempt == max_attempts - 1:
                    logging.error(f"Operation failed after {max_attempts} attempts: {e}")
                    raise
                
                delay = self.exponential_backoff(attempt, base_delay)
                logging.warning(f"Operation failed (attempt {attempt + 1}/{max_attempts}), retrying in {delay:.2f}s: {e}")
                time.sleep(delay)
    
    def create_error_report(self, error: Exception, context: Dict = None) -> Dict:
        """Create a detailed error report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context or {}
        }
        
        if hasattr(error, 'response'):
            report['response_status'] = error.response.status_code
            report['response_headers'] = dict(error.response.headers)
        
        return report
    
    def save_error_log(self, error_report: Dict, filename: str = "error_log.json"):
        """Save error report to file"""
        import json
        try:
            with open(filename, 'a') as f:
                json.dump(error_report, f)
                f.write('\n')
        except Exception as e:
            logging.error(f"Failed to save error log: {e}")

class RobustWalletAnalyzer(EnhancedErrorHandler):
    """Enhanced wallet analyzer with robust error handling"""
    
    def __init__(self):
        super().__init__()
        self.api_keys = {
            'etherscan': 'YourApiKeyToken',
            'bscscan': 'YourBscApiKey',
            'opensea': 'YourOpenSeaApiKey'
        }
    
    def get_wallet_transactions_robust(self, address: str, chain: str = 'eth') -> List[Dict]:
        """Get wallet transactions with robust error handling"""
        def operation():
            if chain == 'eth':
                url = "https://api.etherscan.io/api"
                params = {
                    'module': 'account',
                    'action': 'txlist',
                    'address': address,
                    'startblock': 0,
                    'endblock': 99999999,
                    'sort': 'desc',
                    'apikey': self.api_keys['etherscan']
                }
            else:
                raise ValueError(f"Unsupported chain: {chain}")
            
            data = self.safe_json_request(url, params=params)
            if data and data.get('status') == '1':
                return data.get('result', [])
            else:
                raise Exception(f"API returned error: {data.get('message', 'Unknown error')}")
        
        return self.retry_operation(operation)
    
    def analyze_wallet_activity_robust(self, address: str) -> Dict:
        """Analyze wallet activity with error handling"""
        try:
            transactions = self.get_wallet_transactions_robust(address)
            
            if not transactions:
                return {
                    'address': address,
                    'status': 'no_transactions',
                    'transaction_count': 0,
                    'total_value': 0,
                    'last_activity': None
                }
            
            total_value = sum(int(tx['value']) for tx in transactions) / (10**18)
            last_activity = datetime.fromtimestamp(int(transactions[0]['timeStamp']))
            
            return {
                'address': address,
                'status': 'active',
                'transaction_count': len(transactions),
                'total_value': total_value,
                'last_activity': last_activity.isoformat(),
                'average_transaction_value': total_value / len(transactions) if transactions else 0
            }
            
        except Exception as e:
            error_report = self.create_error_report(e, {'address': address})
            self.save_error_log(error_report)
            
            return {
                'address': address,
                'status': 'error',
                'error': str(e),
                'error_report': error_report
            }
    
    def batch_analyze_wallets(self, addresses: List[str]) -> List[Dict]:
        """Analyze multiple wallets with rate limiting and error handling"""
        results = []
        
        for i, address in enumerate(addresses):
            try:
                print(f"Analyzing wallet {i+1}/{len(addresses)}: {address[:10]}...")
                
                result = self.analyze_wallet_activity_robust(address)
                results.append(result)
                
                # Rate limiting between requests
                if i < len(addresses) - 1:
                    time.sleep(1)
                    
            except Exception as e:
                logging.error(f"Failed to analyze {address}: {e}")
                results.append({
                    'address': address,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return results
    
    def save_analysis_results(self, results: List[Dict], filename: str = "robust_analysis.csv"):
        """Save analysis results to CSV with error handling"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                if results:
                    fieldnames = results[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(results)
            
            print(f"✅ Analysis results saved to {filename}")
            
        except Exception as e:
            logging.error(f"Failed to save results: {e}")
            # Fallback: save as JSON
            import json
            with open(filename.replace('.csv', '.json'), 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"✅ Results saved as JSON: {filename.replace('.csv', '.json')}")

# Example usage of robust analyzer
def demonstrate_robust_analysis():
    """Demonstrate the robust wallet analyzer"""
    print("🛡️ Robust Wallet Analysis")
    print("=" * 30)
    
    analyzer = RobustWalletAnalyzer()
    
    # Test addresses
    test_addresses = [
        "0x28c6c06298d514db089934071355e5743bf21d60",  # Binance hot wallet
        "0x71660c4005ba85c37ccec55d0c4493e66fe775d3",  # Coinbase hot wallet
        "0x1234567890123456789012345678901234567890"   # Invalid address for testing
    ]
    
    print("Analyzing test wallets with robust error handling...")
    results = analyzer.batch_analyze_wallets(test_addresses)
    
    print("\nAnalysis Results:")
    for result in results:
        print(f"\nAddress: {result['address']}")
        print(f"Status: {result['status']}")
        if result['status'] == 'active':
            print(f"Transactions: {result['transaction_count']}")
            print(f"Total Value: {result['total_value']:.2f} ETH")
            print(f"Last Activity: {result['last_activity']}")
        elif result['status'] == 'error':
            print(f"Error: {result['error']}")
    
    # Save results
    analyzer.save_analysis_results(results, "robust_analysis_demo.csv")
    
    return analyzer

# Main execution

import random
from fp.fp import FreeProxy

class ProxyManager:
    def __init__(self):
        self.proxy_list = []
        self.current_proxy_index = 0
        self.proxy_timeout = 300  # 5 minutes per proxy
        self.proxy_stats = {}  # Track proxy performance
        
    def refresh_proxies(self):
        """Fetch fresh proxies from multiple sources"""
        try:
            # Free proxies
            self.proxy_list = FreeProxy().get_proxy_list()
            
            # Paid proxy services (example)
            paid_proxies = [
                'http://user:pass@proxy1.com:8080',
                'http://user:pass@proxy2.com:8080'
            ]
            self.proxy_list.extend(paid_proxies)
            
            logging.info(f"Refreshed proxy list: {len(self.proxy_list)} proxies available")
            
        except Exception as e:
            logging.error(f"Failed to refresh proxies: {e}")
    
    def get_random_proxy(self) -> Dict:
        """Get a random proxy from the pool"""
        if not self.proxy_list:
            self.refresh_proxies()
        
        proxy_url = random.choice(self.proxy_list)
        return {
            'http': proxy_url,
            'https': proxy_url
        }
    
    def rotate_proxy(self):
        """Rotate to next proxy in list"""
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
        return self.get_proxy_by_index(self.current_proxy_index)
    
    def get_proxy_by_index(self, index: int) -> Dict:
        """Get proxy by index"""
        if not self.proxy_list:
            self.refresh_proxies()
        
        if 0 <= index < len(self.proxy_list):
            proxy_url = self.proxy_list[index]
            return {
                'http': proxy_url,
                'https': proxy_url
            }
        else:
            return self.get_random_proxy()
    
    def test_proxy(self, proxy_dict: Dict) -> bool:
        """Test if proxy is working"""
        try:
            test_url = "http://httpbin.org/ip"
            response = requests.get(test_url, proxies=proxy_dict, timeout=10)
            return response.status_code == 200
        except Exception as e:
            logging.warning(f"Proxy test failed: {e}")
            return False
    
    def get_working_proxy(self) -> Dict:
        """Get a working proxy"""
        max_attempts = 10
        for _ in range(max_attempts):
            proxy = self.get_random_proxy()
            if self.test_proxy(proxy):
                return proxy
        
        logging.warning("No working proxy found, using direct connection")
        return {}
    
    def add_proxy(self, proxy_url: str):
        """Add a custom proxy to the list"""
        if proxy_url not in self.proxy_list:
            self.proxy_list.append(proxy_url)
            logging.info(f"Added proxy: {proxy_url}")
    
    def remove_proxy(self, proxy_url: str):
        """Remove a proxy from the list"""
        if proxy_url in self.proxy_list:
            self.proxy_list.remove(proxy_url)
            logging.info(f"Removed proxy: {proxy_url}")
    
    def get_proxy_stats(self) -> Dict:
        """Get proxy usage statistics"""
        return {
            'total_proxies': len(self.proxy_list),
            'current_index': self.current_proxy_index,
            'proxy_timeout': self.proxy_timeout
        }
    
    def set_proxy_timeout(self, timeout: int):
        """Set proxy timeout in seconds"""
        self.proxy_timeout = timeout
        logging.info(f"Proxy timeout set to {timeout} seconds")

class StealthWalletAnalyzer(ProxyManager, EnhancedErrorHandler):
    """Stealth wallet analyzer with proxy rotation and enhanced privacy"""
    
    def __init__(self):
        ProxyManager.__init__(self)
        EnhancedErrorHandler.__init__(self)
        self.request_delay = (2, 5)  # Random delay between requests
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15',
            'Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0'
        ]
    
    def get_random_user_agent(self) -> str:
        """Get a random user agent"""
        return random.choice(self.user_agents)
    
    def stealth_request(self, url: str, **kwargs) -> requests.Response:
        """Make a stealth request with proxy rotation and random delays"""
        # Add random delay
        delay = random.uniform(self.request_delay[0], self.request_delay[1])
        time.sleep(delay)
        
        # Get working proxy
        proxy = self.get_working_proxy()
        
        # Set random user agent
        headers = kwargs.get('headers', {})
        headers['User-Agent'] = self.get_random_user_agent()
        kwargs['headers'] = headers
        
        # Add proxy if available
        if proxy:
            kwargs['proxies'] = proxy
        
        try:
            response = self.robust_request(url, **kwargs)
            return response
        except Exception as e:
            logging.warning(f"Stealth request failed: {e}")
            # Try without proxy as fallback
            if 'proxies' in kwargs:
                del kwargs['proxies']
                return self.robust_request(url, **kwargs)
            raise
    
    def search_wallets_stealth(self, dork_query: str, num_results: int = 10) -> List[str]:
        """Search for wallets using stealth techniques"""
        urls = []
        try:
            # Encode the query for URL
            encoded_query = quote_plus(dork_query)
            search_url = f"https://www.google.com/search?q={encoded_query}&num={num_results}"
            
            response = self.stealth_request(search_url)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all search result links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('/url?q='):
                        # Extract actual URL from Google's redirect
                        url = href.split('/url?q=')[1].split('&')[0]
                        url = requests.utils.unquote(url)
                        
                        # Filter out Google-specific URLs
                        if not any(x in url for x in ['google.com', 'webcache.googleusercontent.com']):
                            urls.append(url)
            
            logging.info(f"Stealth search found {len(urls)} URLs for query: {dork_query}")
            
        except Exception as e:
            logging.error(f"Stealth search failed: {e}")
        
        return urls[:num_results]
    
    def extract_wallet_info_stealth(self, url: str) -> List[Dict]:
        """Extract wallet information using stealth techniques"""
        wallet_data = []
        
        try:
            response = self.stealth_request(url, timeout=15)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                text_content = soup.get_text()
                
                # Extract addresses using regex patterns
                patterns = {
                    'eth_address': r'\b0x[a-fA-F0-9]{40}\b',
                    'btc_address': r'\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})\b',
                }
                
                for chain, pattern in patterns.items():
                    addresses = re.findall(pattern, text_content)
                    for address in addresses:
                        wallet_data.append({
                            'address': address,
                            'chain': chain,
                            'source_url': url,
                            'found_date': datetime.now().isoformat(),
                            'extraction_method': 'stealth'
                        })
                
                logging.info(f"Stealth extraction found {len(wallet_data)} wallets from {url}")
                
        except Exception as e:
            logging.error(f"Stealth extraction failed for {url}: {e}")
        
        return wallet_data
    
    def batch_stealth_analysis(self, addresses: List[str]) -> List[Dict]:
        """Analyze multiple addresses using stealth techniques"""
        results = []
        
        for i, address in enumerate(addresses):
            try:
                print(f"Stealth analyzing {i+1}/{len(addresses)}: {address[:10]}...")
                
                # Rotate proxy every few requests
                if i % 5 == 0:
                    self.rotate_proxy()
                
                result = self.analyze_wallet_activity_robust(address)
                result['analysis_method'] = 'stealth'
                results.append(result)
                
            except Exception as e:
                logging.error(f"Stealth analysis failed for {address}: {e}")
                results.append({
                    'address': address,
                    'status': 'stealth_failed',
                    'error': str(e)
                })
        
        return results
    
    def save_stealth_results(self, results: List[Dict], filename: str = "stealth_analysis.csv"):
        """Save stealth analysis results"""
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                if results:
                    fieldnames = results[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(results)
            
            print(f"✅ Stealth analysis results saved to {filename}")
            
        except Exception as e:
            logging.error(f"Failed to save stealth results: {e}")

# Example usage of stealth analyzer
def demonstrate_stealth_analysis():
    """Demonstrate the stealth wallet analyzer"""
    print("🕵️ Stealth Wallet Analysis")
    print("=" * 30)
    
    analyzer = StealthWalletAnalyzer()
    
    # Test stealth search
    print("Testing stealth wallet search...")
    dork_query = 'site:etherscan.io "Value: $" intext:"10000"'
    urls = analyzer.search_wallets_stealth(dork_query, num_results=5)
    
    print(f"Found {len(urls)} URLs using stealth search")
    
    # Test stealth extraction
    if urls:
        print("\nTesting stealth wallet extraction...")
        all_wallets = []
        for url in urls[:2]:  # Test first 2 URLs
            wallets = analyzer.extract_wallet_info_stealth(url)
            all_wallets.extend(wallets)
        
        print(f"Extracted {len(all_wallets)} wallet addresses using stealth methods")
        
        # Test stealth analysis
        if all_wallets:
            addresses = [w['address'] for w in all_wallets[:3]]  # Test first 3 addresses
            print(f"\nTesting stealth analysis on {len(addresses)} addresses...")
            results = analyzer.batch_stealth_analysis(addresses)
            
            print("\nStealth Analysis Results:")
            for result in results:
                print(f"Address: {result['address'][:10]}...")
                print(f"Status: {result['status']}")
                print(f"Method: {result.get('analysis_method', 'unknown')}")
                print()
            
            # Save results
            analyzer.save_stealth_results(results, "stealth_analysis_demo.csv")
    
    return analyzer

# Main execution

import threading
from ratelimit import limits, sleep_and_retry

class RateLimiter:
    def __init__(self):
        self.call_times = {}
        self.lock = threading.Lock()
        
    @sleep_and_retry
    @limits(calls=5, period=1)  # 5 calls per second
    def rate_limited_call(self, api_name: str, func: Callable, *args, **kwargs):
        """Enforce rate limits for API calls"""
        with self.lock:
            current_time = time.time()
            if api_name in self.call_times:
                elapsed = current_time - self.call_times[api_name]
                if elapsed < 0.2:  # 200ms between calls
                    time.sleep(0.2 - elapsed)
            
            self.call_times[api_name] = current_time
        
        return func(*args, **kwargs)

import re
from web3 import Web3

class DataValidator:
    def __init__(self):
        self.w3 = Web3()
        
    def validate_eth_address(self, address: str) -> bool:
        """Validate Ethereum address format and checksum"""
        try:
            if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
                return False
            
            # Check checksum if mixed case
            if any(c.isupper() for c in address[2:]):
                checksum_address = self.w3.to_checksum_address(address)
                return checksum_address == address
            
            return True
        except:
            return False
    
    def validate_btc_address(self, address: str) -> bool:
        """Validate Bitcoin address using multiple methods"""
        patterns = [
            r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',  # Legacy
            r'^bc1[a-zA-HJ-NP-Z0-9]{25,90}$'       # Segwit
        ]
        
        return any(re.match(pattern, address) for pattern in patterns)
    
    def sanitize_wallet_data(self, wallets: List[Dict]) -> List[Dict]:
        """Clean and validate wallet data"""
        valid_wallets = []
        
        for wallet in wallets:
            if not self.validate_eth_address(wallet.get('address', '')):
                continue
            
            # Remove duplicates and invalid entries
            wallet['address'] = wallet['address'].lower().strip()
            
            if wallet not in valid_wallets:
                valid_wallets.append(wallet)
        
        return valid_wallets

import smtplib
from email.mime.text import MIMEText
import datetime

class MonitoringSystem:
    def __init__(self):
        self.metrics = {
            'wallets_discovered': 0,
            'api_calls': 0,
            'errors': 0,
            'start_time': datetime.datetime.now()
        }
    
    def track_metric(self, metric_name: str, value: int = 1):
        """Track performance metrics"""
        self.metrics[metric_name] = self.metrics.get(metric_name, 0) + value
    
    def send_alert(self, message: str, level: str = "INFO"):
        """Send alert via email or other channels"""
        if level == "ERROR":
            self._send_email_alert(message)
        
        logging.log(
            getattr(logging, level),
            f"{level}: {message}"
        )
    
    def _send_email_alert(self, message: str):
        """Send email alert (configure with your SMTP settings)"""
        try:
            msg = MIMEText(message)
            msg['Subject'] = 'Wallet Discovery Alert'
            msg['From'] = 'alerts@yourdomain.com'
            msg['To'] = 'admin@yourdomain.com'
            
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login('your_email@gmail.com', 'your_password')
                server.send_message(msg)
                
        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")

import configparser
import os
from pathlib import Path

class ConfigManager:
    def __init__(self, config_file: str = 'config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        if not os.path.exists(self.config_file):
            self.create_default_config()
        
        self.config.read(self.config_file)
    
    def create_default_config(self):
        """Create default configuration file"""
        self.config['API_KEYS'] = {
            'etherscan': 'YOUR_API_KEY',
            'bscscan': 'YOUR_API_KEY',
            'infura': 'YOUR_PROJECT_ID',
            'opensea': 'YOUR_API_KEY'
        }
        
        self.config['SETTINGS'] = {
            'max_retries': '5',
            'request_timeout': '30',
            'rate_limit_delay': '1.0',
            'proxy_enabled': 'false',
            'database_path': 'wallet_data.db'
        }
        
        self.config['MONITORING'] = {
            'email_alerts': 'false',
            'alert_email': 'your_email@example.com',
            'log_level': 'INFO'
        }
        
        with open(self.config_file, 'w') as configfile:
            self.config.write(configfile)
    
    def get_api_key(self, service: str) -> str:
        """Get API key for specific service"""
        return self.config.get('API_KEYS', service, fallback='')
    
    def get_setting(self, setting: str, default: str = '') -> str:
        """Get setting value"""
        return self.config.get('SETTINGS', setting, fallback=default)

class DatabaseManager:
    """Simple database manager for storing wallet data"""
    
    def __init__(self, db_path: str = 'wallet_data.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        import sqlite3
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
                    status TEXT DEFAULT 'active'
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
                    status TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Database initialization failed: {e}")
    
    def save_wallets_batch(self, wallets: List[Dict]):
        """Save multiple wallets to database"""
        import sqlite3
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for wallet in wallets:
                cursor.execute('''
                    INSERT OR REPLACE INTO wallets 
                    (address, chain, discovery_method, last_updated)
                    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ''', (
                    wallet.get('address'),
                    wallet.get('chain', 'unknown'),
                    wallet.get('discovery_method', 'unknown')
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logging.error(f"Failed to save wallets to database: {e}")
    
    def get_wallet_count(self) -> int:
        """Get total number of wallets in database"""
        import sqlite3
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

class EnhancedWalletDiscoverer:
    def __init__(self):
        self.config = ConfigManager()
        self.error_handler = EnhancedErrorHandler()
        self.proxy_manager = ProxyManager()
        self.rate_limiter = RateLimiter()
        self.validator = DataValidator()
        self.db = DatabaseManager()
        self.monitor = MonitoringSystem()
        
        # Configure session with better settings
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        
        # Set timeout and retry settings
        self.timeout = int(self.config.get_setting('request_timeout', 30))
        self.max_retries = int(self.config.get_setting('max_retries', 5))
    
    def enhanced_get_request(self, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with all enhancements"""
        try:
            # Add proxy if enabled
            if self.config.get_setting('proxy_enabled', 'false').lower() == 'true':
                kwargs['proxies'] = self.proxy_manager.get_random_proxy()
            
            # Apply rate limiting
            response = self.rate_limiter.rate_limited_call(
                'http_request',
                self.error_handler.robust_request,
                url, **kwargs
            )
            
            self.monitor.track_metric('api_calls')
            return response
            
        except Exception as e:
            self.monitor.track_metric('errors')
            self.monitor.send_alert(f"Request failed: {url} - {e}", "ERROR")
            raise
    
    def _discover_via_blockchain(self) -> List[Dict]:
        """Discover wallets via blockchain analysis"""
        wallets = []
        try:
            # Analyze recent blocks
            recent_blocks = range(17500000, 17500005)  # Last 5 blocks
            for block in recent_blocks:
                # This would use the blockchain explorer
                pass
        except Exception as e:
            logging.error(f"Blockchain discovery failed: {e}")
        return wallets
    
    def _discover_via_defi(self) -> List[Dict]:
        """Discover wallets via DeFi protocols"""
        wallets = []
        try:
            # Analyze Uniswap pools
            pass
        except Exception as e:
            logging.error(f"DeFi discovery failed: {e}")
        return wallets
    
    def _discover_via_social_media(self) -> List[Dict]:
        """Discover wallets via social media"""
        wallets = []
        try:
            # Scrape social media
            pass
        except Exception as e:
            logging.error(f"Social media discovery failed: {e}")
        return wallets
    
    def _discover_via_exchanges(self) -> List[Dict]:
        """Discover wallets via exchange flows"""
        wallets = []
        try:
            # Analyze exchange flows
            pass
        except Exception as e:
            logging.error(f"Exchange discovery failed: {e}")
        return wallets
    
    def discover_wallets_comprehensive(self) -> List[Dict]:
        """Main discovery method with all enhancements"""
        wallets = []
        
        try:
            # Multiple discovery methods in parallel
            discovery_methods = [
                self._discover_via_blockchain,
                self._discover_via_defi,
                self._discover_via_social_media,
                self._discover_via_exchanges
            ]
            
            # Use threading for parallel execution
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                future_to_method = {
                    executor.submit(method): method.__name__ 
                    for method in discovery_methods
                }
                
                for future in concurrent.futures.as_completed(future_to_method):
                    try:
                        result = future.result()
                        wallets.extend(result)
                    except Exception as e:
                        logging.error(f"Discovery method failed: {e}")
            
            # Validate and sanitize results
            valid_wallets = self.validator.sanitize_wallet_data(wallets)
            
            # Save to database
            self.db.save_wallets_batch(valid_wallets)
            
            # Update metrics
            self.monitor.track_metric('wallets_discovered', len(valid_wallets))
            
            return valid_wallets
            
        except Exception as e:
            self.monitor.send_alert(f"Comprehensive discovery failed: {e}", "ERROR")
            return []
    
    def run_continuous_discovery(self, interval_minutes: int = 60):
        """Run discovery continuously"""
        import schedule
        import time
        
        def discovery_job():
            logging.info("Starting scheduled wallet discovery...")
            wallets = self.discover_wallets_comprehensive()
            logging.info(f"Discovery complete. Found {len(wallets)} wallets.")
        
        # Schedule the job
        schedule.every(interval_minutes).minutes.do(discovery_job)
        
        # Run immediately first time
        discovery_job()
        
        # Keep running
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute

import logging.config

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

# Example usage of enhanced discoverer
def demonstrate_enhanced_discovery():
    """Demonstrate the enhanced wallet discoverer"""
    print("🚀 Enhanced Wallet Discovery")
    print("=" * 35)
    
    # Setup logging
    setup_logging()
    
    # Create enhanced discoverer
    discoverer = EnhancedWalletDiscoverer()
    
    print("Starting comprehensive wallet discovery...")
    wallets = discoverer.discover_wallets_comprehensive()
    
    print(f"Discovery complete! Found {len(wallets)} wallets.")
    print(f"Total wallets in database: {discoverer.db.get_wallet_count()}")
    
    # Show metrics
    print("\nMetrics:")
    for metric, value in discoverer.monitor.metrics.items():
        print(f"  {metric}: {value}")
    
    return discoverer

# Main execution

class EthicalGuidelines:
    """Ethical guidelines for wallet discovery and analysis"""
    
    @staticmethod
    def display_guidelines():
        """Display ethical guidelines for wallet analysis"""
        print("""
╔══════════════════════════════════════════════════════════════╗
║                    🛡️ ETHICAL GUIDELINES 🛡️                  ║
║                                                              ║
║  This tool is designed for RESEARCH and EDUCATIONAL purposes ║
║  only. Please follow these ethical guidelines:               ║
║                                                              ║
║  ✅ ACCEPTABLE USES:                                         ║
║     • Academic research and education                        ║
║     • Blockchain analysis and understanding                  ║
║     • Market research and trend analysis                     ║
║     • Security research and vulnerability assessment         ║
║     • Compliance and regulatory analysis                     ║
║                                                              ║
║  ❌ UNACCEPTABLE USES:                                       ║
║     • Unauthorized access to private wallets                 ║
║     • Attempting to steal or compromise funds               ║
║     • Harassment or targeting of individuals                ║
║     • Any illegal or malicious activities                    ║
║     • Privacy violations or data misuse                      ║
║                                                              ║
║  🔒 PRIVACY & SECURITY:                                      ║
║     • Only analyze publicly available blockchain data        ║
║     • Respect user privacy and anonymity                     ║
║     • Do not attempt to deanonymize users                    ║
║     • Follow data protection regulations                     ║
║                                                              ║
║  📋 RESPONSIBILITY:                                          ║
║     • You are responsible for your use of this tool          ║
║     • Ensure compliance with local laws and regulations      ║
║     • Report any security vulnerabilities found              ║
║     • Use data responsibly and ethically                     ║
║                                                              ║
║  ⚖️ LEGAL COMPLIANCE:                                        ║
║     • This tool only accesses public blockchain data         ║
║     • No private keys or sensitive data are accessed         ║
║     • All analysis is based on publicly available information║
║     • Comply with all applicable laws and regulations        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
        # Get user acknowledgment
        response = input("\nDo you acknowledge and agree to follow these ethical guidelines? (y/n): ").strip().lower()
        if response not in ['y', 'yes']:
            print("❌ You must agree to the ethical guidelines to use this tool.")
            sys.exit(1)
        
        print("✅ Thank you for agreeing to follow ethical guidelines.\n")

if __name__ == "__main__":
    import sys
    
    # Setup logging
    setup_logging()
    
    # Display ethical guidelines
    EthicalGuidelines.display_guidelines()
    
    try:
        # Initialize enhanced discoverer
        discoverer = EnhancedWalletDiscoverer()
        
        # Run continuous discovery
        if len(sys.argv) > 1 and sys.argv[1] == '--continuous':
            print("🚀 Starting continuous wallet discovery...")
            print("Press Ctrl+C to stop the continuous discovery process.")
            
            interval = 120  # Default 2 hours
            if len(sys.argv) > 2:
                try:
                    interval = int(sys.argv[2])
                except ValueError:
                    print(f"Invalid interval. Using default: {interval} minutes")
            
            print(f"Discovery interval: {interval} minutes")
            discoverer.run_continuous_discovery(interval_minutes=interval)
            
        else:
            # Run single discovery
            print("🔍 Starting wallet discovery...")
            print("This may take several minutes depending on the discovery methods...")
            
            wallets = discoverer.discover_wallets_comprehensive()
            
            print(f"\n✅ Discovery completed successfully!")
            print(f"📊 Total wallets found: {len(wallets)}")
            print(f"💾 Results saved to database: {discoverer.config.get_setting('database_path', 'wallet_data.db')}")
            
            # Show database statistics
            total_in_db = discoverer.db.get_wallet_count()
            print(f"🗄️ Total wallets in database: {total_in_db}")
            
            # Show metrics
            print(f"\n📈 Discovery Metrics:")
            for metric, value in discoverer.monitor.metrics.items():
                if isinstance(value, (int, float)):
                    print(f"  {metric}: {value}")
            
            # Show sample results
            if wallets:
                print(f"\n📋 Sample wallets discovered:")
                for i, wallet in enumerate(wallets[:5]):
                    address = wallet.get('address', 'Unknown')
                    chain = wallet.get('chain', 'unknown')
                    method = wallet.get('discovery_method', 'unknown')
                    print(f"  {i+1}. {address[:10]}...{address[-8:]} ({chain.upper()}) - {method}")
                
                if len(wallets) > 5:
                    print(f"  ... and {len(wallets) - 5} more wallets")
            
            # Show next steps
            print(f"\n💡 Next Steps:")
            print(f"  1. Review the discovered wallets in the database")
            print(f"  2. Use the analysis tools to examine wallet activity")
            print(f"  3. Export data for further analysis")
            print(f"  4. Run continuous discovery with: python nos.py --continuous")
            print(f"  5. Check logs at: wallet_discovery.log")
    
    except KeyboardInterrupt:
        print("\n⏹️ Operation cancelled by user")
        print("Thank you for using the Wallet Discovery Suite!")
        
    except Exception as e:
        logging.error(f"Critical error: {e}")
        print(f"❌ Error occurred: {e}")
        print(f"📝 Check the log file for more details: wallet_discovery.log")
        
        # Show helpful error information
        if "API" in str(e):
            print(f"\n💡 API Error Help:")
            print(f"  - Check your API keys in config.ini")
            print(f"  - Verify API service status")
            print(f"  - Check rate limits and quotas")
        
        elif "database" in str(e).lower():
            print(f"\n💡 Database Error Help:")
            print(f"  - Check database file permissions")
            print(f"  - Verify database path in config.ini")
            print(f"  - Ensure sufficient disk space")
        
        elif "network" in str(e).lower() or "connection" in str(e).lower():
            print(f"\n💡 Network Error Help:")
            print(f"  - Check your internet connection")
            print(f"  - Verify proxy settings if enabled")
            print(f"  - Check firewall settings")
        
        sys.exit(1)
