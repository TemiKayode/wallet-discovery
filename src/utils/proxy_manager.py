"""
Proxy management module for the Crypto Wallet Discovery & Analysis Toolkit.
Handles proxy rotation, IP management, and anti-blocking techniques.
"""

import requests
import logging
import time
import random
from typing import Dict, List, Optional
from fp.fp import FreeProxy


class ProxyManager:
    """Proxy manager for IP rotation and anti-blocking techniques."""
    
    def __init__(self):
        self.proxies = []
        self.working_proxies = []
        self.failed_proxies = set()
        self.proxy_scores = {}
        self.last_refresh = 0
        self.refresh_interval = 300  # 5 minutes
        self.max_proxies = 50
        self.test_url = 'https://httpbin.org/ip'
        
        # User agent rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59'
        ]
    
    def refresh_proxies(self, force: bool = False):
        """Refresh proxy list"""
        current_time = time.time()
        
        if not force and current_time - self.last_refresh < self.refresh_interval:
            return
        
        try:
            logging.info("Refreshing proxy list...")
            
            # Get free proxies
            free_proxies = []
            for _ in range(self.max_proxies):
                try:
                    proxy = FreeProxy().get()
                    if proxy:
                        free_proxies.append(proxy)
                except Exception as e:
                    logging.debug(f"Error getting free proxy: {e}")
                    continue
            
            # Test proxies
            working_proxies = []
            for proxy in free_proxies:
                if self.test_proxy(proxy):
                    working_proxies.append(proxy)
                    self.proxy_scores[proxy] = 100  # Initial score
            
            self.proxies = working_proxies
            self.working_proxies = working_proxies.copy()
            self.last_refresh = current_time
            
            logging.info(f"Refreshed proxy list: {len(self.working_proxies)} working proxies")
            
        except Exception as e:
            logging.error(f"Error refreshing proxies: {e}")
    
    def test_proxy(self, proxy: str) -> bool:
        """Test if a proxy is working"""
        try:
            proxies = {
                'http': proxy,
                'https': proxy
            }
            
            response = requests.get(
                self.test_url,
                proxies=proxies,
                timeout=10,
                headers={'User-Agent': random.choice(self.user_agents)}
            )
            
            return response.status_code == 200
            
        except Exception as e:
            logging.debug(f"Proxy test failed for {proxy}: {e}")
            return False
    
    def get_random_proxy(self) -> Optional[Dict[str, str]]:
        """Get a random working proxy"""
        if not self.working_proxies:
            self.refresh_proxies()
        
        if not self.working_proxies:
            logging.warning("No working proxies available")
            return None
        
        # Select proxy based on score (higher score = higher chance)
        total_score = sum(self.proxy_scores.get(proxy, 0) for proxy in self.working_proxies)
        
        if total_score == 0:
            proxy = random.choice(self.working_proxies)
        else:
            # Weighted random selection
            rand = random.uniform(0, total_score)
            current_sum = 0
            
            for proxy in self.working_proxies:
                current_sum += self.proxy_scores.get(proxy, 0)
                if current_sum >= rand:
                    break
        
        return {
            'http': proxy,
            'https': proxy
        }
    
    def mark_proxy_failed(self, proxy: str):
        """Mark a proxy as failed"""
        if proxy in self.working_proxies:
            self.working_proxies.remove(proxy)
            self.failed_proxies.add(proxy)
            
            # Reduce score
            current_score = self.proxy_scores.get(proxy, 100)
            self.proxy_scores[proxy] = max(0, current_score - 20)
            
            logging.debug(f"Marked proxy as failed: {proxy}")
    
    def mark_proxy_success(self, proxy: str):
        """Mark a proxy as successful"""
        if proxy in self.proxy_scores:
            current_score = self.proxy_scores.get(proxy, 100)
            self.proxy_scores[proxy] = min(100, current_score + 5)
    
    def get_proxy_stats(self) -> Dict:
        """Get proxy statistics"""
        return {
            'total_proxies': len(self.proxies),
            'working_proxies': len(self.working_proxies),
            'failed_proxies': len(self.failed_proxies),
            'average_score': sum(self.proxy_scores.values()) / len(self.proxy_scores) if self.proxy_scores else 0,
            'last_refresh': self.last_refresh
        }
    
    def add_custom_proxy(self, proxy: str, score: int = 100):
        """Add a custom proxy to the list"""
        if proxy not in self.proxies:
            self.proxies.append(proxy)
            self.working_proxies.append(proxy)
            self.proxy_scores[proxy] = score
            logging.info(f"Added custom proxy: {proxy}")
    
    def remove_proxy(self, proxy: str):
        """Remove a proxy from the list"""
        if proxy in self.proxies:
            self.proxies.remove(proxy)
        if proxy in self.working_proxies:
            self.working_proxies.remove(proxy)
        if proxy in self.proxy_scores:
            del self.proxy_scores[proxy]
        if proxy in self.failed_proxies:
            self.failed_proxies.remove(proxy)
        
        logging.info(f"Removed proxy: {proxy}")
    
    def get_random_user_agent(self) -> str:
        """Get a random user agent"""
        return random.choice(self.user_agents)
    
    def add_user_agent(self, user_agent: str):
        """Add a custom user agent"""
        if user_agent not in self.user_agents:
            self.user_agents.append(user_agent)
    
    def rotate_user_agent(self, session: requests.Session):
        """Rotate user agent for a session"""
        session.headers.update({
            'User-Agent': self.get_random_user_agent()
        })
    
    def create_session_with_proxy(self) -> requests.Session:
        """Create a session with a random proxy"""
        session = requests.Session()
        
        proxy = self.get_random_proxy()
        if proxy:
            session.proxies.update(proxy)
        
        self.rotate_user_agent(session)
        
        return session
    
    def test_all_proxies(self) -> Dict[str, int]:
        """Test all proxies and return working count"""
        working_count = 0
        total_count = len(self.proxies)
        
        for proxy in self.proxies:
            if self.test_proxy(proxy):
                working_count += 1
                self.mark_proxy_success(proxy)
            else:
                self.mark_proxy_failed(proxy)
        
        return {
            'working': working_count,
            'total': total_count,
            'success_rate': working_count / total_count if total_count > 0 else 0
        }
    
    def cleanup_failed_proxies(self):
        """Remove proxies that have failed too many times"""
        failed_threshold = 50  # Minimum score to keep proxy
        
        proxies_to_remove = []
        for proxy, score in self.proxy_scores.items():
            if score < failed_threshold:
                proxies_to_remove.append(proxy)
        
        for proxy in proxies_to_remove:
            self.remove_proxy(proxy)
        
        if proxies_to_remove:
            logging.info(f"Cleaned up {len(proxies_to_remove)} failed proxies")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        # Clean up any resources if needed
        pass
