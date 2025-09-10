"""
Rate limiting module for the Crypto Wallet Discovery & Analysis Toolkit.
Provides intelligent API call throttling and rate limit management.
"""

import time
import threading
import logging
from typing import Callable, Any, Optional
from ratelimit import limits, sleep_and_retry


class RateLimiter:
    """Intelligent rate limiter for API calls with configurable limits."""
    
    def __init__(self):
        self.call_times = {}
        self.lock = threading.Lock()
        self.rate_limits = {
            'default': {'calls': 5, 'period': 1},  # 5 calls per second
            'etherscan': {'calls': 5, 'period': 1},
            'bscscan': {'calls': 5, 'period': 1},
            'polygonscan': {'calls': 5, 'period': 1},
            'opensea': {'calls': 2, 'period': 1},
            'twitter': {'calls': 1, 'period': 2},
            'reddit': {'calls': 1, 'period': 2}
        }
    
    @sleep_and_retry
    @limits(calls=5, period=1)  # 5 calls per second
    def rate_limited_call(self, api_name: str, func: Callable, *args, **kwargs) -> Any:
        """Enforce rate limits for API calls"""
        with self.lock:
            current_time = time.time()
            
            # Get rate limit for this API
            rate_limit = self.rate_limits.get(api_name, self.rate_limits['default'])
            min_interval = rate_limit['period'] / rate_limit['calls']
            
            if api_name in self.call_times:
                elapsed = current_time - self.call_times[api_name]
                if elapsed < min_interval:
                    sleep_time = min_interval - elapsed
                    logging.debug(f"Rate limiting {api_name}: sleeping {sleep_time:.2f}s")
                    time.sleep(sleep_time)
            
            self.call_times[api_name] = time.time()
        
        return func(*args, **kwargs)
    
    def set_rate_limit(self, api_name: str, calls: int, period: int):
        """Set custom rate limit for an API"""
        with self.lock:
            self.rate_limits[api_name] = {'calls': calls, 'period': period}
            logging.info(f"Set rate limit for {api_name}: {calls} calls per {period} seconds")
    
    def get_rate_limit(self, api_name: str) -> dict:
        """Get current rate limit for an API"""
        return self.rate_limits.get(api_name, self.rate_limits['default'])
    
    def check_rate_limit(self, api_name: str) -> bool:
        """Check if we can make a call without hitting rate limit"""
        with self.lock:
            current_time = time.time()
            rate_limit = self.rate_limits.get(api_name, self.rate_limits['default'])
            min_interval = rate_limit['period'] / rate_limit['calls']
            
            if api_name in self.call_times:
                elapsed = current_time - self.call_times[api_name]
                return elapsed >= min_interval
            
            return True
    
    def wait_for_rate_limit(self, api_name: str):
        """Wait until rate limit allows next call"""
        with self.lock:
            current_time = time.time()
            rate_limit = self.rate_limits.get(api_name, self.rate_limits['default'])
            min_interval = rate_limit['period'] / rate_limit['calls']
            
            if api_name in self.call_times:
                elapsed = current_time - self.call_times[api_name]
                if elapsed < min_interval:
                    sleep_time = min_interval - elapsed
                    logging.debug(f"Waiting for rate limit on {api_name}: {sleep_time:.2f}s")
                    time.sleep(sleep_time)
    
    def reset_rate_limit(self, api_name: str):
        """Reset rate limit tracking for an API"""
        with self.lock:
            if api_name in self.call_times:
                del self.call_times[api_name]
                logging.debug(f"Reset rate limit tracking for {api_name}")
    
    def get_rate_limit_status(self) -> dict:
        """Get current rate limit status for all APIs"""
        with self.lock:
            status = {}
            current_time = time.time()
            
            for api_name, rate_limit in self.rate_limits.items():
                if api_name in self.call_times:
                    elapsed = current_time - self.call_times[api_name]
                    min_interval = rate_limit['period'] / rate_limit['calls']
                    can_call = elapsed >= min_interval
                    time_until_next = max(0, min_interval - elapsed)
                else:
                    can_call = True
                    time_until_next = 0
                
                status[api_name] = {
                    'rate_limit': rate_limit,
                    'can_call': can_call,
                    'time_until_next': time_until_next
                }
            
            return status
    
    def adaptive_rate_limit(self, api_name: str, response: Any) -> bool:
        """Adaptively adjust rate limits based on response"""
        try:
            # Check for rate limit headers
            if hasattr(response, 'headers'):
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    try:
                        wait_time = int(retry_after)
                        logging.warning(f"Rate limit detected for {api_name}, waiting {wait_time}s")
                        time.sleep(wait_time)
                        return True
                    except ValueError:
                        pass
            
            # Check for rate limit in response body
            if hasattr(response, 'json'):
                try:
                    data = response.json()
                    if 'error' in data and 'rate limit' in data['error'].lower():
                        logging.warning(f"Rate limit detected for {api_name}")
                        time.sleep(60)  # Wait 1 minute
                        return True
                except (ValueError, KeyError):
                    pass
            
            return False
            
        except Exception as e:
            logging.error(f"Error in adaptive rate limiting: {e}")
            return False
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        # Clean up any resources if needed
        pass
