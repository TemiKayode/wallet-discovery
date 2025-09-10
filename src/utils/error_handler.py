"""
Error handling module for the Crypto Wallet Discovery & Analysis Toolkit.
Provides robust error handling, retry mechanisms, and graceful failure recovery.
"""

import requests
import logging
import time
import random
from typing import Callable, Any, Optional, Dict
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class EnhancedErrorHandler:
    """Enhanced error handler with retry mechanisms and graceful failure recovery."""
    
    def __init__(self):
        self.max_retries = 5
        self.base_delay = 1.0
        self.max_delay = 60.0
        self.exponential_base = 2
        
        # Configure retry strategy for requests
        self.retry_strategy = Retry(
            total=self.max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"],
            backoff_factor=self.base_delay
        )
        
        # Create session with retry adapter
        self.session = requests.Session()
        adapter = HTTPAdapter(max_retries=self.retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type((requests.RequestException, ConnectionError))
    )
    def robust_request(self, url: str, method: str = 'GET', **kwargs) -> requests.Response:
        """Make HTTP request with automatic retry and error handling"""
        try:
            # Add random delay to avoid rate limiting
            time.sleep(random.uniform(0.5, 2.0))
            
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            
            return response
            
        except requests.exceptions.RequestException as e:
            logging.warning(f"Request failed for {url}: {e}")
            raise
        except Exception as e:
            logging.error(f"Unexpected error for {url}: {e}")
            raise
    
    def handle_api_error(self, error: Exception, context: str = "") -> Dict[str, Any]:
        """Handle API errors and return structured error information"""
        error_info = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'context': context,
            'timestamp': time.time(),
            'retryable': self._is_retryable_error(error)
        }
        
        if isinstance(error, requests.exceptions.RequestException):
            error_info.update({
                'status_code': getattr(error.response, 'status_code', None),
                'response_text': getattr(error.response, 'text', ''),
                'url': getattr(error.response, 'url', '')
            })
        
        logging.error(f"API Error in {context}: {error_info}")
        return error_info
    
    def _is_retryable_error(self, error: Exception) -> bool:
        """Determine if an error is retryable"""
        retryable_exceptions = (
            requests.exceptions.ConnectionError,
            requests.exceptions.Timeout,
            requests.exceptions.HTTPError,
            ConnectionError,
            TimeoutError
        )
        
        if isinstance(error, retryable_exceptions):
            return True
        
        # Check for specific HTTP status codes
        if isinstance(error, requests.exceptions.HTTPError):
            if hasattr(error, 'response') and error.response:
                status_code = error.response.status_code
                return status_code in [429, 500, 502, 503, 504]
        
        return False
    
    def exponential_backoff(self, attempt: int, base_delay: float = 1.0) -> float:
        """Calculate exponential backoff delay"""
        delay = base_delay * (self.exponential_base ** attempt)
        jitter = random.uniform(0, 0.1 * delay)
        return min(delay + jitter, self.max_delay)
    
    def safe_execute(self, func: Callable, *args, **kwargs) -> Optional[Any]:
        """Safely execute a function with error handling"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            error_info = self.handle_api_error(e, f"Function: {func.__name__}")
            return None
    
    def retry_with_backoff(self, func: Callable, max_attempts: int = 3, 
                          base_delay: float = 1.0, *args, **kwargs) -> Optional[Any]:
        """Execute function with exponential backoff retry"""
        for attempt in range(max_attempts):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if attempt == max_attempts - 1:
                    # Last attempt failed
                    error_info = self.handle_api_error(e, f"Function: {func.__name__}")
                    return None
                
                if not self._is_retryable_error(e):
                    # Non-retryable error
                    error_info = self.handle_api_error(e, f"Function: {func.__name__}")
                    return None
                
                # Calculate delay and wait
                delay = self.exponential_backoff(attempt, base_delay)
                logging.info(f"Retrying {func.__name__} in {delay:.2f} seconds (attempt {attempt + 1}/{max_attempts})")
                time.sleep(delay)
        
        return None
    
    def handle_rate_limit(self, response: requests.Response) -> bool:
        """Handle rate limiting by waiting appropriate time"""
        if response.status_code == 429:
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                try:
                    wait_time = int(retry_after)
                except ValueError:
                    wait_time = 60  # Default to 60 seconds
            else:
                wait_time = 60
            
            logging.warning(f"Rate limited. Waiting {wait_time} seconds...")
            time.sleep(wait_time)
            return True
        
        return False
    
    def validate_response(self, response: requests.Response, expected_status: int = 200) -> bool:
        """Validate HTTP response"""
        if response.status_code != expected_status:
            logging.error(f"Unexpected status code: {response.status_code} (expected {expected_status})")
            return False
        
        # Check if response is valid JSON
        try:
            response.json()
        except ValueError:
            logging.error("Response is not valid JSON")
            return False
        
        return True
    
    def log_error_summary(self, errors: list):
        """Log summary of errors encountered"""
        if not errors:
            return
        
        error_counts = {}
        for error in errors:
            error_type = error.get('error_type', 'Unknown')
            error_counts[error_type] = error_counts.get(error_type, 0) + 1
        
        logging.info("Error Summary:")
        for error_type, count in error_counts.items():
            logging.info(f"  {error_type}: {count} occurrences")
    
    def cleanup_resources(self):
        """Clean up resources and connections"""
        try:
            self.session.close()
        except Exception as e:
            logging.error(f"Error cleaning up resources: {e}")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.cleanup_resources()
