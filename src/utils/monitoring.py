"""
Monitoring module for the Crypto Wallet Discovery & Analysis Toolkit.
Provides metrics tracking, performance monitoring, and alerting capabilities.
"""

import logging
import time
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from typing import Dict, Any, Optional


class MonitoringSystem:
    """Comprehensive monitoring system for tracking metrics and sending alerts."""
    
    def __init__(self):
        self.metrics = {
            'wallets_discovered': 0,
            'api_calls': 0,
            'errors': 0,
            'start_time': datetime.now(),
            'discovery_sessions': 0,
            'successful_discoveries': 0,
            'failed_discoveries': 0,
            'total_processing_time': 0.0,
            'average_discovery_time': 0.0
        }
        
        # Alert configuration
        self.alert_config = {
            'email_enabled': False,
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_email': '',
            'sender_password': '',
            'recipient_email': '',
            'alert_thresholds': {
                'error_rate': 0.1,  # 10% error rate
                'discovery_failure_rate': 0.2,  # 20% failure rate
                'api_call_limit': 1000,  # Max API calls per hour
                'processing_time_threshold': 300  # 5 minutes
            }
        }
    
    def track_metric(self, metric_name: str, value: int = 1):
        """Track performance metrics"""
        if metric_name in self.metrics:
            if isinstance(self.metrics[metric_name], (int, float)):
                self.metrics[metric_name] += value
            else:
                self.metrics[metric_name] = value
        else:
            self.metrics[metric_name] = value
        
        # Check if we need to send alerts
        self._check_alert_conditions(metric_name, value)
    
    def get_metric(self, metric_name: str) -> Any:
        """Get a specific metric value"""
        return self.metrics.get(metric_name, 0)
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all current metrics"""
        # Calculate derived metrics
        uptime = (datetime.now() - self.metrics['start_time']).total_seconds()
        
        metrics_copy = self.metrics.copy()
        metrics_copy.update({
            'uptime_seconds': uptime,
            'uptime_hours': uptime / 3600,
            'error_rate': self.metrics['errors'] / max(self.metrics['api_calls'], 1),
            'success_rate': self.metrics['successful_discoveries'] / max(self.metrics['discovery_sessions'], 1),
            'api_calls_per_hour': self.metrics['api_calls'] / max(uptime / 3600, 1)
        })
        
        return metrics_copy
    
    def reset_metrics(self):
        """Reset all metrics to initial values"""
        self.metrics = {
            'wallets_discovered': 0,
            'api_calls': 0,
            'errors': 0,
            'start_time': datetime.now(),
            'discovery_sessions': 0,
            'successful_discoveries': 0,
            'failed_discoveries': 0,
            'total_processing_time': 0.0,
            'average_discovery_time': 0.0
        }
        logging.info("Metrics reset")
    
    def send_alert(self, message: str, level: str = "INFO"):
        """Send alert via email or other channels"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {level}: {message}"
        
        # Log the alert
        if level == "ERROR":
            logging.error(formatted_message)
        elif level == "WARNING":
            logging.warning(formatted_message)
        else:
            logging.info(formatted_message)
        
        # Send email alert for errors
        if level == "ERROR" and self.alert_config['email_enabled']:
            self._send_email_alert(formatted_message, level)
    
    def _send_email_alert(self, message: str, level: str):
        """Send email alert"""
        try:
            if not all([
                self.alert_config['sender_email'],
                self.alert_config['sender_password'],
                self.alert_config['recipient_email']
            ]):
                logging.warning("Email alert configuration incomplete")
                return
            
            msg = MIMEText(message)
            msg['Subject'] = f'Wallet Discovery Alert - {level}'
            msg['From'] = self.alert_config['sender_email']
            msg['To'] = self.alert_config['recipient_email']
            
            with smtplib.SMTP(self.alert_config['smtp_server'], self.alert_config['smtp_port']) as server:
                server.starttls()
                server.login(
                    self.alert_config['sender_email'],
                    self.alert_config['sender_password']
                )
                server.send_message(msg)
            
            logging.info("Email alert sent successfully")
            
        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")
    
    def _check_alert_conditions(self, metric_name: str, value: int):
        """Check if alert conditions are met"""
        thresholds = self.alert_config['alert_thresholds']
        
        if metric_name == 'errors':
            total_calls = self.metrics['api_calls']
            if total_calls > 0:
                error_rate = value / total_calls
                if error_rate > thresholds['error_rate']:
                    self.send_alert(
                        f"High error rate detected: {error_rate:.2%}",
                        "WARNING"
                    )
        
        elif metric_name == 'api_calls':
            if value > thresholds['api_call_limit']:
                self.send_alert(
                    f"API call limit exceeded: {value} calls",
                    "WARNING"
                )
        
        elif metric_name == 'failed_discoveries':
            total_sessions = self.metrics['discovery_sessions']
            if total_sessions > 0:
                failure_rate = value / total_sessions
                if failure_rate > thresholds['discovery_failure_rate']:
                    self.send_alert(
                        f"High discovery failure rate: {failure_rate:.2%}",
                        "WARNING"
                    )
    
    def configure_email_alerts(self, smtp_server: str, smtp_port: int,
                             sender_email: str, sender_password: str,
                             recipient_email: str):
        """Configure email alert settings"""
        self.alert_config.update({
            'email_enabled': True,
            'smtp_server': smtp_server,
            'smtp_port': smtp_port,
            'sender_email': sender_email,
            'sender_password': sender_password,
            'recipient_email': recipient_email
        })
        logging.info("Email alerts configured")
    
    def set_alert_threshold(self, threshold_name: str, value: float):
        """Set alert threshold"""
        if threshold_name in self.alert_config['alert_thresholds']:
            self.alert_config['alert_thresholds'][threshold_name] = value
            logging.info(f"Alert threshold '{threshold_name}' set to {value}")
        else:
            logging.warning(f"Unknown alert threshold: {threshold_name}")
    
    def start_discovery_session(self):
        """Start a discovery session"""
        self.track_metric('discovery_sessions', 1)
        self.session_start_time = time.time()
    
    def end_discovery_session(self, success: bool = True, wallets_found: int = 0):
        """End a discovery session"""
        if success:
            self.track_metric('successful_discoveries', 1)
        else:
            self.track_metric('failed_discoveries', 1)
        
        if hasattr(self, 'session_start_time'):
            processing_time = time.time() - self.session_start_time
            self.track_metric('total_processing_time', processing_time)
            
            # Update average processing time
            sessions = self.metrics['discovery_sessions']
            if sessions > 0:
                self.metrics['average_discovery_time'] = (
                    self.metrics['total_processing_time'] / sessions
                )
        
        self.track_metric('wallets_discovered', wallets_found)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        metrics = self.get_all_metrics()
        
        summary = {
            'uptime_hours': metrics['uptime_hours'],
            'total_discoveries': metrics['discovery_sessions'],
            'successful_discoveries': metrics['successful_discoveries'],
            'failed_discoveries': metrics['failed_discoveries'],
            'success_rate': metrics['success_rate'],
            'total_wallets_discovered': metrics['wallets_discovered'],
            'total_api_calls': metrics['api_calls'],
            'total_errors': metrics['errors'],
            'error_rate': metrics['error_rate'],
            'average_discovery_time': metrics['average_discovery_time'],
            'api_calls_per_hour': metrics['api_calls_per_hour']
        }
        
        return summary
    
    def log_performance_summary(self):
        """Log performance summary"""
        summary = self.get_performance_summary()
        
        logging.info("Performance Summary:")
        logging.info(f"  Uptime: {summary['uptime_hours']:.2f} hours")
        logging.info(f"  Total Discoveries: {summary['total_discoveries']}")
        logging.info(f"  Success Rate: {summary['success_rate']:.2%}")
        logging.info(f"  Wallets Discovered: {summary['total_wallets_discovered']}")
        logging.info(f"  API Calls: {summary['total_api_calls']}")
        logging.info(f"  Error Rate: {summary['error_rate']:.2%}")
        logging.info(f"  Avg Discovery Time: {summary['average_discovery_time']:.2f}s")
        logging.info(f"  API Calls/Hour: {summary['api_calls_per_hour']:.2f}")
    
    def export_metrics(self, filename: str):
        """Export metrics to file"""
        try:
            import json
            
            metrics_data = {
                'timestamp': datetime.now().isoformat(),
                'metrics': self.get_all_metrics(),
                'performance_summary': self.get_performance_summary()
            }
            
            with open(filename, 'w') as f:
                json.dump(metrics_data, f, indent=2, default=str)
            
            logging.info(f"Metrics exported to {filename}")
            
        except Exception as e:
            logging.error(f"Failed to export metrics: {e}")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        # Log final performance summary
        self.log_performance_summary()
