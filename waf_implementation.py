from datetime import datetime
import re
import logging
from waf_config import WAFConfig

class ManualWAF:
    def __init__(self):
        self.config = WAFConfig()
        self.logger = logging.getLogger(__name__)
        
    def detect_fingerprinting(self, request):
        """Detect fingerprinting attempts based on manual configuration"""
        ip = request.remote_addr
        current_time = datetime.now()
        
        # Check User-Agent against configured patterns
        user_agent = request.headers.get('User-Agent', '').lower()
        for pattern in self.config.suspicious_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                alert = {
                    'timestamp': current_time,
                    'ip': ip,
                    'type': 'user_agent',
                    'pattern': pattern,
                    'value': user_agent
                }
                self.config.alerts.append(alert)
                self.logger.warning(f"Fingerprinting detected: {alert}")
                return True
                
        # Check headers against configured headers
        for header in self.config.suspicious_headers:
            if header in request.headers:
                alert = {
                    'timestamp': current_time,
                    'ip': ip,
                    'type': 'header',
                    'header': header,
                    'value': request.headers[header]
                }
                self.config.alerts.append(alert)
                self.logger.warning(f"Fingerprinting detected: {alert}")
                return True
                
        return False
        
    def apply_protection(self, request):
        """Apply WAF protection based on detection"""
        if self.detect_fingerprinting(request):
            ip = request.remote_addr
            self.config.blocked_ips.add(ip)
            return False, "Access denied - Fingerprinting detected"
            
        if request.remote_addr in self.config.blocked_ips:
            return False, "Access denied - IP blocked"
            
        return True, None
        
    def add_detection_pattern(self, pattern):
        """Add a new pattern for detection"""
        return self.config.add_pattern(pattern)
        
    def add_detection_header(self, header):
        """Add a new header for detection"""
        return self.config.add_header(header)
        
    def remove_detection_pattern(self, pattern):
        """Remove a pattern from detection"""
        return self.config.remove_pattern(pattern)
        
    def remove_detection_header(self, header):
        """Remove a header from detection"""
        return self.config.remove_header(header)
        
    def get_detection_status(self):
        """Get current detection status and configuration"""
        return self.config.get_config()
        
    def clear_alerts(self):
        """Clear all alerts"""
        self.config.alerts = []
        
    def unblock_ip(self, ip):
        """Unblock a specific IP"""
        if ip in self.config.blocked_ips:
            self.config.blocked_ips.remove(ip)
            return True
        return False 