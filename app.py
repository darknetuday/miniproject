from flask import Flask, request, jsonify, Response, render_template, redirect, url_for, flash
import re
import logging
from datetime import datetime
import socket
from collections import deque
import requests
from bs4 import BeautifulSoup
import urllib3
from urllib.parse import urlparse
import time
import hashlib
import os
import json
from typing import Dict, List, Optional, Tuple
import PyPDF2
import io
from captcha_checker import CaptchaChecker


app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TrojanDetector:
    def __init__(self, vt_api_key: str):
        self.vt_api_key = vt_api_key
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.suspicious_patterns = {
            'file_extension': [
                '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
                '.msi', '.scr', '.pif', '.com', '.hta', '.wsf', '.wsh'
            ],
            'file_signatures': [
                b'MZ',  # Windows executable
                b'PK',  # ZIP/JAR
                b'Rar!',  # RAR
                b'%PDF',  # PDF
                b'<script',  # JavaScript
                b'powershell',  # PowerShell
                b'cmd.exe',  # Command prompt
                b'regsvr32',  # DLL registration
                b'certutil',  # Certificate utility
                b'bitsadmin'  # Background Intelligent Transfer Service
            ],
            'suspicious_strings': [
                'cmd.exe',
                'powershell',
                'regsvr32',
                'certutil',
                'bitsadmin',
                'wscript',
                'cscript',
                'mshta',
                'rundll32',
                'schtasks',
                'net user',
                'net group',
                'net localgroup',
                'net share',
                'net view',
                'ipconfig',
                'nslookup',
                'ping',
                'tracert',
                'route'
            ],
            'suspicious_url_patterns': [
                r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                r'www\.(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                r'ftp://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
            ]
        }
        
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def check_virustotal(self, file_hash: str) -> Dict:
        """Check file hash against VirusTotal database"""
        headers = {
            "x-apikey": self.vt_api_key
        }
        try:
            response = requests.get(
                f"{self.vt_base_url}/files/{file_hash}",
                headers=headers,
                timeout=30
            )
            if response.status_code == 200:
                return response.json()
            return {"error": f"VirusTotal API error: {response.status_code}"}
        except Exception as e:
            return {"error": f"Error checking VirusTotal: {str(e)}"}
    
    def extract_urls_from_pdf(self, file_path: str) -> List[str]:
        """Extract URLs from a PDF file"""
        urls = []
        try:
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                for page in pdf_reader.pages:
                    text = page.extract_text()
                    # Look for URLs in the text
                    for pattern in self.suspicious_patterns['suspicious_url_patterns']:
                        matches = re.findall(pattern, text)
                        urls.extend(matches)
        except Exception as e:
            logger.error(f"Error extracting URLs from PDF: {str(e)}")
        return list(set(urls))  # Remove duplicates

    def analyze_url(self, url: str) -> Dict:
        """Analyze a URL for potential malicious characteristics"""
        result = {
            "url": url,
            "is_suspicious": False,
            "suspicious_features": [],
            "recommendations": []
        }

        try:
            # Check for suspicious URL patterns
            suspicious_domains = [
                'malware', 'virus', 'trojan', 'spyware', 'ransomware',
                'phishing', 'scam', 'fake', 'hack', 'exploit'
            ]
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Check domain for suspicious keywords
            for keyword in suspicious_domains:
                if keyword in domain:
                    result["is_suspicious"] = True
                    result["suspicious_features"].append(f"Suspicious keyword in domain: {keyword}")
            
            # Check for IP addresses in domain
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                result["is_suspicious"] = True
                result["suspicious_features"].append("Domain is an IP address")
            
            # Check for URL shortening services
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
            if any(shortener in domain for shortener in shorteners):
                result["is_suspicious"] = True
                result["suspicious_features"].append("URL is shortened")
            
            # Generate recommendations
            if result["is_suspicious"]:
                result["recommendations"].append("URL shows suspicious characteristics. Do not click.")
                result["recommendations"].append("Consider using a URL scanner service for further analysis.")
            
            return result
            
        except Exception as e:
            return {
                "url": url,
                "error": f"Error analyzing URL: {str(e)}"
            }

    def analyze_file(self, file_path: str) -> Dict:
        """Analyze file for potential Trojan characteristics"""
        results = {
            "is_suspicious": False,
            "suspicious_features": [],
            "virustotal_analysis": None,
            "file_info": {},
            "recommendations": [],
            "url_analysis": []
        }
        
        try:
            # Basic file information
            file_size = os.path.getsize(file_path)
            file_extension = os.path.splitext(file_path)[1].lower()
            
            results["file_info"] = {
                "path": file_path,
                "size": file_size,
                "extension": file_extension
            }
            
            # Check file extension
            if file_extension in self.suspicious_patterns['file_extension']:
                results["is_suspicious"] = True
                results["suspicious_features"].append(f"Suspicious file extension: {file_extension}")
            
            # Check file signature
            with open(file_path, "rb") as f:
                file_header = f.read(1024)  # Read first 1KB
                for signature in self.suspicious_patterns['file_signatures']:
                    if signature in file_header:
                        results["is_suspicious"] = True
                        results["suspicious_features"].append(f"Suspicious file signature detected: {signature}")
            
            # Check file content for suspicious strings
            with open(file_path, "rb") as f:
                content = f.read()
                for string in self.suspicious_patterns['suspicious_strings']:
                    if string.encode() in content:
                        results["is_suspicious"] = True
                        results["suspicious_features"].append(f"Suspicious string found: {string}")
            
            # If file is a PDF, extract and analyze URLs
            if file_extension == '.pdf':
                urls = self.extract_urls_from_pdf(file_path)
                for url in urls:
                    url_analysis = self.analyze_url(url)
                    results["url_analysis"].append(url_analysis)
                    if url_analysis.get("is_suspicious", False):
                        results["is_suspicious"] = True
                        results["suspicious_features"].append(f"Suspicious URL found: {url}")
            
            # Calculate file hash and check VirusTotal
            file_hash = self.calculate_file_hash(file_path)
            vt_result = self.check_virustotal(file_hash)
            results["virustotal_analysis"] = vt_result
            
            # Generate recommendations
            if results["is_suspicious"]:
                results["recommendations"].append("File shows suspicious characteristics. Consider scanning with antivirus software.")
            if "error" not in vt_result:
                if vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
                    results["recommendations"].append("File has been flagged as malicious by VirusTotal. Delete immediately.")
            
            return results
            
        except Exception as e:
            return {
                "error": f"Error analyzing file: {str(e)}",
                "file_path": file_path
            }
    
    def scan_directory(self, directory_path: str) -> Dict:
        """Scan a directory for potential Trojan files"""
        results = {
            "scanned_files": 0,
            "suspicious_files": [],
            "errors": []
        }
        
        try:
            for root, _, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        file_analysis = self.analyze_file(file_path)
                        results["scanned_files"] += 1
                        
                        if file_analysis.get("is_suspicious", False):
                            results["suspicious_files"].append({
                                "path": file_path,
                                "analysis": file_analysis
                            })
                    except Exception as e:
                        results["errors"].append({
                            "file": file_path,
                            "error": str(e)
                        })
            
            return results
            
        except Exception as e:
            return {
                "error": f"Error scanning directory: {str(e)}",
                "directory_path": directory_path
            }

class WAFScanner:
    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': [
                'cloudflare-nginx',
                'cf-ray',
                'cf-cache-status',
                'cf-connecting-ip',
                'cf-ipcountry',
                'cf-worker'
            ],
            'AWS WAF': [
                'x-amz-cf-id',
                'x-amz-cf-pop',
                'x-aws-waf',
                'x-aws-waf-action',
                'x-aws-waf-rule-id'
            ],
            'ModSecurity': [
                'mod_security',
                'modsecurity',
                'x-modsecurity',
                'x-anomaly-score',
                'x-blocked-by'
            ],
            'Akamai': [
                'akamai',
                'x-akamai',
                'x-akamai-transformed',
                'x-akamai-request-id',
                'x-akamai-staging'
            ],
            'Imperva': [
                'incapsula',
                'x-iinfo',
                'x-cdn',
                'x-cdn-srv',
                'x-cdn-ip'
            ],
            'Barracuda': [
                'barracuda',
                'x-barrcuda',
                'x-barracuda-ip',
                'x-barracuda-action'
            ],
            'F5': [
                'f5',
                'x-f5',
                'x-f5-ip',
                'x-f5-action'
            ],
            'Fortinet': [
                'fortinet',
                'x-fortinet',
                'x-fortinet-ip',
                'x-fortinet-action'
            ],
            'Palo Alto': [
                'palo-alto',
                'x-palo-alto',
                'x-palo-alto-ip',
                'x-palo-alto-action'
            ]
        }
        
        self.test_payloads = [
            "' OR '1'='1",
            "<script>alert('xss')</script>",
            "../../../etc/passwd",
            "UNION SELECT",
            "AND 1=1",
            "OR 1=1",
            "<?php system('id'); ?>",
            "document.cookie",
            "eval(",
            "base64_decode(",
            "exec(",
            "system(",
            "passthru(",
            "shell_exec(",
            "popen(",
            "proc_open("
        ]
        
        self.common_headers = [
            'Server',
            'X-Powered-By',
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Content-Security-Policy',
            'Strict-Transport-Security'
        ]
        
    def scan_url(self, url):
        """Scan a URL for WAF presence and vulnerabilities"""
        try:
            # Parse URL
            parsed_url = urlparse(url)
            if not parsed_url.scheme:
                url = 'https://' + url
            
            # Initialize results
            results = {
                'waf_detected': False,
                'waf_type': None,
                'waf_strength': 'None',
                'vulnerabilities': [],
                'recommendations': [],
                'headers': {},
                'server_info': None
            }
            
            # Test for WAF presence
            session = requests.Session()
            session.verify = False
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            })
            
            # First request to get baseline
            try:
                response = session.get(url, timeout=10)
                headers = response.headers
                content = response.text
                
                # Store server information
                results['server_info'] = headers.get('Server', 'Unknown')
                
                # Store important headers
                for header in self.common_headers:
                    if header in headers:
                        results['headers'][header] = headers[header]
                
                # Check for WAF signatures
                for waf_type, signatures in self.waf_signatures.items():
                    if any(sig.lower() in str(headers).lower() for sig in signatures):
                        results['waf_detected'] = True
                        results['waf_type'] = waf_type
                        break
                
                # Additional WAF detection methods
                if not results['waf_detected']:
                    # Check for common WAF response patterns
                    if any(status in str(response.status_code) for status in ['403', '406', '501']):
                        results['waf_detected'] = True
                        results['waf_type'] = 'Generic WAF'
                    
                    # Check for WAF-specific error messages
                    error_patterns = [
                        'access denied',
                        'security violation',
                        'forbidden',
                        'blocked',
                        'unauthorized',
                        'security check',
                        'waf detected'
                    ]
                    
                    if any(pattern in content.lower() for pattern in error_patterns):
                        results['waf_detected'] = True
                        results['waf_type'] = 'Generic WAF'
                
                # Test WAF strength with payloads
                if results['waf_detected']:
                    blocked_count = 0
                    for payload in self.test_payloads:
                        test_url = f"{url}?test={payload}"
                        try:
                            test_response = session.get(test_url, timeout=5)
                            if test_response.status_code in [403, 406, 501]:
                                blocked_count += 1
                            time.sleep(0.5)  # Add delay between requests
                        except:
                            blocked_count += 1
                    
                    # Determine WAF strength
                    if blocked_count == len(self.test_payloads):
                        results['waf_strength'] = 'Strong'
                    elif blocked_count > len(self.test_payloads) / 2:
                        results['waf_strength'] = 'Medium'
                    else:
                        results['waf_strength'] = 'Weak'
                
                # Check for common vulnerabilities
                soup = BeautifulSoup(content, 'html.parser')
                
                # Check for SQL injection vulnerabilities
                if any('sql' in str(error).lower() for error in soup.find_all('div', class_='error')):
                    results['vulnerabilities'].append({
                        'severity': 'High',
                        'description': 'Potential SQL injection vulnerability detected'
                    })
                
                # Check for XSS vulnerabilities
                if any('script' in str(form).lower() for form in soup.find_all('form')):
                    results['vulnerabilities'].append({
                        'severity': 'High',
                        'description': 'Potential XSS vulnerability detected'
                    })
                
                # Check for sensitive information disclosure
                sensitive_patterns = [
                    'password',
                    'username',
                    'email',
                    'credit card',
                    'ssn',
                    'api key',
                    'secret'
                ]
                
                if any(pattern in content.lower() for pattern in sensitive_patterns):
                    results['vulnerabilities'].append({
                        'severity': 'Medium',
                        'description': 'Potential sensitive information disclosure'
                    })
                
                # Generate recommendations
                if not results['waf_detected']:
                    results['recommendations'].append('Implement a WAF solution to protect your web application')
                elif results['waf_strength'] in ['Weak', 'Medium']:
                    results['recommendations'].append('Strengthen WAF rules to improve protection')
                if results['vulnerabilities']:
                    results['recommendations'].append('Address detected vulnerabilities immediately')
                
                # Add security headers recommendations
                if 'X-Frame-Options' not in results['headers']:
                    results['recommendations'].append('Implement X-Frame-Options header to prevent clickjacking')
                if 'X-Content-Type-Options' not in results['headers']:
                    results['recommendations'].append('Implement X-Content-Type-Options header to prevent MIME type sniffing')
                if 'Content-Security-Policy' not in results['headers']:
                    results['recommendations'].append('Implement Content-Security-Policy header to prevent XSS attacks')
                
                return results
                
            except requests.exceptions.Timeout:
                return {
                    'error': 'Request timed out',
                    'waf_detected': False,
                    'waf_type': None,
                    'waf_strength': 'Unknown',
                    'vulnerabilities': [],
                    'recommendations': ['The website took too long to respond. Please try again.']
                }
            
        except Exception as e:
            logger.error(f"Error scanning URL {url}: {str(e)}")
            return {
                'error': str(e),
                'waf_detected': False,
                'waf_type': None,
                'waf_strength': 'Unknown',
                'vulnerabilities': [],
                'recommendations': ['Error occurred during scan. Please try again.']
            }

class SimpleWAF:
    def __init__(self):
        self.fingerprinting_attempts = {}
        self.blocked_ips = set()
        self.alerts = deque(maxlen=10)
        self.suspicious_patterns = [
            r'wafw00f',
            r'waf-fingerprint',
            r'waf-detection',
            r'waf-test',
            r'waf-bypass',
            r'waf-evasion',
            r'waf-scan',
            r'waf-check',
            r'waf-probe',
            r'waf-identify'
        ]
        
    def detect_fingerprinting(self, request):
        """Detect potential WAF fingerprinting attempts"""
        ip = request.remote_addr
        current_time = datetime.now()
        
        # Check for suspicious patterns in headers and user agent
        user_agent = request.headers.get('User-Agent', '').lower()
        for pattern in self.suspicious_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                alert = f"Fingerprinting attempt detected from {ip} using User-Agent: {user_agent}"
                logger.warning(alert)
                self.alerts.append(alert)
                return True
                
        # Check for common fingerprinting headers
        suspicious_headers = [
            'X-WAF-Test',
            'X-WAF-Detection',
            'X-WAF-Fingerprint',
            'X-WAF-Scan'
        ]
        
        for header in suspicious_headers:
            if header in request.headers:
                alert = f"Fingerprinting header detected from {ip}: {header}"
                logger.warning(alert)
                self.alerts.append(alert)
                return True
                
        return False
        
    def apply_protection(self, request):
        """Apply WAF protection measures"""
        if self.detect_fingerprinting(request):
            ip = request.remote_addr
            self.blocked_ips.add(ip)
            return False, "Access denied - WAF fingerprinting detected"
            
        if request.remote_addr in self.blocked_ips:
            return False, "Access denied - IP blocked"
            
        return True, None

# Initialize WAF and Scanner
waf = SimpleWAF()
scanner = WAFScanner()

# Initialize Trojan Detector
trojan_detector = TrojanDetector(vt_api_key="YOUR_VIRUSTOTAL_API_KEY")

# Initialize Captcha Checker
captcha_checker = CaptchaChecker()

# --- Decoy Path Exposure Scanner ---
DEC0Y_PATHS = [
    '/admin', '/phpmyadmin', '/config.php', '/backup.zip', '/.env', '/test', '/wp-admin', '/.git', '/.svn', '/db.sql', '/database.sql', '/setup.php', '/install.php', '/web.config', '/server-status', '/logs', '/error.log', '/debug.log'
]

def scan_decoy_paths(base_url):
    exposed = []
    checked = []
    for path in DEC0Y_PATHS:
        url = base_url.rstrip('/') + path
        try:
            resp = requests.get(url, timeout=5, verify=False)
            checked.append({'path': path, 'status': resp.status_code})
            if resp.status_code not in [403, 404]:
                exposed.append(path)
        except Exception as e:
            checked.append({'path': path, 'status': 'error', 'error': str(e)})
    return exposed, checked

@app.before_request
def before_request():
    """Apply WAF protection before each request"""
    allowed, message = waf.apply_protection(request)
    if not allowed:
        return jsonify({"error": message}), 403

@app.route('/')
def home():
    """Main application route"""
    return render_template('index.html')

@app.route('/status')
def status():
    """Status page showing WAF protection status"""
    return render_template('status.html', 
                         status={
                             'is_monitoring': True,  # You can make this dynamic based on your monitoring state
                             'alert_count': len(waf.alerts)
                         },
                         alerts=list(waf.alerts),
                         blocked_ips=list(waf.blocked_ips))

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    """Start the monitoring process"""
    # Here you would implement the actual monitoring logic
    flash('Monitoring started successfully', 'success')
    return redirect(url_for('status'))

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    """Stop the monitoring process"""
    # Here you would implement the actual monitoring stop logic
    flash('Monitoring stopped successfully', 'success')
    return redirect(url_for('status'))

@app.route('/test')
def test():
    """Test page for WAF protection"""
    return render_template('test.html')

@app.route('/scan')
def scan():
    """Scan page for URL scanning"""
    return render_template('scan.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    """Handle URL scanning"""
    url = request.form.get('url')
    if not url:
        flash('Please enter a valid URL', 'error')
        return redirect(url_for('scan'))
    
    results = scanner.scan_url(url)
    return render_template('scan.html', scan_results=results)

@app.route('/test/fingerprint', methods=['POST'])
def test_fingerprint():
    """Test fingerprinting detection"""
    user_agent = request.form.get('user_agent', '')
    test_request = type('Request', (), {
        'remote_addr': '127.0.0.1',
        'headers': {'User-Agent': user_agent}
    })
    detected = waf.detect_fingerprinting(test_request)
    return render_template('test.html', 
                         test_results={
                             'success': not detected,
                             'message': 'Fingerprinting detected!' if detected else 'No fingerprinting detected.'
                         },
                         user_agent=user_agent)

@app.route('/test/headers', methods=['POST'])
def test_headers():
    """Test suspicious header detection"""
    header_name = request.form.get('header_name', '')
    header_value = request.form.get('header_value', '')
    test_request = type('Request', (), {
        'remote_addr': '127.0.0.1',
        'headers': {header_name: header_value}
    })
    detected = waf.detect_fingerprinting(test_request)
    return render_template('test.html', 
                         test_results={
                             'success': not detected,
                             'message': 'Suspicious header detected!' if detected else 'No suspicious headers detected.'
                         },
                         header_name=header_name,
                         header_value=header_value)

@app.route('/api/data')
def get_data():
    """Example API endpoint"""
    return jsonify({
        "data": "This is protected data",
        "timestamp": datetime.now().isoformat()
    })

# Add new routes for Trojan detection
@app.route('/scan/trojan', methods=['GET', 'POST'])
def scan_trojan():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        # Save the uploaded file temporarily
        temp_path = os.path.join(app.root_path, 'temp', file.filename)
        os.makedirs(os.path.dirname(temp_path), exist_ok=True)
        file.save(temp_path)
        
        # Analyze the file
        results = trojan_detector.analyze_file(temp_path)
        
        # Clean up
        try:
            os.remove(temp_path)
        except:
            pass
        
        return render_template('trojan_scan.html', scan_results=results)
    
    return render_template('trojan_scan.html')

@app.route('/scan/directory', methods=['GET', 'POST'])
def scan_directory():
    if request.method == 'POST':
        directory = request.form.get('directory')
        if not directory or not os.path.isdir(directory):
            flash('Invalid directory path', 'error')
            return redirect(request.url)
        
        results = trojan_detector.scan_directory(directory)
        return render_template('directory_scan.html', scan_results=results)
    
    return render_template('directory_scan.html')

@app.route('/check-captcha', methods=['POST'])
def check_captcha():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
        
    results = captcha_checker.check_url(url)
    report = captcha_checker.generate_report(results)
    
    return jsonify({
        'success': True,
        'report': report,
        'details': results
    })

@app.route('/scan/decoy-paths', methods=['GET', 'POST'])
def scan_decoy_paths_view():
    results = None
    checked = None
    url = ''
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            flash('Please enter a valid URL', 'error')
            return redirect(request.url)
        if not url.startswith('http'):
            url = 'http://' + url
        exposed, checked = scan_decoy_paths(url)
        results = {
            'exposed': exposed,
            'recommendations': []
        }
        if exposed:
            results['recommendations'].append('Restrict access to these paths using authentication, IP whitelisting, or by removing them from the server.')
            results['recommendations'].append('Consider using a web server configuration (e.g., .htaccess, nginx rules) to block access to sensitive files and directories.')
        else:
            results['recommendations'].append('No common decoy paths are exposed. Good job!')
    return render_template('decoy_scan.html', results=results, checked=checked, url=url)

def find_available_port(start_port=5000, max_port=5050):
    """Find an available port to run the server on"""
    for port in range(start_port, max_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', port))
                return port
        except OSError:
            continue
    raise RuntimeError("No available ports found")

if __name__ == '__main__':
    try:
        port = find_available_port()
        print(f"Starting server on port {port}")
        app.run(debug=True, host='127.0.0.1', port=port)
    except Exception as e:
        print(f"Error starting server: {e}") 