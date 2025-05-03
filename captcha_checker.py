import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
import logging

class CaptchaChecker:
    def __init__(self):
        self.captcha_patterns = {
            'reCAPTCHA': [
                r'grecaptcha',
                r'data-sitekey',
                r'recaptcha',
                r'google.com/recaptcha'
            ],
            'hCaptcha': [
                r'hcaptcha',
                r'h-captcha',
                r'hcaptcha.com'
            ],
            'FunCaptcha': [
                r'funcaptcha',
                r'funcaptcha.com'
            ],
            'Cloudflare': [
                r'cf-turnstile',
                r'challenge.cloudflare.com'
            ]
        }
        
        self.captcha_locations = {
            'login': [
                r'login',
                r'signin',
                r'authenticate',
                r'password'
            ],
            'form': [
                r'form',
                r'submit',
                r'register',
                r'signup'
            ],
            'comment': [
                r'comment',
                r'post',
                r'reply'
            ]
        }
        
    def check_url(self, url):
        """Check a URL for CAPTCHA presence and implementation"""
        try:
            # Validate URL
            parsed_url = urlparse(url)
            if not parsed_url.scheme:
                url = 'https://' + url
                
            # Make request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            
            # Parse response
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Initialize results
            results = {
                'url': url,
                'captcha_found': False,
                'captcha_type': None,
                'captcha_location': None,
                'implementation_details': {},
                'vulnerabilities': []
            }
            
            # Check for CAPTCHA types
            for captcha_type, patterns in self.captcha_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, str(soup), re.IGNORECASE):
                        results['captcha_found'] = True
                        results['captcha_type'] = captcha_type
                        
                        # Check implementation
                        if captcha_type == 'reCAPTCHA':
                            sitekey = soup.find('div', {'data-sitekey': True})
                            if sitekey:
                                results['implementation_details']['sitekey'] = sitekey['data-sitekey']
                            else:
                                results['vulnerabilities'].append('reCAPTCHA sitekey not found')
                        
                        # Check location
                        for location, location_patterns in self.captcha_locations.items():
                            for loc_pattern in location_patterns:
                                if re.search(loc_pattern, url, re.IGNORECASE):
                                    results['captcha_location'] = location
                                    break
                        
                        break
                
                if results['captcha_found']:
                    break
            
            # Check for common vulnerabilities
            if results['captcha_found']:
                # Check if CAPTCHA is properly loaded
                if not any(script for script in soup.find_all('script') 
                         if any(pattern in str(script) for pattern in self.captcha_patterns[results['captcha_type']])):
                    results['vulnerabilities'].append('CAPTCHA script not properly loaded')
                
                # Check for missing validation
                forms = soup.find_all('form')
                for form in forms:
                    if not form.find('input', {'name': 'g-recaptcha-response'}):
                        results['vulnerabilities'].append('Missing CAPTCHA validation in form')
            
            return results
            
        except Exception as e:
            logging.error(f"Error checking URL {url}: {str(e)}")
            return {
                'url': url,
                'error': str(e)
            }
            
    def generate_report(self, results):
        """Generate a detailed report of CAPTCHA findings"""
        if 'error' in results:
            return f"Error checking {results['url']}: {results['error']}"
            
        report = []
        report.append(f"CAPTCHA Check Report for {results['url']}")
        report.append("=" * 50)
        
        if results['captcha_found']:
            report.append(f"CAPTCHA Type: {results['captcha_type']}")
            report.append(f"Location: {results['captcha_location'] or 'Unknown'}")
            
            if results['implementation_details']:
                report.append("\nImplementation Details:")
                for key, value in results['implementation_details'].items():
                    report.append(f"- {key}: {value}")
            
            if results['vulnerabilities']:
                report.append("\nPotential Vulnerabilities:")
                for vuln in results['vulnerabilities']:
                    report.append(f"- {vuln}")
            else:
                report.append("\nNo obvious vulnerabilities detected")
        else:
            report.append("No CAPTCHA protection detected")
            report.append("\nRecommendation: Consider implementing CAPTCHA protection")
            
        return "\n".join(report)