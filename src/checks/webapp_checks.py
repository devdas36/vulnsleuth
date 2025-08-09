"""
VulnSleuth Web Application Security Checker
Web application vulnerability scanning and assessment

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import requests
import ssl
import socket
import re
import json
import time
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Any, Optional, Tuple
import logging
from datetime import datetime, timedelta
import concurrent.futures
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class WebAppSecurityChecker:
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.webapp_config = config.get('web_scanning', {})
        self.logger = logging.getLogger('WebAppSecurityChecker')
        
        # Web scanning configuration
        self.timeout = self.webapp_config.get('request_timeout', 30)
        self.user_agent = self.webapp_config.get('user_agent', 'VulnSleuth/2.0 (Security Scanner)')
        self.max_crawl_depth = self.webapp_config.get('max_crawl_depth', 3)
        self.follow_redirects = self.webapp_config.get('follow_redirects', True)
        self.verify_ssl = self.webapp_config.get('verify_ssl', False)
        
        # Security headers that should be present
        self.required_headers = {
            'strict-transport-security': {
                'severity': 'medium',
                'description': 'HTTP Strict Transport Security (HSTS) header missing',
                'solution': 'Implement HSTS header to force HTTPS connections'
            },
            'x-frame-options': {
                'severity': 'medium',
                'description': 'X-Frame-Options header missing - vulnerable to clickjacking',
                'solution': 'Add X-Frame-Options header to prevent framing attacks'
            },
            'x-content-type-options': {
                'severity': 'low',
                'description': 'X-Content-Type-Options header missing',
                'solution': 'Add X-Content-Type-Options: nosniff header'
            },
            'x-xss-protection': {
                'severity': 'low',
                'description': 'X-XSS-Protection header missing',
                'solution': 'Add X-XSS-Protection: 1; mode=block header'
            },
            'content-security-policy': {
                'severity': 'medium',
                'description': 'Content Security Policy (CSP) header missing',
                'solution': 'Implement Content Security Policy to prevent XSS attacks'
            },
            'referrer-policy': {
                'severity': 'low',
                'description': 'Referrer-Policy header missing',
                'solution': 'Add Referrer-Policy header to control referrer information'
            }
        }
        
        # Dangerous HTTP headers
        self.dangerous_headers = {
            'server': {
                'patterns': [r'Apache/[12]\.\d', r'nginx/0\.\d', r'IIS/[1-6]\.'],
                'severity': 'low',
                'description': 'Server version disclosure in headers'
            },
            'x-powered-by': {
                'patterns': [r'.*'],
                'severity': 'low',
                'description': 'Technology disclosure in X-Powered-By header'
            },
            'x-aspnet-version': {
                'patterns': [r'.*'],
                'severity': 'low',
                'description': 'ASP.NET version disclosure'
            }
        }
        
        # Common vulnerability payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<svg onload=alert('XSS')>"
        ]
        
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' AND 1=1--"
        ]
        
        self.lfi_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        ]
    
    def check_security_headers(self, target: str) -> List[Dict[str, Any]]:
        """
        Check HTTP security headers
        
        Args:
            target: Target URL or hostname
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        self.logger.info(f"Checking security headers for {target}")
        
        try:
            # Ensure target has proper URL format
            if not target.startswith(('http://', 'https://')):
                target = f'http://{target}'
            
            # Make request with custom headers
            headers = {
                'User-Agent': self.user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(target, headers=headers, timeout=self.timeout, 
                                  allow_redirects=self.follow_redirects, 
                                  verify=self.verify_ssl)
            
            response_headers = response.headers
            
            # Check for missing security headers
            for header_name, header_info in self.required_headers.items():
                if header_name not in response_headers:
                    finding = {
                        'id': f'missing_header_{hashlib.md5((target + header_name).encode()).hexdigest()[:8]}',
                        'title': f'Missing Security Header: {header_name}',
                        'description': header_info['description'],
                        'severity': header_info['severity'],
                        'confidence': 0.9,
                        'target': target,
                        'plugin_source': 'WebAppSecurityChecker',
                        'metadata': {
                            'missing_header': header_name,
                            'response_headers': dict(response_headers)
                        },
                        'solution': header_info['solution'],
                        'references': ['https://www.owasp.org/www-project-secure-headers/']
                    }
                    findings.append(finding)
            
            # Check for dangerous headers
            for header_name, header_info in self.dangerous_headers.items():
                if header_name in response_headers:
                    header_value = response_headers[header_name]
                    
                    for pattern in header_info['patterns']:
                        if re.search(pattern, header_value, re.IGNORECASE):
                            finding = {
                                'id': f'dangerous_header_{hashlib.md5((target + header_name).encode()).hexdigest()[:8]}',
                                'title': f'Information Disclosure: {header_name}',
                                'description': f'{header_info["description"]}: {header_value}',
                                'severity': header_info['severity'],
                                'confidence': 0.8,
                                'target': target,
                                'plugin_source': 'WebAppSecurityChecker',
                                'metadata': {
                                    'header_name': header_name,
                                    'header_value': header_value
                                },
                                'solution': f'Remove or obfuscate {header_name} header',
                                'references': ['https://www.owasp.org/www-project-web-security-testing-guide/']
                            }
                            findings.append(finding)
            
            # Check for weak CSP if present
            if 'content-security-policy' in response_headers:
                csp_findings = self._analyze_csp(target, response_headers['content-security-policy'])
                findings.extend(csp_findings)
            
            # Check for insecure cookies
            if 'set-cookie' in response_headers:
                cookie_findings = self._analyze_cookies(target, response_headers)
                findings.extend(cookie_findings)
        
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error checking headers for {target}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error checking headers for {target}: {str(e)}")
        
        return findings
    
    def check_ssl_configuration(self, target: str) -> List[Dict[str, Any]]:
        """
        Check SSL/TLS configuration
        
        Args:
            target: Target hostname or URL
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        self.logger.info(f"Checking SSL configuration for {target}")
        
        try:
            # Parse target to get hostname and port
            parsed_url = urlparse(target if target.startswith(('http://', 'https://')) else f'https://{target}')
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Create SSL context for testing
            context = ssl.create_default_context()
            
            # Test with secure context first
            try:
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        protocol = ssock.version()
                        
                        # Check certificate validity
                        cert_findings = self._check_certificate(target, cert)
                        findings.extend(cert_findings)
                        
                        # Check cipher suite
                        cipher_findings = self._check_cipher_suite(target, cipher)
                        findings.extend(cipher_findings)
                        
                        # Check protocol version
                        protocol_findings = self._check_ssl_protocol(target, protocol)
                        findings.extend(protocol_findings)
            
            except ssl.SSLError as e:
                # SSL connection failed - this might indicate problems
                finding = {
                    'id': f'ssl_connection_failed_{hostname}_{port}',
                    'title': 'SSL/TLS Connection Issues',
                    'description': f'SSL/TLS connection failed: {str(e)}',
                    'severity': 'medium',
                    'confidence': 0.8,
                    'target': target,
                    'plugin_source': 'WebAppSecurityChecker',
                    'metadata': {'ssl_error': str(e)},
                    'solution': 'Review and fix SSL/TLS configuration',
                    'references': ['https://ssl-config.mozilla.org/']
                }
                findings.append(finding)
            
            # Test for weak SSL/TLS support
            weak_ssl_findings = self._test_weak_ssl_support(hostname, port)
            findings.extend(weak_ssl_findings)
        
        except Exception as e:
            self.logger.error(f"Error checking SSL configuration for {target}: {str(e)}")
        
        return findings
    
    def check_common_vulnerabilities(self, target: str) -> List[Dict[str, Any]]:
        """
        Check for common web vulnerabilities
        
        Args:
            target: Target URL
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        self.logger.info(f"Checking common vulnerabilities for {target}")
        
        try:
            # Ensure proper URL format
            if not target.startswith(('http://', 'https://')):
                target = f'http://{target}'
            
            # Get initial page
            response = requests.get(target, timeout=self.timeout, verify=self.verify_ssl)
            
            # Parse HTML content
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Check for XSS vulnerabilities
            xss_findings = self._check_xss_vulnerabilities(target, soup)
            findings.extend(xss_findings)
            
            # Check for SQL injection vulnerabilities
            sqli_findings = self._check_sqli_vulnerabilities(target, soup)
            findings.extend(sqli_findings)
            
            # Check for Local File Inclusion vulnerabilities
            lfi_findings = self._check_lfi_vulnerabilities(target, soup)
            findings.extend(lfi_findings)
            
            # Check for directory traversal
            directory_findings = self._check_directory_traversal(target)
            findings.extend(directory_findings)
            
            # Check for information disclosure
            info_findings = self._check_information_disclosure(target, response)
            findings.extend(info_findings)
            
            # Check for CSRF vulnerabilities
            csrf_findings = self._check_csrf_vulnerabilities(target, soup)
            findings.extend(csrf_findings)
        
        except Exception as e:
            self.logger.error(f"Error checking vulnerabilities for {target}: {str(e)}")
        
        return findings
    
    def check_content_security_policy(self, target: str) -> List[Dict[str, Any]]:
        """
        Check Content Security Policy configuration
        
        Args:
            target: Target URL
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        self.logger.info(f"Checking Content Security Policy for {target}")
        
        try:
            if not target.startswith(('http://', 'https://')):
                target = f'http://{target}'
            
            response = requests.get(target, timeout=self.timeout, verify=self.verify_ssl)
            
            csp_header = response.headers.get('content-security-policy')
            if csp_header:
                findings.extend(self._analyze_csp(target, csp_header))
            else:
                finding = {
                    'id': f'missing_csp_{hashlib.md5(target.encode()).hexdigest()[:8]}',
                    'title': 'Missing Content Security Policy',
                    'description': 'Content Security Policy header is not implemented',
                    'severity': 'medium',
                    'confidence': 0.9,
                    'target': target,
                    'plugin_source': 'WebAppSecurityChecker',
                    'solution': 'Implement a strict Content Security Policy',
                    'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP']
                }
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Error checking CSP for {target}: {str(e)}")
        
        return findings
    
    def _analyze_csp(self, target: str, csp_header: str) -> List[Dict[str, Any]]:
        """Analyze Content Security Policy header"""
        findings = []
        
        # Check for unsafe directives
        unsafe_patterns = {
            r"'unsafe-inline'": {
                'severity': 'medium',
                'description': 'CSP allows unsafe-inline, which defeats XSS protection'
            },
            r"'unsafe-eval'": {
                'severity': 'medium',
                'description': 'CSP allows unsafe-eval, which can lead to code injection'
            },
            r'\*': {
                'severity': 'low',
                'description': 'CSP uses wildcard (*) which may be too permissive'
            },
            r'data:': {
                'severity': 'low',
                'description': 'CSP allows data: URIs which may be risky'
            }
        }
        
        for pattern, info in unsafe_patterns.items():
            if re.search(pattern, csp_header, re.IGNORECASE):
                finding = {
                    'id': f'weak_csp_{hashlib.md5((target + pattern).encode()).hexdigest()[:8]}',
                    'title': 'Weak Content Security Policy',
                    'description': info['description'],
                    'severity': info['severity'],
                    'confidence': 0.8,
                    'target': target,
                    'plugin_source': 'WebAppSecurityChecker',
                    'metadata': {'csp_header': csp_header, 'unsafe_pattern': pattern},
                    'solution': 'Strengthen Content Security Policy by removing unsafe directives',
                    'references': ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP']
                }
                findings.append(finding)
        
        return findings
    
    def _analyze_cookies(self, target: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze cookie security"""
        findings = []
        
        cookies = headers.get('set-cookie', '')
        if not cookies:
            return findings
        
        # Check for missing security flags
        if 'secure' not in cookies.lower():
            finding = {
                'id': f'insecure_cookie_{hashlib.md5(target.encode()).hexdigest()[:8]}',
                'title': 'Insecure Cookie Configuration',
                'description': 'Cookies are missing the Secure flag',
                'severity': 'medium',
                'confidence': 0.8,
                'target': target,
                'plugin_source': 'WebAppSecurityChecker',
                'metadata': {'cookies': cookies},
                'solution': 'Add Secure flag to all cookies',
                'references': ['https://www.owasp.org/www-community/controls/SecureCookieAttribute']
            }
            findings.append(finding)
        
        if 'httponly' not in cookies.lower():
            finding = {
                'id': f'cookie_no_httponly_{hashlib.md5(target.encode()).hexdigest()[:8]}',
                'title': 'Cookie Missing HttpOnly Flag',
                'description': 'Cookies are missing the HttpOnly flag, vulnerable to XSS',
                'severity': 'medium',
                'confidence': 0.8,
                'target': target,
                'plugin_source': 'WebAppSecurityChecker',
                'metadata': {'cookies': cookies},
                'solution': 'Add HttpOnly flag to sensitive cookies',
                'references': ['https://www.owasp.org/www-community/HttpOnly']
            }
            findings.append(finding)
        
        return findings
    
    def _check_certificate(self, target: str, cert: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check SSL certificate security"""
        findings = []
        
        try:
            # Check certificate expiration
            not_after = cert.get('notAfter')
            if not_after:
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry_date - datetime.now()).days
                
                if days_until_expiry < 30:
                    severity = 'high' if days_until_expiry < 7 else 'medium'
                    finding = {
                        'id': f'cert_expiry_{hashlib.md5(target.encode()).hexdigest()[:8]}',
                        'title': 'SSL Certificate Expiring Soon',
                        'description': f'SSL certificate expires in {days_until_expiry} days',
                        'severity': severity,
                        'confidence': 1.0,
                        'target': target,
                        'plugin_source': 'WebAppSecurityChecker',
                        'metadata': {'expiry_date': not_after, 'days_until_expiry': days_until_expiry},
                        'solution': 'Renew SSL certificate before expiration',
                        'references': ['https://letsencrypt.org/']
                    }
                    findings.append(finding)
            
            # Check for self-signed certificates
            issuer = cert.get('issuer', [])
            subject = cert.get('subject', [])
            
            if issuer == subject:
                finding = {
                    'id': f'self_signed_cert_{hashlib.md5(target.encode()).hexdigest()[:8]}',
                    'title': 'Self-Signed SSL Certificate',
                    'description': 'SSL certificate is self-signed and not trusted',
                    'severity': 'medium',
                    'confidence': 0.9,
                    'target': target,
                    'plugin_source': 'WebAppSecurityChecker',
                    'metadata': {'issuer': issuer, 'subject': subject},
                    'solution': 'Use a certificate from a trusted Certificate Authority',
                    'references': ['https://letsencrypt.org/']
                }
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Error checking certificate: {str(e)}")
        
        return findings
    
    def _check_cipher_suite(self, target: str, cipher: Tuple[str, str, int]) -> List[Dict[str, Any]]:
        """Check SSL cipher suite security"""
        findings = []
        
        if not cipher:
            return findings
        
        cipher_name, protocol, key_bits = cipher
        
        # Check for weak key lengths
        if key_bits < 128:
            finding = {
                'id': f'weak_cipher_{hashlib.md5(target.encode()).hexdigest()[:8]}',
                'title': 'Weak SSL Cipher Suite',
                'description': f'Weak cipher suite in use: {cipher_name} ({key_bits} bits)',
                'severity': 'high',
                'confidence': 0.9,
                'target': target,
                'plugin_source': 'WebAppSecurityChecker',
                'metadata': {'cipher': cipher_name, 'key_bits': key_bits},
                'solution': 'Configure stronger cipher suites (minimum 128-bit)',
                'references': ['https://ssl-config.mozilla.org/']
            }
            findings.append(finding)
        
        # Check for deprecated ciphers
        deprecated_ciphers = ['RC4', 'DES', '3DES', 'NULL']
        for deprecated in deprecated_ciphers:
            if deprecated in cipher_name.upper():
                finding = {
                    'id': f'deprecated_cipher_{hashlib.md5((target + deprecated).encode()).hexdigest()[:8]}',
                    'title': 'Deprecated SSL Cipher',
                    'description': f'Deprecated cipher in use: {cipher_name}',
                    'severity': 'medium',
                    'confidence': 0.9,
                    'target': target,
                    'plugin_source': 'WebAppSecurityChecker',
                    'metadata': {'cipher': cipher_name, 'deprecated_component': deprecated},
                    'solution': 'Remove deprecated cipher suites from SSL configuration',
                    'references': ['https://ssl-config.mozilla.org/']
                }
                findings.append(finding)
        
        return findings
    
    def _check_ssl_protocol(self, target: str, protocol: str) -> List[Dict[str, Any]]:
        """Check SSL protocol version"""
        findings = []
        
        deprecated_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
        
        if protocol in deprecated_protocols:
            severity = 'critical' if protocol.startswith('SSL') else 'medium'
            finding = {
                'id': f'deprecated_protocol_{hashlib.md5((target + protocol).encode()).hexdigest()[:8]}',
                'title': 'Deprecated SSL/TLS Protocol',
                'description': f'Deprecated protocol in use: {protocol}',
                'severity': severity,
                'confidence': 0.9,
                'target': target,
                'plugin_source': 'WebAppSecurityChecker',
                'metadata': {'protocol': protocol},
                'solution': 'Upgrade to TLS 1.2 or higher',
                'references': ['https://tools.ietf.org/html/rfc8446']
            }
            findings.append(finding)
        
        return findings
    
    def _test_weak_ssl_support(self, hostname: str, port: int) -> List[Dict[str, Any]]:
        """Test for weak SSL/TLS protocol support"""
        findings = []
        
        # Test deprecated protocols
        deprecated_protocols = [
            (ssl.PROTOCOL_SSLv23, 'SSLv2/v3'),
            (ssl.PROTOCOL_TLSv1, 'TLSv1.0'),
        ]
        
        try:
            # Note: Some of these protocols might not be available in newer Python versions
            for protocol, name in deprecated_protocols:
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock) as ssock:
                            # If connection succeeds, the protocol is supported
                            finding = {
                                'id': f'weak_protocol_support_{hostname}_{port}_{name.replace(".", "_")}',
                                'title': f'Weak SSL/TLS Protocol Support: {name}',
                                'description': f'Server supports deprecated protocol {name}',
                                'severity': 'high',
                                'confidence': 0.9,
                                'target': f'{hostname}:{port}',
                                'plugin_source': 'WebAppSecurityChecker',
                                'metadata': {'protocol': name},
                                'solution': f'Disable support for {name} protocol',
                                'references': ['https://ssl-config.mozilla.org/']
                            }
                            findings.append(finding)
                
                except (ssl.SSLError, socket.error, AttributeError):
                    # Protocol not supported or connection failed - this is good
                    continue
        
        except Exception as e:
            self.logger.debug(f"Error testing weak SSL protocols: {str(e)}")
        
        return findings
    
    def _check_xss_vulnerabilities(self, target: str, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Check for Cross-Site Scripting vulnerabilities"""
        findings = []
        
        try:
            # Find forms that might be vulnerable to XSS
            forms = soup.find_all('form')
            
            for i, form in enumerate(forms):
                # Check if form has CSRF protection
                csrf_tokens = form.find_all('input', {'type': 'hidden'})
                has_csrf = any('csrf' in token.get('name', '').lower() or 'token' in token.get('name', '').lower() 
                              for token in csrf_tokens)
                
                if not has_csrf:
                    # Test for XSS in form inputs
                    xss_vuln = self._test_form_xss(target, form)
                    if xss_vuln:
                        findings.append(xss_vuln)
            
            # Check for reflected XSS in URL parameters
            parsed_url = urlparse(target)
            if parsed_url.query:
                reflected_xss = self._test_reflected_xss(target)
                if reflected_xss:
                    findings.append(reflected_xss)
        
        except Exception as e:
            self.logger.error(f"Error checking XSS vulnerabilities: {str(e)}")
        
        return findings
    
    def _check_sqli_vulnerabilities(self, target: str, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Check for SQL Injection vulnerabilities"""
        findings = []
        
        try:
            # Find forms that might be vulnerable to SQLi
            forms = soup.find_all('form')
            
            for form in forms:
                sqli_vuln = self._test_form_sqli(target, form)
                if sqli_vuln:
                    findings.append(sqli_vuln)
            
            # Check for SQLi in URL parameters
            parsed_url = urlparse(target)
            if parsed_url.query:
                url_sqli = self._test_url_sqli(target)
                if url_sqli:
                    findings.append(url_sqli)
        
        except Exception as e:
            self.logger.error(f"Error checking SQL injection vulnerabilities: {str(e)}")
        
        return findings
    
    def _check_lfi_vulnerabilities(self, target: str, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Check for Local File Inclusion vulnerabilities"""
        findings = []
        
        try:
            # Look for file parameter patterns in URLs and forms
            parsed_url = urlparse(target)
            query_params = parse_qs(parsed_url.query)
            
            file_params = ['file', 'page', 'include', 'path', 'doc', 'document']
            
            for param in file_params:
                if param in query_params:
                    lfi_vuln = self._test_lfi_parameter(target, param)
                    if lfi_vuln:
                        findings.append(lfi_vuln)
        
        except Exception as e:
            self.logger.error(f"Error checking LFI vulnerabilities: {str(e)}")
        
        return findings
    
    def _check_directory_traversal(self, target: str) -> List[Dict[str, Any]]:
        """Check for directory traversal vulnerabilities"""
        findings = []
        
        try:
            # Test common directory traversal paths
            traversal_paths = [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd'
            ]
            
            base_url = target.rstrip('/')
            
            for path in traversal_paths:
                test_url = f"{base_url}/{path}"
                
                try:
                    response = requests.get(test_url, timeout=5, verify=self.verify_ssl)
                    
                    # Check for file disclosure indicators
                    if (response.status_code == 200 and 
                        ('root:' in response.text or 'localhost' in response.text)):
                        
                        finding = {
                            'id': f'directory_traversal_{hashlib.md5(test_url.encode()).hexdigest()[:8]}',
                            'title': 'Directory Traversal Vulnerability',
                            'description': f'Directory traversal vulnerability detected at {test_url}',
                            'severity': 'high',
                            'confidence': 0.8,
                            'target': target,
                            'plugin_source': 'WebAppSecurityChecker',
                            'metadata': {'vulnerable_path': path, 'test_url': test_url},
                            'solution': 'Implement proper input validation and file access controls',
                            'references': ['https://www.owasp.org/www-community/attacks/Path_Traversal']
                        }
                        findings.append(finding)
                        break  # Don't test more if we found one
                
                except requests.exceptions.RequestException:
                    continue
        
        except Exception as e:
            self.logger.error(f"Error checking directory traversal: {str(e)}")
        
        return findings
    
    def _check_information_disclosure(self, target: str, response: requests.Response) -> List[Dict[str, Any]]:
        """Check for information disclosure"""
        findings = []
        
        try:
            content = response.text.lower()
            
            # Check for common information disclosure patterns
            disclosure_patterns = {
                r'mysql_connect\(': {
                    'title': 'Database Connection Information Disclosure',
                    'severity': 'medium'
                },
                r'warning:.*on line \d+': {
                    'title': 'PHP Error Information Disclosure',
                    'severity': 'low'
                },
                r'exception.*stack trace': {
                    'title': 'Application Error Information Disclosure',
                    'severity': 'low'
                },
                r'root@.*:\$': {
                    'title': 'System Information Disclosure',
                    'severity': 'medium'
                }
            }
            
            for pattern, info in disclosure_patterns.items():
                if re.search(pattern, content):
                    finding = {
                        'id': f'info_disclosure_{hashlib.md5((target + pattern).encode()).hexdigest()[:8]}',
                        'title': info['title'],
                        'description': f'Information disclosure detected in response content',
                        'severity': info['severity'],
                        'confidence': 0.7,
                        'target': target,
                        'plugin_source': 'WebAppSecurityChecker',
                        'metadata': {'pattern': pattern},
                        'solution': 'Remove or suppress error messages and debug information',
                        'references': ['https://www.owasp.org/www-community/Improper_Error_Handling']
                    }
                    findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Error checking information disclosure: {str(e)}")
        
        return findings
    
    def _check_csrf_vulnerabilities(self, target: str, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Check for Cross-Site Request Forgery vulnerabilities"""
        findings = []
        
        try:
            # Find forms that modify state (POST, PUT, DELETE)
            state_changing_forms = soup.find_all('form', {'method': re.compile(r'post|put|delete', re.IGNORECASE)})
            
            for form in state_changing_forms:
                # Check for CSRF tokens
                has_csrf_token = False
                
                # Look for common CSRF token patterns
                csrf_inputs = form.find_all('input', {'type': 'hidden'})
                for input_field in csrf_inputs:
                    name = input_field.get('name', '').lower()
                    if any(token_name in name for token_name in ['csrf', 'token', '_token', 'authenticity']):
                        has_csrf_token = True
                        break
                
                if not has_csrf_token:
                    finding = {
                        'id': f'csrf_missing_{hashlib.md5((target + str(form)).encode()).hexdigest()[:8]}',
                        'title': 'Missing CSRF Protection',
                        'description': 'Form lacks CSRF protection tokens',
                        'severity': 'medium',
                        'confidence': 0.8,
                        'target': target,
                        'plugin_source': 'WebAppSecurityChecker',
                        'metadata': {'form_action': form.get('action', '')},
                        'solution': 'Implement CSRF tokens for all state-changing forms',
                        'references': ['https://www.owasp.org/www-community/attacks/csrf']
                    }
                    findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Error checking CSRF vulnerabilities: {str(e)}")
        
        return findings
    
    # Helper methods for vulnerability testing
    
    def _test_form_xss(self, target: str, form) -> Optional[Dict[str, Any]]:
        """Test form for XSS vulnerability"""
        # This is a simplified test - in practice, you'd want more comprehensive testing
        # and should only be used with explicit authorization
        return None
    
    def _test_reflected_xss(self, target: str) -> Optional[Dict[str, Any]]:
        """Test for reflected XSS in URL parameters"""
        # Placeholder - implement with caution and authorization
        return None
    
    def _test_form_sqli(self, target: str, form) -> Optional[Dict[str, Any]]:
        """Test form for SQL injection vulnerability"""
        # Placeholder - implement with caution and authorization
        return None
    
    def _test_url_sqli(self, target: str) -> Optional[Dict[str, Any]]:
        """Test URL parameters for SQL injection"""
        # Placeholder - implement with caution and authorization
        return None
    
    def _test_lfi_parameter(self, target: str, param: str) -> Optional[Dict[str, Any]]:
        """Test parameter for Local File Inclusion"""
        # Placeholder - implement with caution and authorization
        return None

if __name__ == "__main__":
    # Test the web app security checker
    config = {'web_scanning': {}}
    checker = WebAppSecurityChecker(config)
    
    target = "https://httpbin.org"
    
    findings = checker.check_security_headers(target)
    findings.extend(checker.check_ssl_configuration(target))
    
    print(f"Found {len(findings)} web application vulnerabilities:")
    for finding in findings:
        print(f"- {finding['title']} [{finding['severity'].upper()}]")
        print(f"  {finding['description']}")
        print()
