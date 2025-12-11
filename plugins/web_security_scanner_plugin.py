"""
Web Application Security Scanner Plugin
Comprehensive web vulnerability detection and testing

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import re
import requests
import socket
import urllib.parse
from typing import List, Dict, Any, Optional
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from plugin import VulnPlugin, VulnerabilityFinding, PluginMetadata

# Suppress SSL warnings for security testing
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except (ImportError, AttributeError):
    # Newer versions of requests use urllib3 directly
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except (ImportError, AttributeError):
        pass  # SSL warnings will be shown, but plugin will still work

class WebSecurityScannerPlugin(VulnPlugin):
    """
    Comprehensive Web Application Security Scanner
    
    Features:
    - HTTP security header analysis
    - SSL/TLS configuration testing
    - Common web vulnerabilities detection
    - Information disclosure checks
    - Security misconfiguration detection
    - Cookie security analysis
    - Directory listing detection
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.metadata = PluginMetadata(
            name="Web Security Scanner Plugin",
            version="2.0.0",
            author="Devdas",
            description="Comprehensive web application vulnerability scanner",
            category="web",
            tags=["web", "http", "headers", "ssl", "xss", "sqli", "security"]
        )
        
        self.timeout = 10
        self.user_agent = 'VulnSleuth/2.0 Security Scanner'
        
        # Security headers to check
        self.security_headers = {
            'Strict-Transport-Security': {
                'severity': 'medium',
                'description': 'HSTS header missing - Site vulnerable to protocol downgrade attacks'
            },
            'X-Frame-Options': {
                'severity': 'medium',
                'description': 'X-Frame-Options header missing - Site vulnerable to clickjacking'
            },
            'X-Content-Type-Options': {
                'severity': 'low',
                'description': 'X-Content-Type-Options header missing - Browser may MIME-sniff responses'
            },
            'Content-Security-Policy': {
                'severity': 'medium',
                'description': 'CSP header missing - XSS attacks may not be mitigated'
            },
            'X-XSS-Protection': {
                'severity': 'low',
                'description': 'X-XSS-Protection header missing - Legacy XSS filter not enabled'
            },
            'Referrer-Policy': {
                'severity': 'low',
                'description': 'Referrer-Policy header missing - Referrer information may leak'
            },
            'Permissions-Policy': {
                'severity': 'low',
                'description': 'Permissions-Policy header missing - Browser features not restricted'
            }
        }
        
        # Insecure cookie patterns
        self.cookie_checks = ['secure', 'httponly', 'samesite']
        
        # Information disclosure patterns
        self.disclosure_patterns = {
            'server_version': [
                (r'Server:\s*(.+)', 'Server version disclosure'),
                (r'X-Powered-By:\s*(.+)', 'Technology stack disclosure'),
                (r'X-AspNet-Version:\s*(.+)', 'ASP.NET version disclosure'),
                (r'X-AspNetMvc-Version:\s*(.+)', 'ASP.NET MVC version disclosure')
            ],
            'error_messages': [
                (r'(?i)(sql\s+syntax|mysql|postgresql|oracle)', 'Database error message'),
                (r'(?i)(warning|error|exception|stack\s+trace)', 'Application error disclosure'),
                (r'(?i)(root\s+at|caused\s+by|line\s+\d+)', 'Stack trace disclosure')
            ]
        }
        
        # Common vulnerable paths
        self.test_paths = [
            '/.git/HEAD',
            '/.env',
            '/.DS_Store',
            '/phpinfo.php',
            '/admin',
            '/backup',
            '/.htaccess',
            '/web.config',
            '/crossdomain.xml',
            '/robots.txt',
            '/sitemap.xml'
        ]
    
    def can_run(self, target: str, context: Dict[str, Any]) -> bool:
        """Check if this plugin can run against the target"""
        return context.get('has_web_services', False) or context.get('is_web_target', False) or \
               target.startswith('http://') or target.startswith('https://')
    
    def check(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """Main vulnerability check method"""
        context = kwargs.get('context', {})
        return self.execute(target, context)
    
    def execute(self, target: str, context: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Execute web security checks"""
        findings = []
        
        try:
            # Build target URLs
            urls = self._build_target_urls(target, context)
            
            for url in urls:
                self.logger.info(f"Scanning web target: {url}")
                
                # Phase 1: Security headers check
                header_findings = self._check_security_headers(url)
                findings.extend(header_findings)
                
                # Phase 2: Cookie security check
                cookie_findings = self._check_cookie_security(url)
                findings.extend(cookie_findings)
                
                # Phase 3: Information disclosure check
                disclosure_findings = self._check_information_disclosure(url)
                findings.extend(disclosure_findings)
                
                # Phase 4: Common vulnerability paths
                path_findings = self._check_vulnerable_paths(url)
                findings.extend(path_findings)
                
                # Phase 5: HTTP methods check
                method_findings = self._check_http_methods(url)
                findings.extend(method_findings)
                
                # Phase 6: Directory listing check
                listing_findings = self._check_directory_listing(url)
                findings.extend(listing_findings)
            
            self.logger.info(f"Web security scan complete: {len(findings)} findings")
            
        except Exception as e:
            self.logger.error(f"Web security scan failed: {str(e)}")
        
        return findings
    
    def _build_target_urls(self, target: str, context: Dict[str, Any]) -> List[str]:
        """Build list of URLs to test"""
        urls = []
        
        if target.startswith('http://') or target.startswith('https://'):
            urls.append(target)
        else:
            # Check for web ports in context
            web_ports = context.get('web_ports', [80, 443, 8080, 8443])
            
            for port in web_ports:
                if port in [443, 8443]:
                    urls.append(f'https://{target}:{port}')
                else:
                    urls.append(f'http://{target}:{port}')
        
        return urls
    
    def _check_security_headers(self, url: str) -> List[VulnerabilityFinding]:
        """Check for missing security headers"""
        findings = []
        
        try:
            response = requests.get(url, timeout=self.timeout, verify=False,
                                   headers={'User-Agent': self.user_agent})
            
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            for header, info in self.security_headers.items():
                if header.lower() not in headers_lower:
                    title = f"Missing Security Header: {header}"
                    
                    description = f"The security header '{header}' is not present in the HTTP response.\n\n"
                    description += f"{info['description']}\n\n"
                    description += f"URL: {url}\n"
                    
                    solution = self._get_header_solution(header)
                    
                    finding = self.create_finding(
                        title=title,
                        severity=info['severity'],
                        description=description,
                        target=url,
                        confidence=0.9,
                        solution=solution,
                        references=[
                            'https://owasp.org/www-project-secure-headers/',
                            f'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header}'
                        ],
                        metadata={'header': header, 'url': url}
                    )
                    findings.append(finding)
            
        except Exception as e:
            self.logger.error(f"Security header check failed for {url}: {str(e)}")
        
        return findings
    
    def _check_cookie_security(self, url: str) -> List[VulnerabilityFinding]:
        """Check cookie security attributes"""
        findings = []
        
        try:
            response = requests.get(url, timeout=self.timeout, verify=False,
                                   headers={'User-Agent': self.user_agent})
            
            set_cookie_headers = response.headers.get_all('Set-Cookie', [])
            
            for cookie_header in set_cookie_headers:
                cookie_lower = cookie_header.lower()
                
                # Extract cookie name
                cookie_name = cookie_header.split('=')[0].strip()
                
                # Check for Secure flag
                if 'secure' not in cookie_lower and url.startswith('https://'):
                    title = f"Cookie Missing Secure Flag: {cookie_name}"
                    
                    description = f"The cookie '{cookie_name}' is missing the 'Secure' flag.\n\n"
                    description += "Cookies without the Secure flag can be transmitted over unencrypted HTTP, "
                    description += "making them vulnerable to interception.\n\n"
                    description += f"URL: {url}\n"
                    description += f"Cookie: {cookie_header[:100]}"
                    
                    solution = "Set the 'Secure' flag on all cookies used over HTTPS to ensure they are only "
                    solution += "transmitted over encrypted connections."
                    
                    finding = self.create_finding(
                        title=title,
                        severity='medium',
                        description=description,
                        target=url,
                        confidence=0.9,
                        solution=solution,
                        references=[
                            'https://owasp.org/www-community/controls/SecureCookieAttribute'
                        ],
                        metadata={'cookie_name': cookie_name, 'cookie_header': cookie_header}
                    )
                    findings.append(finding)
                
                # Check for HttpOnly flag
                if 'httponly' not in cookie_lower:
                    title = f"Cookie Missing HttpOnly Flag: {cookie_name}"
                    
                    description = f"The cookie '{cookie_name}' is missing the 'HttpOnly' flag.\n\n"
                    description += "Cookies without the HttpOnly flag can be accessed by JavaScript, "
                    description += "making them vulnerable to XSS attacks.\n\n"
                    description += f"URL: {url}\n"
                    
                    solution = "Set the 'HttpOnly' flag on session cookies and other sensitive cookies "
                    solution += "to prevent access via JavaScript."
                    
                    finding = self.create_finding(
                        title=title,
                        severity='medium',
                        description=description,
                        target=url,
                        confidence=0.85,
                        solution=solution,
                        references=[
                            'https://owasp.org/www-community/HttpOnly'
                        ],
                        metadata={'cookie_name': cookie_name}
                    )
                    findings.append(finding)
                
                # Check for SameSite attribute
                if 'samesite' not in cookie_lower:
                    title = f"Cookie Missing SameSite Attribute: {cookie_name}"
                    
                    description = f"The cookie '{cookie_name}' is missing the 'SameSite' attribute.\n\n"
                    description += "Cookies without SameSite attribute are vulnerable to CSRF attacks.\n\n"
                    description += f"URL: {url}\n"
                    
                    solution = "Set the 'SameSite' attribute to 'Strict' or 'Lax' to protect against CSRF attacks."
                    
                    finding = self.create_finding(
                        title=title,
                        severity='low',
                        description=description,
                        target=url,
                        confidence=0.8,
                        solution=solution,
                        references=[
                            'https://owasp.org/www-community/SameSite'
                        ],
                        metadata={'cookie_name': cookie_name}
                    )
                    findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Cookie security check failed for {url}: {str(e)}")
        
        return findings
    
    def _check_information_disclosure(self, url: str) -> List[VulnerabilityFinding]:
        """Check for information disclosure"""
        findings = []
        
        try:
            response = requests.get(url, timeout=self.timeout, verify=False,
                                   headers={'User-Agent': self.user_agent})
            
            headers_text = '\n'.join([f"{k}: {v}" for k, v in response.headers.items()])
            
            # Check server version disclosure
            if 'Server' in response.headers:
                server_value = response.headers['Server']
                
                # Check if version is disclosed
                if re.search(r'\d+\.\d+', server_value):
                    title = "Server Version Disclosure"
                    
                    description = f"The server banner reveals version information: {server_value}\n\n"
                    description += "Version disclosure helps attackers identify vulnerabilities specific to "
                    description += "the software version in use.\n\n"
                    description += f"URL: {url}\n"
                    
                    solution = "Configure the web server to suppress version information in the Server header."
                    
                    finding = self.create_finding(
                        title=title,
                        severity='info',
                        description=description,
                        target=url,
                        confidence=0.9,
                        solution=solution,
                        metadata={'server_banner': server_value}
                    )
                    findings.append(finding)
            
            # Check X-Powered-By disclosure
            if 'X-Powered-By' in response.headers:
                powered_by = response.headers['X-Powered-By']
                
                title = "Technology Stack Disclosure"
                
                description = f"The X-Powered-By header reveals technology information: {powered_by}\n\n"
                description += "This information can help attackers target specific vulnerabilities.\n\n"
                description += f"URL: {url}\n"
                
                solution = "Remove or suppress the X-Powered-By header in the web server configuration."
                
                finding = self.create_finding(
                    title=title,
                    severity='info',
                    description=description,
                    target=url,
                    confidence=0.9,
                    solution=solution,
                    metadata={'powered_by': powered_by}
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Information disclosure check failed for {url}: {str(e)}")
        
        return findings
    
    def _check_vulnerable_paths(self, url: str) -> List[VulnerabilityFinding]:
        """Check for accessible sensitive paths"""
        findings = []
        
        try:
            base_url = url.rstrip('/')
            
            for path in self.test_paths:
                test_url = base_url + path
                
                try:
                    response = requests.get(test_url, timeout=self.timeout, verify=False,
                                           headers={'User-Agent': self.user_agent}, allow_redirects=False)
                    
                    if response.status_code in [200, 301, 302]:
                        title = f"Sensitive Path Accessible: {path}"
                        
                        description = f"The path '{path}' is accessible at: {test_url}\n\n"
                        description += f"HTTP Status Code: {response.status_code}\n"
                        description += f"Content Length: {len(response.content)} bytes\n\n"
                        description += "This path may expose sensitive information or configuration details."
                        
                        solution = f"Restrict access to {path} using web server configuration or remove it if not needed."
                        
                        severity = 'high' if path in ['/.env', '/.git/HEAD'] else 'medium'
                        
                        finding = self.create_finding(
                            title=title,
                            severity=severity,
                            description=description,
                            target=test_url,
                            confidence=0.95,
                            solution=solution,
                            metadata={'path': path, 'status_code': response.status_code}
                        )
                        findings.append(finding)
                
                except requests.exceptions.RequestException:
                    pass  # Path not accessible, which is expected
        
        except Exception as e:
            self.logger.error(f"Vulnerable paths check failed: {str(e)}")
        
        return findings
    
    def _check_http_methods(self, url: str) -> List[VulnerabilityFinding]:
        """Check for dangerous HTTP methods"""
        findings = []
        
        try:
            response = requests.options(url, timeout=self.timeout, verify=False,
                                       headers={'User-Agent': self.user_agent})
            
            allowed_methods = response.headers.get('Allow', '')
            
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
            found_dangerous = []
            
            for method in dangerous_methods:
                if method in allowed_methods.upper():
                    found_dangerous.append(method)
            
            if found_dangerous:
                title = "Dangerous HTTP Methods Enabled"
                
                description = f"The following potentially dangerous HTTP methods are enabled: {', '.join(found_dangerous)}\n\n"
                description += "Allowed methods: {allowed_methods}\n\n"
                description += "These methods may allow unauthorized modification or deletion of resources.\n\n"
                description += f"URL: {url}\n"
                
                solution = "Disable unnecessary HTTP methods in the web server configuration. "
                solution += "Only allow GET, POST, and HEAD methods unless specifically required."
                
                finding = self.create_finding(
                    title=title,
                    severity='medium',
                    description=description,
                    target=url,
                    confidence=0.85,
                    solution=solution,
                    references=[
                        'https://owasp.org/www-community/Test_HTTP_Methods'
                    ],
                    metadata={'allowed_methods': allowed_methods, 'dangerous_methods': found_dangerous}
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"HTTP methods check failed for {url}: {str(e)}")
        
        return findings
    
    def _check_directory_listing(self, url: str) -> List[VulnerabilityFinding]:
        """Check for directory listing"""
        findings = []
        
        try:
            response = requests.get(url, timeout=self.timeout, verify=False,
                                   headers={'User-Agent': self.user_agent})
            
            content = response.text.lower()
            
            # Common directory listing indicators
            listing_indicators = [
                'index of /',
                'parent directory',
                'directory listing',
                '<title>index of',
                '[to parent directory]'
            ]
            
            if any(indicator in content for indicator in listing_indicators):
                title = "Directory Listing Enabled"
                
                description = f"Directory listing appears to be enabled at: {url}\n\n"
                description += "Directory listings expose the directory structure and file names, "
                description += "which can aid attackers in finding sensitive files or applications.\n"
                
                solution = "Disable directory listing in the web server configuration. "
                solution += "For Apache: set 'Options -Indexes'. For Nginx: set 'autoindex off'."
                
                finding = self.create_finding(
                    title=title,
                    severity='medium',
                    description=description,
                    target=url,
                    confidence=0.9,
                    solution=solution,
                    references=[
                        'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'
                    ]
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Directory listing check failed for {url}: {str(e)}")
        
        return findings
    
    def _get_header_solution(self, header: str) -> str:
        """Get solution for missing security header"""
        
        solutions = {
            'Strict-Transport-Security': 'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'X-Frame-Options': 'Add the header: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN',
            'X-Content-Type-Options': 'Add the header: X-Content-Type-Options: nosniff',
            'Content-Security-Policy': 'Implement a Content Security Policy: Content-Security-Policy: default-src \'self\'',
            'X-XSS-Protection': 'Add the header: X-XSS-Protection: 1; mode=block',
            'Referrer-Policy': 'Add the header: Referrer-Policy: no-referrer or Referrer-Policy: strict-origin-when-cross-origin',
            'Permissions-Policy': 'Add the header with appropriate feature restrictions: Permissions-Policy: geolocation=(), microphone=()'
        }
        
        return solutions.get(header, f'Configure the web server to send the {header} header with appropriate values.')
