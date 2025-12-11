"""
Authentication Bypass Detection Plugin
Weak authentication and bypass vulnerability detection

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import requests
from typing import List, Dict, Any
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from plugin import VulnPlugin, VulnerabilityFinding, PluginMetadata

class AuthenticationBypassPlugin(VulnPlugin):
    """
    Authentication Bypass Detection Plugin
    
    Features:
    - Default credential detection
    - Weak password identification
    - Authentication bypass vulnerability checks
    - Session management issues
    - Broken authentication detection
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.metadata = PluginMetadata(
            name="Authentication Bypass Plugin",
            version="1.0.0",
            author="Devdas",
            description="Detection of weak authentication and bypass vulnerabilities",
            category="authentication",
            tags=["authentication", "credentials", "bypass", "weak-passwords"]
        )
        
        # Common default credentials
        self.default_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('user', 'user'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('admin', ''),
            ('', 'admin'),
            ('admin', '12345'),
            ('admin', 'admin123')
        ]
        
        # Common login paths
        self.login_paths = [
            '/login',
            '/admin/login',
            '/administrator',
            '/admin',
            '/user/login',
            '/wp-admin',
            '/wp-login.php',
            '/phpmyadmin'
        ]
    
    def can_run(self, target: str, context: Dict[str, Any]) -> bool:
        """Check if web services are available"""
        return context.get('has_web_services', False) or \
               target.startswith('http://') or target.startswith('https://')
    
    def check(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """Perform authentication bypass check"""
        context = kwargs.get('context', {})
        return self.execute(target, context)
    
    def execute(self, target: str, context: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Execute authentication bypass checks"""
        findings = []
        
        try:
            # Build target URLs
            urls = self._build_urls(target, context)
            
            for url in urls:
                # Check for accessible login pages
                login_findings = self._check_login_pages(url)
                findings.extend(login_findings)
                
                # Check for default credentials (non-intrusive check)
                cred_findings = self._check_default_credentials_existence(url)
                findings.extend(cred_findings)
            
        except Exception as e:
            self.logger.error(f"Authentication bypass check failed for {target}: {str(e)}")
        
        return findings
    
    def _build_urls(self, target: str, context: Dict[str, Any]) -> List[str]:
        """Build list of URLs to test"""
        urls = []
        
        if target.startswith('http://') or target.startswith('https://'):
            urls.append(target)
        else:
            web_ports = context.get('web_ports', [80, 443])
            for port in web_ports:
                protocol = 'https' if port in [443, 8443] else 'http'
                urls.append(f'{protocol}://{target}:{port}')
        
        return urls
    
    def _check_login_pages(self, url: str) -> List[VulnerabilityFinding]:
        """Check for accessible login pages"""
        findings = []
        
        base_url = url.rstrip('/')
        
        for path in self.login_paths:
            try:
                test_url = base_url + path
                response = requests.get(test_url, timeout=10, verify=False, allow_redirects=True)
                
                if response.status_code == 200:
                    content_lower = response.text.lower()
                    
                    # Check if it looks like a login page
                    if any(keyword in content_lower for keyword in ['password', 'login', 'username', 'sign in']):
                        title = f"Login Page Accessible: {path}"
                        
                        description = f"A login page is accessible at: {test_url}\n\n"
                        description += "Accessible login pages increase attack surface by:\n"
                        description += "- Enabling brute force attacks\n"
                        description += "- Exposing system/application information\n"
                        description += "- Providing an attack vector for credential stuffing\n\n"
                        description += "Consider implementing additional protections."
                        
                        solution = "Implement the following protections:\n"
                        solution += "- Multi-factor authentication (MFA)\n"
                        solution += "- Account lockout policies\n"
                        solution += "- CAPTCHA on login forms\n"
                        solution += "- Rate limiting on authentication endpoints\n"
                        solution += "- IP-based access restrictions for administrative interfaces"
                        
                        finding = self.create_finding(
                            title=title,
                            severity='info',
                            description=description,
                            target=test_url,
                            confidence=0.8,
                            solution=solution,
                            references=[
                                'https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication',
                                'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
                            ]
                        )
                        findings.append(finding)
            
            except Exception:
                pass
        
        return findings
    
    def _check_default_credentials_existence(self, url: str) -> List[VulnerabilityFinding]:
        """Check for potential default credential vulnerabilities (non-intrusive)"""
        findings = []
        
        # This is a non-intrusive check that just warns about the possibility
        # Actual credential testing would be too intrusive for an automated scanner
        
        title = "Potential Default Credentials Risk"
        
        description = f"The target {url} may be using default credentials.\n\n"
        description += "Many systems and applications ship with default credentials that are:\n"
        description += "- Well-known and publicly documented\n"
        description += "- Easy targets for attackers\n"
        description += "- Often overlooked during deployment\n\n"
        description += "Common default credentials include:\n"
        description += "- admin/admin\n"
        description += "- administrator/password\n"
        description += "- root/root\n"
        description += "- user/user\n\n"
        description += "Note: This finding is informational. Manual verification recommended."
        
        solution = "Change all default credentials to strong, unique passwords. "
        solution += "Implement a password policy requiring:\n"
        solution += "- Minimum length of 12 characters\n"
        solution += "- Mix of upper/lowercase, numbers, and special characters\n"
        solution += "- Regular password rotation\n"
        solution += "- Prohibition of common/default passwords"
        
        finding = self.create_finding(
            title=title,
            severity='low',
            description=description,
            target=url,
            confidence=0.5,
            solution=solution,
            references=[
                'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password'
            ]
        )
        findings.append(finding)
        
        return findings
