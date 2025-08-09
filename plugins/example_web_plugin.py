"""
Example Custom Plugin for VulnSleuth
Demonstrates how to create custom vulnerability checks

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import re
import requests
import socket
import sys
import os
from typing import List, Dict, Any, Optional

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from plugin import VulnPlugin, VulnerabilityFinding, PluginMetadata

class ExampleWebVulnPlugin(VulnPlugin):
    """
    Example plugin for detecting web application vulnerabilities
    
    This plugin demonstrates:
    - HTTP header analysis
    - Response content examination
    - Custom vulnerability detection logic
    - Proper error handling and logging
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.metadata = PluginMetadata(
            name="Example Web Vulnerability Plugin",
            version="1.0.0",
            author="Security Team",
            description="Example plugin demonstrating custom web vulnerability checks",
            category="web",
            tags=["example", "web", "headers", "disclosure"]
        )
    
    def can_run(self, target: str, context: Dict[str, Any]) -> bool:
        """
        Check if this plugin can run against the target
        
        Args:
            target: Target identifier (IP, hostname, URL)
            context: Additional context information
            
        Returns:
            True if plugin can run against this target
        """
        # This plugin only runs against web targets
        return context.get('has_web_services', False) or context.get('is_web_target', False)
    
    def check(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """
        Main vulnerability check method (required by VulnPlugin base class)
        
        Args:
            target: Target to scan
            **kwargs: Additional scan parameters
            
        Returns:
            List of vulnerability findings
        """
        context = kwargs.get('context', {})
        return self.execute(target, context)
    
    def execute(self, target: str, context: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """
        Execute the plugin against the target
        
        Args:
            target: Target to scan
            context: Scan context with additional information
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        try:
            # Get web ports from context or use defaults
            web_ports = context.get('web_ports', [80, 443, 8080, 8443])
            
            for port in web_ports:
                port_findings = self._check_web_port(target, port, context)
                findings.extend(port_findings)
        
        except Exception as e:
            self.logger.error(f"Plugin execution failed for {target}: {str(e)}")
        
        return findings
    
    def _check_web_port(self, target: str, port: int, context: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check specific web port for vulnerabilities"""
        findings = []
        
        try:
            # Determine protocol
            protocol = 'https' if port in [443, 8443] else 'http'
            base_url = f"{protocol}://{target}:{port}"
            
            # Check if port is open
            if not self._is_port_open(target, port):
                return findings
            
            # Perform HTTP checks
            findings.extend(self._check_server_headers(base_url))
            findings.extend(self._check_information_disclosure(base_url))
            findings.extend(self._check_common_files(base_url))
            
        except Exception as e:
            self.logger.error(f"Web port check failed {target}:{port}: {str(e)}")
        
        return findings
    
    def _check_server_headers(self, base_url: str) -> List[VulnerabilityFinding]:
        """Check for server information disclosure in headers"""
        findings = []
        
        try:
            response = requests.head(base_url, timeout=10, verify=False)
            headers = response.headers
            
            # Check for server header disclosure
            if 'Server' in headers:
                server_header = headers['Server']
                
                # Check for version information
                if re.search(r'\d+\.\d+', server_header):
                    finding = VulnerabilityFinding(
                        title="Server Version Disclosure",
                        description=f"Web server discloses version information: {server_header}",
                        severity="low",
                        cvss_score=2.0,
                        solution="Configure the web server to hide version information",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
                        ],
                        evidence={'server_header': server_header, 'url': base_url}
                    )
                    findings.append(finding)
            
            # Check for X-Powered-By header
            if 'X-Powered-By' in headers:
                powered_by = headers['X-Powered-By']
                finding = VulnerabilityFinding(
                    title="Technology Stack Disclosure",
                    description=f"Web application discloses technology stack: {powered_by}",
                    severity="informational",
                    cvss_score=0.0,
                    solution="Remove or customize the X-Powered-By header",
                    references=[
                        "https://owasp.org/www-project-secure-headers/"
                    ],
                    evidence={'powered_by_header': powered_by, 'url': base_url}
                )
                findings.append(finding)
            
            # Check for missing security headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': None,
                'Content-Security-Policy': None
            }
            
            missing_headers = []
            for header, expected_value in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                elif expected_value and isinstance(expected_value, list):
                    if headers[header] not in expected_value:
                        missing_headers.append(f"{header} (incorrect value)")
                elif expected_value and headers[header] != expected_value:
                    missing_headers.append(f"{header} (incorrect value)")
            
            if missing_headers:
                finding = VulnerabilityFinding(
                    title="Missing Security Headers",
                    description=f"Web application missing security headers: {', '.join(missing_headers)}",
                    severity="medium",
                    cvss_score=4.0,
                    solution="Configure web server to include security headers",
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://securityheaders.com/"
                    ],
                    evidence={'missing_headers': missing_headers, 'url': base_url}
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Header check failed for {base_url}: {str(e)}")
        
        return findings
    
    def _check_information_disclosure(self, base_url: str) -> List[VulnerabilityFinding]:
        """Check for information disclosure vulnerabilities"""
        findings = []
        
        try:
            # Check for directory listing
            response = requests.get(f"{base_url}/", timeout=10, verify=False)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Check for directory listing indicators
                directory_indicators = [
                    'index of /',
                    'directory listing',
                    'parent directory',
                    '<title>index of',
                    'folder listing'
                ]
                
                if any(indicator in content for indicator in directory_indicators):
                    finding = VulnerabilityFinding(
                        title="Directory Listing Enabled",
                        description="Web server allows directory browsing",
                        severity="low",
                        cvss_score=2.0,
                        solution="Disable directory listing in web server configuration",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
                        ],
                        evidence={'url': base_url, 'response_snippet': content[:200]}
                    )
                    findings.append(finding)
                
                # Check for error pages with stack traces
                error_indicators = [
                    'stack trace',
                    'exception',
                    'traceback',
                    'error occurred',
                    'internal server error'
                ]
                
                if response.status_code >= 400 and any(indicator in content for indicator in error_indicators):
                    finding = VulnerabilityFinding(
                        title="Verbose Error Messages",
                        description="Application exposes detailed error information",
                        severity="low",
                        cvss_score=2.0,
                        solution="Configure application to show generic error messages",
                        references=[
                            "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"
                        ],
                        evidence={'url': base_url, 'status_code': response.status_code}
                    )
                    findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Information disclosure check failed for {base_url}: {str(e)}")
        
        return findings
    
    def _check_common_files(self, base_url: str) -> List[VulnerabilityFinding]:
        """Check for common sensitive files"""
        findings = []
        
        # Common sensitive files to check
        sensitive_files = [
            'robots.txt',
            'sitemap.xml',
            '.htaccess',
            '.htpasswd',
            'web.config',
            'phpinfo.php',
            'info.php',
            'test.php',
            'admin/',
            'backup/',
            'config.php',
            'database.sql',
            '.git/',
            '.svn/',
            'readme.txt',
            'changelog.txt'
        ]
        
        accessible_files = []
        
        for file_path in sensitive_files:
            try:
                url = f"{base_url}/{file_path}"
                response = requests.head(url, timeout=5, verify=False)
                
                if response.status_code == 200:
                    accessible_files.append(file_path)
            
            except Exception:
                continue
        
        if accessible_files:
            finding = VulnerabilityFinding(
                title="Sensitive Files Accessible",
                description=f"Sensitive files accessible: {', '.join(accessible_files)}",
                severity="medium",
                cvss_score=5.0,
                solution="Remove or restrict access to sensitive files",
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
                ],
                evidence={'accessible_files': accessible_files, 'base_url': base_url}
            )
            findings.append(finding)
        
        return findings
    
    def _is_port_open(self, target: str, port: int, timeout: int = 3) -> bool:
        """Check if a port is open on target"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                return result == 0
        except Exception:
            return False
    
    def cleanup(self):
        """Cleanup resources if needed"""
        pass

# Plugin registration
def get_plugin():
    """Return plugin instance for VulnSleuth"""
    return ExampleWebVulnPlugin()
