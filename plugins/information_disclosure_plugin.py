"""
Information Disclosure Scanner Plugin
Sensitive data exposure and information leakage detection

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import re
import requests
from typing import List, Dict, Any
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from plugin import VulnPlugin, VulnerabilityFinding, PluginMetadata

class InformationDisclosurePlugin(VulnPlugin):
    """
    Information Disclosure Scanner Plugin
    
    Features:
    - Sensitive file detection (.env, .git, backups)
    - Error message disclosure
    - Debug information leakage
    - API key and secret exposure
    - Source code disclosure
    - Directory traversal indicators
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.metadata = PluginMetadata(
            name="Information Disclosure Scanner Plugin",
            version="1.0.0",
            author="Devdas",
            description="Detection of sensitive data exposure and information leaks",
            category="information-disclosure",
            tags=["disclosure", "sensitive-data", "leakage", "exposure"]
        )
        
        # Sensitive file patterns
        self.sensitive_paths = {
            '/.env': 'Environment configuration file',
            '/.git/config': 'Git configuration',
            '/.git/HEAD': 'Git repository HEAD',
            '/.svn/entries': 'SVN repository entries',
            '/config.php': 'PHP configuration',
            '/config.yml': 'YAML configuration',
            '/web.config': 'ASP.NET configuration',
            '/.htaccess': 'Apache configuration',
            '/.htpasswd': 'Apache password file',
            '/backup.sql': 'Database backup',
            '/dump.sql': 'Database dump',
            '/phpinfo.php': 'PHP information page',
            '/info.php': 'PHP information page',
            '/.DS_Store': 'macOS directory metadata',
            '/Thumbs.db': 'Windows thumbnail cache',
            '/.npmrc': 'NPM configuration',
            '/.dockerenv': 'Docker environment file',
            '/docker-compose.yml': 'Docker Compose configuration',
            '/Dockerfile': 'Docker build file',
            '/.bash_history': 'Bash command history',
            '/id_rsa': 'SSH private key',
            '/id_rsa.pub': 'SSH public key',
            '/.ssh/id_rsa': 'SSH private key',
            '/database.yml': 'Database configuration',
            '/credentials.json': 'Credentials file',
            '/secrets.yml': 'Secrets file'
        }
        
        # Patterns for sensitive information in content
        self.content_patterns = {
            'api_key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'aws_key': r'(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*["\']?([A-Z0-9]{20,})["\']?',
            'db_password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{3,})["\']',
            'private_key': r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
            'jwt_token': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'connection_string': r'(?i)(server|data source|host)=.*(user id|uid|username)=.*(password|pwd)=',
        }
        
        # Error message patterns
        self.error_patterns = {
            'sql_error': r'(?i)(SQL syntax|mysql_fetch|ORA-\d+|PostgreSQL|Microsoft SQL)',
            'php_error': r'(?i)(Warning|Fatal error|Notice):\s+in\s+.*\.php\s+on\s+line\s+\d+',
            'asp_error': r'(?i)(ASP\.NET|Server Error|Exception Details|Stack Trace)',
            'python_error': r'(?i)(Traceback \(most recent call last\)|File ".*\.py")',
            'java_error': r'(?i)(Exception in thread|at\s+.*\.java:\d+)',
            'stack_trace': r'(?i)(stack trace|call stack|backtrace)',
        }
    
    def can_run(self, target: str, context: Dict[str, Any]) -> bool:
        """Check if web services are available"""
        return context.get('has_web_services', False) or \
               target.startswith('http://') or target.startswith('https://')
    
    def check(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """Perform information disclosure check"""
        context = kwargs.get('context', {})
        return self.execute(target, context)
    
    def execute(self, target: str, context: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Execute information disclosure checks"""
        findings = []
        
        try:
            urls = self._build_urls(target, context)
            
            for url in urls:
                # Check for sensitive files
                file_findings = self._check_sensitive_files(url)
                findings.extend(file_findings)
                
                # Check main page for disclosure
                content_findings = self._check_content_disclosure(url)
                findings.extend(content_findings)
                
                # Check for error messages
                error_findings = self._check_error_disclosure(url)
                findings.extend(error_findings)
            
        except Exception as e:
            self.logger.error(f"Information disclosure check failed for {target}: {str(e)}")
        
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
    
    def _check_sensitive_files(self, url: str) -> List[VulnerabilityFinding]:
        """Check for accessible sensitive files"""
        findings = []
        
        base_url = url.rstrip('/')
        
        for path, description in self.sensitive_paths.items():
            try:
                test_url = base_url + path
                response = requests.get(test_url, timeout=10, verify=False, allow_redirects=False)
                
                if response.status_code == 200 and len(response.content) > 0:
                    title = f"Sensitive File Exposed: {path}"
                    
                    finding_description = f"Sensitive file accessible at: {test_url}\n\n"
                    finding_description += f"File Type: {description}\n"
                    finding_description += f"Size: {len(response.content)} bytes\n\n"
                    finding_description += "This file may contain sensitive information such as:\n"
                    finding_description += "- Credentials and API keys\n"
                    finding_description += "- Configuration details\n"
                    finding_description += "- Internal paths and structure\n"
                    finding_description += "- Database connection strings\n"
                    
                    # Check content for sensitive patterns
                    sensitive_data = self._scan_content_patterns(response.text)
                    if sensitive_data:
                        finding_description += f"\n⚠️  Potentially sensitive data detected in file:\n"
                        for data_type, _ in sensitive_data[:3]:  # Show top 3
                            finding_description += f"- {data_type}\n"
                    
                    solution = f"Remove or restrict access to {path}. "
                    solution += "Use web server configuration to deny access to sensitive files. "
                    solution += "Ensure version control directories (.git, .svn) are not deployed to production."
                    
                    severity = 'critical' if any(x in path.lower() for x in ['.env', 'password', 'secret', 'key', '.git']) else 'high'
                    
                    finding = self.create_finding(
                        title=title,
                        severity=severity,
                        description=finding_description,
                        target=test_url,
                        confidence=0.95,
                        solution=solution,
                        references=[
                            'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url',
                            'https://cwe.mitre.org/data/definitions/200.html'
                        ],
                        metadata={'path': path, 'file_size': len(response.content)}
                    )
                    findings.append(finding)
            
            except Exception:
                pass
        
        return findings
    
    def _check_content_disclosure(self, url: str) -> List[VulnerabilityFinding]:
        """Check page content for information disclosure"""
        findings = []
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            
            if response.status_code == 200:
                sensitive_data = self._scan_content_patterns(response.text)
                
                for data_type, matches in sensitive_data:
                    title = f"Information Disclosure: {data_type}"
                    
                    description = f"Sensitive information ({data_type}) detected at: {url}\n\n"
                    description += f"Found {len(matches)} potential instance(s) in the response.\n\n"
                    description += "Exposing sensitive information can lead to:\n"
                    description += "- Credential theft\n"
                    description += "- System compromise\n"
                    description += "- Data breaches\n"
                    description += "- Social engineering attacks\n\n"
                    
                    # Show first match as example (redacted)
                    if matches:
                        example = matches[0][:50] + '...' if len(matches[0]) > 50 else matches[0]
                        description += f"Example: {example}\n"
                    
                    solution = "Remove sensitive information from publicly accessible pages. "
                    solution += "Use environment variables for configuration. "
                    solution += "Implement proper access controls and authentication."
                    
                    finding = self.create_finding(
                        title=title,
                        severity='high',
                        description=description,
                        target=url,
                        confidence=0.7,
                        solution=solution,
                        references=[
                            'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure'
                        ],
                        metadata={'data_type': data_type, 'match_count': len(matches)}
                    )
                    findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Content disclosure check failed: {str(e)}")
        
        return findings
    
    def _check_error_disclosure(self, url: str) -> List[VulnerabilityFinding]:
        """Check for error message disclosure"""
        findings = []
        
        try:
            # Try to trigger error by requesting non-existent page
            error_url = url.rstrip('/') + '/nonexistent_page_test_12345'
            response = requests.get(error_url, timeout=10, verify=False)
            
            for error_type, pattern in self.error_patterns.items():
                if re.search(pattern, response.text):
                    title = f"Error Message Disclosure: {error_type}"
                    
                    description = f"Detailed error messages detected at: {error_url}\n\n"
                    description += f"Error Type: {error_type}\n\n"
                    description += "Detailed error messages can reveal:\n"
                    description += "- Application framework and version\n"
                    description += "- File paths and directory structure\n"
                    description += "- Database schema information\n"
                    description += "- Code structure and logic\n"
                    
                    solution = "Configure custom error pages. "
                    solution += "Disable debug mode in production. "
                    solution += "Log detailed errors server-side instead of displaying them to users."
                    
                    finding = self.create_finding(
                        title=title,
                        severity='medium',
                        description=description,
                        target=url,
                        confidence=0.9,
                        solution=solution,
                        references=[
                            'https://owasp.org/www-community/Improper_Error_Handling'
                        ],
                        metadata={'error_type': error_type}
                    )
                    findings.append(finding)
        
        except Exception:
            pass
        
        return findings
    
    def _scan_content_patterns(self, content: str) -> List[tuple]:
        """Scan content for sensitive patterns"""
        found_data = []
        
        for data_type, pattern in self.content_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                # Extract actual sensitive values
                if isinstance(matches[0], tuple):
                    values = [m[1] if len(m) > 1 else m[0] for m in matches]
                else:
                    values = matches
                
                found_data.append((data_type, values))
        
        return found_data
