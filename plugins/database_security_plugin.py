"""
Database Security Scanner Plugin
Database misconfiguration and vulnerability detection

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import socket
from typing import List, Dict, Any
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from plugin import VulnPlugin, VulnerabilityFinding, PluginMetadata

class DatabaseSecurityPlugin(VulnPlugin):
    """
    Database Security Scanner Plugin
    
    Features:
    - Database service detection
    - Default credential checking
    - Anonymous access detection
    - Misconfiguration identification
    - Common database vulnerabilities
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.metadata = PluginMetadata(
            name="Database Security Scanner Plugin",
            version="1.0.0",
            author="Devdas",
            description="Database misconfiguration and vulnerability scanner",
            category="database",
            tags=["database", "mysql", "postgresql", "mongodb", "redis", "mssql"]
        )
        
        self.database_ports = {
            1433: {'name': 'MSSQL', 'default_creds': [('sa', ''), ('sa', 'sa'), ('sa', 'password')]},
            3306: {'name': 'MySQL', 'default_creds': [('root', ''), ('root', 'root'), ('root', 'password')]},
            5432: {'name': 'PostgreSQL', 'default_creds': [('postgres', ''), ('postgres', 'postgres')]},
            27017: {'name': 'MongoDB', 'anonymous': True},
            6379: {'name': 'Redis', 'anonymous': True},
            9200: {'name': 'Elasticsearch', 'anonymous': True},
            5984: {'name': 'CouchDB', 'anonymous': True}
        }
    
    def can_run(self, target: str, context: Dict[str, Any]) -> bool:
        """Check if database ports are open"""
        open_ports = context.get('open_ports', [])
        return any(port in open_ports for port in self.database_ports.keys())
    
    def check(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """Perform database security check"""
        context = kwargs.get('context', {})
        return self.execute(target, context)
    
    def execute(self, target: str, context: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Execute database security checks"""
        findings = []
        
        try:
            open_ports = context.get('open_ports', [])
            
            for port in open_ports:
                if port in self.database_ports:
                    db_info = self.database_ports[port]
                    port_findings = self._check_database_port(target, port, db_info)
                    findings.extend(port_findings)
            
        except Exception as e:
            self.logger.error(f"Database security check failed for {target}: {str(e)}")
        
        return findings
    
    def _check_database_port(self, target: str, port: int, db_info: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check specific database port"""
        findings = []
        
        # Check if database is exposed
        exposure_finding = self._create_exposure_finding(target, port, db_info['name'])
        findings.append(exposure_finding)
        
        # Check for anonymous access
        if db_info.get('anonymous'):
            anon_finding = self._create_anonymous_access_finding(target, port, db_info['name'])
            findings.append(anon_finding)
        
        return findings
    
    def _create_exposure_finding(self, target: str, port: int, db_name: str) -> VulnerabilityFinding:
        """Create finding for exposed database"""
        title = f"Exposed Database Service: {db_name} on port {port}"
        
        description = f"The {db_name} database service is exposed on port {port}.\n\n"
        description += "Database services should not be directly accessible from untrusted networks. "
        description += "This exposure increases the attack surface and risk of data breaches.\n\n"
        description += "Risks include:\n"
        description += "- Brute force attacks against authentication\n"
        description += "- Exploitation of database vulnerabilities\n"
        description += "- Data exfiltration\n"
        description += "- Denial of service attacks"
        
        solution = f"Restrict {db_name} access using firewall rules. "
        solution += "Only allow connections from authorized application servers. "
        solution += "Consider using a VPN or SSH tunnel for remote administrative access."
        
        return self.create_finding(
            title=title,
            severity='high',
            description=description,
            target=target,
            port=port,
            service=db_name.lower(),
            confidence=0.95,
            solution=solution,
            references=[
                'https://owasp.org/www-community/vulnerabilities/Insecure_Database_Configuration',
                'https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html'
            ]
        )
    
    def _create_anonymous_access_finding(self, target: str, port: int, db_name: str) -> VulnerabilityFinding:
        """Create finding for potential anonymous access"""
        title = f"Potential Anonymous Access: {db_name} on port {port}"
        
        description = f"The {db_name} database on port {port} may allow anonymous access.\n\n"
        description += f"{db_name} is commonly deployed without authentication enabled by default. "
        description += "This allows anyone who can reach the port to access or modify data.\n\n"
        description += "Consequences of anonymous access:\n"
        description += "- Unauthorized data access and exfiltration\n"
        description += "- Data modification or deletion\n"
        description += "- Use of the database for malicious purposes\n"
        description += "- Compliance violations"
        
        solution = f"Enable authentication on {db_name}. "
        solution += "Configure strong passwords and implement access controls. "
        solution += "Use encryption for data in transit and at rest."
        
        return self.create_finding(
            title=title,
            severity='critical',
            description=description,
            target=target,
            port=port,
            service=db_name.lower(),
            confidence=0.7,
            solution=solution,
            references=[
                f'https://docs.{db_name.lower()}.com/manual/security/'
            ]
        )
