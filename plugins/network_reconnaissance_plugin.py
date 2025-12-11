"""
Advanced Network Reconnaissance Plugin
Comprehensive network scanning using Nmap integration

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import nmap
import socket
import subprocess
import threading
import time
from typing import Dict, List, Any, Optional
import logging
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from plugin import VulnPlugin, VulnerabilityFinding, PluginMetadata

class NetworkReconnaissancePlugin(VulnPlugin):
    """
    Advanced Network Reconnaissance Plugin
    
    Features:
    - Host discovery and enumeration
    - Comprehensive port scanning
    - Service version detection
    - OS fingerprinting
    - Network topology mapping
    - Vulnerability detection via NSE scripts
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.metadata = PluginMetadata(
            name="Network Reconnaissance Plugin",
            version="2.0.0",
            author="Devdas",
            description="Advanced network scanning and reconnaissance using Nmap",
            category="network",
            tags=["network", "nmap", "reconnaissance", "port-scan", "service-detection", "os-fingerprint"]
        )
        
        # Nmap configuration
        nmap_config = config.get('network_scanning', {}) if config else {}
        self.nmap_path = nmap_config.get('nmap_path', 'nmap')
        self.timing = nmap_config.get('nmap_timing', '-T4')
        self.default_ports = nmap_config.get('default_ports', '1-10000')
        self.top_ports = nmap_config.get('top_ports_count', 1000)
        
        # Initialize nmap
        try:
            self.nm = nmap.PortScanner()
            self.nmap_available = True
            self.logger.info("Nmap scanner initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize nmap: {str(e)}")
            self.nmap_available = False
        
        # Vulnerable service signatures
        self.vulnerable_services = {
            21: {'service': 'ftp', 'risk': 'medium', 'description': 'FTP - Unencrypted file transfer, often misconfigured'},
            23: {'service': 'telnet', 'risk': 'high', 'description': 'Telnet - Unencrypted remote access protocol'},
            25: {'service': 'smtp', 'risk': 'medium', 'description': 'SMTP - Potential open relay vulnerability'},
            53: {'service': 'dns', 'risk': 'medium', 'description': 'DNS - Potential zone transfer vulnerability'},
            69: {'service': 'tftp', 'risk': 'high', 'description': 'TFTP - Unauthenticated file transfer'},
            79: {'service': 'finger', 'risk': 'high', 'description': 'Finger - Information disclosure protocol'},
            110: {'service': 'pop3', 'risk': 'medium', 'description': 'POP3 - Unencrypted email protocol'},
            111: {'service': 'rpcbind', 'risk': 'high', 'description': 'RPCbind - RPC service enumeration'},
            135: {'service': 'msrpc', 'risk': 'high', 'description': 'MS-RPC - Windows RPC endpoint mapper'},
            139: {'service': 'netbios-ssn', 'risk': 'high', 'description': 'NetBIOS - SMB over NetBIOS'},
            143: {'service': 'imap', 'risk': 'medium', 'description': 'IMAP - Unencrypted email protocol'},
            161: {'service': 'snmp', 'risk': 'high', 'description': 'SNMP - Often uses default community strings'},
            445: {'service': 'microsoft-ds', 'risk': 'high', 'description': 'SMB - File sharing, numerous vulnerabilities'},
            512: {'service': 'rexec', 'risk': 'high', 'description': 'Rexec - Insecure remote execution'},
            513: {'service': 'rlogin', 'risk': 'high', 'description': 'Rlogin - Insecure remote login'},
            514: {'service': 'rsh', 'risk': 'high', 'description': 'RSH - Insecure remote shell'},
            873: {'service': 'rsync', 'risk': 'medium', 'description': 'Rsync - Potential anonymous access'},
            1433: {'service': 'ms-sql-s', 'risk': 'high', 'description': 'MSSQL - Database service'},
            1521: {'service': 'oracle', 'risk': 'high', 'description': 'Oracle - Database service'},
            2049: {'service': 'nfs', 'risk': 'high', 'description': 'NFS - Network file system'},
            3306: {'service': 'mysql', 'risk': 'high', 'description': 'MySQL - Database service'},
            3389: {'service': 'ms-wbt-server', 'risk': 'high', 'description': 'RDP - Remote Desktop Protocol'},
            5432: {'service': 'postgresql', 'risk': 'high', 'description': 'PostgreSQL - Database service'},
            5900: {'service': 'vnc', 'risk': 'high', 'description': 'VNC - Remote desktop, often weak passwords'},
            6379: {'service': 'redis', 'risk': 'high', 'description': 'Redis - Often exposed without authentication'},
            8080: {'service': 'http-proxy', 'risk': 'medium', 'description': 'HTTP Proxy/Alt HTTP port'},
            9200: {'service': 'elasticsearch', 'risk': 'high', 'description': 'Elasticsearch - Often exposed without auth'},
            27017: {'service': 'mongod', 'risk': 'high', 'description': 'MongoDB - Often exposed without authentication'},
        }
    
    def can_run(self, target: str, context: Dict[str, Any]) -> bool:
        """This plugin can run against any network target"""
        return self.nmap_available and self.enabled
    
    def check(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """
        Perform comprehensive network reconnaissance
        
        Args:
            target: Target to scan (IP, hostname, or CIDR)
            **kwargs: Additional scan parameters
            
        Returns:
            List of vulnerability findings
        """
        context = kwargs.get('context', {})
        return self.execute(target, context)
    
    def execute(self, target: str, context: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Execute network reconnaissance"""
        findings = []
        
        try:
            self.logger.info(f"Starting network reconnaissance for {target}")
            
            # Phase 1: Port scanning
            open_ports = self._port_scan(target)
            
            if not open_ports:
                self.logger.info(f"No open ports found on {target}")
                return findings
            
            # Phase 2: Service detection
            services = self._service_detection(target, open_ports)
            
            # Store detected services in context for other plugins
            context['detected_services'] = services
            context['open_ports'] = list(open_ports)
            
            # Phase 3: Analyze services for vulnerabilities
            for port, service_info in services.items():
                service_findings = self._analyze_service(target, port, service_info)
                findings.extend(service_findings)
            
            # Phase 4: Check for vulnerable service combinations
            combination_findings = self._check_service_combinations(target, services)
            findings.extend(combination_findings)
            
            self.logger.info(f"Network reconnaissance complete for {target}: {len(findings)} findings")
            
        except Exception as e:
            self.logger.error(f"Network reconnaissance failed for {target}: {str(e)}")
        
        return findings
    
    def _port_scan(self, target: str) -> List[int]:
        """Perform port scanning"""
        open_ports = []
        
        try:
            self.logger.info(f"Scanning ports on {target}")
            
            # Use SYN scan for speed and stealth
            nmap_args = f"{self.timing} -sS --top-ports {self.top_ports}"
            
            scan_result = self.nm.scan(hosts=target, arguments=nmap_args)
            
            if target in scan_result['scan']:
                host_data = scan_result['scan'][target]
                
                if 'tcp' in host_data:
                    for port, port_info in host_data['tcp'].items():
                        if port_info['state'] == 'open':
                            open_ports.append(port)
                            self.logger.debug(f"Open port found: {port}/tcp")
            
            self.logger.info(f"Port scan complete: {len(open_ports)} open ports found")
            
        except Exception as e:
            self.logger.error(f"Port scan failed: {str(e)}")
        
        return sorted(open_ports)
    
    def _service_detection(self, target: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
        """Perform service version detection"""
        services = {}
        
        try:
            self.logger.info(f"Detecting services on {target}")
            
            # Convert port list to nmap format
            port_spec = ','.join(map(str, ports))
            
            # Service version detection with aggressive timing
            nmap_args = f"{self.timing} -sV -p {port_spec}"
            
            scan_result = self.nm.scan(hosts=target, arguments=nmap_args)
            
            if target in scan_result['scan']:
                host_data = scan_result['scan'][target]
                
                if 'tcp' in host_data:
                    for port, port_info in host_data['tcp'].items():
                        if port_info['state'] == 'open':
                            services[port] = {
                                'name': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'conf': port_info.get('conf', '0'),
                                'cpe': port_info.get('cpe', ''),
                                'banner': f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(),
                                'port': port,
                                'proto': 'tcp'
                            }
            
            self.logger.info(f"Service detection complete: {len(services)} services identified")
            
        except Exception as e:
            self.logger.error(f"Service detection failed: {str(e)}")
        
        return services
    
    def _analyze_service(self, target: str, port: int, service_info: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Analyze a service for vulnerabilities"""
        findings = []
        
        try:
            service_name = service_info.get('name', 'unknown')
            
            # Check if this is a known vulnerable service
            if port in self.vulnerable_services:
                vuln_info = self.vulnerable_services[port]
                
                severity_map = {'high': 'high', 'medium': 'medium', 'low': 'low'}
                severity = severity_map.get(vuln_info['risk'], 'medium')
                
                title = f"Potentially Insecure Service: {service_name} on port {port}"
                
                description = f"Service '{service_name}' detected on port {port}.\n\n"
                description += f"Risk Level: {vuln_info['risk'].upper()}\n"
                description += f"Description: {vuln_info['description']}\n\n"
                
                if service_info.get('product'):
                    description += f"Product: {service_info['product']}\n"
                if service_info.get('version'):
                    description += f"Version: {service_info['version']}\n"
                if service_info.get('extrainfo'):
                    description += f"Extra Info: {service_info['extrainfo']}\n"
                
                solution = self._get_service_solution(service_name, port)
                
                finding = self.create_finding(
                    title=title,
                    severity=severity,
                    description=description,
                    target=target,
                    confidence=0.8,
                    port=port,
                    service=service_name,
                    solution=solution,
                    metadata=service_info
                )
                findings.append(finding)
            
            # Check for unencrypted protocols
            unencrypted_services = ['ftp', 'telnet', 'http', 'smtp', 'pop3', 'imap']
            if service_name in unencrypted_services:
                finding = self._create_unencrypted_finding(target, port, service_name, service_info)
                findings.append(finding)
            
            # Check for outdated versions
            if service_info.get('version'):
                version_finding = self._check_outdated_version(target, port, service_info)
                if version_finding:
                    findings.append(version_finding)
        
        except Exception as e:
            self.logger.error(f"Service analysis failed: {str(e)}")
        
        return findings
    
    def _create_unencrypted_finding(self, target: str, port: int, service: str, service_info: Dict[str, Any]) -> VulnerabilityFinding:
        """Create finding for unencrypted protocol"""
        
        title = f"Unencrypted Protocol: {service.upper()} on port {port}"
        
        description = f"The service '{service}' on port {port} uses an unencrypted protocol.\n\n"
        description += "Unencrypted protocols transmit data in cleartext, allowing:\n"
        description += "- Credential theft via network sniffing\n"
        description += "- Man-in-the-middle attacks\n"
        description += "- Data interception and manipulation\n"
        
        solution = f"Replace {service} with its encrypted alternative:\n"
        solution_map = {
            'ftp': 'Use SFTP or FTPS instead of FTP',
            'telnet': 'Use SSH instead of Telnet',
            'http': 'Use HTTPS with valid TLS certificates',
            'smtp': 'Use SMTP with STARTTLS or SMTPS',
            'pop3': 'Use POP3S instead of POP3',
            'imap': 'Use IMAPS instead of IMAP'
        }
        solution += solution_map.get(service, 'Use an encrypted alternative')
        
        return self.create_finding(
            title=title,
            severity='medium',
            description=description,
            target=target,
            confidence=0.9,
            port=port,
            service=service,
            solution=solution,
            references=[
                'https://owasp.org/www-community/vulnerabilities/Unencrypted_Data_Transmission'
            ],
            metadata=service_info
        )
    
    def _check_outdated_version(self, target: str, port: int, service_info: Dict[str, Any]) -> Optional[VulnerabilityFinding]:
        """Check if service version is outdated (placeholder for version database)"""
        # This would integrate with a version database to check for outdated versions
        # For now, we'll flag very old versions
        
        version = service_info.get('version', '')
        product = service_info.get('product', '')
        
        # Simple heuristic: versions starting with 0.x or 1.x might be outdated
        if version and (version.startswith('0.') or version.startswith('1.')):
            title = f"Potentially Outdated Software: {product} {version}"
            
            description = f"The detected version of {product} ({version}) may be outdated.\n\n"
            description += "Outdated software often contains known security vulnerabilities.\n"
            description += "Consider checking for available updates and security patches."
            
            solution = f"Update {product} to the latest stable version and apply security patches."
            
            return self.create_finding(
                title=title,
                severity='info',
                description=description,
                target=target,
                confidence=0.5,
                port=port,
                service=service_info.get('name'),
                solution=solution,
                metadata=service_info
            )
        
        return None
    
    def _check_service_combinations(self, target: str, services: Dict[int, Dict[str, Any]]) -> List[VulnerabilityFinding]:
        """Check for vulnerable service combinations"""
        findings = []
        
        # Check for exposed database + web server combination
        has_database = any(port in [1433, 3306, 5432, 27017, 6379] for port in services.keys())
        has_web = any(port in [80, 443, 8080, 8443] for port in services.keys())
        
        if has_database and has_web:
            title = "Database and Web Server Both Exposed"
            
            description = "Both database services and web services are exposed on this host.\n\n"
            description += "This configuration may indicate:\n"
            description += "- Database directly accessible from the internet\n"
            description += "- Potential for direct database attacks\n"
            description += "- Missing network segmentation\n\n"
            description += "Databases should typically only be accessible from application servers."
            
            solution = "Implement network segmentation. Place databases in a separate network segment "
            solution += "and restrict access using firewall rules. Only allow connections from authorized "
            solution += "application servers."
            
            finding = self.create_finding(
                title=title,
                severity='medium',
                description=description,
                target=target,
                confidence=0.7,
                solution=solution,
                references=[
                    'https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html'
                ]
            )
            findings.append(finding)
        
        return findings
    
    def _get_service_solution(self, service: str, port: int) -> str:
        """Get remediation solution for a service"""
        
        solutions = {
            'ftp': 'Replace FTP with SFTP or FTPS. If FTP is required, ensure it uses explicit TLS (FTPS).',
            'telnet': 'Disable Telnet and use SSH instead for secure remote access.',
            'smtp': 'Configure SMTP to require authentication and use encryption (STARTTLS or SMTPS).',
            'dns': 'Restrict zone transfers to authorized secondary DNS servers only.',
            'snmp': 'Use SNMPv3 with strong authentication. Disable SNMPv1/v2c or use complex community strings.',
            'netbios-ssn': 'Disable NetBIOS over TCP/IP if not required. Use SMB over direct TCP instead.',
            'microsoft-ds': 'Apply latest Windows security patches. Disable SMBv1. Use network-level authentication.',
            'ms-sql-s': 'Place database behind firewall. Use SQL authentication with strong passwords. Enable encryption.',
            'mysql': 'Bind MySQL to localhost only. Use strong passwords. Enable SSL/TLS for remote connections.',
            'postgresql': 'Configure pg_hba.conf properly. Use SSL for connections. Implement least privilege access.',
            'ms-wbt-server': 'Use Network Level Authentication. Implement account lockout policies. Use VPN for remote access.',
            'vnc': 'Use strong passwords. Enable SSH tunneling. Consider using VNC over VPN.',
            'redis': 'Enable authentication. Bind to localhost or trusted IPs only. Use TLS for remote access.',
            'mongod': 'Enable authentication. Configure IP binding. Use TLS for remote connections.',
            'elasticsearch': 'Enable security features. Configure authentication. Bind to trusted interfaces only.'
        }
        
        return solutions.get(service, 'Review service configuration and apply vendor security best practices. '
                                      'Restrict access using firewall rules and implement strong authentication.')


if __name__ == "__main__":
    # Test the plugin
    config = {
        'network_scanning': {
            'nmap_path': 'nmap',
            'nmap_timing': '-T4',
            'default_ports': '1-1000',
            'top_ports_count': 100
        }
    }
    
    plugin = NetworkReconnaissancePlugin(config)
    
    if plugin.nmap_available:
        print("Testing network reconnaissance plugin...")
        findings = plugin.check('scanme.nmap.org', context={})
        print(f"Found {len(findings)} vulnerabilities")
        for finding in findings:
            print(f"- {finding.title} ({finding.severity})")
    else:
        print("Nmap not available for testing")
