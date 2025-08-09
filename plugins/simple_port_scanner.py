"""
Simple Network Port Scanner Plugin
Example of a basic network plugin

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import socket
import threading
import time
from typing import List, Dict, Any
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from plugin import VulnPlugin, VulnerabilityFinding, PluginMetadata

class SimplePortScannerPlugin(VulnPlugin):
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.metadata = PluginMetadata(
            name="Simple Port Scanner",
            version="1.0.0", 
            author="Security Team",
            description="Basic port scanner to identify open services",
            category="network",
            tags=["network", "ports", "services", "reconnaissance"]
        )
        
        # Common vulnerable services and their default ports
        self.vulnerable_services = {
            21: {'service': 'ftp', 'risk': 'medium', 'description': 'FTP service - often misconfigured'},
            22: {'service': 'ssh', 'risk': 'low', 'description': 'SSH service - check for weak authentication'},
            23: {'service': 'telnet', 'risk': 'high', 'description': 'Telnet - unencrypted remote access'},
            25: {'service': 'smtp', 'risk': 'medium', 'description': 'SMTP - potential relay vulnerability'},
            53: {'service': 'dns', 'risk': 'medium', 'description': 'DNS - potential zone transfer'},
            80: {'service': 'http', 'risk': 'medium', 'description': 'HTTP web server'},
            110: {'service': 'pop3', 'risk': 'medium', 'description': 'POP3 - unencrypted email'},
            135: {'service': 'rpc', 'risk': 'high', 'description': 'RPC - Windows RPC endpoint'},
            139: {'service': 'netbios', 'risk': 'high', 'description': 'NetBIOS - SMB over NetBIOS'},
            143: {'service': 'imap', 'risk': 'medium', 'description': 'IMAP - unencrypted email'},
            443: {'service': 'https', 'risk': 'low', 'description': 'HTTPS web server'},
            445: {'service': 'smb', 'risk': 'high', 'description': 'SMB - file sharing protocol'},
            993: {'service': 'imaps', 'risk': 'low', 'description': 'IMAP over SSL'},
            995: {'service': 'pop3s', 'risk': 'low', 'description': 'POP3 over SSL'},
            1433: {'service': 'mssql', 'risk': 'high', 'description': 'Microsoft SQL Server'},
            3306: {'service': 'mysql', 'risk': 'high', 'description': 'MySQL database'},
            3389: {'service': 'rdp', 'risk': 'high', 'description': 'Remote Desktop Protocol'},
            5432: {'service': 'postgresql', 'risk': 'high', 'description': 'PostgreSQL database'},
            5900: {'service': 'vnc', 'risk': 'high', 'description': 'VNC remote desktop'},
            6379: {'service': 'redis', 'risk': 'high', 'description': 'Redis database'},
            27017: {'service': 'mongodb', 'risk': 'high', 'description': 'MongoDB database'}
        }
    
    def can_run(self, target: str, context: Dict[str, Any]) -> bool:
        """
        This plugin can run against any network target
        
        Args:
            target: Target IP or hostname
            context: Scan context
            
        Returns:
            True - this plugin can run against any target
        """
        return True
    
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
        Execute port scan against the target
        
        Args:
            target: Target to scan
            context: Scan context with configuration
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        try:
            # Get port range from context or use common ports
            port_range = context.get('ports', list(self.vulnerable_services.keys()))
            
            if isinstance(port_range, str):
                # Parse port range string
                port_range = self._parse_port_range(port_range)
            
            # Perform port scan
            self.logger.info(f"Scanning {len(port_range)} ports on {target}")
            open_ports = self._scan_ports(target, port_range)
            
            # Analyze open ports for vulnerabilities
            for port in open_ports:
                port_findings = self._analyze_port(target, port, context)
                findings.extend(port_findings)
            
            # Add general finding if many ports are open
            if len(open_ports) > 10:
                finding = VulnerabilityFinding(
                    title="Multiple Open Ports Detected",
                    description=f"Target has {len(open_ports)} open ports, indicating large attack surface",
                    severity="medium",
                    cvss_score=4.0,
                    solution="Review all open services and close unnecessary ports",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Port_scanning"
                    ],
                    evidence={'open_ports': open_ports, 'port_count': len(open_ports)}
                )
                findings.append(finding)
                
        except Exception as e:
            self.logger.error(f"Port scan failed for {target}: {str(e)}")
        
        return findings
    
    def _scan_ports(self, target: str, ports: List[int], timeout: int = 2) -> List[int]:
        """
        Scan list of ports on target
        
        Args:
            target: Target IP/hostname
            ports: List of ports to scan
            timeout: Connection timeout in seconds
            
        Returns:
            List of open ports
        """
        open_ports = []
        threads = []
        lock = threading.Lock()
        
        def scan_port(port):
            if self._is_port_open(target, port, timeout):
                with lock:
                    open_ports.append(port)
        
        # Create threads for parallel scanning
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
            
            # Limit concurrent threads
            if len(threads) >= 50:
                for t in threads:
                    t.join()
                threads = []
        
        # Wait for remaining threads
        for thread in threads:
            thread.join()
        
        return sorted(open_ports)
    
    def _is_port_open(self, target: str, port: int, timeout: int = 2) -> bool:
        """
        Check if specific port is open
        
        Args:
            target: Target IP/hostname
            port: Port number to check
            timeout: Connection timeout
            
        Returns:
            True if port is open
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                return result == 0
        except Exception:
            return False
    
    def _analyze_port(self, target: str, port: int, context: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """
        Analyze open port for potential vulnerabilities
        
        Args:
            target: Target address
            port: Open port number
            context: Scan context
            
        Returns:
            List of findings for this port
        """
        findings = []
        
        # Check if this is a known vulnerable service
        if port in self.vulnerable_services:
            service_info = self.vulnerable_services[port]
            
            # Determine severity based on service risk
            risk_to_severity = {
                'low': ('low', 2.0),
                'medium': ('medium', 5.0), 
                'high': ('high', 7.0)
            }
            
            severity, cvss_score = risk_to_severity.get(service_info['risk'], ('medium', 5.0))
            
            # Try to get banner information
            banner = self._get_service_banner(target, port)
            evidence = {'port': port, 'service': service_info['service']}
            
            if banner:
                evidence['banner'] = banner
                
                # Check for version information in banner
                if self._has_version_info(banner):
                    # Increase severity if version is disclosed
                    if severity == 'low':
                        severity = 'medium'
                        cvss_score = 4.0
            
            finding = VulnerabilityFinding(
                title=f"{service_info['service'].upper()} Service Detected",
                description=f"{service_info['description']} detected on port {port}",
                severity=severity,
                cvss_score=cvss_score,
                solution=f"Review {service_info['service']} service configuration and security settings",
                references=[
                    f"https://www.speedguide.net/port.php?port={port}"
                ],
                evidence=evidence
            )
            findings.append(finding)
        
        else:
            # Unknown service on unusual port
            banner = self._get_service_banner(target, port)
            
            finding = VulnerabilityFinding(
                title=f"Unknown Service on Port {port}",
                description=f"Unidentified service running on port {port}",
                severity="low",
                cvss_score=2.0,
                solution="Identify the service and ensure it's properly secured",
                references=[
                    "https://nmap.org/book/man-port-specification.html"
                ],
                evidence={'port': port, 'banner': banner if banner else 'No banner'}
            )
            findings.append(finding)
        
        return findings
    
    def _get_service_banner(self, target: str, port: int, timeout: int = 3) -> str:
        """
        Attempt to grab service banner
        
        Args:
            target: Target address
            port: Port number
            timeout: Connection timeout
            
        Returns:
            Service banner string or empty string
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((target, port))
                
                # Try to receive banner
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    return banner
                except socket.timeout:
                    # Try sending a request for HTTP-like services
                    if port in [80, 443, 8080, 8443]:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        time.sleep(1)
                        response = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        return response
                    return ""
                
        except Exception:
            return ""
    
    def _has_version_info(self, banner: str) -> bool:
        """
        Check if banner contains version information
        
        Args:
            banner: Service banner string
            
        Returns:
            True if version info detected
        """
        import re
        # Look for version patterns like "1.2.3", "v2.1", "Version 3.0"
        version_patterns = [
            r'\d+\.\d+\.\d+',  # x.y.z
            r'\d+\.\d+',       # x.y
            r'v\d+\.\d+',      # vx.y
            r'version\s+\d+',   # version x
        ]
        
        for pattern in version_patterns:
            if re.search(pattern, banner, re.IGNORECASE):
                return True
        
        return False
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """
        Parse port range string into list of ports
        
        Args:
            port_range: Port range string (e.g., "80,443,8080-8090")
            
        Returns:
            List of port numbers
        """
        ports = []
        
        for part in port_range.split(','):
            part = part.strip()
            
            if '-' in part:
                # Range like "80-90"
                try:
                    start, end = map(int, part.split('-'))
                    ports.extend(range(start, end + 1))
                except ValueError:
                    continue
            else:
                # Single port
                try:
                    ports.append(int(part))
                except ValueError:
                    continue
        
        return sorted(list(set(ports)))
    
    def cleanup(self):
        """Cleanup resources"""
        pass

# Plugin registration function
def get_plugin():
    """Return plugin instance for VulnSleuth"""
    return SimplePortScannerPlugin()
