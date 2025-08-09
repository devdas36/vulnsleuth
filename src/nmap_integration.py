"""
VulnSleuth Nmap Integration
Advanced network scanning capabilities using Nmap

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import nmap
import subprocess
import json
import xml.etree.ElementTree as ET
import re
import time
from typing import Dict, List, Any, Optional, Tuple
import logging
import threading
import concurrent.futures
from dataclasses import dataclass
import ipaddress

logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    """Container for scan results"""
    host: str
    state: str
    ports: Dict[int, Dict[str, Any]]
    hostnames: List[str]
    os_info: Dict[str, Any]
    scan_time: float
    nmap_command: str

class NmapScanner:
    """
    Advanced Nmap integration for network scanning
    
    Provides comprehensive network reconnaissance capabilities including:
    - Host discovery and port scanning
    - Service detection and version identification
    - OS detection and fingerprinting
    - Script-based vulnerability scanning
    - Advanced scan techniques
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.nmap_config = config.get('network_scanning', {})
        self.logger = logging.getLogger('NmapScanner')
        
        # Nmap configuration
        self.nmap_path = self.nmap_config.get('nmap_path', 'nmap')
        self.timing = self.nmap_config.get('nmap_timing', '-T4')
        self.default_ports = self.nmap_config.get('default_ports', '1-1000')
        self.top_ports = self.nmap_config.get('top_ports_count', 1000)
        
        # Scan options
        self.os_detection_enabled = self.nmap_config.get('os_detection', True)
        self.service_detection_enabled = self.nmap_config.get('service_detection', True)
        self.script_scanning_enabled = self.nmap_config.get('script_scanning', True)
        self.ping_sweep_enabled = self.nmap_config.get('ping_sweep', True)
        
        # Initialize nmap python library
        try:
            self.nm = nmap.PortScanner()
            self.nmap_available = True
            self.logger.info("Nmap scanner initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize nmap: {str(e)}")
            self.nmap_available = False
            
        # Threading for parallel scans
        self.max_concurrent_scans = 5
        self.scan_timeout = 300  # 5 minutes default timeout
    
    def host_discovery(self, target: str, discovery_method: str = 'ping') -> List[str]:
        """
        Discover live hosts in the target network
        
        Args:
            target: Target network or host
            discovery_method: Discovery method ('ping', 'arp', 'syn', 'udp')
            
        Returns:
            List of live host IP addresses
        """
        live_hosts = []
        
        self.logger.info(f"Starting host discovery for {target}")
        
        if not self.nmap_available:
            self.logger.error("Nmap not available for host discovery")
            return live_hosts
        
        try:
            # Build nmap command based on discovery method
            nmap_args = self.timing
            
            if discovery_method == 'ping':
                nmap_args += ' -sn'  # Ping scan
            elif discovery_method == 'arp':
                nmap_args += ' -PR -sn'  # ARP ping
            elif discovery_method == 'syn':
                nmap_args += ' -PS80,443 -sn'  # TCP SYN ping
            elif discovery_method == 'udp':
                nmap_args += ' -PU53,161 -sn'  # UDP ping
            else:
                nmap_args += ' -sn'  # Default to ping scan
            
            # Execute scan
            scan_result = self.nm.scan(hosts=target, arguments=nmap_args)
            
            # Extract live hosts
            for host in scan_result['scan']:
                if scan_result['scan'][host]['status']['state'] == 'up':
                    live_hosts.append(host)
                    self.logger.debug(f"Live host discovered: {host}")
            
            self.logger.info(f"Host discovery completed: {len(live_hosts)} live hosts found")
            
        except Exception as e:
            self.logger.error(f"Host discovery failed: {str(e)}")
        
        return live_hosts
    
    def port_scan(self, target: str, ports: str = None, scan_type: str = 'syn') -> Dict[str, Any]:
        """
        Perform port scanning on target
        
        Args:
            target: Target host or network
            ports: Port specification (e.g., '1-1000', '80,443,8080')
            scan_type: Scan type ('syn', 'tcp', 'udp', 'stealth')
            
        Returns:
            Dictionary containing scan results
        """
        self.logger.info(f"Starting port scan for {target}")
        
        if not self.nmap_available:
            self.logger.error("Nmap not available for port scanning")
            return {}
        
        try:
            # Use default ports if not specified
            if not ports:
                ports = self.default_ports
            
            # Build scan arguments
            nmap_args = self.timing
            
            if scan_type == 'syn':
                nmap_args += ' -sS'  # TCP SYN scan
            elif scan_type == 'tcp':
                nmap_args += ' -sT'  # TCP connect scan
            elif scan_type == 'udp':
                nmap_args += ' -sU'  # UDP scan
            elif scan_type == 'stealth':
                nmap_args += ' -sS -f'  # Fragmented SYN scan
            else:
                nmap_args += ' -sS'  # Default to SYN scan
            
            # Add port specification
            nmap_args += f' -p {ports}'
            
            # Execute scan
            start_time = time.time()
            scan_result = self.nm.scan(hosts=target, arguments=nmap_args)
            scan_time = time.time() - start_time
            
            # Process results
            processed_results = self._process_port_scan_results(scan_result, scan_time)
            
            self.logger.info(f"Port scan completed in {scan_time:.2f} seconds")
            
            return processed_results
            
        except Exception as e:
            self.logger.error(f"Port scan failed: {str(e)}")
            return {}
    
    def service_detection(self, target: str, ports: str = None) -> Dict[int, Dict[str, Any]]:
        """
        Perform service version detection
        
        Args:
            target: Target host
            ports: Specific ports to scan
            
        Returns:
            Dictionary mapping ports to service information
        """
        self.logger.info(f"Starting service detection for {target}")
        
        if not self.nmap_available:
            self.logger.error("Nmap not available for service detection")
            return {}
        
        try:
            # Build arguments for service detection
            nmap_args = self.timing + ' -sV'  # Service version detection
            
            if ports:
                nmap_args += f' -p {ports}'
            else:
                nmap_args += f' --top-ports {self.top_ports}'
            
            # Execute scan
            scan_result = self.nm.scan(hosts=target, arguments=nmap_args)
            
            # Extract service information
            services = {}
            if target in scan_result['scan']:
                host_data = scan_result['scan'][target]
                
                if 'tcp' in host_data:
                    for port, port_info in host_data['tcp'].items():
                        if port_info['state'] == 'open':
                            services[port] = {
                                'name': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'conf': port_info.get('conf', '0'),
                                'method': port_info.get('method', ''),
                                'proto': 'tcp',
                                'target': target
                            }
                
                if 'udp' in host_data:
                    for port, port_info in host_data['udp'].items():
                        if port_info['state'] == 'open':
                            services[port] = {
                                'name': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'conf': port_info.get('conf', '0'),
                                'method': port_info.get('method', ''),
                                'proto': 'udp',
                                'target': target
                            }
            
            self.logger.info(f"Service detection completed: {len(services)} services identified")
            
            return services
            
        except Exception as e:
            self.logger.error(f"Service detection failed: {str(e)}")
            return {}
    
    def os_detection(self, target: str) -> Dict[str, Any]:
        """
        Perform operating system detection
        
        Args:
            target: Target host
            
        Returns:
            Dictionary containing OS information
        """
        self.logger.info(f"Starting OS detection for {target}")
        
        if not self.nmap_available:
            self.logger.error("Nmap not available for OS detection")
            return {}
        
        try:
            # Build arguments for OS detection
            nmap_args = self.timing + ' -O'  # OS detection
            
            # Execute scan
            scan_result = self.nm.scan(hosts=target, arguments=nmap_args)
            
            # Extract OS information
            os_info = {}
            if target in scan_result['scan']:
                host_data = scan_result['scan'][target]
                
                if 'osmatch' in host_data:
                    os_matches = []
                    for match in host_data['osmatch']:
                        os_matches.append({
                            'name': match.get('name', ''),
                            'accuracy': match.get('accuracy', ''),
                            'line': match.get('line', ''),
                            'osclass': match.get('osclass', [])
                        })
                    
                    os_info = {
                        'matches': os_matches,
                        'fingerprint': host_data.get('fingerprint', ''),
                        'uptime': host_data.get('uptime', {}),
                        'distance': host_data.get('distance', {}),
                        'target': target
                    }
            
            self.logger.info(f"OS detection completed")
            
            return os_info
            
        except Exception as e:
            self.logger.error(f"OS detection failed: {str(e)}")
            return {}
    
    def vulnerability_scan(self, target: str, script_categories: List[str] = None) -> Dict[str, Any]:
        """
        Perform vulnerability scanning using Nmap scripts
        
        Args:
            target: Target host
            script_categories: NSE script categories to run
            
        Returns:
            Dictionary containing vulnerability scan results
        """
        self.logger.info(f"Starting vulnerability scan for {target}")
        
        if not self.nmap_available:
            self.logger.error("Nmap not available for vulnerability scanning")
            return {}
        
        try:
            # Default script categories for vulnerability scanning
            if not script_categories:
                script_categories = ['vuln', 'exploit', 'malware']
            
            # Build script arguments
            scripts = ','.join(script_categories)
            nmap_args = f'{self.timing} -sV --script {scripts}'
            
            # Execute scan with timeout
            scan_result = self.nm.scan(hosts=target, arguments=nmap_args)
            
            # Extract script results
            vulnerabilities = {}
            if target in scan_result['scan']:
                host_data = scan_result['scan'][target]
                
                # Process TCP ports
                if 'tcp' in host_data:
                    for port, port_info in host_data['tcp'].items():
                        if 'script' in port_info:
                            port_vulns = []
                            for script_name, script_output in port_info['script'].items():
                                port_vulns.append({
                                    'script': script_name,
                                    'output': script_output,
                                    'port': port,
                                    'protocol': 'tcp'
                                })
                            
                            if port_vulns:
                                vulnerabilities[f'tcp_{port}'] = port_vulns
                
                # Process host scripts
                if 'hostscript' in host_data:
                    host_vulns = []
                    for script in host_data['hostscript']:
                        host_vulns.append({
                            'script': script.get('id', ''),
                            'output': script.get('output', ''),
                            'port': None,
                            'protocol': 'host'
                        })
                    
                    if host_vulns:
                        vulnerabilities['host'] = host_vulns
            
            self.logger.info(f"Vulnerability scan completed: {len(vulnerabilities)} categories found")
            
            return vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Vulnerability scan failed: {str(e)}")
            return {}
    
    def comprehensive_scan(self, target: str, scan_options: Dict[str, Any] = None) -> ScanResult:
        """
        Perform comprehensive network scan
        
        Args:
            target: Target host or network
            scan_options: Custom scan options
            
        Returns:
            ScanResult object containing all scan data
        """
        self.logger.info(f"Starting comprehensive scan for {target}")
        
        if not scan_options:
            scan_options = {}
        
        start_time = time.time()
        
        try:
            # Build comprehensive scan arguments
            nmap_args = self.timing
            
            # Add scan techniques
            if scan_options.get('syn_scan', True):
                nmap_args += ' -sS'
            
            if scan_options.get('udp_scan', False):
                nmap_args += ' -sU'
            
            # Add detection options
            if self.service_detection_enabled and scan_options.get('service_detection', True):
                nmap_args += ' -sV'
            
            if self.os_detection_enabled and scan_options.get('os_detection', True):
                nmap_args += ' -O'
            
            # Add script scanning
            if self.script_scanning_enabled and scan_options.get('script_scanning', True):
                script_categories = scan_options.get('script_categories', ['default', 'safe'])
                scripts = ','.join(script_categories)
                nmap_args += f' --script {scripts}'
            
            # Port specification
            ports = scan_options.get('ports', self.default_ports)
            nmap_args += f' -p {ports}'
            
            # Additional options
            if scan_options.get('aggressive', False):
                nmap_args += ' -A'
            
            if scan_options.get('no_ping', False):
                nmap_args += ' -Pn'
            
            # Execute comprehensive scan
            self.logger.debug(f"Executing nmap command: nmap {nmap_args} {target}")
            scan_result = self.nm.scan(hosts=target, arguments=nmap_args)
            
            scan_time = time.time() - start_time
            
            # Process and organize results
            processed_result = self._create_scan_result(target, scan_result, scan_time, f"nmap {nmap_args} {target}")
            
            self.logger.info(f"Comprehensive scan completed in {scan_time:.2f} seconds")
            
            return processed_result
            
        except Exception as e:
            self.logger.error(f"Comprehensive scan failed: {str(e)}")
            return ScanResult(
                host=target,
                state='error',
                ports={},
                hostnames=[],
                os_info={},
                scan_time=time.time() - start_time,
                nmap_command=''
            )
    
    def parallel_scan(self, targets: List[str], scan_options: Dict[str, Any] = None) -> List[ScanResult]:
        """
        Perform parallel scanning of multiple targets
        
        Args:
            targets: List of target hosts/networks
            scan_options: Scan configuration options
            
        Returns:
            List of ScanResult objects
        """
        self.logger.info(f"Starting parallel scan of {len(targets)} targets")
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent_scans) as executor:
            # Submit scan jobs
            future_to_target = {
                executor.submit(self.comprehensive_scan, target, scan_options): target 
                for target in targets
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_target, timeout=self.scan_timeout * len(targets)):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results.append(result)
                    self.logger.debug(f"Scan completed for {target}")
                except Exception as e:
                    self.logger.error(f"Scan failed for {target}: {str(e)}")
                    # Add error result
                    error_result = ScanResult(
                        host=target,
                        state='error',
                        ports={},
                        hostnames=[],
                        os_info={},
                        scan_time=0,
                        nmap_command=''
                    )
                    results.append(error_result)
        
        self.logger.info(f"Parallel scan completed: {len(results)} results")
        
        return results
    
    def custom_nmap_scan(self, target: str, nmap_args: str) -> Dict[str, Any]:
        """
        Execute custom nmap scan with user-provided arguments
        
        Args:
            target: Target host or network
            nmap_args: Custom nmap arguments
            
        Returns:
            Raw nmap scan results
        """
        self.logger.info(f"Executing custom nmap scan: {nmap_args}")
        
        if not self.nmap_available:
            self.logger.error("Nmap not available for custom scan")
            return {}
        
        try:
            scan_result = self.nm.scan(hosts=target, arguments=nmap_args)
            self.logger.info("Custom nmap scan completed")
            return scan_result
            
        except Exception as e:
            self.logger.error(f"Custom nmap scan failed: {str(e)}")
            return {}
    
    def _process_port_scan_results(self, scan_result: Dict[str, Any], scan_time: float) -> Dict[str, Any]:
        """Process port scan results into standardized format"""
        processed = {
            'scan_time': scan_time,
            'total_hosts': len(scan_result.get('scan', {})),
            'hosts': {}
        }
        
        for host, host_data in scan_result.get('scan', {}).items():
            host_info = {
                'state': host_data.get('status', {}).get('state', 'unknown'),
                'hostnames': [hn.get('name', '') for hn in host_data.get('hostnames', [])],
                'addresses': host_data.get('addresses', {}),
                'ports': {}
            }
            
            # Process TCP ports
            if 'tcp' in host_data:
                for port, port_info in host_data['tcp'].items():
                    host_info['ports'][f'tcp_{port}'] = {
                        'port': port,
                        'protocol': 'tcp',
                        'state': port_info.get('state', 'unknown'),
                        'service': port_info.get('name', ''),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', ''),
                        'extrainfo': port_info.get('extrainfo', '')
                    }
            
            # Process UDP ports
            if 'udp' in host_data:
                for port, port_info in host_data['udp'].items():
                    host_info['ports'][f'udp_{port}'] = {
                        'port': port,
                        'protocol': 'udp',
                        'state': port_info.get('state', 'unknown'),
                        'service': port_info.get('name', ''),
                        'version': port_info.get('version', ''),
                        'product': port_info.get('product', ''),
                        'extrainfo': port_info.get('extrainfo', '')
                    }
            
            processed['hosts'][host] = host_info
        
        return processed
    
    def _create_scan_result(self, target: str, scan_data: Dict[str, Any], scan_time: float, nmap_command: str) -> ScanResult:
        """Create ScanResult object from scan data"""
        
        if target in scan_data.get('scan', {}):
            host_data = scan_data['scan'][target]
            
            # Extract basic info
            state = host_data.get('status', {}).get('state', 'unknown')
            hostnames = [hn.get('name', '') for hn in host_data.get('hostnames', [])]
            
            # Extract port information
            ports = {}
            for protocol in ['tcp', 'udp']:
                if protocol in host_data:
                    for port, port_info in host_data[protocol].items():
                        ports[port] = {
                            'protocol': protocol,
                            'state': port_info.get('state', 'unknown'),
                            'service': port_info.get('name', ''),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', ''),
                            'script_results': port_info.get('script', {})
                        }
            
            # Extract OS information
            os_info = {}
            if 'osmatch' in host_data:
                os_info['matches'] = host_data['osmatch']
            if 'osclass' in host_data:
                os_info['classes'] = host_data['osclass']
            
            return ScanResult(
                host=target,
                state=state,
                ports=ports,
                hostnames=hostnames,
                os_info=os_info,
                scan_time=scan_time,
                nmap_command=nmap_command
            )
        else:
            return ScanResult(
                host=target,
                state='unknown',
                ports={},
                hostnames=[],
                os_info={},
                scan_time=scan_time,
                nmap_command=nmap_command
            )
    
    def get_nmap_version(self) -> str:
        """Get installed nmap version"""
        try:
            result = subprocess.run([self.nmap_path, '--version'], 
                                  capture_output=True, text=True)
            version_line = result.stdout.split('\n')[0]
            return version_line
        except Exception as e:
            self.logger.error(f"Failed to get nmap version: {str(e)}")
            return "Unknown"
    
    def validate_target(self, target: str) -> bool:
        """Validate target format and accessibility"""
        try:
            # Try to parse as IP address
            ipaddress.ip_address(target)
            return True
        except ValueError:
            # Try as network range
            try:
                ipaddress.ip_network(target, strict=False)
                return True
            except ValueError:
                # Try as hostname
                if '.' in target and not target.endswith('.'):
                    return True
                return False

if __name__ == "__main__":
    # Test the nmap scanner
    config = {'network_scanning': {}}
    scanner = NmapScanner(config)
    
    if scanner.nmap_available:
        print(f"Nmap version: {scanner.get_nmap_version()}")
        
        # Test host discovery
        target = "127.0.0.1"
        live_hosts = scanner.host_discovery(target)
        print(f"Live hosts: {live_hosts}")
        
        # Test port scan
        if live_hosts:
            port_results = scanner.port_scan(live_hosts[0], "80,443,22")
            print(f"Port scan results: {json.dumps(port_results, indent=2)}")
    else:
        print("Nmap not available for testing")
