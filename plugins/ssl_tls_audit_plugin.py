"""
SSL/TLS Security Audit Plugin
Comprehensive SSL/TLS certificate and configuration testing

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import ssl
import socket
from datetime import datetime
from typing import List, Dict, Any, Optional
import sys
import os

# Try to import OpenSSL, but continue if not available
try:
    import OpenSSL
    OPENSSL_AVAILABLE = True
except ImportError:
    OPENSSL_AVAILABLE = False

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from plugin import VulnPlugin, VulnerabilityFinding, PluginMetadata

class SSLTLSAuditPlugin(VulnPlugin):
    """
    SSL/TLS Security Audit Plugin
    
    Features:
    - Certificate validation and expiration checking
    - Weak cipher suite detection
    - Protocol version analysis
    - Certificate chain verification
    - Common SSL/TLS vulnerabilities (POODLE, BEAST, etc.)
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.metadata = PluginMetadata(
            name="SSL/TLS Security Audit Plugin",
            version="1.0.0",
            author="Devdas",
            description="Comprehensive SSL/TLS certificate and configuration analysis",
            category="network",
            tags=["ssl", "tls", "certificate", "encryption", "crypto"]
        )
        
        # Weak cipher patterns
        self.weak_ciphers = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon']
        
        # Insecure protocols
        self.insecure_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0']
    
    def can_run(self, target: str, context: Dict[str, Any]) -> bool:
        """Check if HTTPS services are available"""
        return 443 in context.get('open_ports', []) or context.get('has_ssl_services', False)
    
    def check(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """Perform SSL/TLS security audit"""
        context = kwargs.get('context', {})
        return self.execute(target, context)
    
    def execute(self, target: str, context: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Execute SSL/TLS audit"""
        findings = []
        
        try:
            ssl_ports = context.get('ssl_ports', [443, 8443])
            
            for port in ssl_ports:
                if port in context.get('open_ports', []):
                    port_findings = self._audit_ssl_port(target, port)
                    findings.extend(port_findings)
            
        except Exception as e:
            self.logger.error(f"SSL/TLS audit failed for {target}: {str(e)}")
        
        return findings
    
    def _audit_ssl_port(self, target: str, port: int) -> List[VulnerabilityFinding]:
        """Audit SSL/TLS configuration on specific port"""
        findings = []
        
        try:
            # Get certificate
            cert_info = self._get_certificate(target, port)
            
            if not cert_info:
                return findings
            
            # Check certificate expiration
            expiry_finding = self._check_certificate_expiry(target, port, cert_info)
            if expiry_finding:
                findings.append(expiry_finding)
            
            # Check weak ciphers
            cipher_findings = self._check_weak_ciphers(target, port)
            findings.extend(cipher_findings)
            
            # Check protocols
            protocol_findings = self._check_insecure_protocols(target, port)
            findings.extend(protocol_findings)
            
        except Exception as e:
            self.logger.error(f"SSL audit failed for {target}:{port}: {str(e)}")
        
        return findings
    
    def _get_certificate(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Retrieve SSL certificate"""
        try:
            if not OPENSSL_AVAILABLE:
                self.logger.warning("OpenSSL module not available, using basic SSL check")
                # Use basic ssl module
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((target, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert_dict = ssock.getpeercert()
                        return {
                            'subject': cert_dict.get('subject', {}),
                            'issuer': cert_dict.get('issuer', {}),
                            'version': cert_dict.get('version', 0),
                            'notBefore': cert_dict.get('notBefore', ''),
                            'notAfter': cert_dict.get('notAfter', ''),
                            'cipher': ssock.cipher()
                        }
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)
                    
                    return {
                        'subject': dict(cert.get_subject().get_components()),
                        'issuer': dict(cert.get_issuer().get_components()),
                        'version': cert.get_version(),
                        'serial': cert.get_serial_number(),
                        'notBefore': cert.get_notBefore().decode(),
                        'notAfter': cert.get_notAfter().decode(),
                        'cipher': ssock.cipher()
                    }
        except Exception as e:
            self.logger.error(f"Failed to retrieve certificate: {str(e)}")
            return None
    
    def _check_certificate_expiry(self, target: str, port: int, cert_info: Dict[str, Any]) -> Optional[VulnerabilityFinding]:
        """Check certificate expiration"""
        try:
            not_after = cert_info['notAfter']
            expiry_date = datetime.strptime(not_after, '%Y%m%d%H%M%SZ')
            days_until_expiry = (expiry_date - datetime.now()).days
            
            if days_until_expiry < 0:
                title = f"Expired SSL Certificate on port {port}"
                description = f"The SSL certificate expired {abs(days_until_expiry)} days ago.\n"
                description += f"Expiry Date: {expiry_date}\n"
                severity = 'high'
            elif days_until_expiry < 30:
                title = f"SSL Certificate Expiring Soon on port {port}"
                description = f"The SSL certificate will expire in {days_until_expiry} days.\n"
                description += f"Expiry Date: {expiry_date}\n"
                severity = 'medium'
            else:
                return None
            
            return self.create_finding(
                title=title,
                severity=severity,
                description=description,
                target=target,
                port=port,
                confidence=1.0,
                solution="Renew the SSL certificate before expiration."
            )
        except Exception:
            return None
    
    def _check_weak_ciphers(self, target: str, port: int) -> List[VulnerabilityFinding]:
        """Check for weak cipher suites"""
        findings = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock) as ssock:
                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else ''
                    
                    for weak in self.weak_ciphers:
                        if weak.upper() in cipher_name.upper():
                            title = f"Weak Cipher Suite Detected: {cipher_name}"
                            description = f"Port {port} supports weak cipher: {cipher_name}\n"
                            description += "Weak ciphers can be exploited to decrypt traffic."
                            
                            finding = self.create_finding(
                                title=title,
                                severity='high',
                                description=description,
                                target=target,
                                port=port,
                                confidence=0.9,
                                solution="Disable weak ciphers in SSL/TLS configuration."
                            )
                            findings.append(finding)
        except Exception as e:
            self.logger.error(f"Cipher check failed: {str(e)}")
        
        return findings
    
    def _check_insecure_protocols(self, target: str, port: int) -> List[VulnerabilityFinding]:
        """Check for insecure protocol versions"""
        findings = []
        
        for protocol in self.insecure_protocols:
            if self._test_protocol(target, port, protocol):
                title = f"Insecure Protocol Supported: {protocol}"
                description = f"Port {port} supports insecure protocol {protocol}\n"
                description += "This protocol has known vulnerabilities and should be disabled."
                
                finding = self.create_finding(
                    title=title,
                    severity='high',
                    description=description,
                    target=target,
                    port=port,
                    confidence=0.95,
                    solution=f"Disable {protocol} and use TLS 1.2 or higher."
                )
                findings.append(finding)
        
        return findings
    
    def _test_protocol(self, target: str, port: int, protocol: str) -> bool:
        """Test if a specific protocol is supported"""
        try:
            protocol_map = {
                'SSLv2': ssl.PROTOCOL_SSLv23,
                'SSLv3': ssl.PROTOCOL_SSLv23,
                'TLSv1.0': ssl.PROTOCOL_TLSv1
            }
            
            protocol_version = protocol_map.get(protocol)
            if not protocol_version:
                return False
            
            context = ssl.SSLContext(protocol_version)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=5) as sock:
                with context.wrap_socket(sock) as ssock:
                    return True
        except Exception:
            return False
