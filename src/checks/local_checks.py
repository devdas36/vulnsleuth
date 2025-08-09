"""
VulnSleuth Local System Security Checks
Local system vulnerability scanning and assessment

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import os
import pwd
import grp
import stat
import subprocess
import glob
import re
import json
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import logging
import platform
import configparser

logger = logging.getLogger(__name__)

class LocalSecurityChecker:
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.local_config = config.get('local_checks', {})
        self.logger = logging.getLogger('LocalSecurityChecker')
        self.system = platform.system().lower()
        
        # Security baselines and known vulnerabilities
        self.security_baselines = {
            'file_permissions': {
                'sensitive_files': [
                    '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
                    '/root/.ssh/id_rsa', '/home/*/.ssh/id_rsa',
                    '/etc/ssh/sshd_config', '/etc/crontab'
                ],
                'world_writable_paths': [
                    '/tmp', '/var/tmp', '/dev/shm'
                ]
            },
            'services': {
                'risky_services': [
                    'telnet', 'rsh', 'rlogin', 'ftp', 'tftp',
                    'finger', 'nfs', 'nis', 'rpcbind'
                ],
                'ssh_weak_configs': [
                    'PermitRootLogin yes',
                    'PasswordAuthentication yes',
                    'PermitEmptyPasswords yes',
                    'Protocol 1'
                ]
            }
        }
    
    def check_all(self) -> List[Dict[str, Any]]:
        """Run all local security checks"""
        all_findings = []
        
        if self.local_config.get('check_permissions', True):
            all_findings.extend(self.check_file_permissions())
        
        if self.local_config.get('check_users', True):
            all_findings.extend(self.check_user_accounts())
        
        if self.local_config.get('check_services', True):
            all_findings.extend(self.check_service_configurations())
        
        if self.local_config.get('check_suid_binaries', True):
            all_findings.extend(self.check_suid_binaries())
        
        if self.local_config.get('check_world_writable', True):
            all_findings.extend(self.check_world_writable_files())
        
        if self.local_config.get('check_ssh_config', True):
            all_findings.extend(self.check_ssh_configuration())
        
        if self.local_config.get('check_cron_jobs', True):
            all_findings.extend(self.check_cron_jobs())
        
        if self.local_config.get('check_packages', True):
            all_findings.extend(self.check_installed_packages())
        
        if self.local_config.get('check_kernel', True):
            all_findings.extend(self.check_kernel_security())
        
        return all_findings
    
    def check_file_permissions(self) -> List[Dict[str, Any]]:
        """Check file permissions and ownership vulnerabilities"""
        findings = []
        
        self.logger.info("Checking file permissions and ownership")
        
        # Check sensitive files
        sensitive_files = self.security_baselines['file_permissions']['sensitive_files']
        
        for file_pattern in sensitive_files:
            for file_path in glob.glob(file_pattern):
                if not os.path.exists(file_path):
                    continue
                
                try:
                    stat_info = os.stat(file_path)
                    file_mode = stat.filemode(stat_info.st_mode)
                    
                    # Check for overly permissive permissions
                    if self._is_overly_permissive(file_path, stat_info):
                        finding = {
                            'id': f'file_perm_{hashlib.md5(file_path.encode()).hexdigest()[:8]}',
                            'title': f'Insecure File Permissions: {file_path}',
                            'description': f'File {file_path} has overly permissive permissions ({file_mode})',
                            'severity': 'medium',
                            'confidence': 0.9,
                            'target': 'localhost',
                            'plugin_source': 'LocalSecurityChecker',
                            'metadata': {
                                'file_path': file_path,
                                'current_permissions': file_mode,
                                'owner_uid': stat_info.st_uid,
                                'group_gid': stat_info.st_gid
                            },
                            'solution': f'Restrict permissions on {file_path} using chmod and ensure proper ownership',
                            'references': ['https://www.cisecurity.org/']
                        }
                        findings.append(finding)
                
                except (OSError, PermissionError) as e:
                    self.logger.warning(f"Could not check permissions for {file_path}: {str(e)}")
        
        return findings
    
    def check_user_accounts(self) -> List[Dict[str, Any]]:
        """Check user account security vulnerabilities"""
        findings = []
        
        self.logger.info("Checking user account security")
        
        try:
            # Check for users with empty passwords
            with open('/etc/shadow', 'r') as shadow_file:
                for line in shadow_file:
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        password_hash = parts[1]
                        
                        # Empty password
                        if password_hash in ('', '!', '*'):
                            if username not in ['root', 'daemon', 'bin', 'sys']:  # System accounts
                                finding = {
                                    'id': f'empty_pwd_{username}',
                                    'title': f'User Account with Empty Password: {username}',
                                    'description': f'User {username} has an empty password',
                                    'severity': 'high',
                                    'confidence': 1.0,
                                    'target': 'localhost',
                                    'plugin_source': 'LocalSecurityChecker',
                                    'metadata': {'username': username},
                                    'solution': f'Set a strong password for user {username} or disable the account',
                                    'references': ['https://www.nist.gov/password-guidelines']
                                }
                                findings.append(finding)
        
        except (FileNotFoundError, PermissionError) as e:
            self.logger.warning(f"Could not check shadow file: {str(e)}")
        
        # Check for privileged users
        try:
            privileged_users = self._get_privileged_users()
            if len(privileged_users) > 2:  # root + one admin should be sufficient
                finding = {
                    'id': 'excessive_privileged_users',
                    'title': 'Excessive Privileged User Accounts',
                    'description': f'Found {len(privileged_users)} users with root privileges: {", ".join(privileged_users)}',
                    'severity': 'medium',
                    'confidence': 0.8,
                    'target': 'localhost',
                    'plugin_source': 'LocalSecurityChecker',
                    'metadata': {'privileged_users': privileged_users},
                    'solution': 'Review and minimize the number of users with administrative privileges',
                    'references': ['https://www.cisecurity.org/controls/']
                }
                findings.append(finding)
        
        except Exception as e:
            self.logger.warning(f"Could not check privileged users: {str(e)}")
        
        return findings
    
    def check_service_configurations(self) -> List[Dict[str, Any]]:
        """Check system service configurations for vulnerabilities"""
        findings = []
        
        self.logger.info("Checking service configurations")
        
        # Check for risky services
        risky_services = self.security_baselines['services']['risky_services']
        
        active_services = self._get_active_services()
        
        for service in risky_services:
            if service in active_services:
                finding = {
                    'id': f'risky_service_{service}',
                    'title': f'Risky Service Running: {service}',
                    'description': f'Potentially insecure service {service} is running',
                    'severity': 'medium',
                    'confidence': 0.8,
                    'target': 'localhost',
                    'plugin_source': 'LocalSecurityChecker',
                    'metadata': {'service_name': service},
                    'solution': f'Consider disabling {service} service if not required, or secure it properly',
                    'references': ['https://www.cisecurity.org/']
                }
                findings.append(finding)
        
        return findings
    
    def check_suid_binaries(self) -> List[Dict[str, Any]]:
        """Check for suspicious SUID/SGID binaries"""
        findings = []
        
        self.logger.info("Checking SUID/SGID binaries")
        
        # Find SUID and SGID files
        try:
            suid_files = self._find_suid_files()
            suspicious_suid = self._identify_suspicious_suid(suid_files)
            
            for suid_file in suspicious_suid:
                finding = {
                    'id': f'suspicious_suid_{hashlib.md5(suid_file.encode()).hexdigest()[:8]}',
                    'title': f'Suspicious SUID Binary: {suid_file}',
                    'description': f'Found potentially dangerous SUID binary: {suid_file}',
                    'severity': 'high',
                    'confidence': 0.7,
                    'target': 'localhost',
                    'plugin_source': 'LocalSecurityChecker',
                    'metadata': {'suid_file': suid_file},
                    'solution': f'Review the necessity of SUID bit on {suid_file} and remove if not required',
                    'references': ['https://www.cyberciti.biz/faq/unix-suid-sgid-file-permission/']
                }
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Error checking SUID binaries: {str(e)}")
        
        return findings
    
    def check_world_writable_files(self) -> List[Dict[str, Any]]:
        """Check for world-writable files outside safe locations"""
        findings = []
        
        self.logger.info("Checking for world-writable files")
        
        try:
            world_writable = self._find_world_writable_files()
            safe_locations = self.security_baselines['file_permissions']['world_writable_paths']
            
            for file_path in world_writable:
                # Check if it's in a safe location
                is_safe = any(file_path.startswith(safe_path) for safe_path in safe_locations)
                
                if not is_safe:
                    finding = {
                        'id': f'world_writable_{hashlib.md5(file_path.encode()).hexdigest()[:8]}',
                        'title': f'World-Writable File: {file_path}',
                        'description': f'File {file_path} is world-writable outside safe locations',
                        'severity': 'medium',
                        'confidence': 0.9,
                        'target': 'localhost',
                        'plugin_source': 'LocalSecurityChecker',
                        'metadata': {'file_path': file_path},
                        'solution': f'Remove world-write permissions from {file_path}',
                        'references': ['https://www.cisecurity.org/']
                    }
                    findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Error checking world-writable files: {str(e)}")
        
        return findings
    
    def check_ssh_configuration(self) -> List[Dict[str, Any]]:
        """Check SSH daemon configuration for security issues"""
        findings = []
        
        self.logger.info("Checking SSH configuration")
        
        ssh_config_file = '/etc/ssh/sshd_config'
        
        if not os.path.exists(ssh_config_file):
            return findings
        
        try:
            with open(ssh_config_file, 'r') as f:
                ssh_config = f.read()
            
            weak_configs = self.security_baselines['services']['ssh_weak_configs']
            
            for weak_config in weak_configs:
                if weak_config.lower() in ssh_config.lower():
                    # Parse the specific setting
                    setting_name = weak_config.split()[0]
                    
                    finding = {
                        'id': f'ssh_weak_{setting_name.lower()}',
                        'title': f'Weak SSH Configuration: {setting_name}',
                        'description': f'SSH configuration contains weak setting: {weak_config}',
                        'severity': 'high' if 'root' in weak_config.lower() else 'medium',
                        'confidence': 0.9,
                        'target': 'localhost',
                        'plugin_source': 'LocalSecurityChecker',
                        'metadata': {'weak_setting': weak_config},
                        'solution': f'Update SSH configuration to secure {setting_name}',
                        'references': ['https://www.ssh.com/ssh/sshd_config/']
                    }
                    findings.append(finding)
        
        except (IOError, PermissionError) as e:
            self.logger.warning(f"Could not check SSH configuration: {str(e)}")
        
        return findings
    
    def check_cron_jobs(self) -> List[Dict[str, Any]]:
        """Check cron jobs for security vulnerabilities"""
        findings = []
        
        self.logger.info("Checking cron job configurations")
        
        cron_locations = [
            '/etc/crontab',
            '/etc/cron.d/',
            '/var/spool/cron/crontabs/',
            '/var/spool/cron/'
        ]
        
        for location in cron_locations:
            try:
                if os.path.isfile(location):
                    findings.extend(self._check_cron_file(location))
                elif os.path.isdir(location):
                    for cron_file in os.listdir(location):
                        file_path = os.path.join(location, cron_file)
                        if os.path.isfile(file_path):
                            findings.extend(self._check_cron_file(file_path))
            
            except (OSError, PermissionError) as e:
                self.logger.warning(f"Could not check cron location {location}: {str(e)}")
        
        return findings
    
    def check_installed_packages(self) -> List[Dict[str, Any]]:
        """Check for vulnerable installed packages"""
        findings = []
        
        self.logger.info("Checking installed packages for vulnerabilities")
        
        try:
            if self.system == 'linux':
                # Check with different package managers
                if os.path.exists('/usr/bin/dpkg'):
                    packages = self._get_dpkg_packages()
                elif os.path.exists('/usr/bin/rpm'):
                    packages = self._get_rpm_packages()
                else:
                    packages = []
                
                # Check for known vulnerable packages (simplified example)
                vulnerable_patterns = [
                    r'openssh.*[0-6]\.[0-9]',  # Old SSH versions
                    r'openssl.*1\.0\.[0-1]',   # Old OpenSSL versions
                    r'apache2.*2\.[0-2]\.',    # Old Apache versions
                ]
                
                for package in packages:
                    for pattern in vulnerable_patterns:
                        if re.match(pattern, package):
                            finding = {
                                'id': f'vulnerable_package_{hashlib.md5(package.encode()).hexdigest()[:8]}',
                                'title': f'Potentially Vulnerable Package: {package}',
                                'description': f'Package {package} may contain known vulnerabilities',
                                'severity': 'medium',
                                'confidence': 0.6,
                                'target': 'localhost',
                                'plugin_source': 'LocalSecurityChecker',
                                'metadata': {'package': package},
                                'solution': f'Update {package} to the latest version',
                                'references': ['https://cve.mitre.org/']
                            }
                            findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Error checking installed packages: {str(e)}")
        
        return findings
    
    def check_kernel_security(self) -> List[Dict[str, Any]]:
        """Check kernel security configurations"""
        findings = []
        
        self.logger.info("Checking kernel security configurations")
        
        try:
            # Check kernel version
            kernel_version = platform.release()
            
            # Simple check for very old kernels (this would need a comprehensive CVE database)
            major_version = kernel_version.split('.')[0]
            minor_version = kernel_version.split('.')[1] if len(kernel_version.split('.')) > 1 else '0'
            
            if int(major_version) < 4:  # Very old kernel
                finding = {
                    'id': 'old_kernel_version',
                    'title': f'Outdated Kernel Version: {kernel_version}',
                    'description': f'Running potentially vulnerable kernel version {kernel_version}',
                    'severity': 'high',
                    'confidence': 0.7,
                    'target': 'localhost',
                    'plugin_source': 'LocalSecurityChecker',
                    'metadata': {'kernel_version': kernel_version},
                    'solution': 'Update to a supported kernel version with latest security patches',
                    'references': ['https://www.kernel.org/']
                }
                findings.append(finding)
            
            # Check kernel security features
            self._check_kernel_hardening_features(findings)
        
        except Exception as e:
            self.logger.error(f"Error checking kernel security: {str(e)}")
        
        return findings
    
    def check_system_hardening(self) -> List[Dict[str, Any]]:
        """Check overall system hardening status"""
        findings = []
        
        self.logger.info("Checking system hardening configurations")
        
        # Check firewall status
        firewall_active = self._check_firewall_status()
        if not firewall_active:
            finding = {
                'id': 'firewall_disabled',
                'title': 'Firewall Disabled',
                'description': 'System firewall is not active',
                'severity': 'medium',
                'confidence': 0.9,
                'target': 'localhost',
                'plugin_source': 'LocalSecurityChecker',
                'metadata': {'firewall_status': 'disabled'},
                'solution': 'Enable and configure system firewall',
                'references': ['https://www.cisecurity.org/']
            }
            findings.append(finding)
        
        # Check for security updates
        security_updates = self._check_security_updates()
        if security_updates:
            finding = {
                'id': 'pending_security_updates',
                'title': 'Pending Security Updates',
                'description': f'{len(security_updates)} security updates available',
                'severity': 'medium',
                'confidence': 0.8,
                'target': 'localhost',
                'plugin_source': 'LocalSecurityChecker',
                'metadata': {'update_count': len(security_updates)},
                'solution': 'Install pending security updates',
                'references': ['https://www.cisecurity.org/']
            }
            findings.append(finding)
        
        return findings
    
    # Helper methods
    
    def _is_overly_permissive(self, file_path: str, stat_info) -> bool:
        """Check if file permissions are overly permissive"""
        mode = stat_info.st_mode
        
        # Check for world-writable files
        if mode & stat.S_IWOTH:
            return True
        
        # Check specific sensitive files
        if '/etc/shadow' in file_path and (mode & 0o077):
            return True
        
        if '.ssh/id_rsa' in file_path and (mode & 0o077):
            return True
        
        return False
    
    def _get_privileged_users(self) -> List[str]:
        """Get list of users with root privileges"""
        privileged_users = []
        
        try:
            # Check /etc/passwd for UID 0
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 3 and parts[2] == '0':
                        privileged_users.append(parts[0])
            
            # Check sudoers
            if os.path.exists('/etc/sudoers'):
                with open('/etc/sudoers', 'r') as f:
                    content = f.read()
                    # Simple regex to find sudo users (this could be improved)
                    sudo_users = re.findall(r'^(\w+)\s+ALL=', content, re.MULTILINE)
                    privileged_users.extend(sudo_users)
        
        except (FileNotFoundError, PermissionError):
            pass
        
        return list(set(privileged_users))
    
    def _get_active_services(self) -> List[str]:
        """Get list of active services"""
        active_services = []
        
        try:
            if os.path.exists('/bin/systemctl'):
                result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=active'], 
                                      capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if '.service' in line:
                        service_name = line.split('.service')[0].split()[-1]
                        active_services.append(service_name)
            
        except Exception as e:
            self.logger.warning(f"Could not get active services: {str(e)}")
        
        return active_services
    
    def _find_suid_files(self) -> List[str]:
        """Find SUID and SGID files"""
        suid_files = []
        
        try:
            # Use find command to locate SUID/SGID files
            result = subprocess.run(['find', '/', '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', '2>/dev/null'], 
                                  capture_output=True, text=True, shell=True)
            suid_files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
        
        except Exception as e:
            self.logger.warning(f"Could not find SUID files: {str(e)}")
        
        return suid_files
    
    def _identify_suspicious_suid(self, suid_files: List[str]) -> List[str]:
        """Identify potentially suspicious SUID binaries"""
        # Known good SUID binaries (this list should be comprehensive)
        known_good = [
            '/usr/bin/passwd', '/usr/bin/gpasswd', '/usr/bin/chsh', '/usr/bin/chfn',
            '/usr/bin/newgrp', '/usr/bin/su', '/usr/bin/sudo', '/bin/mount', '/bin/umount',
            '/usr/bin/pkexec'
        ]
        
        suspicious = []
        for suid_file in suid_files:
            if suid_file not in known_good:
                suspicious.append(suid_file)
        
        return suspicious
    
    def _find_world_writable_files(self) -> List[str]:
        """Find world-writable files"""
        world_writable = []
        
        try:
            result = subprocess.run(['find', '/', '-type', 'f', '-perm', '-002', '2>/dev/null'], 
                                  capture_output=True, text=True, shell=True)
            world_writable = [f.strip() for f in result.stdout.split('\n') if f.strip()]
        
        except Exception as e:
            self.logger.warning(f"Could not find world-writable files: {str(e)}")
        
        return world_writable
    
    def _check_cron_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Check individual cron file for vulnerabilities"""
        findings = []
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Check for potentially dangerous cron jobs
            dangerous_patterns = [
                r'chmod.*777',
                r'rm\s+-rf\s+/',
                r'curl.*\|\s*sh',
                r'wget.*\|\s*sh'
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, content):
                    finding = {
                        'id': f'dangerous_cron_{hashlib.md5(file_path.encode()).hexdigest()[:8]}',
                        'title': f'Potentially Dangerous Cron Job: {file_path}',
                        'description': f'Cron file {file_path} contains potentially dangerous commands',
                        'severity': 'high',
                        'confidence': 0.8,
                        'target': 'localhost',
                        'plugin_source': 'LocalSecurityChecker',
                        'metadata': {'cron_file': file_path, 'pattern': pattern},
                        'solution': f'Review and secure cron job in {file_path}',
                        'references': ['https://www.cyberciti.biz/faq/how-do-i-add-jobs-to-cron-under-linux-or-unix-oses/']
                    }
                    findings.append(finding)
        
        except (IOError, PermissionError) as e:
            self.logger.warning(f"Could not check cron file {file_path}: {str(e)}")
        
        return findings
    
    def _get_dpkg_packages(self) -> List[str]:
        """Get installed packages using dpkg"""
        packages = []
        
        try:
            result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if line.startswith('ii '):
                    parts = line.split()
                    if len(parts) >= 3:
                        packages.append(f"{parts[1]} {parts[2]}")
        
        except Exception as e:
            self.logger.warning(f"Could not get dpkg packages: {str(e)}")
        
        return packages
    
    def _get_rpm_packages(self) -> List[str]:
        """Get installed packages using rpm"""
        packages = []
        
        try:
            result = subprocess.run(['rpm', '-qa'], capture_output=True, text=True)
            packages = [p.strip() for p in result.stdout.split('\n') if p.strip()]
        
        except Exception as e:
            self.logger.warning(f"Could not get rpm packages: {str(e)}")
        
        return packages
    
    def _check_kernel_hardening_features(self, findings: List[Dict[str, Any]]):
        """Check for kernel hardening features"""
        try:
            # Check for ASLR
            with open('/proc/sys/kernel/randomize_va_space', 'r') as f:
                aslr_value = f.read().strip()
                if aslr_value != '2':
                    finding = {
                        'id': 'aslr_disabled',
                        'title': 'ASLR Not Fully Enabled',
                        'description': f'Address Space Layout Randomization is set to {aslr_value} (should be 2)',
                        'severity': 'medium',
                        'confidence': 0.9,
                        'target': 'localhost',
                        'plugin_source': 'LocalSecurityChecker',
                        'metadata': {'aslr_value': aslr_value},
                        'solution': 'Enable full ASLR by setting kernel.randomize_va_space = 2',
                        'references': ['https://www.kernel.org/doc/Documentation/sysctl/kernel.txt']
                    }
                    findings.append(finding)
        
        except (FileNotFoundError, PermissionError):
            pass
    
    def _check_firewall_status(self) -> bool:
        """Check if firewall is active"""
        try:
            # Check ufw
            if os.path.exists('/usr/sbin/ufw'):
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                return 'Status: active' in result.stdout
            
            # Check iptables
            if os.path.exists('/sbin/iptables'):
                result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
                return len(result.stdout.split('\n')) > 10  # Simple heuristic
            
        except Exception:
            pass
        
        return False
    
    def _check_security_updates(self) -> List[str]:
        """Check for available security updates"""
        updates = []
        
        try:
            # Check with apt
            if os.path.exists('/usr/bin/apt'):
                result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True)
                security_lines = [line for line in result.stdout.split('\n') if 'security' in line.lower()]
                updates = [line.split()[0] for line in security_lines]
            
        except Exception as e:
            self.logger.warning(f"Could not check security updates: {str(e)}")
        
        return updates

if __name__ == "__main__":
    # Test the local security checker
    config = {'local_checks': {}}
    checker = LocalSecurityChecker(config)
    
    findings = checker.check_all()
    
    print(f"Found {len(findings)} security issues:")
    for finding in findings:
        print(f"- {finding['title']} [{finding['severity'].upper()}]")
        print(f"  {finding['description']}")
        print()
