"""
VulnSleuth Utilities
Common utility functions and helpers

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import os
import sys
import logging
import json
import yaml
import configparser
import hashlib
import uuid
import time
import socket
import ipaddress
import re
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path
import threading
from dataclasses import dataclass, asdict
import tempfile
import shutil
import platform

logger = logging.getLogger(__name__)

@dataclass
class NetworkTarget:
    ip: str
    hostname: Optional[str] = None
    ports: List[int] = None
    
    def __post_init__(self):
        if self.ports is None:
            self.ports = []

class ConfigManager:
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config_data = {}
        self.logger = logging.getLogger('ConfigManager')
        
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file"""
        if not os.path.exists(self.config_path):
            self.logger.warning(f"Configuration file not found: {self.config_path}")
            return
        
        try:
            file_ext = Path(self.config_path).suffix.lower()
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                if file_ext in ['.yml', '.yaml']:
                    self.config_data = yaml.safe_load(f) or {}
                elif file_ext == '.json':
                    self.config_data = json.load(f)
                elif file_ext in ['.ini', '.cfg']:
                    parser = configparser.ConfigParser()
                    parser.read(self.config_path)
                    self.config_data = {section: dict(parser[section]) for section in parser.sections()}
                else:
                    raise ValueError(f"Unsupported config format: {file_ext}")
            
            self.logger.info(f"Configuration loaded from: {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {str(e)}")
            self.config_data = {}
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value with dot notation support"""
        keys = key.split('.')
        value = self.config_data
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """Set configuration value with dot notation support"""
        keys = key.split('.')
        target = self.config_data
        
        for k in keys[:-1]:
            if k not in target or not isinstance(target[k], dict):
                target[k] = {}
            target = target[k]
        
        target[keys[-1]] = value
    
    def save(self, backup: bool = True):
        """Save configuration to file"""
        if backup and os.path.exists(self.config_path):
            backup_path = f"{self.config_path}.backup.{int(time.time())}"
            shutil.copy2(self.config_path, backup_path)
            self.logger.info(f"Configuration backup created: {backup_path}")
        
        try:
            file_ext = Path(self.config_path).suffix.lower()
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                if file_ext in ['.yml', '.yaml']:
                    yaml.dump(self.config_data, f, default_flow_style=False)
                elif file_ext == '.json':
                    json.dump(self.config_data, f, indent=2)
                elif file_ext in ['.ini', '.cfg']:
                    parser = configparser.ConfigParser()
                    for section, options in self.config_data.items():
                        parser.add_section(section)
                        for option, value in options.items():
                            parser.set(section, option, str(value))
                    parser.write(f)
            
            self.logger.info(f"Configuration saved to: {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {str(e)}")
            raise
    
    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary"""
        return self.config_data.copy()

class Logger:
    """
    Advanced logging utility with multiple handlers and formatters
    """
    
    @staticmethod
    def setup_logging(config: Dict[str, Any]):
        """Setup comprehensive logging configuration"""
        log_config = config.get('logging', {})
        
        # Log level
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        
        # Create logger
        logger = logging.getLogger()
        logger.setLevel(log_level)
        
        # Remove existing handlers
        logger.handlers.clear()
        
        # Console handler
        if log_config.get('console_enabled', True):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(log_level)
            
            console_format = log_config.get('console_format', 
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            console_formatter = logging.Formatter(console_format)
            console_handler.setFormatter(console_formatter)
            
            logger.addHandler(console_handler)
        
        # File handler
        if log_config.get('file_enabled', True):
            log_dir = log_config.get('log_dir', 'logs')
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, log_config.get('log_file', 'vulnsleuth.log'))
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            
            file_format = log_config.get('file_format',
                '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s')
            file_formatter = logging.Formatter(file_format)
            file_handler.setFormatter(file_formatter)
            
            logger.addHandler(file_handler)
        
        # Rotating file handler for large logs
        if log_config.get('rotating_enabled', False):
            from logging.handlers import RotatingFileHandler
            
            log_dir = log_config.get('log_dir', 'logs')
            os.makedirs(log_dir, exist_ok=True)
            
            rotating_file = os.path.join(log_dir, 'vulnsleuth_rotating.log')
            max_bytes = log_config.get('max_log_size_mb', 10) * 1024 * 1024
            backup_count = log_config.get('log_backup_count', 5)
            
            rotating_handler = RotatingFileHandler(
                rotating_file, maxBytes=max_bytes, backupCount=backup_count
            )
            rotating_handler.setLevel(log_level)
            rotating_handler.setFormatter(file_formatter)
            
            logger.addHandler(rotating_handler)
        
        logging.info("Logging system initialized")

class NetworkUtils:
    """
    Network utility functions for target validation and manipulation
    """
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_network(network: str) -> bool:
        """Validate network CIDR format"""
        try:
            ipaddress.ip_network(network, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def expand_cidr(cidr: str) -> List[str]:
        """Expand CIDR notation to list of IP addresses"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []
    
    @staticmethod
    def parse_port_range(port_range: str) -> List[int]:
        """Parse port range string to list of ports"""
        ports = []
        
        for part in port_range.split(','):
            part = part.strip()
            
            if '-' in part:
                # Range like "80-443"
                try:
                    start, end = map(int, part.split('-', 1))
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
    
    @staticmethod
    def resolve_hostname(hostname: str, timeout: int = 5) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            socket.setdefaulttimeout(timeout)
            ip = socket.gethostbyname(hostname)
            return ip
        except socket.error:
            return None
        finally:
            socket.setdefaulttimeout(None)
    
    @staticmethod
    def reverse_dns(ip: str, timeout: int = 5) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            socket.setdefaulttimeout(timeout)
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except socket.error:
            return None
        finally:
            socket.setdefaulttimeout(None)
    
    @staticmethod
    def is_port_open(ip: str, port: int, timeout: int = 3) -> bool:
        """Check if a port is open on target"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                return result == 0
        except Exception:
            return False
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local machine IP address"""
        try:
            # Connect to remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                local_ip = sock.getsockname()[0]
                return local_ip
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def parse_targets(target_input: str) -> List[NetworkTarget]:
        """
        Parse various target formats into NetworkTarget objects
        Supports: IP, hostname, CIDR, ranges, mixed formats
        """
        targets = []
        
        # Split by commas and process each target
        for target_part in target_input.split(','):
            target_part = target_part.strip()
            
            if not target_part:
                continue
            
            # Check if it's a CIDR network
            if '/' in target_part and NetworkUtils.validate_network(target_part):
                ips = NetworkUtils.expand_cidr(target_part)
                for ip in ips:
                    targets.append(NetworkTarget(ip=ip))
            
            # Check if it's an IP range like "192.168.1.1-192.168.1.10"
            elif '-' in target_part and target_part.count('.') >= 6:
                try:
                    start_ip, end_ip = target_part.split('-', 1)
                    start_ip = start_ip.strip()
                    end_ip = end_ip.strip()
                    
                    start_addr = ipaddress.IPv4Address(start_ip)
                    end_addr = ipaddress.IPv4Address(end_ip)
                    
                    current = start_addr
                    while current <= end_addr:
                        targets.append(NetworkTarget(ip=str(current)))
                        current += 1
                
                except (ValueError, ipaddress.AddressValueError):
                    # Treat as hostname if not valid IP range
                    hostname = target_part
                    ip = NetworkUtils.resolve_hostname(hostname)
                    if ip:
                        targets.append(NetworkTarget(ip=ip, hostname=hostname))
                    else:
                        targets.append(NetworkTarget(ip=hostname, hostname=hostname))
            
            # Check if it's a valid IP address
            elif NetworkUtils.validate_ip(target_part):
                hostname = NetworkUtils.reverse_dns(target_part)
                targets.append(NetworkTarget(ip=target_part, hostname=hostname))
            
            # Treat as hostname
            else:
                hostname = target_part
                ip = NetworkUtils.resolve_hostname(hostname)
                if ip:
                    targets.append(NetworkTarget(ip=ip, hostname=hostname))
                else:
                    # Add anyway, might be resolved later
                    targets.append(NetworkTarget(ip=hostname, hostname=hostname))
        
        return targets

class FileUtils:
    """
    File and directory utility functions
    """
    
    @staticmethod
    def ensure_dir(path: str):
        """Ensure directory exists, create if not"""
        os.makedirs(path, exist_ok=True)
    
    @staticmethod
    def safe_filename(filename: str) -> str:
        """Generate safe filename by removing/replacing invalid characters"""
        # Remove or replace invalid characters
        safe_chars = re.sub(r'[<>:"/\\|?*]', '_', filename)
        safe_chars = re.sub(r'[^\w\s-.]', '', safe_chars)
        safe_chars = re.sub(r'[-\s]+', '-', safe_chars)
        
        # Limit length
        return safe_chars[:100]
    
    @staticmethod
    def get_file_hash(filepath: str, algorithm: str = 'sha256') -> str:
        """Calculate file hash"""
        hash_obj = hashlib.new(algorithm)
        
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception:
            return ''
    
    @staticmethod
    def backup_file(filepath: str, backup_dir: str = None) -> str:
        """Create backup of file"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        if backup_dir is None:
            backup_dir = os.path.dirname(filepath)
        
        FileUtils.ensure_dir(backup_dir)
        
        filename = os.path.basename(filepath)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"{filename}.backup.{timestamp}"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        shutil.copy2(filepath, backup_path)
        return backup_path
    
    @staticmethod
    def cleanup_temp_files(temp_dir: str, max_age_hours: int = 24):
        """Clean up temporary files older than specified age"""
        if not os.path.exists(temp_dir):
            return
        
        cutoff_time = time.time() - (max_age_hours * 3600)
        cleaned_count = 0
        
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    if os.path.getmtime(filepath) < cutoff_time:
                        os.remove(filepath)
                        cleaned_count += 1
                except Exception:
                    continue
        
        logger.info(f"Cleaned up {cleaned_count} temporary files")

class SystemUtils:
    """
    System utility functions for platform detection and command execution
    """
    
    @staticmethod
    def get_system_info() -> Dict[str, str]:
        """Get comprehensive system information"""
        return {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'hostname': platform.node(),
            'processor': platform.processor(),
            'python_version': platform.python_version()
        }
    
    @staticmethod
    def is_root() -> bool:
        """Check if running with root/admin privileges"""
        if platform.system() == 'Windows':
            import ctypes
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        else:
            return os.geteuid() == 0
    
    @staticmethod
    def run_command(command: str, timeout: int = 30, shell: bool = True) -> Tuple[int, str, str]:
        """
        Run system command and return results
        
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            return -1, '', f'Command timed out after {timeout} seconds'
        except Exception as e:
            return -1, '', str(e)
    
    @staticmethod
    def which(command: str) -> Optional[str]:
        """Find full path of command (cross-platform which)"""
        return shutil.which(command)
    
    @staticmethod
    def get_available_memory() -> int:
        """Get available system memory in bytes"""
        try:
            if platform.system() == 'Linux':
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemAvailable:'):
                            return int(line.split()[1]) * 1024
            elif platform.system() == 'Windows':
                import psutil
                return psutil.virtual_memory().available
            else:
                # Fallback
                return 1024 * 1024 * 1024  # 1GB default
        except Exception:
            return 1024 * 1024 * 1024
    
    @staticmethod
    def get_cpu_count() -> int:
        """Get number of CPU cores"""
        return os.cpu_count() or 1

class CacheManager:
    """
    Simple in-memory cache with TTL support
    """
    
    def __init__(self, default_ttl: int = 3600):
        self.cache = {}
        self.default_ttl = default_ttl
        self.lock = threading.RLock()
    
    def get(self, key: str) -> Any:
        """Get value from cache"""
        with self.lock:
            if key in self.cache:
                value, expiry = self.cache[key]
                if time.time() < expiry:
                    return value
                else:
                    del self.cache[key]
            return None
    
    def set(self, key: str, value: Any, ttl: int = None):
        """Set value in cache with TTL"""
        if ttl is None:
            ttl = self.default_ttl
        
        with self.lock:
            expiry = time.time() + ttl
            self.cache[key] = (value, expiry)
    
    def delete(self, key: str):
        """Delete key from cache"""
        with self.lock:
            self.cache.pop(key, None)
    
    def clear(self):
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
    
    def cleanup_expired(self) -> int:
        """Remove expired cache entries"""
        current_time = time.time()
        expired_keys = []
        
        with self.lock:
            for key, (value, expiry) in self.cache.items():
                if current_time >= expiry:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.cache[key]
        
        return len(expired_keys)

class SecurityUtils:
    """
    Security-related utility functions
    """
    
    @staticmethod
    def generate_random_string(length: int = 16, charset: str = None) -> str:
        """Generate cryptographically secure random string"""
        if charset is None:
            charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        
        import secrets
        return ''.join(secrets.choice(charset) for _ in range(length))
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> Tuple[str, str]:
        """Hash password with salt"""
        if salt is None:
            salt = SecurityUtils.generate_random_string(32)
        
        # Use PBKDF2 for password hashing
        import hashlib
        pwdhash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # iterations
        )
        
        return pwdhash.hex(), salt
    
    @staticmethod
    def verify_password(password: str, hashed: str, salt: str) -> bool:
        """Verify password against hash"""
        new_hash, _ = SecurityUtils.hash_password(password, salt)
        return new_hash == hashed
    
    @staticmethod
    def sanitize_input(user_input: str, max_length: int = 1000) -> str:
        """Sanitize user input for security"""
        # Remove null bytes and limit length
        sanitized = user_input.replace('\x00', '').strip()[:max_length]
        
        # Remove potentially dangerous characters for shell commands
        dangerous_chars = ['&', '|', ';', '`', '$', '(', ')', '<', '>']
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized
    
    @staticmethod
    def validate_uuid(uuid_string: str) -> bool:
        """Validate UUID format"""
        try:
            uuid.UUID(uuid_string)
            return True
        except ValueError:
            return False

class ProgressTracker:
    """
    Progress tracking utility for long-running operations
    """
    
    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = time.time()
        self.last_update = 0
        
    def update(self, increment: int = 1):
        """Update progress"""
        self.current = min(self.current + increment, self.total)
        current_time = time.time()
        
        # Update every second or on completion
        if current_time - self.last_update >= 1 or self.current >= self.total:
            self._display_progress()
            self.last_update = current_time
    
    def _display_progress(self):
        """Display progress information"""
        if self.total == 0:
            percentage = 100
        else:
            percentage = (self.current / self.total) * 100
        
        elapsed = time.time() - self.start_time
        
        if self.current > 0 and elapsed > 0:
            rate = self.current / elapsed
            remaining = (self.total - self.current) / rate if rate > 0 else 0
            eta = f"ETA: {remaining:.0f}s"
        else:
            eta = "ETA: --:--"
        
        logger.info(f"{self.description}: {self.current}/{self.total} ({percentage:.1f}%) - {eta}")
    
    def is_complete(self) -> bool:
        """Check if progress is complete"""
        return self.current >= self.total

# Global cache instance
cache = CacheManager()

if __name__ == "__main__":
    # Test utilities
    
    # Test network utilities
    print("Testing Network Utils:")
    targets = NetworkUtils.parse_targets("192.168.1.1-192.168.1.3,google.com,10.0.0.0/30")
    for target in targets:
        print(f"  Target: {target.ip} ({target.hostname})")
    
    ports = NetworkUtils.parse_port_range("80,443,8080-8090")
    print(f"  Parsed ports: {ports}")
    
    # Test system info
    print("\nSystem Info:")
    sys_info = SystemUtils.get_system_info()
    for key, value in sys_info.items():
        print(f"  {key}: {value}")
    
    print(f"  Is root: {SystemUtils.is_root()}")
    print(f"  CPU count: {SystemUtils.get_cpu_count()}")
    
    # Test config manager
    print("\nTesting Config Manager:")
    config_data = {
        'database': {'host': 'localhost', 'port': 5432},
        'logging': {'level': 'INFO'}
    }
    
    config_file = 'test_config.yaml'
    with open(config_file, 'w') as f:
        yaml.dump(config_data, f)
    
    config = ConfigManager(config_file)
    print(f"  Database host: {config.get('database.host')}")
    print(f"  Log level: {config.get('logging.level')}")
    
    # Cleanup
    os.remove(config_file)


class ThreadSafeLogger:
    """Thread-safe logging utility"""
    
    def __init__(self, name: str = __name__, level: str = 'INFO'):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        self._lock = threading.Lock()
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def debug(self, message: str):
        with self._lock:
            self.logger.debug(message)
    
    def info(self, message: str):
        with self._lock:
            self.logger.info(message)
    
    def warning(self, message: str):
        with self._lock:
            self.logger.warning(message)
    
    def error(self, message: str):
        with self._lock:
            self.logger.error(message)
    
    def critical(self, message: str):
        with self._lock:
            self.logger.critical(message)


@dataclass
class SecurityContext:
    """Security context for scan operations"""
    user_id: Optional[str] = None
    permissions: List[str] = None
    scan_level: str = 'standard'
    rate_limit: int = 10
    timeout: int = 30
    
    def __post_init__(self):
        if self.permissions is None:
            self.permissions = ['scan:basic']
    
    def has_permission(self, permission: str) -> bool:
        """Check if context has specific permission"""
        return permission in self.permissions
    
    def can_scan_target(self, target: str) -> bool:
        """Check if context can scan specific target"""
        # Add target-specific permission logic here
        return 'scan:network' in self.permissions


@dataclass
class ScanMetrics:
    """Metrics tracking for scan operations"""
    start_time: datetime = None
    end_time: datetime = None
    targets_scanned: int = 0
    vulnerabilities_found: int = 0
    errors_encountered: int = 0
    plugins_executed: int = 0
    
    def __post_init__(self):
        if self.start_time is None:
            self.start_time = datetime.now()
    
    def finish(self):
        """Mark scan as finished"""
        self.end_time = datetime.now()
    
    @property
    def duration(self) -> timedelta:
        """Get scan duration"""
        end = self.end_time or datetime.now()
        return end - self.start_time
    
    @property
    def duration_seconds(self) -> float:
        """Get scan duration in seconds"""
        return self.duration.total_seconds()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary"""
        return {
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.duration_seconds,
            'targets_scanned': self.targets_scanned,
            'vulnerabilities_found': self.vulnerabilities_found,
            'errors_encountered': self.errors_encountered,
            'plugins_executed': self.plugins_executed
        }


def load_config(config_path: str = 'vulnsluth.cfg') -> Dict[str, Any]:
    """
    Load configuration from file
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    if not os.path.exists(config_path):
        logger.warning(f"Configuration file {config_path} not found, using defaults")
        return get_default_config()
    
    try:
        config_manager = ConfigManager(config_path)
        return config_manager.to_dict()
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        return get_default_config()


def get_default_config() -> Dict[str, Any]:
    """
    Get default configuration
    
    Returns:
        Default configuration dictionary
    """
    return {
        'database': {
            'path': 'vulnsleuth.db',
            'backup_enabled': True,
            'backup_interval': 24
        },
        'logging': {
            'level': 'INFO',
            'file': 'vulnsleuth.log',
            'max_size': 10485760,
            'backup_count': 5
        },
        'scanning': {
            'max_threads': 10,
            'timeout': 30,
            'retry_attempts': 3,
            'rate_limit': 10
        },
        'nmap': {
            'path': 'nmap',
            'arguments': '-sV -sC --script vuln',
            'timeout': 300
        },
        'cve_lookup': {
            'api_key': '',
            'cache_enabled': True,
            'cache_ttl': 86400
        },
        'reporting': {
            'output_dir': 'reports',
            'formats': ['html', 'json'],
            'include_charts': True
        },
        'remediation': {
            'enabled': False,
            'approval_required': True,
            'backup_before_fix': True
        },
        'web': {
            'host': '127.0.0.1',
            'port': 8080,
            'secret_key': 'change-this-secret-key',
            'session_timeout': 3600
        }
    }


def validate_target(target: str) -> bool:
    """
    Validate if a target is in acceptable format
    
    Args:
        target: Target to validate (IP, hostname, CIDR, etc.)
        
    Returns:
        True if target is valid, False otherwise
    """
    if not target or not isinstance(target, str):
        return False
    
    target = target.strip()
    if not target:
        return False
    
    # Check for CIDR notation
    if '/' in target:
        return NetworkUtils.validate_network(target)
    
    # Check for IP range notation (192.168.1.1-192.168.1.10)
    if '-' in target and target.count('.') >= 6:
        try:
            start_ip, end_ip = target.split('-', 1)
            return NetworkUtils.validate_ip(start_ip.strip()) and NetworkUtils.validate_ip(end_ip.strip())
        except ValueError:
            pass
    
    # Check for single IP
    if NetworkUtils.validate_ip(target):
        return True
    
    # Check for hostname/FQDN
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', target):
        return True
    
    return False


def setup_logging(config: Dict[str, Any] = None):
    """
    Setup logging configuration
    
    Args:
        config: Configuration dictionary
    """
    if config is None:
        config = get_default_config()
    
    Logger.setup_logging(config)
