"""
VulnSleuth Plugin System
Extensible plugin architecture for custom vulnerability checks

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import os
import sys
import importlib.util
import inspect
import json
import threading
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Type
from dataclasses import dataclass
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class PluginMetadata:
    name: str
    version: str
    author: str
    description: str
    category: str = "general"
    tags: List[str] = None
    enabled: bool = True
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []

@dataclass
class VulnerabilityFinding:
    """Standard vulnerability finding structure"""
    id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    confidence: float  # 0.0 to 1.0
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    solution: Optional[str] = None
    references: List[str] = None
    cve_ids: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.cve_ids is None:
            self.cve_ids = []
        if self.metadata is None:
            self.metadata = {}

@dataclass
class PluginMetadata:
    """Plugin metadata structure"""
    name: str
    version: str
    author: str
    description: str
    category: str = "general"
    tags: List[str] = None
    enabled: bool = True
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []

class VulnPlugin(ABC):
    """
    Base class for VulnSleuth plugins
    
    All custom vulnerability scanning plugins should inherit from this class
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.plugin_config = self.config.get('plugins', {})
        self.logger = logging.getLogger(f"plugin.{self.__class__.__name__}")
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.description = "Custom vulnerability plugin"
        self.author = "Unknown"
        self.category = "general"
        self.enabled = True
        self.metadata = None  # Can be set by subclasses
        
    def can_run(self, target: str, context: Dict[str, Any] = None) -> bool:
        """
        Check if this plugin can run against the target
        
        Args:
            target: Target to scan
            context: Scan context information
            
        Returns:
            True if plugin can run, False otherwise
        """
        return self.enabled
        
    @abstractmethod
    def check(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """
        Main vulnerability check method
        
        Args:
            target: Target to scan (IP, domain, etc.)
            **kwargs: Additional scan parameters
            
        Returns:
            List of vulnerability findings
        """
        pass
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': self.author,
            'category': self.category,
            'enabled': self.enabled
        }
    
    def create_finding(self, title: str, severity: str, description: str, 
                      target: str, confidence: float = 1.0, **kwargs) -> VulnerabilityFinding:
        """
        Helper method to create standardized vulnerability findings
        
        Args:
            title: Vulnerability title
            severity: Severity level (critical, high, medium, low, info)
            description: Detailed description
            target: Target system
            confidence: Confidence level (0.0 to 1.0)
            **kwargs: Additional parameters for the finding
            
        Returns:
            VulnerabilityFinding object
        """
        finding_id = f"{self.name}_{int(time.time() * 1000)}"
        
        return VulnerabilityFinding(
            id=finding_id,
            title=title,
            description=description,
            severity=severity.lower(),
            confidence=confidence,
            target=target,
            port=kwargs.get('port'),
            service=kwargs.get('service'),
            solution=kwargs.get('solution'),
            references=kwargs.get('references', []),
            cve_ids=kwargs.get('cve_ids', []),
            metadata=kwargs.get('metadata', {})
        )
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is appropriate for this plugin"""
        return True
    
    def pre_check(self, target: str, **kwargs) -> bool:
        """Pre-check validation before running main check"""
        return self.validate_target(target)
    
    def post_check(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Post-processing of findings"""
        return findings

class NetworkPlugin(VulnPlugin):
    """Base class for network-based plugins"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.category = "network"
    
    def validate_target(self, target: str) -> bool:
        """Validate target is a valid network address"""
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            # Could be a hostname
            return '.' in target or target == 'localhost'

class WebPlugin(VulnPlugin):
    """Base class for web application plugins"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.category = "web"
    
    def validate_target(self, target: str) -> bool:
        """Validate target is a valid web URL"""
        return target.startswith(('http://', 'https://')) or self._is_web_target(target)
    
    def _is_web_target(self, target: str) -> bool:
        """Check if target likely serves web content"""
        common_web_ports = [80, 443, 8080, 8443, 3000, 5000]
        # This is a simplified check - could be enhanced
        return ':' in target and any(str(port) in target for port in common_web_ports)

class LocalPlugin(VulnPlugin):
    """Base class for local system plugins"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.category = "local"
    
    def validate_target(self, target: str) -> bool:
        """Validate target is localhost"""
        return target in ['localhost', '127.0.0.1', '::1']

class PluginManager:
    """
    Plugin management system for VulnSleuth
    
    Handles loading, executing, and managing vulnerability scanning plugins
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.plugin_config = config.get('plugins', {})
        self.plugin_dir = self.plugin_config.get('plugin_dir', 'plugins')
        self.logger = logging.getLogger('PluginManager')
        
        # Plugin storage
        self.loaded_plugins: Dict[str, VulnPlugin] = {}
        self.plugin_metadata: Dict[str, Dict[str, Any]] = {}
        self.plugin_errors: Dict[str, str] = {}
        
        # Thread safety
        self.lock = threading.RLock()
        
        # Load plugins
        self._load_all_plugins()
    
    def _load_all_plugins(self):
        """Load all plugins from the plugin directory"""
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir)
            self.logger.info(f"Created plugin directory: {self.plugin_dir}")
            return
        
        self.logger.info(f"Loading plugins from {self.plugin_dir}")
        
        for file_path in Path(self.plugin_dir).glob("*.py"):
            if file_path.name.startswith('__'):
                continue  # Skip __init__.py and similar
            
            plugin_name = file_path.stem
            try:
                self._load_plugin_from_file(plugin_name, str(file_path))
            except Exception as e:
                self.logger.error(f"Failed to load plugin {plugin_name}: {str(e)}")
                self.plugin_errors[plugin_name] = str(e)
    
    def _load_plugin_from_file(self, plugin_name: str, file_path: str):
        """Load a single plugin from file"""
        spec = importlib.util.spec_from_file_location(plugin_name, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load spec for {plugin_name}")
        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Find plugin classes in the module
        plugin_classes = []
        for name, obj in inspect.getmembers(module):
            if (inspect.isclass(obj) and 
                issubclass(obj, VulnPlugin) and 
                obj != VulnPlugin and
                not inspect.isabstract(obj)):
                plugin_classes.append(obj)
        
        if not plugin_classes:
            raise ValueError(f"No valid plugin classes found in {plugin_name}")
        
        # Load each plugin class
        for plugin_class in plugin_classes:
            try:
                plugin_instance = plugin_class(self.config)
                class_name = plugin_class.__name__
                
                with self.lock:
                    self.loaded_plugins[class_name] = plugin_instance
                    self.plugin_metadata[class_name] = plugin_instance.get_info()
                
                self.logger.info(f"Loaded plugin: {class_name} v{plugin_instance.version}")
                
            except Exception as e:
                self.logger.error(f"Failed to instantiate plugin {plugin_class.__name__}: {str(e)}")
                self.plugin_errors[plugin_class.__name__] = str(e)
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all available plugins"""
        plugins = []
        
        with self.lock:
            for name, metadata in self.plugin_metadata.items():
                plugin_info = metadata.copy()
                plugin_info['loaded'] = name in self.loaded_plugins
                plugin_info['error'] = self.plugin_errors.get(name)
                plugins.append(plugin_info)
        
        return sorted(plugins, key=lambda x: x['name'])
    
    def get_plugin(self, plugin_name: str) -> Optional[VulnPlugin]:
        """Get a specific plugin by name"""
        with self.lock:
            return self.loaded_plugins.get(plugin_name)
    
    def execute_plugin(self, plugin_name: str, scan_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute a specific plugin
        
        Args:
            plugin_name: Name of the plugin to execute
            scan_config: Scan configuration parameters
            
        Returns:
            List of vulnerability findings as dictionaries
        """
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            raise ValueError(f"Plugin {plugin_name} not found or not loaded")
        
        if not plugin.enabled:
            self.logger.warning(f"Plugin {plugin_name} is disabled")
            return []
        
        target = scan_config['target']
        
        self.logger.info(f"Executing plugin {plugin_name} on target {target}")
        
        try:
            # Create a config copy without conflicting parameters
            # Remove target, timeout, threads to avoid duplicate parameter errors
            excluded_keys = {'target', 'timeout', 'threads', 'aggressive', 'user_id', 'username'}
            config_filtered = {k: v for k, v in scan_config.items() if k not in excluded_keys}
            
            # Pre-check validation
            if not plugin.pre_check(target, **config_filtered):
                self.logger.warning(f"Plugin {plugin_name} pre-check failed for target {target}")
                return []
            
            # Execute main check with timeout (ensure it's an integer, strip comments)
            timeout_val = str(self.plugin_config.get('plugin_timeout', 120)).split('#')[0].strip()
            timeout = int(timeout_val) if timeout_val else 120
            findings = self._execute_with_timeout(plugin.check, timeout, target, **config_filtered)
            
            # Post-process findings
            processed_findings = plugin.post_check(findings)
            
            # Convert to dictionaries
            result_dicts = []
            for finding in processed_findings:
                finding_dict = {
                    'id': finding.id,
                    'title': finding.title,
                    'description': finding.description,
                    'severity': finding.severity,
                    'confidence': finding.confidence,
                    'target': finding.target,
                    'port': finding.port,
                    'service': finding.service,
                    'solution': finding.solution,
                    'references': finding.references,
                    'cve_ids': finding.cve_ids,
                    'metadata': finding.metadata,
                    'plugin_source': plugin_name,
                    'plugin_category': plugin.category
                }
                result_dicts.append(finding_dict)
            
            self.logger.info(f"Plugin {plugin_name} found {len(result_dicts)} vulnerabilities")
            return result_dicts
            
        except Exception as e:
            self.logger.error(f"Plugin {plugin_name} execution failed: {str(e)}")
            return []
    
    def _execute_with_timeout(self, func, timeout: int, *args, **kwargs):
        """Execute function with timeout"""
        import concurrent.futures
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(func, *args, **kwargs)
            try:
                return future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                raise TimeoutError(f"Plugin execution timed out after {timeout} seconds")
    
    def execute_multiple_plugins(self, plugin_names: List[str], scan_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute multiple plugins in parallel"""
        all_results = []
        
        import concurrent.futures
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Submit all plugin executions
            future_to_plugin = {
                executor.submit(self.execute_plugin, name, scan_config): name 
                for name in plugin_names
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_plugin):
                plugin_name = future_to_plugin[future]
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    self.logger.error(f"Plugin {plugin_name} failed: {str(e)}")
        
        return all_results
    
    def install_plugin(self, plugin_source: str) -> bool:
        """
        Install a plugin from file path or URL
        
        Args:
            plugin_source: File path or URL to plugin
            
        Returns:
            True if installation successful
        """
        try:
            if plugin_source.startswith(('http://', 'https://')):
                # Download from URL
                import requests
                response = requests.get(plugin_source)
                response.raise_for_status()
                
                # Extract filename from URL
                filename = plugin_source.split('/')[-1]
                if not filename.endswith('.py'):
                    filename += '.py'
                
                plugin_path = os.path.join(self.plugin_dir, filename)
                with open(plugin_path, 'w') as f:
                    f.write(response.text)
            else:
                # Copy from local file
                import shutil
                filename = os.path.basename(plugin_source)
                plugin_path = os.path.join(self.plugin_dir, filename)
                shutil.copy2(plugin_source, plugin_path)
            
            # Load the new plugin
            plugin_name = os.path.splitext(filename)[0]
            self._load_plugin_from_file(plugin_name, plugin_path)
            
            self.logger.info(f"Plugin {plugin_name} installed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Plugin installation failed: {str(e)}")
            return False
    
    def remove_plugin(self, plugin_name: str) -> bool:
        """Remove a plugin"""
        try:
            with self.lock:
                # Remove from loaded plugins
                if plugin_name in self.loaded_plugins:
                    del self.loaded_plugins[plugin_name]
                if plugin_name in self.plugin_metadata:
                    del self.plugin_metadata[plugin_name]
                if plugin_name in self.plugin_errors:
                    del self.plugin_errors[plugin_name]
            
            # Remove plugin file
            plugin_file = os.path.join(self.plugin_dir, f"{plugin_name}.py")
            if os.path.exists(plugin_file):
                os.remove(plugin_file)
            
            self.logger.info(f"Plugin {plugin_name} removed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Plugin removal failed: {str(e)}")
            return False
    
    def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a plugin"""
        with self.lock:
            return self.plugin_metadata.get(plugin_name)
    
    def get_all_plugins(self) -> List[VulnPlugin]:
        """Get all loaded plugin instances"""
        with self.lock:
            return list(self.loaded_plugins.values())
    
    def reload_plugins(self):
        """Reload all plugins"""
        self.logger.info("Reloading all plugins...")
        
        with self.lock:
            self.loaded_plugins.clear()
            self.plugin_metadata.clear()
            self.plugin_errors.clear()
        
        self._load_all_plugins()
    
    def load_plugins(self) -> int:
        """
        Load/reload all plugins and return the count of successfully loaded plugins
        
        Returns:
            Number of successfully loaded plugins
        """
        self.reload_plugins()
        return len(self.loaded_plugins)

def generate_plugin_template(output_path: str):
    """Generate a template for creating new plugins"""
    
    template = '''"""
VulnSleuth Plugin Template
Custom vulnerability scanning plugin

Author: Your Name
License: MIT
"""

import sys
import os
from typing import List

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from plugin import VulnPlugin, VulnerabilityFinding
import requests
import socket

class ExamplePlugin(VulnPlugin):
    """
    Example vulnerability scanning plugin
    
    This plugin demonstrates how to create custom vulnerability checks
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "ExamplePlugin"
        self.version = "1.0.0"
        self.description = "Example plugin for demonstration"
        self.author = "Your Name"
        self.category = "network"  # network, web, local, or custom category
    
    def check(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """
        Main vulnerability check method
        
        Args:
            target: Target to scan
            **kwargs: Additional parameters from scan config
            
        Returns:
            List of VulnerabilityFinding objects
        """
        findings = []
        
        # Example check: Open port 22 (SSH)
        if self._is_port_open(target, 22):
            finding = self.create_finding(
                title="SSH Service Detected",
                severity="info",
                description=f"SSH service is running on {target}:22",
                target=target,
                port=22,
                service="ssh",
                confidence=0.9,
                solution="Ensure SSH is properly configured with key-based authentication",
                references=["https://example.com/ssh-security"]
            )
            findings.append(finding)
        
        # Example check: HTTP service banner grabbing
        http_banner = self._get_http_banner(target)
        if http_banner and "Server" in http_banner:
            server_header = http_banner["Server"]
            
            # Check for outdated server versions (simplified example)
            if "Apache/2.2" in server_header:
                finding = self.create_finding(
                    title="Outdated Apache Server",
                    severity="medium",
                    description=f"Outdated Apache server detected: {server_header}",
                    target=target,
                    port=80,
                    service="http",
                    confidence=0.8,
                    solution="Update Apache to the latest stable version",
                    cve_ids=["CVE-2017-15710", "CVE-2017-15715"]  # Example CVEs
                )
                findings.append(finding)
        
        return findings
    
    def _is_port_open(self, target: str, port: int, timeout: int = 3) -> bool:
        """Check if a port is open on the target"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _get_http_banner(self, target: str, port: int = 80, timeout: int = 5) -> dict:
        """Get HTTP response headers"""
        try:
            url = f"http://{target}:{port}"
            response = requests.head(url, timeout=timeout, allow_redirects=False)
            return dict(response.headers)
        except Exception:
            return {}
    
    def validate_target(self, target: str) -> bool:
        """Validate if this plugin can scan the target"""
        # This plugin works with IP addresses and hostnames
        return target != "localhost" or target.replace(".", "").isdigit()

# Multiple plugins can be defined in one file
class AnotherExamplePlugin(VulnPlugin):
    """Another example plugin"""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "AnotherExamplePlugin"
        self.version = "1.0.0"
        self.description = "Another example plugin"
        self.author = "Your Name"
        self.category = "web"
    
    def check(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """Example web application check"""
        findings = []
        
        # Add your custom vulnerability checks here
        
        return findings
'''
    
    with open(output_path, 'w') as f:
        f.write(template)
    
    print(f"Plugin template generated: {output_path}")
    print("Customize the template and place it in your plugins/ directory")

if __name__ == "__main__":
    # Test plugin system
    config = {'plugins': {'plugin_dir': 'plugins'}}
    manager = PluginManager(config)
    
    print("Available plugins:")
    for plugin in manager.list_plugins():
        print(f"  {plugin['name']} v{plugin['version']} - {plugin['description']}")
