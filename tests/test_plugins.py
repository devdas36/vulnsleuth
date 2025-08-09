"""
Test cases for VulnSleuth plugin system

Tests plugin functionality including:
- Plugin loading and management
- Plugin execution
- Plugin metadata validation
- Custom plugin development
"""

import unittest
import os
import tempfile
from unittest.mock import Mock, patch
from conftest import VulnSleuthTestCase


class TestPluginSystem(VulnSleuthTestCase):
    """Test cases for the plugin system"""
    
    def setUp(self):
        """Set up test environment"""
        super().setUp()
    
    def test_vulnerability_finding_creation(self):
        """Test VulnerabilityFinding data class"""
        from plugin import VulnerabilityFinding
        
        finding = VulnerabilityFinding(
            title="Test Vulnerability",
            description="Test description",
            severity="high",
            cvss_score=7.5,
            solution="Test solution",
            references=["https://example.com"],
            evidence={"test": True}
        )
        
        self.assertEqual(finding.title, "Test Vulnerability")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.cvss_score, 7.5)
        self.assertIn("test", finding.evidence)
    
    def test_plugin_metadata_creation(self):
        """Test PluginMetadata data class"""
        from plugin import PluginMetadata
        
        metadata = PluginMetadata(
            name="Test Plugin",
            version="1.0.0",
            author="Test Author",
            description="Test plugin description",
            category="network",
            tags=["test", "network"]
        )
        
        self.assertEqual(metadata.name, "Test Plugin")
        self.assertEqual(metadata.category, "network")
        self.assertIn("test", metadata.tags)
    
    def test_base_plugin_interface(self):
        """Test VulnPlugin base class interface"""
        from plugin import VulnPlugin, PluginMetadata
        
        class TestPlugin(VulnPlugin):
            def __init__(self):
                super().__init__()
                self.metadata = PluginMetadata(
                    name="Test Plugin",
                    version="1.0.0",
                    author="Test",
                    description="Test",
                    category="test"
                )
            
            def can_run(self, target, context):
                return True
            
            def execute(self, target, context):
                return []
            
            def cleanup(self):
                pass
        
        plugin = TestPlugin()
        self.assertEqual(plugin.metadata.name, "Test Plugin")
        self.assertTrue(plugin.can_run("test", {}))
        self.assertEqual(len(plugin.execute("test", {})), 0)
    
    def test_plugin_manager_initialization(self):
        """Test PluginManager initialization"""
        from plugin import PluginManager
        
        # Create temporary plugin directory
        plugin_dir = tempfile.mkdtemp()
        
        manager = PluginManager(plugin_dir)
        self.assertIsNotNone(manager)
        self.assertEqual(manager.plugin_directory, plugin_dir)
    
    @patch('importlib.util.spec_from_file_location')
    @patch('importlib.util.module_from_spec')
    def test_plugin_loading(self, mock_module_from_spec, mock_spec_from_file):
        """Test plugin loading functionality"""
        from plugin import PluginManager, VulnPlugin, PluginMetadata
        
        # Create mock plugin
        class MockPlugin(VulnPlugin):
            def __init__(self):
                super().__init__()
                self.metadata = PluginMetadata(
                    name="Mock Plugin",
                    version="1.0.0",
                    author="Test",
                    description="Mock plugin",
                    category="test"
                )
            
            def can_run(self, target, context):
                return True
            
            def execute(self, target, context):
                return [self.create_mock_vulnerability()]
            
            def cleanup(self):
                pass
        
        # Setup mocks
        mock_module = Mock()
        mock_module.get_plugin.return_value = MockPlugin()
        mock_module_from_spec.return_value = mock_module
        mock_spec_from_file.return_value = Mock()
        
        # Create plugin directory with mock plugin file
        plugin_dir = tempfile.mkdtemp()
        plugin_file = os.path.join(plugin_dir, "mock_plugin.py")
        
        with open(plugin_file, 'w') as f:
            f.write("# Mock plugin file")
        
        manager = PluginManager(plugin_dir)
        manager.load_plugins()
        
        plugins = manager.get_plugins()
        self.assertGreater(len(plugins), 0)
    
    def test_plugin_filtering_by_category(self):
        """Test plugin filtering by category"""
        from plugin import PluginManager, VulnPlugin, PluginMetadata
        
        # Create mock plugins with different categories
        class NetworkPlugin(VulnPlugin):
            def __init__(self):
                super().__init__()
                self.metadata = PluginMetadata(
                    name="Network Plugin",
                    version="1.0.0",
                    author="Test",
                    description="Network plugin",
                    category="network"
                )
            
            def can_run(self, target, context):
                return True
            
            def execute(self, target, context):
                return []
        
        class WebPlugin(VulnPlugin):
            def __init__(self):
                super().__init__()
                self.metadata = PluginMetadata(
                    name="Web Plugin",
                    version="1.0.0",
                    author="Test",
                    description="Web plugin",
                    category="web"
                )
            
            def can_run(self, target, context):
                return True
            
            def execute(self, target, context):
                return []
        
        manager = PluginManager(tempfile.mkdtemp())
        manager.plugins = [NetworkPlugin(), WebPlugin()]
        
        # Filter by category
        network_plugins = manager.get_plugins_by_category("network")
        web_plugins = manager.get_plugins_by_category("web")
        
        self.assertEqual(len(network_plugins), 1)
        self.assertEqual(len(web_plugins), 1)
        self.assertEqual(network_plugins[0].metadata.category, "network")
        self.assertEqual(web_plugins[0].metadata.category, "web")
    
    def test_plugin_execution_context(self):
        """Test plugin execution with context"""
        from plugin import VulnPlugin, PluginMetadata, VulnerabilityFinding
        
        class ContextPlugin(VulnPlugin):
            def __init__(self):
                super().__init__()
                self.metadata = PluginMetadata(
                    name="Context Plugin",
                    version="1.0.0",
                    author="Test",
                    description="Context-aware plugin",
                    category="test"
                )
            
            def can_run(self, target, context):
                return context.get('enable_test', False)
            
            def execute(self, target, context):
                timeout = context.get('timeout', 5)
                return [VulnerabilityFinding(
                    title="Context Test",
                    description=f"Executed with timeout {timeout}",
                    severity="low",
                    cvss_score=2.0,
                    solution="No action needed"
                )]
        
        plugin = ContextPlugin()
        
        # Test can_run with different contexts
        self.assertFalse(plugin.can_run("test", {}))
        self.assertTrue(plugin.can_run("test", {'enable_test': True}))
        
        # Test execute with context
        context = {'enable_test': True, 'timeout': 10}
        findings = plugin.execute("test", context)
        
        self.assertEqual(len(findings), 1)
        self.assertIn("timeout 10", findings[0].description)
    
    def test_plugin_error_handling(self):
        """Test plugin error handling"""
        from plugin import VulnPlugin, PluginMetadata
        
        class FailingPlugin(VulnPlugin):
            def __init__(self):
                super().__init__()
                self.metadata = PluginMetadata(
                    name="Failing Plugin",
                    version="1.0.0",
                    author="Test",
                    description="Plugin that fails",
                    category="test"
                )
            
            def can_run(self, target, context):
                return True
            
            def execute(self, target, context):
                raise Exception("Plugin execution failed")
            
            def cleanup(self):
                pass
        
        plugin = FailingPlugin()
        
        # Should raise exception (handling is done at engine level)
        with self.assertRaises(Exception):
            plugin.execute("test", {})


class TestBuiltinPlugins(VulnSleuthTestCase):
    """Test built-in plugins functionality"""
    
    def test_local_system_checker(self):
        """Test LocalSystemChecker plugin"""
        try:
            from checks.local_checks import LocalSystemChecker
            
            checker = LocalSystemChecker()
            self.assertIsNotNone(checker.metadata)
            self.assertEqual(checker.metadata.category, "local")
            
            # Test can_run (should work on localhost)
            can_run = checker.can_run("localhost", {})
            self.assertTrue(can_run)
            
        except ImportError:
            self.skipTest("LocalSystemChecker not available")
    
    def test_network_scanner(self):
        """Test NetworkScanner plugin"""
        try:
            from checks.network_checks import NetworkScanner
            
            scanner = NetworkScanner()
            self.assertIsNotNone(scanner.metadata)
            self.assertEqual(scanner.metadata.category, "network")
            
        except ImportError:
            self.skipTest("NetworkScanner not available")
    
    def test_web_application_scanner(self):
        """Test WebApplicationScanner plugin"""
        try:
            from checks.web_checks import WebApplicationScanner
            
            scanner = WebApplicationScanner()
            self.assertIsNotNone(scanner.metadata)
            self.assertEqual(scanner.metadata.category, "web")
            
        except ImportError:
            self.skipTest("WebApplicationScanner not available")


class TestPluginDevelopment(VulnSleuthTestCase):
    """Test custom plugin development utilities"""
    
    def test_plugin_template_structure(self):
        """Test plugin template structure requirements"""
        # A valid plugin should have these required methods
        required_methods = ['can_run', 'execute', 'cleanup']
        
        from plugin import VulnPlugin
        
        for method in required_methods:
            self.assertTrue(hasattr(VulnPlugin, method))
    
    def test_plugin_metadata_validation(self):
        """Test plugin metadata validation"""
        from plugin import PluginMetadata
        
        # Valid metadata
        metadata = PluginMetadata(
            name="Test Plugin",
            version="1.0.0",
            author="Test Author",
            description="Test description",
            category="test"
        )
        
        self.assertIsNotNone(metadata.name)
        self.assertIsNotNone(metadata.version)
        self.assertIsNotNone(metadata.category)
    
    def test_finding_severity_validation(self):
        """Test vulnerability finding severity validation"""
        from plugin import VulnerabilityFinding
        
        valid_severities = ["critical", "high", "medium", "low", "info"]
        
        for severity in valid_severities:
            finding = VulnerabilityFinding(
                title="Test",
                description="Test",
                severity=severity,
                cvss_score=5.0,
                solution="Test"
            )
            self.assertEqual(finding.severity, severity)


if __name__ == '__main__':
    unittest.main()
