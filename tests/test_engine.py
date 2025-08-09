"""
Test cases for the core VulnSleuth engine

Tests the main scanning engine functionality including:
- Scan initialization and execution
- Plugin management
- Target processing
- Result aggregation
"""

import unittest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from conftest import VulnSleuthTestCase


class TestScanEngine(VulnSleuthTestCase):
    """Test cases for the ScanEngine class"""
    
    def setUp(self):
        """Set up test environment"""
        super().setUp()
        
        # Import after setting up path
        from engine import ScanEngine
        from plugin import VulnerabilityFinding
        
        self.ScanEngine = ScanEngine
        self.VulnerabilityFinding = VulnerabilityFinding
        
        # Create engine with test config
        self.engine = ScanEngine(config=self.mock_config)
    
    def test_engine_initialization(self):
        """Test engine initializes correctly"""
        self.assertIsNotNone(self.engine)
        self.assertIsNotNone(self.engine.config)
        self.assertIsNotNone(self.engine.logger)
        self.assertEqual(self.engine.scan_results, [])
    
    @patch('engine.PluginManager')
    def test_scan_execution_with_targets(self, mock_plugin_manager):
        """Test scan execution with valid targets"""
        # Setup mock plugin manager
        mock_plugin = Mock()
        mock_plugin.can_run.return_value = True
        mock_plugin.execute.return_value = [
            self.create_mock_vulnerability()
        ]
        mock_plugin_manager.return_value.get_plugins.return_value = [mock_plugin]
        
        # Execute scan
        targets = ['192.168.1.100', '192.168.1.101']
        results = self.engine.scan_targets(targets, scan_types=['network'])
        
        # Verify results
        self.assertIsNotNone(results)
        self.assertGreater(len(results), 0)
        
        # Verify plugin was called
        mock_plugin.can_run.assert_called()
        mock_plugin.execute.assert_called()
    
    def test_scan_execution_no_targets(self):
        """Test scan behavior with no targets"""
        results = self.engine.scan_targets([], scan_types=['network'])
        self.assertEqual(len(results), 0)
    
    def test_scan_execution_invalid_targets(self):
        """Test scan behavior with invalid targets"""
        invalid_targets = ['invalid.target', '999.999.999.999']
        results = self.engine.scan_targets(invalid_targets, scan_types=['network'])
        
        # Should handle gracefully without crashing
        self.assertIsInstance(results, list)
    
    @patch('engine.PluginManager')
    def test_plugin_filtering_by_type(self, mock_plugin_manager):
        """Test that plugins are filtered by scan type"""
        # Setup mock plugins
        network_plugin = Mock()
        network_plugin.metadata.category = 'network'
        network_plugin.can_run.return_value = True
        
        web_plugin = Mock()
        web_plugin.metadata.category = 'web'
        web_plugin.can_run.return_value = True
        
        mock_plugin_manager.return_value.get_plugins.return_value = [
            network_plugin, web_plugin
        ]
        
        # Execute network scan
        targets = ['192.168.1.100']
        self.engine.scan_targets(targets, scan_types=['network'])
        
        # Only network plugin should be called
        network_plugin.can_run.assert_called()
        web_plugin.can_run.assert_not_called()
    
    def test_result_aggregation(self):
        """Test that scan results are properly aggregated"""
        # Create mock findings
        finding1 = self.create_mock_vulnerability()
        finding2 = self.create_mock_vulnerability()
        finding2.title = "Second Test Vulnerability"
        
        # Add findings to engine
        self.engine._add_findings('192.168.1.100', [finding1, finding2])
        
        # Check aggregation
        self.assertEqual(len(self.engine.scan_results), 2)
        self.assertEqual(self.engine.scan_results[0]['target'], '192.168.1.100')
    
    def test_error_handling_in_scan(self):
        """Test error handling during scan execution"""
        with patch('engine.PluginManager') as mock_plugin_manager:
            # Setup plugin that raises exception
            failing_plugin = Mock()
            failing_plugin.can_run.return_value = True
            failing_plugin.execute.side_effect = Exception("Test error")
            
            mock_plugin_manager.return_value.get_plugins.return_value = [failing_plugin]
            
            # Should not crash on plugin error
            targets = ['192.168.1.100']
            results = self.engine.scan_targets(targets, scan_types=['network'])
            
            # Should return empty results gracefully
            self.assertIsInstance(results, list)
    
    def test_concurrent_scanning(self):
        """Test concurrent execution of scans"""
        with patch('engine.PluginManager') as mock_plugin_manager:
            # Setup mock plugin with delay
            import time
            slow_plugin = Mock()
            slow_plugin.can_run.return_value = True
            slow_plugin.execute.side_effect = lambda target, context: (
                time.sleep(0.1), [self.create_mock_vulnerability()]
            )[1]
            
            mock_plugin_manager.return_value.get_plugins.return_value = [slow_plugin]
            
            # Scan multiple targets
            targets = ['192.168.1.100', '192.168.1.101', '192.168.1.102']
            start_time = time.time()
            results = self.engine.scan_targets(targets, scan_types=['network'])
            end_time = time.time()
            
            # Should complete faster than sequential execution
            # (3 targets * 0.1s delay should be < 0.3s with threading)
            self.assertLess(end_time - start_time, 0.25)
            self.assertEqual(len(results), 3)


class TestScanConfiguration(VulnSleuthTestCase):
    """Test scan configuration and options"""
    
    def setUp(self):
        """Set up test environment"""
        super().setUp()
        from engine import ScanEngine
        self.ScanEngine = ScanEngine
    
    def test_config_loading(self):
        """Test configuration loading"""
        engine = self.ScanEngine(config=self.mock_config)
        
        self.assertEqual(
            engine.config['scanning']['max_threads'],
            self.mock_config['scanning']['max_threads']
        )
    
    def test_default_config_fallback(self):
        """Test fallback to default configuration"""
        engine = self.ScanEngine()
        
        # Should have default config values
        self.assertIsNotNone(engine.config)
        self.assertIn('scanning', engine.config)
    
    def test_scan_options_processing(self):
        """Test scan options are processed correctly"""
        engine = self.ScanEngine(config=self.mock_config)
        
        # Test various scan options
        options = {
            'timeout': 10,
            'threads': 5,
            'verbose': True
        }
        
        # Should not crash with custom options
        processed_options = engine._process_scan_options(options)
        self.assertIsInstance(processed_options, dict)


if __name__ == '__main__':
    unittest.main()
