"""
Test Configuration for VulnSleuth

This file provides test configuration and common utilities
for the VulnSleuth test suite.
"""

import os
import sys
import unittest
import tempfile
import sqlite3
from unittest.mock import Mock, patch

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

class VulnSleuthTestCase(unittest.TestCase):
    """Base test case class for VulnSleuth tests"""
    
    def setUp(self):
        """Set up test environment"""
        # Create temporary directory for test data
        self.test_dir = tempfile.mkdtemp()
        self.test_db_path = os.path.join(self.test_dir, 'test_vulnsleuth.db')
        
        # Mock configuration
        self.mock_config = {
            'database': {
                'path': self.test_db_path,
                'backup_enabled': False
            },
            'logging': {
                'level': 'DEBUG',
                'file': os.path.join(self.test_dir, 'test.log')
            },
            'scanning': {
                'max_threads': 2,
                'timeout': 5,
                'retry_attempts': 1
            },
            'nmap': {
                'path': 'nmap',
                'arguments': '-sV -sC'
            }
        }
    
    def tearDown(self):
        """Clean up test environment"""
        # Clean up temporary files
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def create_test_db(self):
        """Create a test database with basic schema"""
        from db import DatabaseManager
        
        db_manager = DatabaseManager(self.test_db_path)
        db_manager.init_db()
        return db_manager
    
    def create_mock_target(self):
        """Create a mock target for testing"""
        return {
            'id': 1,
            'ip': '192.168.1.100',
            'hostname': 'test.example.com',
            'scan_id': 1
        }
    
    def create_mock_vulnerability(self):
        """Create a mock vulnerability for testing"""
        from plugin import VulnerabilityFinding
        
        return VulnerabilityFinding(
            title="Test Vulnerability",
            description="A test vulnerability for unit testing",
            severity="medium",
            cvss_score=5.0,
            solution="Fix the test vulnerability",
            references=["https://test.example.com"],
            evidence={'test': True}
        )
