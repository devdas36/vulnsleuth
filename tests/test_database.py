"""
Test cases for VulnSleuth database functionality

Tests database operations including:
- Database initialization
- CRUD operations
- Data integrity
- Query performance
"""

import unittest
import sqlite3
import os
from conftest import VulnSleuthTestCase


class TestDatabaseManager(VulnSleuthTestCase):
    """Test cases for DatabaseManager class"""
    
    def setUp(self):
        """Set up test environment"""
        super().setUp()
        
        # Create database manager
        self.db_manager = self.create_test_db()
    
    def test_database_initialization(self):
        """Test database is initialized correctly"""
        self.assertTrue(os.path.exists(self.test_db_path))
        
        # Check tables exist
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        expected_tables = [
            'scans', 'targets', 'vulnerabilities', 'scan_results',
            'cve_data', 'remediation_history', 'plugins', 'config'
        ]
        
        for table in expected_tables:
            self.assertIn(table, tables)
        
        conn.close()
    
    def test_scan_operations(self):
        """Test scan CRUD operations"""
        # Create scan
        scan_data = {
            'name': 'Test Scan',
            'description': 'Test scan description',
            'scan_type': 'network',
            'status': 'running'
        }
        
        scan_id = self.db_manager.create_scan(scan_data)
        self.assertIsNotNone(scan_id)
        self.assertGreater(scan_id, 0)
        
        # Read scan
        scan = self.db_manager.get_scan(scan_id)
        self.assertIsNotNone(scan)
        self.assertEqual(scan['name'], 'Test Scan')
        
        # Update scan
        updates = {'status': 'completed'}
        self.db_manager.update_scan(scan_id, updates)
        
        updated_scan = self.db_manager.get_scan(scan_id)
        self.assertEqual(updated_scan['status'], 'completed')
    
    def test_target_operations(self):
        """Test target CRUD operations"""
        # Create scan first
        scan_id = self.db_manager.create_scan({
            'name': 'Test Scan',
            'scan_type': 'network'
        })
        
        # Create target
        target_data = {
            'ip': '192.168.1.100',
            'hostname': 'test.example.com',
            'scan_id': scan_id
        }
        
        target_id = self.db_manager.add_target(target_data)
        self.assertIsNotNone(target_id)
        
        # Read target
        target = self.db_manager.get_target(target_id)
        self.assertIsNotNone(target)
        self.assertEqual(target['ip'], '192.168.1.100')
        
        # List targets for scan
        targets = self.db_manager.get_targets_for_scan(scan_id)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]['ip'], '192.168.1.100')
    
    def test_vulnerability_operations(self):
        """Test vulnerability CRUD operations"""
        # Create vulnerability
        vuln_data = {
            'title': 'Test Vulnerability',
            'description': 'Test vulnerability description',
            'severity': 'high',
            'cvss_score': 7.5,
            'cve_id': 'CVE-2023-12345',
            'solution': 'Apply security patch'
        }
        
        vuln_id = self.db_manager.add_vulnerability(vuln_data)
        self.assertIsNotNone(vuln_id)
        
        # Read vulnerability
        vuln = self.db_manager.get_vulnerability(vuln_id)
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln['title'], 'Test Vulnerability')
        self.assertEqual(vuln['cvss_score'], 7.5)
    
    def test_scan_results_operations(self):
        """Test scan results storage and retrieval"""
        # Create prerequisites
        scan_id = self.db_manager.create_scan({
            'name': 'Test Scan',
            'scan_type': 'network'
        })
        
        target_id = self.db_manager.add_target({
            'ip': '192.168.1.100',
            'scan_id': scan_id
        })
        
        vuln_id = self.db_manager.add_vulnerability({
            'title': 'Test Vulnerability',
            'severity': 'medium',
            'cvss_score': 5.0
        })
        
        # Add scan result
        result_data = {
            'scan_id': scan_id,
            'target_id': target_id,
            'vulnerability_id': vuln_id,
            'evidence': '{"test": true}'
        }
        
        result_id = self.db_manager.add_scan_result(result_data)
        self.assertIsNotNone(result_id)
        
        # Get scan results
        results = self.db_manager.get_scan_results(scan_id)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['target_id'], target_id)
    
    def test_cve_data_operations(self):
        """Test CVE data storage and lookup"""
        # Add CVE data
        cve_data = {
            'cve_id': 'CVE-2023-12345',
            'description': 'Test CVE description',
            'severity': 'high',
            'cvss_score': 8.5,
            'published_date': '2023-01-01',
            'references': '["https://nvd.nist.gov"]'
        }
        
        self.db_manager.add_cve_data(cve_data)
        
        # Lookup CVE
        cve = self.db_manager.get_cve_data('CVE-2023-12345')
        self.assertIsNotNone(cve)
        self.assertEqual(cve['cvss_score'], 8.5)
    
    def test_data_integrity(self):
        """Test data integrity constraints"""
        # Test foreign key constraint
        with self.assertRaises(sqlite3.IntegrityError):
            # Try to add target with non-existent scan_id
            self.db_manager.add_target({
                'ip': '192.168.1.100',
                'scan_id': 99999  # Non-existent
            })
    
    def test_database_backup(self):
        """Test database backup functionality"""
        # Add some data
        scan_id = self.db_manager.create_scan({
            'name': 'Test Scan',
            'scan_type': 'network'
        })
        
        # Create backup
        backup_path = os.path.join(self.test_dir, 'backup.db')
        self.db_manager.backup_database(backup_path)
        
        # Verify backup exists and contains data
        self.assertTrue(os.path.exists(backup_path))
        
        backup_conn = sqlite3.connect(backup_path)
        cursor = backup_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans")
        count = cursor.fetchone()[0]
        backup_conn.close()
        
        self.assertGreater(count, 0)
    
    def test_database_cleanup(self):
        """Test database cleanup operations"""
        # Add old scan data
        import datetime
        old_date = datetime.datetime.now() - datetime.timedelta(days=90)
        
        # Create old scan (mock the created_at date)
        scan_id = self.db_manager.create_scan({
            'name': 'Old Scan',
            'scan_type': 'network'
        })
        
        # Test cleanup (should handle gracefully)
        self.db_manager.cleanup_old_data(days=30)
    
    def test_query_performance(self):
        """Test query performance with bulk data"""
        import time
        
        # Create multiple scans and targets
        scan_ids = []
        for i in range(10):
            scan_id = self.db_manager.create_scan({
                'name': f'Test Scan {i}',
                'scan_type': 'network'
            })
            scan_ids.append(scan_id)
            
            # Add targets for each scan
            for j in range(5):
                self.db_manager.add_target({
                    'ip': f'192.168.1.{i*10 + j}',
                    'scan_id': scan_id
                })
        
        # Test query performance
        start_time = time.time()
        all_scans = self.db_manager.get_all_scans()
        end_time = time.time()
        
        # Should complete quickly
        self.assertLess(end_time - start_time, 1.0)  # < 1 second
        self.assertEqual(len(all_scans), 10)


class TestDatabaseMigration(VulnSleuthTestCase):
    """Test database migration functionality"""
    
    def test_schema_version_tracking(self):
        """Test schema version is tracked correctly"""
        db_manager = self.create_test_db()
        
        # Check initial schema version
        version = db_manager.get_schema_version()
        self.assertIsNotNone(version)
        self.assertGreater(version, 0)
    
    def test_migration_detection(self):
        """Test migration detection logic"""
        db_manager = self.create_test_db()
        
        # Should not need migration on fresh database
        needs_migration = db_manager.needs_migration()
        self.assertFalse(needs_migration)


if __name__ == '__main__':
    unittest.main()
