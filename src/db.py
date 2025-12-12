"""
VulnSleuth Database Management
SQLite database integration for scan results and data persistence

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import sqlite3
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict
import os
import threading
import contextlib
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    scan_id: str
    target: str
    scan_type: str
    timestamp: str
    status: str
    vulnerabilities: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class TargetInfo:
    target_id: str
    ip_address: str
    hostname: str
    ports: List[int]
    services: List[Dict[str, Any]]
    os_info: Dict[str, Any]
    first_seen: str
    last_seen: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class DatabaseManager:
    """
    Comprehensive database management for VulnSleuth
    
    Features:
    - SQLite database with proper indexing
    - Scan result persistence and retrieval
    - Target asset management
    - Vulnerability tracking and deduplication
    - Historical trend analysis
    - Data retention and cleanup
    - Thread-safe operations
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.db_config = config.get('database', {})
        self.logger = logging.getLogger('DatabaseManager')
        
        # Database configuration
        self.db_path = self.db_config.get('path', self.db_config.get('db_path', 'vulnsleuth.db'))
        
        # Ensure we have a valid path
        if not self.db_path or self.db_path.strip() == '':
            self.db_path = 'vulnsleuth.db'
        
        self.backup_enabled = self.db_config.get('backup_enabled', True)
        self.backup_interval_hours = self.db_config.get('backup_interval_hours', 24)
        self.retention_days = self.db_config.get('retention_days', 90)
        self.max_db_size_mb = self.db_config.get('max_db_size_mb', 1000)
        
        # Thread safety
        self.db_lock = threading.RLock()
        
        # Initialize database
        self._init_database()
        
        # Set up maintenance
        self._last_maintenance = datetime.now()
        self.maintenance_interval_hours = 6
        
        self.logger.info(f"Database manager initialized: {self.db_path}")
    
    def init_db(self):
        """
        Public method to initialize database
        This is called from external code
        """
        try:
            self._init_database()
            self.logger.info("Database initialization completed")
        except Exception as e:
            self.logger.error(f"Database initialization failed: {str(e)}")
            raise
    
    def _init_database(self):
        """Initialize SQLite database with all required tables"""
        try:
            # Ensure data directory exists (only if db_path has a directory component)
            db_dir = os.path.dirname(self.db_path)
            if db_dir and db_dir.strip():
                os.makedirs(db_dir, exist_ok=True)
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Enable foreign keys
                cursor.execute('PRAGMA foreign_keys = ON')
                
                # Create scans table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id TEXT PRIMARY KEY,
                        target TEXT NOT NULL,
                        scan_type TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        status TEXT NOT NULL,
                        duration_seconds INTEGER,
                        command_line TEXT,
                        metadata TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create vulnerabilities table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        vuln_id TEXT PRIMARY KEY,
                        scan_id TEXT NOT NULL,
                        target TEXT NOT NULL,
                        vulnerability_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        cvss_score REAL,
                        title TEXT NOT NULL,
                        description TEXT,
                        solution TEXT,
                        reference_urls TEXT,
                        cve_ids TEXT,
                        port INTEGER,
                        service TEXT,
                        protocol TEXT,
                        evidence TEXT,
                        status TEXT DEFAULT 'open',
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        false_positive INTEGER DEFAULT 0,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
                    )
                ''')
                
                # Create targets table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS targets (
                        target_id TEXT PRIMARY KEY,
                        ip_address TEXT NOT NULL,
                        hostname TEXT,
                        mac_address TEXT,
                        os_name TEXT,
                        os_version TEXT,
                        os_confidence REAL,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        scan_count INTEGER DEFAULT 1,
                        status TEXT DEFAULT 'active',
                        notes TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create ports table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        target_id TEXT NOT NULL,
                        port_number INTEGER NOT NULL,
                        protocol TEXT NOT NULL,
                        state TEXT NOT NULL,
                        service_name TEXT,
                        service_version TEXT,
                        service_banner TEXT,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (target_id) REFERENCES targets (target_id) ON DELETE CASCADE,
                        UNIQUE(target_id, port_number, protocol)
                    )
                ''')
                
                # Create scan_targets junction table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_targets (
                        scan_id TEXT NOT NULL,
                        target_id TEXT NOT NULL,
                        PRIMARY KEY (scan_id, target_id),
                        FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE,
                        FOREIGN KEY (target_id) REFERENCES targets (target_id) ON DELETE CASCADE
                    )
                ''')
                
                # Create CVE cache table (integrated with cve_lookup.py)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cve_data (
                        cve_id TEXT PRIMARY KEY,
                        description TEXT,
                        severity TEXT,
                        cvss_score REAL,
                        cvss_vector TEXT,
                        published_date TEXT,
                        modified_date TEXT,
                        reference_links TEXT,
                        cwe_ids TEXT,
                        affected_products TEXT,
                        exploit_available INTEGER DEFAULT 0,
                        patch_available INTEGER DEFAULT 0,
                        cached_date TEXT,
                        source TEXT
                    )
                ''')
                
                # Create vulnerability correlation table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS vuln_correlation (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        product_name TEXT,
                        version TEXT,
                        cve_id TEXT,
                        confidence REAL,
                        created_date TEXT,
                        FOREIGN KEY (cve_id) REFERENCES cve_data (cve_id)
                    )
                ''')
                
                # Create reports table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS reports (
                        report_id TEXT PRIMARY KEY,
                        scan_id TEXT,
                        report_type TEXT NOT NULL,
                        format TEXT NOT NULL,
                        file_path TEXT,
                        generated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        metadata TEXT,
                        FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
                    )
                ''')
                
                # Create configuration table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS config (
                        key TEXT PRIMARY KEY,
                        value TEXT,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create metadata table for system info
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create users table for web authentication
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        user_id TEXT PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        is_active INTEGER DEFAULT 1,
                        is_admin INTEGER DEFAULT 0,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        last_login TEXT,
                        login_count INTEGER DEFAULT 0,
                        failed_login_attempts INTEGER DEFAULT 0,
                        locked_until TEXT
                    )
                ''')
                
                # Create user sessions table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        session_id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        expires_at TEXT NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
                    )
                ''')
                
                # Create user activity log table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_activity (
                        activity_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id TEXT NOT NULL,
                        activity_type TEXT NOT NULL,
                        description TEXT,
                        ip_address TEXT,
                        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
                    )
                ''')
                
                # Create indexes for better performance
                self._create_indexes(cursor)
                
                conn.commit()
                
                self.logger.info("Database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {str(e)}")
            raise
    
    def _create_indexes(self, cursor):
        """Create database indexes for better query performance"""
        indexes = [
            # Scans table indexes
            'CREATE INDEX IF NOT EXISTS idx_scans_target ON scans (target)',
            'CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans (timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_scans_type ON scans (scan_type)',
            'CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status)',
            
            # Vulnerabilities table indexes
            'CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities (scan_id)',
            'CREATE INDEX IF NOT EXISTS idx_vulns_target ON vulnerabilities (target)',
            
            # Users table indexes
            'CREATE INDEX IF NOT EXISTS idx_users_username ON users (username)',
            'CREATE INDEX IF NOT EXISTS idx_users_email ON users (email)',
            'CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions (user_id)',
            'CREATE INDEX IF NOT EXISTS idx_user_activity_user ON user_activity (user_id)',
            'CREATE INDEX IF NOT EXISTS idx_user_activity_timestamp ON user_activity (timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities (severity)',
            'CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities (vulnerability_type)',
            'CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities (status)',
            'CREATE INDEX IF NOT EXISTS idx_vulns_cvss ON vulnerabilities (cvss_score)',
            'CREATE INDEX IF NOT EXISTS idx_vulns_first_seen ON vulnerabilities (first_seen)',
            
            # Targets table indexes
            'CREATE INDEX IF NOT EXISTS idx_targets_ip ON targets (ip_address)',
            'CREATE INDEX IF NOT EXISTS idx_targets_hostname ON targets (hostname)',
            'CREATE INDEX IF NOT EXISTS idx_targets_last_seen ON targets (last_seen)',
            'CREATE INDEX IF NOT EXISTS idx_targets_status ON targets (status)',
            
            # Ports table indexes
            'CREATE INDEX IF NOT EXISTS idx_ports_target ON ports (target_id)',
            'CREATE INDEX IF NOT EXISTS idx_ports_number ON ports (port_number)',
            'CREATE INDEX IF NOT EXISTS idx_ports_service ON ports (service_name)',
            
            # CVE table indexes
            'CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_data (severity)',
            'CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve_data (cvss_score)',
            'CREATE INDEX IF NOT EXISTS idx_cve_products ON cve_data (affected_products)',
            
            # Correlation indexes
            'CREATE INDEX IF NOT EXISTS idx_correlation_product ON vuln_correlation (product_name, version)',
            
            # Reports indexes
            'CREATE INDEX IF NOT EXISTS idx_reports_scan ON reports (scan_id)',
            'CREATE INDEX IF NOT EXISTS idx_reports_type ON reports (report_type)',
        ]
        
        for index_sql in indexes:
            try:
                cursor.execute(index_sql)
            except sqlite3.Error as e:
                self.logger.warning(f"Failed to create index: {str(e)}")
    
    @contextlib.contextmanager
    def _get_connection(self):
        """Get thread-safe database connection"""
        with self.db_lock:
            conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
                check_same_thread=False
            )
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()
    
    def save_scan_result(self, scan_result: Union[ScanResult, Dict[str, Any]]) -> bool:
        """
        Save scan result to database
        
        Args:
            scan_result: ScanResult object or dict to save
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Handle both ScanResult objects and dictionaries
            if isinstance(scan_result, dict):
                scan_id = scan_result['scan_id']
                target = scan_result['target']
                scan_type = scan_result['scan_type']
                timestamp = scan_result['timestamp']
                status = scan_result['status']
                vulnerabilities = scan_result['vulnerabilities']
                metadata = scan_result.get('metadata', {})
            else:
                scan_id = scan_result.scan_id
                target = scan_result.target
                scan_type = scan_result.scan_type
                timestamp = scan_result.timestamp
                status = scan_result.status
                vulnerabilities = scan_result.vulnerabilities
                metadata = scan_result.metadata
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Insert or update scan record
                cursor.execute('''
                    INSERT OR REPLACE INTO scans 
                    (scan_id, target, scan_type, timestamp, status, metadata, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    target,
                    scan_type,
                    timestamp,
                    status,
                    json.dumps(metadata) if isinstance(metadata, dict) else metadata,
                    datetime.now().isoformat()
                ))
                
                # Save vulnerabilities
                for vuln in vulnerabilities:
                    self._save_vulnerability(cursor, scan_id, target, vuln)
                
                conn.commit()
                
                self.logger.debug(f"Saved scan result: {scan_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to save scan result: {str(e)}")
            return False
    
    def _save_vulnerability(self, cursor, scan_id: str, target: str, vuln: Dict[str, Any]):
        """Save individual vulnerability to database"""
        try:
            # Generate vulnerability ID
            vuln_id = self._generate_vuln_id(target, vuln)
            
            # Check if vulnerability already exists
            cursor.execute('SELECT vuln_id FROM vulnerabilities WHERE vuln_id = ?', (vuln_id,))
            existing = cursor.fetchone()
            
            current_time = datetime.now().isoformat()
            
            if existing:
                # Update existing vulnerability
                cursor.execute('''
                    UPDATE vulnerabilities 
                    SET last_seen = ?, evidence = ?, scan_id = ?
                    WHERE vuln_id = ?
                ''', (current_time, json.dumps(vuln.get('evidence', {})), scan_id, vuln_id))
            else:
                # Insert new vulnerability
                cursor.execute('''
                    INSERT INTO vulnerabilities 
                    (vuln_id, scan_id, target, vulnerability_type, severity, cvss_score,
                     title, description, solution, reference_urls, cve_ids, port, service,
                     protocol, evidence, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    vuln_id,
                    scan_id,
                    target,
                    vuln.get('type', 'unknown'),
                    vuln.get('severity', 'unknown'),
                    vuln.get('cvss_score', 0.0),
                    vuln.get('title', 'Unknown Vulnerability'),
                    vuln.get('description', ''),
                    vuln.get('solution', ''),
                    json.dumps(vuln.get('references', [])),
                    json.dumps(vuln.get('cve_ids', [])),
                    vuln.get('port'),
                    vuln.get('service'),
                    vuln.get('protocol'),
                    json.dumps(vuln.get('evidence', {})),
                    current_time,
                    current_time
                ))
                
        except Exception as e:
            self.logger.error(f"Failed to save vulnerability: {str(e)}")
    
    def get_scan_results(self, 
                        target: str = None, 
                        scan_type: str = None,
                        days_back: int = 30,
                        limit: int = 100) -> List[ScanResult]:
        """
        Retrieve scan results from database
        
        Args:
            target: Optional target filter
            scan_type: Optional scan type filter
            days_back: Number of days to look back
            limit: Maximum number of results
            
        Returns:
            List of ScanResult objects
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Build query
                query = '''
                    SELECT scan_id, target, scan_type, timestamp, status, metadata
                    FROM scans
                    WHERE timestamp >= ?
                '''
                params = [(datetime.now() - timedelta(days=days_back)).isoformat()]
                
                if target:
                    query += ' AND target = ?'
                    params.append(target)
                
                if scan_type:
                    query += ' AND scan_type = ?'
                    params.append(scan_type)
                
                # Add LIMIT only if specified
                if limit:
                    query += ' ORDER BY timestamp DESC LIMIT ?'
                    params.append(limit)
                else:
                    query += ' ORDER BY timestamp DESC'
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                results = []
                for row in rows:
                    # Get vulnerabilities for this scan
                    cursor.execute('''
                        SELECT * FROM vulnerabilities WHERE scan_id = ?
                    ''', (row['scan_id'],))
                    vuln_rows = cursor.fetchall()
                    
                    vulnerabilities = []
                    for vuln_row in vuln_rows:
                        vuln_dict = dict(vuln_row)
                        # Parse JSON fields
                        for json_field in ['reference_urls', 'cve_ids', 'evidence']:
                            if vuln_dict.get(json_field):
                                try:
                                    vuln_dict[json_field] = json.loads(vuln_dict[json_field])
                                except json.JSONDecodeError:
                                    vuln_dict[json_field] = []
                        
                        # For backward compatibility, also set 'references' field
                        vuln_dict['references'] = vuln_dict.get('reference_urls', [])
                        vulnerabilities.append(vuln_dict)
                    
                    metadata = {}
                    if row['metadata']:
                        try:
                            metadata = json.loads(row['metadata'])
                        except json.JSONDecodeError:
                            pass
                    
                    scan_result = ScanResult(
                        scan_id=row['scan_id'],
                        target=row['target'],
                        scan_type=row['scan_type'],
                        timestamp=row['timestamp'],
                        status=row['status'],
                        vulnerabilities=vulnerabilities,
                        metadata=metadata
                    )
                    
                    results.append(scan_result)
                
                return results
                
        except Exception as e:
            self.logger.error(f"Failed to get scan results: {str(e)}")
            return []
    
    def save_target_info(self, target_info: TargetInfo) -> bool:
        """
        Save target information to database
        
        Args:
            target_info: TargetInfo object to save
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Check if target exists
                cursor.execute('SELECT target_id FROM targets WHERE target_id = ?', (target_info.target_id,))
                existing = cursor.fetchone()
                
                current_time = datetime.now().isoformat()
                
                if existing:
                    # Update existing target
                    cursor.execute('''
                        UPDATE targets 
                        SET hostname = ?, os_name = ?, os_version = ?, 
                            last_seen = ?, scan_count = scan_count + 1,
                            updated_at = ?
                        WHERE target_id = ?
                    ''', (
                        target_info.hostname,
                        target_info.os_info.get('name'),
                        target_info.os_info.get('version'),
                        target_info.last_seen,
                        current_time,
                        target_info.target_id
                    ))
                else:
                    # Insert new target
                    cursor.execute('''
                        INSERT INTO targets 
                        (target_id, ip_address, hostname, os_name, os_version, 
                         os_confidence, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        target_info.target_id,
                        target_info.ip_address,
                        target_info.hostname,
                        target_info.os_info.get('name'),
                        target_info.os_info.get('version'),
                        target_info.os_info.get('confidence', 0.0),
                        target_info.first_seen,
                        target_info.last_seen
                    ))
                
                # Save port information
                for port in target_info.ports:
                    service_info = next((s for s in target_info.services if s.get('port') == port), {})
                    
                    cursor.execute('''
                        INSERT OR REPLACE INTO ports
                        (target_id, port_number, protocol, state, service_name,
                         service_version, service_banner, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        target_info.target_id,
                        port,
                        service_info.get('protocol', 'tcp'),
                        service_info.get('state', 'open'),
                        service_info.get('name'),
                        service_info.get('version'),
                        service_info.get('banner'),
                        target_info.first_seen,
                        target_info.last_seen
                    ))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to save target info: {str(e)}")
            return False
    
    def get_targets(self, 
                   active_only: bool = True,
                   days_back: int = 30) -> List[TargetInfo]:
        """
        Retrieve target information from database
        
        Args:
            active_only: Only return active targets
            days_back: Number of days to look back
            
        Returns:
            List of TargetInfo objects
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                query = '''
                    SELECT target_id, ip_address, hostname, os_name, os_version,
                           os_confidence, first_seen, last_seen
                    FROM targets
                    WHERE last_seen >= ?
                '''
                params = [(datetime.now() - timedelta(days=days_back)).isoformat()]
                
                if active_only:
                    query += " AND status = 'active'"
                
                query += ' ORDER BY last_seen DESC'
                
                cursor.execute(query, params)
                rows = cursor.fetchall()
                
                targets = []
                for row in rows:
                    # Get ports for this target
                    cursor.execute('''
                        SELECT port_number, protocol, state, service_name,
                               service_version, service_banner
                        FROM ports
                        WHERE target_id = ?
                    ''', (row['target_id'],))
                    port_rows = cursor.fetchall()
                    
                    ports = []
                    services = []
                    
                    for port_row in port_rows:
                        ports.append(port_row['port_number'])
                        
                        service = {
                            'port': port_row['port_number'],
                            'protocol': port_row['protocol'],
                            'state': port_row['state'],
                            'name': port_row['service_name'],
                            'version': port_row['service_version'],
                            'banner': port_row['service_banner']
                        }
                        services.append(service)
                    
                    os_info = {
                        'name': row['os_name'],
                        'version': row['os_version'],
                        'confidence': row['os_confidence']
                    }
                    
                    target_info = TargetInfo(
                        target_id=row['target_id'],
                        ip_address=row['ip_address'],
                        hostname=row['hostname'] or '',
                        ports=ports,
                        services=services,
                        os_info=os_info,
                        first_seen=row['first_seen'],
                        last_seen=row['last_seen']
                    )
                    
                    targets.append(target_info)
                
                return targets
                
        except Exception as e:
            self.logger.error(f"Failed to get targets: {str(e)}")
            return []
    
    def get_vulnerability_stats(self, days_back: int = 30) -> Dict[str, Any]:
        """
        Get vulnerability statistics
        
        Args:
            days_back: Number of days to analyze
            
        Returns:
            Dictionary with vulnerability statistics
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cutoff_date = (datetime.now() - timedelta(days=days_back)).isoformat()
                
                # Total vulnerabilities
                cursor.execute('''
                    SELECT COUNT(*) FROM vulnerabilities 
                    WHERE first_seen >= ? AND status = 'open'
                ''', (cutoff_date,))
                total_vulns = cursor.fetchone()[0]
                
                # Vulnerabilities by severity
                cursor.execute('''
                    SELECT severity, COUNT(*) 
                    FROM vulnerabilities 
                    WHERE first_seen >= ? AND status = 'open'
                    GROUP BY severity
                ''', (cutoff_date,))
                severity_counts = dict(cursor.fetchall())
                
                # Vulnerabilities by type
                cursor.execute('''
                    SELECT vulnerability_type, COUNT(*) 
                    FROM vulnerabilities 
                    WHERE first_seen >= ? AND status = 'open'
                    GROUP BY vulnerability_type
                    ORDER BY COUNT(*) DESC
                    LIMIT 10
                ''', (cutoff_date,))
                type_counts = dict(cursor.fetchall())
                
                # Top vulnerable targets
                cursor.execute('''
                    SELECT target, COUNT(*) as vuln_count
                    FROM vulnerabilities 
                    WHERE first_seen >= ? AND status = 'open'
                    GROUP BY target
                    ORDER BY COUNT(*) DESC
                    LIMIT 10
                ''', (cutoff_date,))
                top_targets = dict(cursor.fetchall())
                
                # Average CVSS score
                cursor.execute('''
                    SELECT AVG(cvss_score) 
                    FROM vulnerabilities 
                    WHERE first_seen >= ? AND status = 'open' AND cvss_score > 0
                ''', (cutoff_date,))
                avg_cvss = cursor.fetchone()[0] or 0
                
                # False positives
                cursor.execute('''
                    SELECT COUNT(*) FROM vulnerabilities 
                    WHERE first_seen >= ? AND false_positive = 1
                ''', (cutoff_date,))
                false_positives = cursor.fetchone()[0]
                
                return {
                    'total_vulnerabilities': total_vulns,
                    'severity_breakdown': severity_counts,
                    'vulnerability_types': type_counts,
                    'top_vulnerable_targets': top_targets,
                    'average_cvss_score': round(avg_cvss, 2),
                    'false_positives': false_positives,
                    'analysis_period_days': days_back
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get vulnerability stats: {str(e)}")
            return {}
    
    def mark_false_positive(self, vuln_id: str, is_false_positive: bool = True) -> bool:
        """
        Mark vulnerability as false positive
        
        Args:
            vuln_id: Vulnerability ID
            is_false_positive: True to mark as false positive
            
        Returns:
            True if successful
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE vulnerabilities 
                    SET false_positive = ?
                    WHERE vuln_id = ?
                ''', (int(is_false_positive), vuln_id))
                
                conn.commit()
                
                return cursor.rowcount > 0
                
        except Exception as e:
            self.logger.error(f"Failed to mark false positive: {str(e)}")
            return False
    
    def cleanup_old_data(self) -> int:
        """
        Clean up old scan data based on retention policy
        
        Returns:
            Number of records cleaned up
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=self.retention_days)).isoformat()
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Delete old scans (cascades to vulnerabilities)
                cursor.execute('''
                    DELETE FROM scans WHERE timestamp < ?
                ''', (cutoff_date,))
                
                deleted_scans = cursor.rowcount
                
                # Delete old CVE cache
                cursor.execute('''
                    DELETE FROM cve_data WHERE cached_date < ?
                ''', (cutoff_date,))
                
                deleted_cves = cursor.rowcount
                
                # Delete old reports
                cursor.execute('''
                    DELETE FROM reports WHERE generated_at < ?
                ''', (cutoff_date,))
                
                deleted_reports = cursor.rowcount
                
                conn.commit()
                
                total_deleted = deleted_scans + deleted_cves + deleted_reports
                
                if total_deleted > 0:
                    self.logger.info(f"Cleaned up {total_deleted} old records")
                
                return total_deleted
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {str(e)}")
            return 0
    
    def backup_database(self, backup_path: str = None) -> bool:
        """
        Create database backup
        
        Args:
            backup_path: Optional custom backup path
            
        Returns:
            True if successful
        """
        try:
            if not backup_path:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_dir = os.path.join(os.path.dirname(self.db_path), 'backups')
                os.makedirs(backup_dir, exist_ok=True)
                backup_path = os.path.join(backup_dir, f'vulnsleuth_backup_{timestamp}.db')
            
            # Use SQLite backup API
            with sqlite3.connect(self.db_path) as source:
                with sqlite3.connect(backup_path) as backup:
                    source.backup(backup)
            
            self.logger.info(f"Database backup created: {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to backup database: {str(e)}")
            return False
    
    def get_database_info(self) -> Dict[str, Any]:
        """Get database information and statistics"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Database file size
                db_size_bytes = os.path.getsize(self.db_path)
                db_size_mb = db_size_bytes / (1024 * 1024)
                
                # Table counts
                table_counts = {}
                tables = ['scans', 'vulnerabilities', 'targets', 'ports', 'cve_data', 'reports']
                
                for table in tables:
                    cursor.execute(f'SELECT COUNT(*) FROM {table}')
                    table_counts[table] = cursor.fetchone()[0]
                
                # Database version
                cursor.execute('PRAGMA user_version')
                db_version = cursor.fetchone()[0]
                
                return {
                    'database_path': self.db_path,
                    'size_bytes': db_size_bytes,
                    'size_mb': round(db_size_mb, 2),
                    'table_counts': table_counts,
                    'database_version': db_version,
                    'retention_days': self.retention_days,
                    'max_size_mb': self.max_db_size_mb
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get database info: {str(e)}")
            return {}
    
    def _generate_vuln_id(self, target: str, vuln: Dict[str, Any]) -> str:
        """Generate unique vulnerability ID"""
        # Create hash from target, type, port, and title
        hash_input = f"{target}:{vuln.get('type', '')}:{vuln.get('port', '')}:{vuln.get('title', '')}"
        return f"vuln_{hash(hash_input) & 0x7fffffff:08x}"
    
    def maintenance(self) -> Dict[str, Any]:
        """
        Perform database maintenance tasks
        
        Returns:
            Dictionary with maintenance results
        """
        try:
            results = {}
            
            # Check if maintenance is needed
            if (datetime.now() - self._last_maintenance).total_seconds() < self.maintenance_interval_hours * 3600:
                return {'skipped': 'Maintenance not needed yet'}
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Vacuum database
                cursor.execute('VACUUM')
                results['vacuum'] = 'completed'
                
                # Analyze database
                cursor.execute('ANALYZE')
                results['analyze'] = 'completed'
                
                # Check integrity
                cursor.execute('PRAGMA integrity_check')
                integrity_result = cursor.fetchone()[0]
                results['integrity_check'] = integrity_result
            
            # Cleanup old data
            cleaned_records = self.cleanup_old_data()
            results['cleanup_records'] = cleaned_records
            
            # Backup if enabled
            if self.backup_enabled:
                backup_success = self.backup_database()
                results['backup'] = 'success' if backup_success else 'failed'
            
            self._last_maintenance = datetime.now()
            
            self.logger.info("Database maintenance completed")
            return results
            
        except Exception as e:
            self.logger.error(f"Database maintenance failed: {str(e)}")
            return {'error': str(e)}
    
    # User management methods
    def create_user(self, username: str, email: str, password_hash: str, is_admin: bool = False) -> Optional[str]:
        """
        Create a new user account
        
        Args:
            username: Unique username
            email: Unique email address
            password_hash: Hashed password
            is_admin: Whether user has admin privileges
            
        Returns:
            User ID if successful, None otherwise
        """
        try:
            user_id = f"user_{uuid.uuid4().hex[:12]}"
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (user_id, username, email, password_hash, is_admin)
                    VALUES (?, ?, ?, ?, ?)
                ''', (user_id, username, email, password_hash, 1 if is_admin else 0))
                conn.commit()
            
            self.logger.info(f"User created: {username}")
            return user_id
            
        except sqlite3.IntegrityError as e:
            self.logger.error(f"User creation failed (duplicate): {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"User creation failed: {str(e)}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT user_id, username, email, password_hash, is_active, is_admin, 
                           created_at, last_login, login_count, failed_login_attempts, locked_until
                    FROM users WHERE username = ?
                ''', (username,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        'user_id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'password_hash': row[3],
                        'is_active': bool(row[4]),
                        'is_admin': bool(row[5]),
                        'created_at': row[6],
                        'last_login': row[7],
                        'login_count': row[8],
                        'failed_login_attempts': row[9],
                        'locked_until': row[10]
                    }
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get user: {str(e)}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Get user by email"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT user_id, username, email, password_hash, is_active, is_admin, 
                           created_at, last_login, login_count, failed_login_attempts, locked_until
                    FROM users WHERE email = ?
                ''', (email,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        'user_id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'password_hash': row[3],
                        'is_active': bool(row[4]),
                        'is_admin': bool(row[5]),
                        'created_at': row[6],
                        'last_login': row[7],
                        'login_count': row[8],
                        'failed_login_attempts': row[9],
                        'locked_until': row[10]
                    }
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get user by email: {str(e)}")
            return None
    
    def update_user_login(self, user_id: str, success: bool = True):
        """Update user login information"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                if success:
                    cursor.execute('''
                        UPDATE users 
                        SET last_login = ?, 
                            login_count = login_count + 1,
                            failed_login_attempts = 0
                        WHERE user_id = ?
                    ''', (datetime.now().isoformat(), user_id))
                else:
                    cursor.execute('''
                        UPDATE users 
                        SET failed_login_attempts = failed_login_attempts + 1
                        WHERE user_id = ?
                    ''', (user_id,))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to update user login: {str(e)}")
    
    def get_all_users(self) -> List[Dict[str, Any]]:
        """Get all users"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT user_id, username, email, is_active, is_admin, 
                           created_at, last_login, login_count
                    FROM users
                    ORDER BY created_at DESC
                ''')
                
                users = []
                for row in cursor.fetchall():
                    users.append({
                        'user_id': row[0],
                        'username': row[1],
                        'email': row[2],
                        'is_active': bool(row[3]),
                        'is_admin': bool(row[4]),
                        'created_at': row[5],
                        'last_login': row[6],
                        'login_count': row[7]
                    })
                
                return users
                
        except Exception as e:
            self.logger.error(f"Failed to get all users: {str(e)}")
            return []
    
    def user_exists(self) -> bool:
        """Check if any users exist in the database"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM users')
                count = cursor.fetchone()[0]
                return count > 0
                
        except Exception as e:
            self.logger.error(f"Failed to check if users exist: {str(e)}")
            return False
    
    def log_user_activity(self, user_id: str, activity_type: str, description: str, ip_address: str = None):
        """Log user activity"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO user_activity (user_id, activity_type, description, ip_address)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, activity_type, description, ip_address))
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Failed to log user activity: {str(e)}")
    
    # ==================== Web Interface Helper Methods ====================
    
    def get_all_scans(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get all scans for web interface"""
        scan_results = self.get_scan_results(limit=limit)
        # Convert ScanResult objects to dictionaries
        return [scan.to_dict() if hasattr(scan, 'to_dict') else scan for scan in scan_results]
    
    def get_scan_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific scan by ID with vulnerabilities"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM scans WHERE scan_id = ?
                ''', (scan_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                scan = dict(row)
                
                # Get vulnerabilities for this scan
                cursor.execute('''
                    SELECT * FROM vulnerabilities WHERE scan_id = ?
                ''', (scan_id,))
                
                vulns = []
                for vuln_row in cursor.fetchall():
                    vuln_dict = dict(vuln_row)
                    # Parse JSON fields
                    if vuln_dict.get('cve_ids'):
                        vuln_dict['cve_ids'] = json.loads(vuln_dict['cve_ids'])
                    if vuln_dict.get('reference_urls'):
                        vuln_dict['reference_urls'] = json.loads(vuln_dict['reference_urls'])
                    vulns.append(vuln_dict)
                
                scan['vulnerabilities'] = vulns
                
                # Parse metadata if present
                if scan.get('metadata'):
                    scan['metadata'] = json.loads(scan['metadata'])
                
                return scan
                
        except Exception as e:
            self.logger.error(f"Error getting scan by ID: {str(e)}")
            return None
    
    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and its vulnerabilities"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Delete vulnerabilities first
                cursor.execute('DELETE FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
                
                # Delete scan
                cursor.execute('DELETE FROM scans WHERE scan_id = ?', (scan_id,))
                
                conn.commit()
                self.logger.info(f"Deleted scan: {scan_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error deleting scan: {str(e)}")
            return False

if __name__ == "__main__":
    # Test database operations
    config = {
        'database': {
            'db_path': 'test_vulnsleuth.db',
            'retention_days': 30
        }
    }
    
    db_manager = DatabaseManager(config)
    
    # Test scan result
    test_scan = ScanResult(
        scan_id='test_scan_001',
        target='192.168.1.100',
        scan_type='network',
        timestamp=datetime.now().isoformat(),
        status='completed',
        vulnerabilities=[
            {
                'type': 'open_port',
                'severity': 'medium',
                'cvss_score': 5.0,
                'title': 'SSH Service Detected',
                'description': 'SSH service running on port 22',
                'port': 22,
                'service': 'ssh',
                'protocol': 'tcp',
                'evidence': {'banner': 'OpenSSH_8.2p1'}
            }
        ],
        metadata={'scan_duration': 30.5}
    )
    
    # Save and retrieve
    success = db_manager.save_scan_result(test_scan)
    print(f"Save result: {success}")
    
    results = db_manager.get_scan_results(limit=5)
    print(f"Retrieved {len(results)} scan results")
    
    # Get stats
    stats = db_manager.get_vulnerability_stats()
    print(f"Vulnerability stats: {stats}")
    
    # Database info
    info = db_manager.get_database_info()
    print(f"Database info: {info}")
