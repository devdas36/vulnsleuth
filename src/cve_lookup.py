"""
VulnSleuth CVE Lookup and Management
CVE database integration and vulnerability correlation

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import requests
import sqlite3
import json
import time
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import logging
import threading
import concurrent.futures
from dataclasses import dataclass, asdict
import os

logger = logging.getLogger(__name__)

@dataclass
class CVEInfo:
    """Container for CVE information"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    published_date: str
    modified_date: str
    references: List[str]
    cwe_ids: List[str]
    affected_products: List[str]
    exploit_available: bool
    patch_available: bool
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class CVELookup:
    """
    Comprehensive CVE lookup and vulnerability correlation system
    
    Features:
    - Integration with multiple CVE data sources (NVD, MITRE, etc.)
    - Local CVE database caching
    - Vulnerability correlation and scoring
    - Exploit availability checking
    - Patch status tracking
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cve_config = config.get('cve_sources', {})
        self.logger = logging.getLogger('CVELookup')
        
        # API configurations
        self.nvd_api_key = self.cve_config.get('nvd_api_key', '')
        self.nvd_base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        self.mitre_enabled = self.cve_config.get('mitre_enabled', True)
        self.exploit_db_enabled = self.cve_config.get('exploit_db_enabled', True)
        self.github_advisories = self.cve_config.get('github_advisories', True)
        
        # Database configuration
        self.db_path = config.get('database', {}).get('db_path', 'data/vulnsleuth.db')
        self.cache_days = self.cve_config.get('cve_cache_days', 7)
        self.update_frequency = self.cve_config.get('update_frequency_hours', 6)
        
        # Rate limiting
        self.rate_limit = 5  # requests per second
        self.last_request_time = 0
        self.request_lock = threading.Lock()
        
        # Initialize database
        self._init_database()
        
        # Product/service patterns for vulnerability correlation
        self.product_patterns = {
            'apache': [r'apache[\s/](\d+\.[\d.]+)', r'httpd[\s/](\d+\.[\d.]+)'],
            'nginx': [r'nginx[\s/](\d+\.[\d.]+)'],
            'openssh': [r'openssh[\s/_](\d+\.[\d.]+)', r'ssh[\s-](\d+\.[\d.]+)'],
            'openssl': [r'openssl[\s/](\d+\.[\d.]+[a-z]?)'],
            'mysql': [r'mysql[\s/](\d+\.[\d.]+)'],
            'postgresql': [r'postgresql[\s/](\d+\.[\d.]+)', r'postgres[\s/](\d+\.[\d.]+)'],
            'php': [r'php[\s/](\d+\.[\d.]+)'],
            'python': [r'python[\s/](\d+\.[\d.]+)'],
            'node': [r'node\.js[\s/](\d+\.[\d.]+)', r'nodejs[\s/](\d+\.[\d.]+)'],
            'iis': [r'microsoft-iis[\s/](\d+\.[\d.]+)', r'iis[\s/](\d+\.[\d.]+)'],
            'windows': [r'windows\s+(nt\s+)?(\d+\.[\d.]+)', r'microsoft\s+windows\s+(\d+)'],
            'linux': [r'linux[\s/](\d+\.[\d.]+)', r'ubuntu[\s/](\d+\.[\d.]+)', r'debian[\s/](\d+\.[\d.]+)'],
        }
    
    def _init_database(self):
        """Initialize SQLite database for CVE caching"""
        try:
            # Ensure data directory exists
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create CVE table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cve_data (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    published_date TEXT,
                    modified_date TEXT,
                    reference_urls TEXT,
                    cwe_ids TEXT,
                    affected_products TEXT,
                    exploit_available INTEGER,
                    patch_available INTEGER,
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
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_products ON cve_data (affected_products)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_correlation_product ON vuln_correlation (product_name, version)')
            
            conn.commit()
            conn.close()
            
            self.logger.info("CVE database initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize CVE database: {str(e)}")
    
    def lookup_vulnerability(self, vulnerability_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Look up CVE information for a vulnerability finding
        
        Args:
            vulnerability_data: Vulnerability information (service, version, banner, etc.)
            
        Returns:
            CVE data dictionary or None
        """
        try:
            # Extract product and version information
            products = self._extract_products_from_vulnerability(vulnerability_data)
            
            if not products:
                return None
            
            all_cves = []
            
            # Look up CVEs for each identified product
            for product_name, version in products:
                cves = self._lookup_product_cves(product_name, version)
                all_cves.extend(cves)
            
            if not all_cves:
                return None
            
            # Sort by CVSS score and recency
            sorted_cves = sorted(all_cves, key=lambda x: (x.cvss_score, x.published_date), reverse=True)
            
            # Return aggregated CVE information
            return {
                'cve_ids': [cve.cve_id for cve in sorted_cves[:10]],  # Top 10 most relevant
                'highest_cvss_score': sorted_cves[0].cvss_score if sorted_cves else 0,
                'cvss_vector': sorted_cves[0].cvss_vector if sorted_cves else '',
                'cwe_ids': list(set([cwe for cve in sorted_cves for cwe in cve.cwe_ids])),
                'references': list(set([ref for cve in sorted_cves for ref in cve.references])),
                'exploit_available': any(cve.exploit_available for cve in sorted_cves),
                'patch_available': any(cve.patch_available for cve in sorted_cves),
                'total_cves': len(sorted_cves)
            }
            
        except Exception as e:
            self.logger.error(f"CVE lookup failed: {str(e)}")
            return None
    
    def search_cve(self, cve_id: str) -> Optional[CVEInfo]:
        """
        Search for specific CVE by ID
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2021-44228')
            
        Returns:
            CVEInfo object or None
        """
        self.logger.debug(f"Searching for CVE: {cve_id}")
        
        # Check cache first
        cached_cve = self._get_cached_cve(cve_id)
        if cached_cve and self._is_cache_fresh(cached_cve['cached_date']):
            return self._dict_to_cve_info(cached_cve)
        
        # Search online sources
        cve_info = None
        
        # Try NVD first
        if self.nvd_api_key:
            cve_info = self._search_nvd_cve(cve_id)
        
        # Try other sources if NVD fails
        if not cve_info and self.mitre_enabled:
            cve_info = self._search_mitre_cve(cve_id)
        
        if cve_info:
            # Cache the result
            self._cache_cve(cve_info)
            return cve_info
        
        return None
    
    def search_product_vulnerabilities(self, product: str, version: str = None, limit: int = 50) -> List[CVEInfo]:
        """
        Search for vulnerabilities affecting a specific product/version
        
        Args:
            product: Product name (e.g., 'apache', 'openssh')
            version: Optional version string
            limit: Maximum number of CVEs to return
            
        Returns:
            List of CVEInfo objects
        """
        self.logger.info(f"Searching vulnerabilities for {product} {version or 'all versions'}")
        
        # Check cache first
        cached_cves = self._get_cached_product_cves(product, version)
        
        if cached_cves and len(cached_cves) > 0:
            recent_cache = [cve for cve in cached_cves if self._is_cache_fresh(cve['cached_date'])]
            if len(recent_cache) > limit // 2:  # If we have reasonable cached data
                return [self._dict_to_cve_info(cve) for cve in recent_cache[:limit]]
        
        # Search online
        online_cves = []
        
        if self.nvd_api_key:
            online_cves.extend(self._search_nvd_product(product, version, limit))
        
        # Cache results
        for cve in online_cves:
            self._cache_cve(cve)
            self._cache_correlation(product, version, cve.cve_id, 0.8)
        
        return online_cves[:limit]
    
    def update_all_cves(self, force: bool = False) -> int:
        """
        Update CVE database from all sources
        
        Args:
            force: Force update even if recently updated
            
        Returns:
            Number of CVEs updated
        """
        self.logger.info("Starting CVE database update")
        
        if not force and self._is_recent_update():
            self.logger.info("CVE database recently updated, skipping")
            return 0
        
        total_updated = 0
        
        # Update from NVD
        if self.nvd_api_key:
            nvd_updated = self._update_from_nvd()
            total_updated += nvd_updated
            self.logger.info(f"Updated {nvd_updated} CVEs from NVD")
        
        # Update exploit information
        if self.exploit_db_enabled:
            exploit_updated = self._update_exploit_info()
            total_updated += exploit_updated
            self.logger.info(f"Updated exploit info for {exploit_updated} CVEs")
        
        # Update GitHub security advisories
        if self.github_advisories:
            github_updated = self._update_github_advisories()
            total_updated += github_updated
            self.logger.info(f"Updated {github_updated} GitHub advisories")
        
        # Record update timestamp
        self._record_update_timestamp()
        
        self.logger.info(f"CVE database update completed: {total_updated} total updates")
        
        return total_updated
    
    def update_target_cves(self, target: str, force: bool = False) -> int:
        """
        Update CVEs for a specific target based on its services
        
        Args:
            target: Target identifier
            force: Force update even if recently updated
            
        Returns:
            Number of CVEs updated
        """
        # This would integrate with scan results to identify services
        # and update relevant CVEs
        return 0
    
    def get_cve_statistics(self) -> Dict[str, Any]:
        """Get CVE database statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total CVEs
            cursor.execute('SELECT COUNT(*) FROM cve_data')
            total_cves = cursor.fetchone()[0]
            
            # CVEs by severity
            cursor.execute('''
                SELECT severity, COUNT(*) 
                FROM cve_data 
                GROUP BY severity
            ''')
            severity_counts = dict(cursor.fetchall())
            
            # Recent CVEs (last 30 days)
            thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
            cursor.execute('''
                SELECT COUNT(*) 
                FROM cve_data 
                WHERE published_date > ?
            ''', (thirty_days_ago,))
            recent_cves = cursor.fetchone()[0]
            
            # Cache age
            cursor.execute('SELECT MIN(cached_date) FROM cve_data')
            oldest_cache = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_cves': total_cves,
                'severity_breakdown': severity_counts,
                'recent_cves': recent_cves,
                'oldest_cache': oldest_cache,
                'cache_age_days': (datetime.now() - datetime.fromisoformat(oldest_cache)).days if oldest_cache else None
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get CVE statistics: {str(e)}")
            return {}
    
    def _extract_products_from_vulnerability(self, vuln_data: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Extract product and version information from vulnerability data"""
        products = []
        
        # Get banner/version information
        banner = vuln_data.get('banner', '').lower()
        service = vuln_data.get('service', '').lower()
        version = vuln_data.get('version', '').lower()
        
        # Combine text to search
        search_text = f"{banner} {service} {version}".strip()
        
        if not search_text:
            return products
        
        # Match against known product patterns
        for product_name, patterns in self.product_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, search_text, re.IGNORECASE)
                for match in matches:
                    version = match if isinstance(match, str) else match[0]
                    products.append((product_name, version))
        
        return list(set(products))  # Remove duplicates
    
    def _lookup_product_cves(self, product: str, version: str) -> List[CVEInfo]:
        """Look up CVEs for a specific product/version"""
        # Check correlation cache first
        cached_cves = self._get_correlated_cves(product, version)
        
        if cached_cves:
            return cached_cves
        
        # Search online if not cached
        online_cves = self.search_product_vulnerabilities(product, version, 20)
        
        return online_cves
    
    def _search_nvd_cve(self, cve_id: str) -> Optional[CVEInfo]:
        """Search NVD for specific CVE"""
        try:
            self._rate_limit()
            
            url = f"{self.nvd_base_url}"
            params = {
                'cveId': cve_id
            }
            
            headers = {}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key
            
            response = requests.get(url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('totalResults', 0) == 0:
                return None
            
            cve_item = data['vulnerabilities'][0]['cve']
            
            return self._parse_nvd_cve(cve_item)
            
        except Exception as e:
            self.logger.error(f"NVD CVE search failed for {cve_id}: {str(e)}")
            return None
    
    def _search_nvd_product(self, product: str, version: str, limit: int) -> List[CVEInfo]:
        """Search NVD for product vulnerabilities"""
        try:
            self._rate_limit()
            
            url = f"{self.nvd_base_url}"
            params = {
                'keywordSearch': f"{product} {version}" if version else product,
                'resultsPerPage': min(limit, 2000)
            }
            
            headers = {}
            if self.nvd_api_key:
                headers['apiKey'] = self.nvd_api_key
            
            response = requests.get(url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            cves = []
            
            for vuln in data.get('vulnerabilities', []):
                cve_info = self._parse_nvd_cve(vuln['cve'])
                if cve_info:
                    cves.append(cve_info)
            
            return cves
            
        except Exception as e:
            self.logger.error(f"NVD product search failed for {product}: {str(e)}")
            return []
    
    def _parse_nvd_cve(self, cve_data: Dict[str, Any]) -> Optional[CVEInfo]:
        """Parse NVD CVE data into CVEInfo object"""
        try:
            cve_id = cve_data['id']
            
            # Description
            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc['value']
                    break
            
            # CVSS scoring
            cvss_score = 0.0
            cvss_vector = ''
            severity = 'unknown'
            
            metrics = cve_data.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_vector = cvss_data.get('vectorString', '')
                severity = cvss_data.get('baseSeverity', '').lower()
            elif 'cvssMetricV30' in metrics:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_vector = cvss_data.get('vectorString', '')
                severity = cvss_data.get('baseSeverity', '').lower()
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_vector = cvss_data.get('vectorString', '')
                if cvss_score >= 7.0:
                    severity = 'high'
                elif cvss_score >= 4.0:
                    severity = 'medium'
                else:
                    severity = 'low'
            
            # Dates
            published = cve_data.get('published', '')
            modified = cve_data.get('lastModified', '')
            
            # References
            references = []
            for ref in cve_data.get('references', []):
                references.append(ref.get('url', ''))
            
            # CWE IDs
            cwe_ids = []
            for weakness in cve_data.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_ids.append(desc['value'])
            
            # Affected products (simplified)
            affected_products = []
            for config in cve_data.get('configurations', []):
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('vulnerable', False):
                            cpe_name = cpe_match.get('criteria', '')
                            affected_products.append(cpe_name)
            
            return CVEInfo(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                published_date=published,
                modified_date=modified,
                references=references,
                cwe_ids=cwe_ids,
                affected_products=affected_products,
                exploit_available=False,  # Will be updated by exploit check
                patch_available=False     # Will be updated by patch check
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse NVD CVE data: {str(e)}")
            return None
    
    def _search_mitre_cve(self, cve_id: str) -> Optional[CVEInfo]:
        """Search MITRE for CVE information"""
        # Placeholder for MITRE integration
        return None
    
    def _update_from_nvd(self) -> int:
        """Update CVE database from NVD"""
        # Placeholder for full NVD database sync
        return 0
    
    def _update_exploit_info(self) -> int:
        """Update exploit availability information"""
        # Placeholder for exploit database integration
        return 0
    
    def _update_github_advisories(self) -> int:
        """Update GitHub security advisories"""
        # Placeholder for GitHub advisory integration
        return 0
    
    def _get_cached_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get CVE from cache"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM cve_data WHERE cve_id = ?
            ''', (cve_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                columns = ['cve_id', 'description', 'severity', 'cvss_score', 'cvss_vector',
                          'published_date', 'modified_date', 'reference_urls', 'cwe_ids',
                          'affected_products', 'exploit_available', 'patch_available',
                          'cached_date', 'source']
                return dict(zip(columns, row))
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get cached CVE: {str(e)}")
            return None
    
    def _cache_cve(self, cve_info: CVEInfo):
        """Cache CVE information"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO cve_data 
                (cve_id, description, severity, cvss_score, cvss_vector,
                 published_date, modified_date, reference_urls, cwe_ids,
                 affected_products, exploit_available, patch_available,
                 cached_date, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_info.cve_id,
                cve_info.description,
                cve_info.severity,
                cve_info.cvss_score,
                cve_info.cvss_vector,
                cve_info.published_date,
                cve_info.modified_date,
                json.dumps(cve_info.references),
                json.dumps(cve_info.cwe_ids),
                json.dumps(cve_info.affected_products),
                int(cve_info.exploit_available),
                int(cve_info.patch_available),
                datetime.now().isoformat(),
                'nvd'
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to cache CVE: {str(e)}")
    
    def _cache_correlation(self, product: str, version: str, cve_id: str, confidence: float):
        """Cache product-CVE correlation"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO vuln_correlation
                (product_name, version, cve_id, confidence, created_date)
                VALUES (?, ?, ?, ?, ?)
            ''', (product, version, cve_id, confidence, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to cache correlation: {str(e)}")
    
    def _get_cached_product_cves(self, product: str, version: str) -> List[Dict[str, Any]]:
        """Get cached CVEs for a product"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if version:
                cursor.execute('''
                    SELECT c.* FROM cve_data c
                    JOIN vuln_correlation v ON c.cve_id = v.cve_id
                    WHERE v.product_name = ? AND v.version = ?
                    ORDER BY c.cvss_score DESC
                ''', (product, version))
            else:
                cursor.execute('''
                    SELECT c.* FROM cve_data c
                    JOIN vuln_correlation v ON c.cve_id = v.cve_id
                    WHERE v.product_name = ?
                    ORDER BY c.cvss_score DESC
                ''', (product,))
            
            rows = cursor.fetchall()
            conn.close()
            
            columns = ['cve_id', 'description', 'severity', 'cvss_score', 'cvss_vector',
                      'published_date', 'modified_date', 'references', 'cwe_ids',
                      'affected_products', 'exploit_available', 'patch_available',
                      'cached_date', 'source']
            
            return [dict(zip(columns, row)) for row in rows]
            
        except Exception as e:
            self.logger.error(f"Failed to get cached product CVEs: {str(e)}")
            return []
    
    def _get_correlated_cves(self, product: str, version: str) -> List[CVEInfo]:
        """Get correlated CVEs for product/version"""
        cached_data = self._get_cached_product_cves(product, version)
        return [self._dict_to_cve_info(data) for data in cached_data if self._is_cache_fresh(data['cached_date'])]
    
    def _dict_to_cve_info(self, data: Dict[str, Any]) -> CVEInfo:
        """Convert dictionary to CVEInfo object"""
        return CVEInfo(
            cve_id=data['cve_id'],
            description=data['description'],
            severity=data['severity'],
            cvss_score=data['cvss_score'],
            cvss_vector=data['cvss_vector'],
            published_date=data['published_date'],
            modified_date=data['modified_date'],
            references=json.loads(data['reference_urls']) if data.get('reference_urls') else [],
            cwe_ids=json.loads(data['cwe_ids']) if data['cwe_ids'] else [],
            affected_products=json.loads(data['affected_products']) if data['affected_products'] else [],
            exploit_available=bool(data['exploit_available']),
            patch_available=bool(data['patch_available'])
        )
    
    def _is_cache_fresh(self, cached_date: str) -> bool:
        """Check if cached data is still fresh"""
        try:
            cached = datetime.fromisoformat(cached_date)
            age = datetime.now() - cached
            return age.days < self.cache_days
        except Exception:
            return False
    
    def _is_recent_update(self) -> bool:
        """Check if database was recently updated"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT value FROM metadata WHERE key = 'last_update'
            ''')
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                last_update = datetime.fromisoformat(result[0])
                age = datetime.now() - last_update
                return age.total_seconds() < self.update_frequency * 3600
            
            return False
            
        except Exception:
            return False
    
    def _record_update_timestamp(self):
        """Record last update timestamp"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create metadata table if it doesn't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            ''')
            
            cursor.execute('''
                INSERT OR REPLACE INTO metadata (key, value)
                VALUES ('last_update', ?)
            ''', (datetime.now().isoformat(),))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to record update timestamp: {str(e)}")
    
    def _rate_limit(self):
        """Implement rate limiting for API calls"""
        with self.request_lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            min_interval = 1.0 / self.rate_limit
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                time.sleep(sleep_time)
            
            self.last_request_time = time.time()

if __name__ == "__main__":
    # Test CVE lookup
    config = {
        'cve_sources': {'nvd_api_key': ''},
        'database': {'db_path': 'test_cve.db'}
    }
    
    cve_lookup = CVELookup(config)
    
    # Test vulnerability lookup
    test_vuln = {
        'service': 'apache',
        'version': '2.4.41',
        'banner': 'Apache/2.4.41 (Ubuntu)'
    }
    
    result = cve_lookup.lookup_vulnerability(test_vuln)
    if result:
        print(f"Found {result['total_cves']} CVEs")
        print(f"Highest CVSS: {result['highest_cvss_score']}")
        print(f"CVE IDs: {result['cve_ids'][:5]}")
    else:
        print("No CVEs found")
    
    # Test statistics
    stats = cve_lookup.get_cve_statistics()
    print(f"CVE Database Stats: {stats}")
