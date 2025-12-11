"""
CVE Intelligence and Correlation Plugin
Advanced CVE lookup, correlation, and vulnerability intelligence

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
import sys

sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from plugin import VulnPlugin, VulnerabilityFinding, PluginMetadata

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

class CVEIntelligencePlugin(VulnPlugin):
    """
    CVE Intelligence and Correlation Plugin
    
    Features:
    - Integration with NVD and multiple CVE data sources
    - Service-to-CVE correlation
    - Exploit availability checking
    - Patch status tracking
    - Local CVE database caching
    - Automatic vulnerability enrichment
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.metadata = PluginMetadata(
            name="CVE Intelligence Plugin",
            version="2.0.0",
            author="Devdas",
            description="Advanced CVE lookup, correlation, and vulnerability intelligence",
            category="intelligence",
            tags=["cve", "nvd", "correlation", "exploit", "intelligence"]
        )
        
        # CVE Configuration
        self.cve_config = config.get('cve_sources', {}) if config else {}
        self.nvd_api_key = self.cve_config.get('nvd_api_key', '')
        self.nvd_base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        
        # Database configuration
        self.db_path = config.get('database', {}).get('db_path', 'data/vulnsleuth.db') if config else 'data/vulnsleuth.db'
        self.cache_days = self.cve_config.get('cve_cache_days', 7)
        
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
            'tomcat': [r'tomcat[\s/](\d+\.[\d.]+)'],
            'redis': [r'redis[\s/](\d+\.[\d.]+)'],
            'mongodb': [r'mongodb[\s/](\d+\.[\d.]+)'],
            'elasticsearch': [r'elasticsearch[\s/](\d+\.[\d.]+)'],
        }
    
    def can_run(self, target: str, context: Dict[str, Any]) -> bool:
        """This plugin can enrich any scan with CVE intelligence"""
        return True
    
    def check(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """
        Perform CVE correlation for detected services
        
        Args:
            target: Target to analyze
            **kwargs: Additional scan parameters including service detection results
            
        Returns:
            List of vulnerability findings with CVE correlation
        """
        context = kwargs.get('context', {})
        return self.execute(target, context)
    
    def execute(self, target: str, context: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Execute CVE correlation against detected services"""
        findings = []
        
        try:
            # Get detected services from context
            services = context.get('detected_services', [])
            
            if not services:
                self.logger.info("No services detected for CVE correlation")
                return findings
            
            # Correlate CVEs for each service
            for service in services:
                service_findings = self._correlate_service_cves(target, service)
                findings.extend(service_findings)
            
            self.logger.info(f"CVE correlation complete for {target}: {len(findings)} findings")
            
        except Exception as e:
            self.logger.error(f"CVE correlation failed for {target}: {str(e)}")
        
        return findings
    
    def _correlate_service_cves(self, target: str, service: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Correlate CVEs for a detected service"""
        findings = []
        
        try:
            # Extract product and version
            products = self._extract_products_from_service(service)
            
            if not products:
                return findings
            
            # Look up CVEs for each identified product
            for product_name, version in products:
                cves = self._lookup_product_cves(product_name, version)
                
                for cve in cves[:10]:  # Top 10 most relevant CVEs
                    finding = self._create_cve_finding(target, service, cve, product_name, version)
                    findings.append(finding)
            
        except Exception as e:
            self.logger.error(f"Service CVE correlation failed: {str(e)}")
        
        return findings
    
    def _create_cve_finding(self, target: str, service: Dict[str, Any], cve: CVEInfo, product: str, version: str) -> VulnerabilityFinding:
        """Create a vulnerability finding from CVE data"""
        
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'unknown': 'info'
        }
        
        title = f"{cve.cve_id}: {product} {version} Vulnerability"
        
        description = f"CVE {cve.cve_id} affects {product} version {version}.\n\n"
        description += f"Description: {cve.description}\n\n"
        description += f"CVSS Score: {cve.cvss_score} ({cve.severity.upper()})\n"
        description += f"CVSS Vector: {cve.cvss_vector}\n\n"
        
        if cve.cwe_ids:
            description += f"CWE IDs: {', '.join(cve.cwe_ids)}\n"
        
        if cve.exploit_available:
            description += "\n⚠️  PUBLIC EXPLOIT AVAILABLE\n"
        
        solution = "Update the affected software to a patched version. "
        if cve.patch_available:
            solution += "Patches are available for this vulnerability."
        else:
            solution += "Check vendor advisories for available patches or workarounds."
        
        return self.create_finding(
            title=title,
            severity=severity_map.get(cve.severity, 'medium'),
            description=description,
            target=target,
            confidence=0.9 if cve.exploit_available else 0.7,
            port=service.get('port'),
            service=service.get('name'),
            solution=solution,
            references=cve.references[:5],  # Top 5 references
            cve_ids=[cve.cve_id],
            metadata={
                'cvss_score': cve.cvss_score,
                'cvss_vector': cve.cvss_vector,
                'published_date': cve.published_date,
                'exploit_available': cve.exploit_available,
                'patch_available': cve.patch_available,
                'product': product,
                'version': version,
                'cwe_ids': cve.cwe_ids
            }
        )
    
    def _extract_products_from_service(self, service: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Extract product and version information from service data"""
        products = []
        
        banner = service.get('banner', '').lower()
        service_name = service.get('name', '').lower()
        version = service.get('version', '').lower()
        
        search_text = f"{banner} {service_name} {version}".strip()
        
        if not search_text:
            return products
        
        # Match against known product patterns
        for product_name, patterns in self.product_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, search_text, re.IGNORECASE)
                for match in matches:
                    ver = match if isinstance(match, str) else match[0] if isinstance(match, tuple) else str(match)
                    products.append((product_name, ver))
        
        return list(set(products))
    
    def _lookup_product_cves(self, product: str, version: str) -> List[CVEInfo]:
        """Look up CVEs for a specific product/version"""
        # Check cache first
        cached_cves = self._get_cached_product_cves(product, version)
        
        if cached_cves and len(cached_cves) > 0:
            recent_cache = [cve for cve in cached_cves if self._is_cache_fresh(cve['cached_date'])]
            if len(recent_cache) > 5:
                return [self._dict_to_cve_info(cve) for cve in recent_cache[:20]]
        
        # Search online if not enough cached data
        online_cves = self._search_nvd_product(product, version, 20)
        
        # Cache results
        for cve in online_cves:
            self._cache_cve(cve)
            self._cache_correlation(product, version, cve.cve_id, 0.8)
        
        return online_cves
    
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
            
            descriptions = cve_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc['value']
                    break
            
            cvss_score = 0.0
            cvss_vector = ''
            severity = 'unknown'
            
            metrics = cve_data.get('metrics', {})
            if 'cvssMetricV31' in metrics and len(metrics['cvssMetricV31']) > 0:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_vector = cvss_data.get('vectorString', '')
                severity = cvss_data.get('baseSeverity', '').lower()
            elif 'cvssMetricV30' in metrics and len(metrics['cvssMetricV30']) > 0:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                cvss_vector = cvss_data.get('vectorString', '')
                severity = cvss_data.get('baseSeverity', '').lower()
            
            published = cve_data.get('published', '')
            modified = cve_data.get('lastModified', '')
            
            references = []
            for ref in cve_data.get('references', []):
                references.append(ref.get('url', ''))
            
            cwe_ids = []
            for weakness in cve_data.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_ids.append(desc['value'])
            
            affected_products = []
            
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
                exploit_available=False,
                patch_available=False
            )
            
        except Exception as e:
            self.logger.error(f"Failed to parse NVD CVE data: {str(e)}")
            return None
    
    def _init_database(self):
        """Initialize SQLite database for CVE caching"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
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
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_correlation_product ON vuln_correlation (product_name, version)')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize CVE database: {str(e)}")
    
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
                      'published_date', 'modified_date', 'reference_urls', 'cwe_ids',
                      'affected_products', 'exploit_available', 'patch_available',
                      'cached_date', 'source']
            
            return [dict(zip(columns, row)) for row in rows]
            
        except Exception as e:
            self.logger.error(f"Failed to get cached product CVEs: {str(e)}")
            return []
    
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
            cwe_ids=json.loads(data['cwe_ids']) if data.get('cwe_ids') else [],
            affected_products=json.loads(data['affected_products']) if data.get('affected_products') else [],
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
