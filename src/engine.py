"""
VulnSleuth Scan Engine
Core scanning engine with scheduling and orchestration capabilities

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import threading
import queue
import time
import asyncio
import concurrent.futures
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import json
import logging
from contextlib import contextmanager

from checks.local_checks import LocalSecurityChecker
from checks.network_checks import NetworkSecurityChecker
from checks.webapp_checks import WebAppSecurityChecker
from db import DatabaseManager
from utils import Logger, NetworkUtils, SecurityUtils, ProgressTracker, ThreadSafeLogger, SecurityContext, ScanMetrics

logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    id: str
    target: str
    vulnerability: str
    severity: str
    confidence: float
    description: str
    solution: str
    cve_ids: List[str]
    references: List[str]
    plugin_source: str
    timestamp: datetime
    scan_id: str
    metadata: Dict[str, Any]

@dataclass
class ScanJob:
    """Represents a scanning job"""
    job_id: str
    target: str
    config: Dict[str, Any]
    priority: int
    created_at: datetime
    status: str = 'pending'
    progress: float = 0.0
    results: List[ScanResult] = None
    error: str = None

class VulnSleuthEngine:
    """
    Main vulnerability scanning engine with multi-threading,
    scheduling, and plugin orchestration capabilities.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = ThreadSafeLogger('VulnSleuthEngine')
        
        # Initialize components
        self.db = DatabaseManager(config)
        
        # Lazy import to avoid circular dependency
        from plugin import PluginManager
        self.plugin_manager = PluginManager(config)
        
        # Initialize checkers
        self.local_checker = LocalSecurityChecker(config)
        self.network_checker = NetworkSecurityChecker(config)
        self.webapp_checker = WebAppSecurityChecker(config)
        
        # Threading and job management
        self.max_threads = int(config.get('general', {}).get('max_threads', 10))
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads)
        self.job_queue = queue.PriorityQueue()
        self.active_jobs = {}
        self.job_results = {}
        self.shutdown_event = threading.Event()
        
        # Metrics and monitoring
        self.metrics = ScanMetrics()
        self.scan_history = []
        
        # Start background worker
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        
        self.logger.info("VulnSleuth Engine initialized")

    def scan(self, scan_config: Dict[str, Any], progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """
        Perform comprehensive vulnerability scan
        
        Args:
            scan_config: Scan configuration parameters
            progress_callback: Optional progress update callback
            
        Returns:
            List of vulnerability findings
        """
        scan_id = f"scan_{int(time.time())}"
        target = scan_config['target']
        
        self.logger.info(f"Starting scan {scan_id} on target {target}")
        
        # Initialize progress tracking
        total_phases = self._count_scan_phases(scan_config)
        current_phase = 0
        
        def update_progress(phase_progress: float = 0):
            nonlocal current_phase
            if progress_callback:
                overall_progress = (current_phase + phase_progress) / total_phases * 100
                progress_callback(min(overall_progress, 100))
        
        all_results = []
        scan_context = SecurityContext(target, scan_config)
        
        try:
            with self._scan_context(scan_id, scan_context):
                
                # Phase 1: Network Discovery and Port Scanning
                if scan_config.get('network_checks', True):
                    self.logger.info("Phase 1: Network discovery and port scanning")
                    update_progress(0)
                    
                    try:
                        network_results = self._run_network_discovery(scan_config, update_progress)
                        all_results.extend(network_results)
                    except Exception as e:
                        self.logger.error(f"Network discovery phase failed: {str(e)}")
                        import traceback
                        self.logger.error(f"Traceback: {traceback.format_exc()}")
                        raise e
                    
                    current_phase += 1
                    update_progress(0)
                
                # Phase 2: Service Detection and Enumeration
                if scan_config.get('network_checks', True):
                    self.logger.info("Phase 2: Service detection and enumeration")
                    
                    service_results = self._run_service_detection(scan_config, update_progress)
                    all_results.extend(service_results)
                    
                    current_phase += 1
                    update_progress(0)
                
                # Phase 3: Local System Checks
                if scan_config.get('local_checks', False):
                    self.logger.info("Phase 3: Local system security checks")
                    
                    local_results = self._run_local_checks(scan_config, update_progress)
                    all_results.extend(local_results)
                    
                    current_phase += 1
                    update_progress(0)
                
                # Phase 4: Web Application Security Testing
                if scan_config.get('webapp_checks', False):
                    self.logger.info("Phase 4: Web application security testing")
                    
                    webapp_results = self._run_webapp_checks(scan_config, update_progress)
                    all_results.extend(webapp_results)
                    
                    current_phase += 1
                    update_progress(0)
                
                # Phase 5: Plugin Execution
                if scan_config.get('plugins'):
                    self.logger.info("Phase 5: Running custom plugins")
                    
                    plugin_results = self._run_plugins(scan_config, update_progress)
                    all_results.extend(plugin_results)
                    
                    current_phase += 1
                    update_progress(0)
                
                # Phase 6: CVE Correlation and Enrichment
                self.logger.info("Phase 6: CVE correlation and vulnerability enrichment")
                
                enriched_results = self._enrich_with_cve_data(all_results, update_progress)
                
                current_phase += 1
                update_progress(0)
                
                # Phase 7: Risk Assessment and Prioritization
                self.logger.info("Phase 7: Risk assessment and prioritization")
                
                prioritized_results = self._assess_and_prioritize(enriched_results, scan_config)
                
                current_phase += 1
                update_progress(100)
                
                # Update metrics
                self.metrics.targets_scanned += 1
                self.metrics.vulnerabilities_found = len(prioritized_results)
                self.metrics.finish()
                
                self.logger.info(f"Scan {scan_id} completed with {len(prioritized_results)} findings")
                
                return prioritized_results
                
        except Exception as e:
            self.logger.error(f"Scan {scan_id} failed: {str(e)}")
            raise
    
    def schedule_scan(self, scan_config: Dict[str, Any], priority: int = 5) -> str:
        """
        Schedule a scan job for background execution
        
        Args:
            scan_config: Scan configuration
            priority: Job priority (lower = higher priority)
            
        Returns:
            Job ID for tracking
        """
        job_id = f"job_{int(time.time() * 1000)}"
        
        job = ScanJob(
            job_id=job_id,
            target=scan_config['target'],
            config=scan_config,
            priority=priority,
            created_at=datetime.now()
        )
        
        self.job_queue.put((priority, job))
        self.active_jobs[job_id] = job
        
        self.logger.info(f"Scheduled scan job {job_id} for target {job.target}")
        
        return job_id
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a scheduled job"""
        job = self.active_jobs.get(job_id)
        if job:
            return {
                'job_id': job.job_id,
                'target': job.target,
                'status': job.status,
                'progress': job.progress,
                'created_at': job.created_at.isoformat(),
                'error': job.error
            }
        return None
    
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a scheduled or running job"""
        if job_id in self.active_jobs:
            job = self.active_jobs[job_id]
            job.status = 'cancelled'
            self.logger.info(f"Job {job_id} cancelled")
            return True
        return False
    
    def get_scan_metrics(self) -> Dict[str, Any]:
        """Get scanning engine metrics"""
        return {
            'total_scans': self.metrics.total_scans,
            'active_jobs': len([j for j in self.active_jobs.values() if j.status == 'running']),
            'queued_jobs': self.job_queue.qsize(),
            'average_scan_time': self.metrics.average_scan_time,
            'last_scan_time': self.metrics.last_scan_time,
            'thread_pool_active': self.thread_pool._threads,
            'uptime': time.time() - self.metrics.start_time
        }
    
    def _worker_loop(self):
        """Background worker thread for processing scan jobs"""
        while not self.shutdown_event.is_set():
            try:
                # Get next job with timeout
                priority, job = self.job_queue.get(timeout=1.0)
                
                if job.status == 'cancelled':
                    continue
                
                self.logger.info(f"Processing job {job.job_id}")
                job.status = 'running'
                
                # Execute scan
                try:
                    def progress_update(progress):
                        job.progress = progress
                    
                    results = self.scan(job.config, progress_update)
                    
                    job.results = results
                    job.status = 'completed'
                    job.progress = 100.0
                    
                    # Store results
                    self.job_results[job.job_id] = results
                    
                    self.logger.info(f"Job {job.job_id} completed successfully")
                    
                except Exception as e:
                    job.status = 'failed'
                    job.error = str(e)
                    self.logger.error(f"Job {job.job_id} failed: {str(e)}")
                
                finally:
                    self.job_queue.task_done()
            
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Worker thread error: {str(e)}")
    
    def _run_network_discovery(self, scan_config: Dict[str, Any], progress_callback: Callable) -> List[Dict[str, Any]]:
        """Run network discovery phase using plugins"""
        results = []
        target = scan_config['target']
        
        try:
            progress_callback(0.1)
            self.logger.info(f"Starting network discovery for {target}")
            
            # Use network reconnaissance plugin if available
            network_plugins = [p for p in self.plugin_manager.get_all_plugins() 
                             if p.metadata.category == 'network' and 'reconnaissance' in p.name.lower()]
            
            if network_plugins:
                self.logger.info("Using network reconnaissance plugin")
                plugin = network_plugins[0]
                context = {'target': target, 'ports': scan_config.get('ports', '1-1000')}
                
                progress_callback(0.5)
                plugin_results = plugin.check(target, context=context)
                
                # Convert plugin findings to results format
                for finding in plugin_results:
                    results.append({
                        'vulnerability': finding.title,
                        'severity': finding.severity,
                        'description': finding.description,
                        'solution': finding.solution,
                        'target': target,
                        'port': finding.port,
                        'service': finding.service,
                        'confidence': finding.confidence,
                        'cve_ids': finding.cve_ids,
                        'references': finding.references,
                        'metadata': finding.metadata
                    })
                
                progress_callback(0.8)
            else:
                self.logger.warning("No network reconnaissance plugin found, using basic checks")
                # Fallback to basic network checks
                network_vulns = self.network_checker.check_network_vulnerabilities(target, {})
                results.extend(network_vulns)
            
            progress_callback(1.0)
            self.logger.info(f"Network discovery completed, found {len(results)} findings")
            return results
        
        except Exception as e:
            self.logger.error(f"Error in network discovery: {str(e)}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            # Return empty results instead of raising to allow scan to continue
            return results
    
    def _run_service_detection(self, scan_config: Dict[str, Any], progress_callback: Callable) -> List[Dict[str, Any]]:
        """Run service detection and enumeration using plugins"""
        results = []
        target = scan_config['target']
        
        try:
            progress_callback(0.2)
            self.logger.info(f"Starting service detection for {target}")
            
            # Service detection is now part of network reconnaissance plugin
            # Use basic service checks as fallback
            progress_callback(0.5)
            service_vulns = self.network_checker.check_service_vulnerabilities({})
            results.extend(service_vulns)
            
            progress_callback(1.0)
            self.logger.info(f"Service detection completed")
        except Exception as e:
            self.logger.error(f"Service detection failed: {str(e)}")
        
        return results
    
    def _run_local_checks(self, scan_config: Dict[str, Any], progress_callback: Callable) -> List[Dict[str, Any]]:
        """Run local system security checks"""
        results = []
        
        # File system checks
        progress_callback(0.2)
        fs_vulns = self.local_checker.check_file_permissions()
        results.extend(fs_vulns)
        
        # User and access controls
        progress_callback(0.4)
        access_vulns = self.local_checker.check_user_accounts()
        results.extend(access_vulns)
        
        # Service configuration
        progress_callback(0.6)
        service_vulns = self.local_checker.check_service_configurations()
        results.extend(service_vulns)
        
        # System hardening
        progress_callback(0.8)
        hardening_vulns = self.local_checker.check_system_hardening()
        results.extend(hardening_vulns)
        
        progress_callback(1.0)
        return results
    
    def _run_webapp_checks(self, scan_config: Dict[str, Any], progress_callback: Callable) -> List[Dict[str, Any]]:
        """Run web application security tests"""
        results = []
        target = scan_config['target']
        
        # HTTP security headers
        progress_callback(0.2)
        header_vulns = self.webapp_checker.check_security_headers(target)
        results.extend(header_vulns)
        
        # SSL/TLS configuration
        progress_callback(0.4)
        ssl_vulns = self.webapp_checker.check_ssl_configuration(target)
        results.extend(ssl_vulns)
        
        # Common web vulnerabilities
        progress_callback(0.7)
        web_vulns = self.webapp_checker.check_common_vulnerabilities(target)
        results.extend(web_vulns)
        
        # Content security policy
        progress_callback(0.9)
        csp_vulns = self.webapp_checker.check_content_security_policy(target)
        results.extend(csp_vulns)
        
        progress_callback(1.0)
        return results
    
    def _run_plugins(self, scan_config: Dict[str, Any], progress_callback: Callable) -> List[Dict[str, Any]]:
        """Execute custom vulnerability scanning plugins"""
        results = []
        plugins = scan_config.get('plugins', [])
        exclude_plugins = scan_config.get('exclude_plugins', [])
        
        # Filter plugins
        active_plugins = [p for p in plugins if p not in exclude_plugins]
        
        for i, plugin_name in enumerate(active_plugins):
            progress = (i + 1) / len(active_plugins)
            progress_callback(progress)
            
            try:
                plugin_results = self.plugin_manager.execute_plugin(plugin_name, scan_config)
                results.extend(plugin_results)
            except Exception as e:
                self.logger.error(f"Plugin {plugin_name} failed: {str(e)}")
        
        return results
    
    def _enrich_with_cve_data(self, results: List[Dict[str, Any]], progress_callback: Callable) -> List[Dict[str, Any]]:
        """Enrich vulnerability results with CVE data using CVE intelligence plugin"""
        enriched_results = []
        
        try:
            # Find CVE intelligence plugin
            cve_plugins = [p for p in self.plugin_manager.get_all_plugins() 
                          if p.metadata.category == 'intelligence' and 'cve' in p.name.lower()]
            
            if not cve_plugins:
                self.logger.warning("No CVE intelligence plugin found, skipping CVE enrichment")
                return results
            
            # CVE enrichment is handled by the CVE intelligence plugin during its execution
            # The plugin correlates services with CVEs automatically
            # Just return the results as-is since CVE data should already be included
            enriched_results = results
            
            for i, result in enumerate(enriched_results):
                progress = (i + 1) / len(enriched_results) if enriched_results else 1.0
                progress_callback(progress)
            
            self.logger.info(f"CVE enrichment completed for {len(enriched_results)} results")
        
        except Exception as e:
            self.logger.error(f"CVE enrichment failed: {str(e)}")
            enriched_results = results
        
        return enriched_results
    
    def _assess_and_prioritize(self, results: List[Dict[str, Any]], scan_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Assess risk and prioritize vulnerabilities"""
        # Risk scoring algorithm
        for result in results:
            risk_score = self._calculate_risk_score(result, scan_config)
            result['risk_score'] = risk_score
        
        # Sort by risk score (highest first)
        prioritized = sorted(results, key=lambda x: x.get('risk_score', 0), reverse=True)
        
        # Filter by severity threshold
        severity_threshold = scan_config.get('severity_threshold', 'low')
        severity_levels = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        threshold_level = severity_levels.get(severity_threshold.lower() if isinstance(severity_threshold, str) else str(severity_threshold).lower(), 1)
        
        filtered_results = []
        for r in prioritized:
            result_severity = r.get('severity', 'info')
            # Ensure severity is a string for proper comparison
            result_severity = result_severity.lower() if isinstance(result_severity, str) else str(result_severity).lower()
            result_level = severity_levels.get(result_severity, 0)
            
            if result_level >= threshold_level:
                filtered_results.append(r)
        
        return filtered_results
    
    def _calculate_risk_score(self, result: Dict[str, Any], scan_config: Dict[str, Any]) -> float:
        """Calculate risk score for a vulnerability"""
        base_scores = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        severity = result.get('severity', 'info')
        base_score = base_scores.get(severity, 1.0)
        
        # Adjust based on factors
        confidence = result.get('confidence', 0.5)
        exploitability = result.get('exploitability', 0.5)
        network_exposure = 1.0 if scan_config.get('network_checks') else 0.5
        
        # CVSS score if available
        cvss_score = result.get('cvss_score', 0)
        if cvss_score:
            base_score = max(base_score, cvss_score)
        
        # Final risk calculation
        risk_score = base_score * confidence * exploitability * network_exposure
        
        return min(risk_score, 10.0)  # Cap at 10.0
    
    def _count_scan_phases(self, scan_config: Dict[str, Any]) -> int:
        """Count the number of scan phases to execute"""
        phases = 2  # CVE enrichment and risk assessment are always done
        
        if scan_config.get('network_checks', True):
            phases += 2  # Network discovery + service detection
        if scan_config.get('local_checks', False):
            phases += 1
        if scan_config.get('webapp_checks', False):
            phases += 1
        if scan_config.get('plugins'):
            phases += 1
        
        return phases
    
    @contextmanager
    def _scan_context(self, scan_id: str, context: SecurityContext):
        """Context manager for scan execution"""
        try:
            self.logger.info(f"Entering scan context for {scan_id}")
            context.start_time = time.time()
            yield context
        finally:
            context.end_time = time.time()
            context.duration = context.end_time - context.start_time
            self.logger.info(f"Exiting scan context for {scan_id}, duration: {context.duration:.2f}s")
    
    def shutdown(self):
        """Graceful shutdown of the scanning engine"""
        self.logger.info("Shutting down VulnSleuth Engine...")
        
        self.shutdown_event.set()
        
        # Cancel all pending jobs
        while not self.job_queue.empty():
            try:
                priority, job = self.job_queue.get_nowait()
                job.status = 'cancelled'
            except queue.Empty:
                break
        
        # Wait for worker thread
        if self.worker_thread.is_alive():
            self.worker_thread.join(timeout=30)
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        self.logger.info("VulnSleuth Engine shutdown complete")

if __name__ == '__main__':
    # Worker mode for distributed scanning
    import argparse
    from utils import ConfigManager
    
    parser = argparse.ArgumentParser(description='VulnSleuth Scan Engine')
    parser.add_argument('--worker', action='store_true', help='Run in worker mode')
    parser.add_argument('--config', default='vulnsluth.cfg', help='Configuration file')
    
    args = parser.parse_args()
    
    config_manager = ConfigManager()
    config = config_manager.load_config(args.config)
    engine = VulnSleuthEngine(config)
    
    if args.worker:
        print("Starting VulnSleuth worker...")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Worker shutting down...")
            engine.shutdown()
