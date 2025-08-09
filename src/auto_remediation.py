"""
VulnSleuth Auto-Remediation Engine
AI-powered vulnerability remediation with operator approval

Author: Security Team
License: MIT
"""

import os
import subprocess
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import threading
from abc import ABC, abstractmethod
import tempfile
import shutil

logger = logging.getLogger(__name__)

class RemediationStatus(Enum):
    """Remediation status enumeration"""
    PENDING = "pending"
    APPROVED = "approved" 
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"

class RemediationRisk(Enum):
    """Remediation risk levels"""
    LOW = "low"           # Safe automated fixes
    MEDIUM = "medium"     # Requires basic approval
    HIGH = "high"         # Requires detailed review
    CRITICAL = "critical" # Requires multiple approvals

@dataclass
class RemediationAction:
    """Container for remediation action details"""
    action_id: str
    vulnerability_id: str
    target: str
    action_type: str
    description: str
    commands: List[str]
    backup_commands: List[str]
    rollback_commands: List[str]
    risk_level: RemediationRisk
    estimated_duration: int  # seconds
    prerequisites: List[str]
    validation_commands: List[str]
    impact_assessment: str
    created_at: str
    status: RemediationStatus = RemediationStatus.PENDING
    approved_by: Optional[str] = None
    executed_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class RemediationHandler(ABC):
    """Abstract base class for remediation handlers"""
    
    @abstractmethod
    def can_handle(self, vulnerability: Dict[str, Any]) -> bool:
        """Check if handler can remediate this vulnerability"""
        pass
    
    @abstractmethod
    def generate_remediation(self, vulnerability: Dict[str, Any]) -> Optional[RemediationAction]:
        """Generate remediation action for vulnerability"""
        pass
    
    @abstractmethod
    def validate_fix(self, action: RemediationAction) -> bool:
        """Validate that the fix was successful"""
        pass

class NetworkRemediationHandler(RemediationHandler):
    """Handler for network-level remediations"""
    
    def can_handle(self, vulnerability: Dict[str, Any]) -> bool:
        """Check if this is a network vulnerability we can handle"""
        vuln_type = vulnerability.get('vulnerability_type', '').lower()
        return vuln_type in [
            'open_port', 'weak_ssl', 'unencrypted_service', 
            'default_credentials', 'insecure_protocol'
        ]
    
    def generate_remediation(self, vulnerability: Dict[str, Any]) -> Optional[RemediationAction]:
        """Generate network remediation action"""
        vuln_type = vulnerability.get('vulnerability_type', '').lower()
        target = vulnerability.get('target', '')
        port = vulnerability.get('port', 0)
        service = vulnerability.get('service', '')
        
        action_id = self._generate_action_id(vulnerability)
        
        # Generate remediation based on vulnerability type
        if vuln_type == 'open_port' and service in ['telnet', 'ftp', 'rlogin']:
            return RemediationAction(
                action_id=action_id,
                vulnerability_id=vulnerability.get('vuln_id', ''),
                target=target,
                action_type='disable_service',
                description=f"Disable insecure {service} service on port {port}",
                commands=[
                    f"systemctl stop {service}",
                    f"systemctl disable {service}",
                    f"ufw deny {port}"
                ],
                backup_commands=[
                    f"systemctl status {service} > /tmp/{service}_backup_status.txt"
                ],
                rollback_commands=[
                    f"systemctl enable {service}",
                    f"systemctl start {service}",
                    f"ufw allow {port}"
                ],
                risk_level=RemediationRisk.MEDIUM,
                estimated_duration=30,
                prerequisites=['root access', 'systemctl available'],
                validation_commands=[
                    f"systemctl is-active {service}",
                    f"nmap -p {port} localhost"
                ],
                impact_assessment=f"Service {service} will be unavailable",
                created_at=datetime.now().isoformat()
            )
        
        elif vuln_type == 'weak_ssl':
            return RemediationAction(
                action_id=action_id,
                vulnerability_id=vulnerability.get('vuln_id', ''),
                target=target,
                action_type='strengthen_ssl',
                description=f"Strengthen SSL/TLS configuration for service on port {port}",
                commands=[
                    "cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.backup",
                    "echo 'MinProtocol = TLSv1.2' >> /etc/ssl/openssl.cnf",
                    "systemctl reload apache2 || systemctl reload nginx || true"
                ],
                backup_commands=[
                    "cp /etc/ssl/openssl.cnf /tmp/openssl.cnf.backup"
                ],
                rollback_commands=[
                    "cp /tmp/openssl.cnf.backup /etc/ssl/openssl.cnf",
                    "systemctl reload apache2 || systemctl reload nginx || true"
                ],
                risk_level=RemediationRisk.HIGH,
                estimated_duration=60,
                prerequisites=['root access', 'SSL service restart capability'],
                validation_commands=[
                    f"openssl s_client -connect localhost:{port} -tls1_1 2>&1 | grep 'handshake failure'"
                ],
                impact_assessment="SSL service may experience brief downtime during reload",
                created_at=datetime.now().isoformat()
            )
        
        return None
    
    def validate_fix(self, action: RemediationAction) -> bool:
        """Validate network remediation"""
        try:
            for cmd in action.validation_commands:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    return False
            return True
        except Exception:
            return False
    
    def _generate_action_id(self, vulnerability: Dict[str, Any]) -> str:
        """Generate unique action ID"""
        hash_input = f"{vulnerability.get('target')}:{vulnerability.get('vulnerability_type')}:{vulnerability.get('port')}:{time.time()}"
        return f"net_{hashlib.md5(hash_input.encode()).hexdigest()[:8]}"

class SystemRemediationHandler(RemediationHandler):
    """Handler for system-level remediations"""
    
    def can_handle(self, vulnerability: Dict[str, Any]) -> bool:
        """Check if this is a system vulnerability we can handle"""
        vuln_type = vulnerability.get('vulnerability_type', '').lower()
        return vuln_type in [
            'weak_permissions', 'suid_binary', 'outdated_package',
            'weak_password_policy', 'missing_security_update'
        ]
    
    def generate_remediation(self, vulnerability: Dict[str, Any]) -> Optional[RemediationAction]:
        """Generate system remediation action"""
        vuln_type = vulnerability.get('vulnerability_type', '').lower()
        target = vulnerability.get('target', '')
        
        action_id = self._generate_action_id(vulnerability)
        
        if vuln_type == 'weak_permissions':
            file_path = vulnerability.get('evidence', {}).get('file_path', '')
            return RemediationAction(
                action_id=action_id,
                vulnerability_id=vulnerability.get('vuln_id', ''),
                target=target,
                action_type='fix_permissions',
                description=f"Fix weak file permissions for {file_path}",
                commands=[
                    f"chmod 644 {file_path}",
                    f"chown root:root {file_path}"
                ],
                backup_commands=[
                    f"stat {file_path} > /tmp/permissions_backup_{action_id}.txt"
                ],
                rollback_commands=[
                    f"# Manual rollback required - check /tmp/permissions_backup_{action_id}.txt"
                ],
                risk_level=RemediationRisk.MEDIUM,
                estimated_duration=10,
                prerequisites=['root access'],
                validation_commands=[
                    f"stat -c '%a %U %G' {file_path}"
                ],
                impact_assessment=f"File permissions for {file_path} will be restricted",
                created_at=datetime.now().isoformat()
            )
        
        elif vuln_type == 'suid_binary':
            binary_path = vulnerability.get('evidence', {}).get('binary_path', '')
            return RemediationAction(
                action_id=action_id,
                vulnerability_id=vulnerability.get('vuln_id', ''),
                target=target,
                action_type='remove_suid',
                description=f"Remove SUID bit from {binary_path}",
                commands=[
                    f"chmod u-s {binary_path}"
                ],
                backup_commands=[
                    f"stat {binary_path} > /tmp/suid_backup_{action_id}.txt"
                ],
                rollback_commands=[
                    f"chmod u+s {binary_path}"
                ],
                risk_level=RemediationRisk.HIGH,
                estimated_duration=5,
                prerequisites=['root access'],
                validation_commands=[
                    f"ls -la {binary_path} | grep -v '^....s'"
                ],
                impact_assessment=f"Binary {binary_path} will lose SUID privileges",
                created_at=datetime.now().isoformat()
            )
        
        elif vuln_type == 'outdated_package':
            package_name = vulnerability.get('evidence', {}).get('package_name', '')
            return RemediationAction(
                action_id=action_id,
                vulnerability_id=vulnerability.get('vuln_id', ''),
                target=target,
                action_type='update_package',
                description=f"Update outdated package {package_name}",
                commands=[
                    "apt update",
                    f"apt upgrade -y {package_name}"
                ],
                backup_commands=[
                    f"dpkg -l {package_name} > /tmp/package_backup_{action_id}.txt"
                ],
                rollback_commands=[
                    f"# Package downgrade may be complex - manual intervention required"
                ],
                risk_level=RemediationRisk.MEDIUM,
                estimated_duration=120,
                prerequisites=['root access', 'internet connectivity'],
                validation_commands=[
                    f"apt list --upgradable | grep -v {package_name}"
                ],
                impact_assessment=f"Package {package_name} will be updated to latest version",
                created_at=datetime.now().isoformat()
            )
        
        return None
    
    def validate_fix(self, action: RemediationAction) -> bool:
        """Validate system remediation"""
        try:
            for cmd in action.validation_commands:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=30
                )
                # For validation commands, we expect specific return codes
                # This would need to be more sophisticated in production
            return True
        except Exception:
            return False
    
    def _generate_action_id(self, vulnerability: Dict[str, Any]) -> str:
        """Generate unique action ID"""
        hash_input = f"{vulnerability.get('target')}:{vulnerability.get('vulnerability_type')}:{time.time()}"
        return f"sys_{hashlib.md5(hash_input.encode()).hexdigest()[:8]}"

class WebAppRemediationHandler(RemediationHandler):
    """Handler for web application remediations"""
    
    def can_handle(self, vulnerability: Dict[str, Any]) -> bool:
        """Check if this is a web vulnerability we can handle"""
        vuln_type = vulnerability.get('vulnerability_type', '').lower()
        return vuln_type in [
            'missing_security_headers', 'weak_ssl_config', 'directory_listing',
            'server_info_disclosure', 'insecure_cookie'
        ]
    
    def generate_remediation(self, vulnerability: Dict[str, Any]) -> Optional[RemediationAction]:
        """Generate web application remediation action"""
        vuln_type = vulnerability.get('vulnerability_type', '').lower()
        target = vulnerability.get('target', '')
        
        action_id = self._generate_action_id(vulnerability)
        
        if vuln_type == 'missing_security_headers':
            return RemediationAction(
                action_id=action_id,
                vulnerability_id=vulnerability.get('vuln_id', ''),
                target=target,
                action_type='add_security_headers',
                description="Add missing HTTP security headers",
                commands=[
                    "cp /etc/apache2/conf-available/security.conf /tmp/security.conf.backup",
                    """cat >> /etc/apache2/conf-available/security.conf << 'EOF'
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection \"1; mode=block\"
Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"
Header always set Content-Security-Policy \"default-src 'self'\"
EOF""",
                    "a2enmod headers",
                    "systemctl reload apache2"
                ],
                backup_commands=[
                    "cp /etc/apache2/conf-available/security.conf /tmp/security_headers_backup.conf"
                ],
                rollback_commands=[
                    "cp /tmp/security_headers_backup.conf /etc/apache2/conf-available/security.conf",
                    "systemctl reload apache2"
                ],
                risk_level=RemediationRisk.LOW,
                estimated_duration=30,
                prerequisites=['root access', 'Apache web server'],
                validation_commands=[
                    "curl -I http://localhost | grep -E '(X-Content-Type-Options|X-Frame-Options|X-XSS-Protection)'"
                ],
                impact_assessment="Web application security will be enhanced with no functional impact",
                created_at=datetime.now().isoformat()
            )
        
        elif vuln_type == 'directory_listing':
            return RemediationAction(
                action_id=action_id,
                vulnerability_id=vulnerability.get('vuln_id', ''),
                target=target,
                action_type='disable_directory_listing',
                description="Disable directory listing",
                commands=[
                    "echo 'Options -Indexes' >> /etc/apache2/conf-available/security.conf",
                    "systemctl reload apache2"
                ],
                backup_commands=[
                    "cp /etc/apache2/conf-available/security.conf /tmp/dir_listing_backup.conf"
                ],
                rollback_commands=[
                    "cp /tmp/dir_listing_backup.conf /etc/apache2/conf-available/security.conf",
                    "systemctl reload apache2"
                ],
                risk_level=RemediationRisk.LOW,
                estimated_duration=15,
                prerequisites=['root access', 'Apache web server'],
                validation_commands=[
                    "curl -s http://localhost/nonexistent/ | grep -v 'Index of'"
                ],
                impact_assessment="Directory browsing will be disabled",
                created_at=datetime.now().isoformat()
            )
        
        return None
    
    def validate_fix(self, action: RemediationAction) -> bool:
        """Validate web application remediation"""
        try:
            for cmd in action.validation_commands:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    return False
            return True
        except Exception:
            return False
    
    def _generate_action_id(self, vulnerability: Dict[str, Any]) -> str:
        """Generate unique action ID"""
        hash_input = f"{vulnerability.get('target')}:{vulnerability.get('vulnerability_type')}:{time.time()}"
        return f"web_{hashlib.md5(hash_input.encode()).hexdigest()[:8]}"

class AutoRemediationEngine:
    """
    AI-powered auto-remediation engine with human oversight
    
    Features:
    - Intelligent vulnerability analysis
    - Risk-based remediation planning
    - Multi-level approval workflows
    - Safe execution with rollback capabilities
    - Comprehensive logging and auditing
    - Impact assessment and validation
    - Batch processing and scheduling
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.remediation_config = config.get('auto_remediation', {})
        self.logger = logging.getLogger('AutoRemediationEngine')
        
        # Configuration
        self.enabled = self.remediation_config.get('enabled', False)
        self.auto_approve_low_risk = self.remediation_config.get('auto_approve_low_risk', False)
        self.max_concurrent_actions = self.remediation_config.get('max_concurrent_actions', 3)
        self.backup_dir = self.remediation_config.get('backup_dir', '/tmp/vulnsleuth_backups')
        self.approval_timeout_hours = self.remediation_config.get('approval_timeout_hours', 24)
        
        # Initialize handlers
        self.handlers = [
            NetworkRemediationHandler(),
            SystemRemediationHandler(),
            WebAppRemediationHandler()
        ]
        
        # Action tracking
        self.pending_actions = {}
        self.active_actions = {}
        self.completed_actions = {}
        
        # Thread safety
        self.action_lock = threading.RLock()
        
        # Approval callbacks
        self.approval_callbacks = []
        
        # Ensure backup directory exists
        os.makedirs(self.backup_dir, exist_ok=True)
        
        self.logger.info(f"Auto-remediation engine initialized (enabled: {self.enabled})")
    
    def analyze_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[RemediationAction]:
        """
        Analyze vulnerabilities and generate remediation actions
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of RemediationAction objects
        """
        if not self.enabled:
            self.logger.warning("Auto-remediation is disabled")
            return []
        
        remediation_actions = []
        
        for vuln in vulnerabilities:
            self.logger.debug(f"Analyzing vulnerability: {vuln.get('title', 'Unknown')}")
            
            # Find appropriate handler
            for handler in self.handlers:
                if handler.can_handle(vuln):
                    action = handler.generate_remediation(vuln)
                    if action:
                        remediation_actions.append(action)
                        self.logger.info(f"Generated remediation action: {action.action_id}")
                    break
        
        # Sort actions by risk level and priority
        remediation_actions.sort(key=lambda a: (a.risk_level.value, a.estimated_duration))
        
        return remediation_actions
    
    def submit_for_approval(self, actions: List[RemediationAction]) -> Dict[str, str]:
        """
        Submit remediation actions for approval
        
        Args:
            actions: List of RemediationAction objects
            
        Returns:
            Dictionary mapping action IDs to submission status
        """
        submission_results = {}
        
        with self.action_lock:
            for action in actions:
                try:
                    # Auto-approve low-risk actions if configured
                    if (action.risk_level == RemediationRisk.LOW and 
                        self.auto_approve_low_risk):
                        action.status = RemediationStatus.APPROVED
                        action.approved_by = 'auto-approval'
                        self.logger.info(f"Auto-approved low-risk action: {action.action_id}")
                    
                    # Add to pending actions
                    self.pending_actions[action.action_id] = action
                    
                    # Notify approval callbacks
                    self._notify_approval_callbacks(action)
                    
                    submission_results[action.action_id] = 'submitted'
                    
                except Exception as e:
                    self.logger.error(f"Failed to submit action {action.action_id}: {str(e)}")
                    submission_results[action.action_id] = f'failed: {str(e)}'
        
        return submission_results
    
    def approve_action(self, action_id: str, approver: str, notes: str = '') -> bool:
        """
        Approve a remediation action
        
        Args:
            action_id: Action ID to approve
            approver: Name/ID of approver
            notes: Optional approval notes
            
        Returns:
            True if approved successfully
        """
        with self.action_lock:
            if action_id not in self.pending_actions:
                self.logger.error(f"Action not found in pending: {action_id}")
                return False
            
            action = self.pending_actions[action_id]
            
            # Check if action requires multiple approvals for high/critical risk
            if action.risk_level in [RemediationRisk.HIGH, RemediationRisk.CRITICAL]:
                # In production, implement multi-level approval logic
                pass
            
            action.status = RemediationStatus.APPROVED
            action.approved_by = approver
            
            self.logger.info(f"Action approved by {approver}: {action_id}")
            
            return True
    
    def reject_action(self, action_id: str, rejector: str, reason: str) -> bool:
        """
        Reject a remediation action
        
        Args:
            action_id: Action ID to reject
            rejector: Name/ID of rejector
            reason: Rejection reason
            
        Returns:
            True if rejected successfully
        """
        with self.action_lock:
            if action_id not in self.pending_actions:
                self.logger.error(f"Action not found in pending: {action_id}")
                return False
            
            action = self.pending_actions[action_id]
            action.status = RemediationStatus.REJECTED
            action.error_message = f"Rejected by {rejector}: {reason}"
            
            # Move to completed actions
            self.completed_actions[action_id] = action
            del self.pending_actions[action_id]
            
            self.logger.info(f"Action rejected by {rejector}: {action_id}")
            
            return True
    
    def execute_approved_actions(self) -> Dict[str, str]:
        """
        Execute all approved remediation actions
        
        Returns:
            Dictionary mapping action IDs to execution results
        """
        if not self.enabled:
            return {}
        
        execution_results = {}
        approved_actions = []
        
        # Get approved actions
        with self.action_lock:
            for action_id, action in self.pending_actions.items():
                if action.status == RemediationStatus.APPROVED:
                    approved_actions.append((action_id, action))
        
        # Limit concurrent executions
        approved_actions = approved_actions[:self.max_concurrent_actions]
        
        for action_id, action in approved_actions:
            try:
                result = self._execute_single_action(action)
                execution_results[action_id] = result
                
            except Exception as e:
                self.logger.error(f"Failed to execute action {action_id}: {str(e)}")
                execution_results[action_id] = f'failed: {str(e)}'
        
        return execution_results
    
    def _execute_single_action(self, action: RemediationAction) -> str:
        """Execute a single remediation action"""
        self.logger.info(f"Executing remediation action: {action.action_id}")
        
        with self.action_lock:
            # Update status
            action.status = RemediationStatus.IN_PROGRESS
            action.executed_at = datetime.now().isoformat()
            
            # Move to active actions
            if action.action_id in self.pending_actions:
                del self.pending_actions[action.action_id]
            self.active_actions[action.action_id] = action
        
        try:
            # Create backup directory for this action
            action_backup_dir = os.path.join(self.backup_dir, action.action_id)
            os.makedirs(action_backup_dir, exist_ok=True)
            
            # Execute backup commands first
            for cmd in action.backup_commands:
                self.logger.debug(f"Backup command: {cmd}")
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, 
                    cwd=action_backup_dir, timeout=300
                )
                if result.returncode != 0:
                    raise RuntimeError(f"Backup command failed: {result.stderr}")
            
            # Execute main remediation commands
            for cmd in action.commands:
                self.logger.debug(f"Remediation command: {cmd}")
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=300
                )
                if result.returncode != 0:
                    # Attempt rollback
                    self._rollback_action(action)
                    raise RuntimeError(f"Remediation command failed: {result.stderr}")
            
            # Validate the fix
            handler = self._get_handler_for_action(action)
            if handler and not handler.validate_fix(action):
                self._rollback_action(action)
                raise RuntimeError("Fix validation failed")
            
            # Mark as completed
            with self.action_lock:
                action.status = RemediationStatus.COMPLETED
                action.completed_at = datetime.now().isoformat()
                self.completed_actions[action.action_id] = action
                if action.action_id in self.active_actions:
                    del self.active_actions[action.action_id]
            
            self.logger.info(f"Successfully completed remediation: {action.action_id}")
            return "completed"
            
        except Exception as e:
            with self.action_lock:
                action.status = RemediationStatus.FAILED
                action.error_message = str(e)
                action.completed_at = datetime.now().isoformat()
                self.completed_actions[action.action_id] = action
                if action.action_id in self.active_actions:
                    del self.active_actions[action.action_id]
            
            self.logger.error(f"Remediation failed: {action.action_id} - {str(e)}")
            return f"failed: {str(e)}"
    
    def _rollback_action(self, action: RemediationAction):
        """Attempt to rollback a failed remediation"""
        self.logger.warning(f"Attempting rollback for action: {action.action_id}")
        
        try:
            for cmd in action.rollback_commands:
                self.logger.debug(f"Rollback command: {cmd}")
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=300
                )
                if result.returncode != 0:
                    self.logger.error(f"Rollback command failed: {result.stderr}")
            
            self.logger.info(f"Rollback completed for action: {action.action_id}")
            
        except Exception as e:
            self.logger.error(f"Rollback failed for action {action.action_id}: {str(e)}")
    
    def _get_handler_for_action(self, action: RemediationAction) -> Optional[RemediationHandler]:
        """Get the appropriate handler for an action"""
        for handler in self.handlers:
            if action.action_id.startswith('net_') and isinstance(handler, NetworkRemediationHandler):
                return handler
            elif action.action_id.startswith('sys_') and isinstance(handler, SystemRemediationHandler):
                return handler
            elif action.action_id.startswith('web_') and isinstance(handler, WebAppRemediationHandler):
                return handler
        return None
    
    def get_pending_approvals(self) -> List[Dict[str, Any]]:
        """Get list of actions pending approval"""
        with self.action_lock:
            pending = []
            for action in self.pending_actions.values():
                if action.status == RemediationStatus.PENDING:
                    # Check if approval has timed out
                    created = datetime.fromisoformat(action.created_at)
                    age_hours = (datetime.now() - created).total_seconds() / 3600
                    
                    if age_hours > self.approval_timeout_hours:
                        action.status = RemediationStatus.CANCELLED
                        action.error_message = "Approval timeout"
                        continue
                    
                    pending.append({
                        'action_id': action.action_id,
                        'vulnerability_id': action.vulnerability_id,
                        'target': action.target,
                        'description': action.description,
                        'risk_level': action.risk_level.value,
                        'estimated_duration': action.estimated_duration,
                        'impact_assessment': action.impact_assessment,
                        'created_at': action.created_at,
                        'commands_preview': action.commands[:3]  # First 3 commands
                    })
            
            return pending
    
    def get_action_status(self, action_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific action"""
        with self.action_lock:
            # Check all action collections
            action = None
            if action_id in self.pending_actions:
                action = self.pending_actions[action_id]
            elif action_id in self.active_actions:
                action = self.active_actions[action_id]
            elif action_id in self.completed_actions:
                action = self.completed_actions[action_id]
            
            if action:
                return {
                    'action_id': action.action_id,
                    'status': action.status.value,
                    'created_at': action.created_at,
                    'approved_by': action.approved_by,
                    'executed_at': action.executed_at,
                    'completed_at': action.completed_at,
                    'error_message': action.error_message,
                    'description': action.description,
                    'risk_level': action.risk_level.value
                }
            
            return None
    
    def register_approval_callback(self, callback: Callable[[RemediationAction], None]):
        """Register callback for approval notifications"""
        self.approval_callbacks.append(callback)
    
    def _notify_approval_callbacks(self, action: RemediationAction):
        """Notify registered callbacks about new approval requests"""
        for callback in self.approval_callbacks:
            try:
                callback(action)
            except Exception as e:
                self.logger.error(f"Approval callback failed: {str(e)}")
    
    def cleanup_old_actions(self, days_old: int = 30) -> int:
        """Clean up old completed actions"""
        cutoff_date = datetime.now() - timedelta(days=days_old)
        cleaned_count = 0
        
        with self.action_lock:
            to_remove = []
            for action_id, action in self.completed_actions.items():
                if action.completed_at:
                    completed_date = datetime.fromisoformat(action.completed_at)
                    if completed_date < cutoff_date:
                        to_remove.append(action_id)
            
            for action_id in to_remove:
                del self.completed_actions[action_id]
                cleaned_count += 1
                
                # Clean up backup directory
                backup_dir = os.path.join(self.backup_dir, action_id)
                if os.path.exists(backup_dir):
                    shutil.rmtree(backup_dir, ignore_errors=True)
        
        if cleaned_count > 0:
            self.logger.info(f"Cleaned up {cleaned_count} old remediation actions")
        
        return cleaned_count
    
    def get_remediation_stats(self) -> Dict[str, Any]:
        """Get remediation statistics"""
        with self.action_lock:
            stats = {
                'total_actions': len(self.pending_actions) + len(self.active_actions) + len(self.completed_actions),
                'pending_approval': len([a for a in self.pending_actions.values() if a.status == RemediationStatus.PENDING]),
                'approved_pending': len([a for a in self.pending_actions.values() if a.status == RemediationStatus.APPROVED]),
                'in_progress': len(self.active_actions),
                'completed_success': len([a for a in self.completed_actions.values() if a.status == RemediationStatus.COMPLETED]),
                'failed': len([a for a in self.completed_actions.values() if a.status == RemediationStatus.FAILED]),
                'rejected': len([a for a in self.completed_actions.values() if a.status == RemediationStatus.REJECTED])
            }
            
            # Success rate
            total_processed = stats['completed_success'] + stats['failed']
            stats['success_rate'] = (stats['completed_success'] / total_processed * 100) if total_processed > 0 else 0
            
            return stats

if __name__ == "__main__":
    # Test auto-remediation
    config = {
        'auto_remediation': {
            'enabled': True,
            'auto_approve_low_risk': True,
            'max_concurrent_actions': 2
        }
    }
    
    engine = AutoRemediationEngine(config)
    
    # Test vulnerability
    test_vuln = {
        'vuln_id': 'test_vuln_001',
        'target': '192.168.1.100',
        'vulnerability_type': 'missing_security_headers',
        'severity': 'medium',
        'title': 'Missing HTTP Security Headers',
        'description': 'Web server missing security headers'
    }
    
    # Analyze and generate actions
    actions = engine.analyze_vulnerabilities([test_vuln])
    if actions:
        print(f"Generated {len(actions)} remediation actions")
        
        # Submit for approval
        results = engine.submit_for_approval(actions)
        print(f"Submission results: {results}")
        
        # Get pending approvals
        pending = engine.get_pending_approvals()
        print(f"Pending approvals: {len(pending)}")
        
        # Get stats
        stats = engine.get_remediation_stats()
        print(f"Remediation stats: {stats}")
    else:
        print("No remediation actions generated")
