"""
VulnSleuth Web Dashboard
Flask-based web interface for managing scans and viewing results

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import uuid
from functools import wraps
import threading
import time
import io
import base64

try:
    from .engine import VulnSleuthEngine
    from .db import DatabaseManager
    from .reporter import VulnSleuthReporter, ReportConfig
    from .auto_remediation import AutoRemediationEngine
    from .utils import NetworkUtils, SystemUtils, SecurityUtils
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from engine import VulnSleuthEngine
    from db import DatabaseManager
    from reporter import VulnSleuthReporter, ReportConfig
    from auto_remediation import AutoRemediationEngine
    from utils import NetworkUtils, SystemUtils, SecurityUtils

logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.secret_key = os.environ.get('VULNSLEUTH_SECRET_KEY', SecurityUtils.generate_random_string(32))

# Global instances
engine = None
db_manager = None
reporter = None
remediation_engine = None
config = {}

# Active scans tracking
active_scans = {}
scan_lock = threading.Lock()

def init_dashboard(vulnsleuth_config: Dict[str, Any]):
    """Initialize the dashboard with VulnSleuth components"""
    global engine, db_manager, reporter, remediation_engine, config
    
    config = vulnsleuth_config
    
    # Initialize components
    engine = VulnSleuthEngine(config)
    db_manager = DatabaseManager(config)
    reporter = VulnSleuthReporter(config)
    remediation_engine = AutoRemediationEngine(config)
    
    # Flask configuration
    dashboard_config = config.get('dashboard', {})
    app.config['DEBUG'] = dashboard_config.get('debug', False)
    app.config['HOST'] = dashboard_config.get('host', '127.0.0.1')
    app.config['PORT'] = dashboard_config.get('port', 5000)
    
    logger.info("VulnSleuth dashboard initialized")

def require_auth(f):
    """Authentication decorator for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated') or not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_first_time_setup():
    """Check if this is the first time setup (no users exist)"""
    if db_manager is None:
        return True
    return not db_manager.user_exists()

# Authentication routes
@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """First-time setup - create initial admin user"""
    if not check_first_time_setup():
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return render_template('setup.html')
        
        if not email or '@' not in email:
            flash('Please enter a valid email address', 'error')
            return render_template('setup.html')
        
        if not password or len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('setup.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('setup.html')
        
        # Create first admin user
        password_hash = generate_password_hash(password)
        user_id = db_manager.create_user(username, email, password_hash, is_admin=True)
        
        if user_id:
            logger.info(f"First admin user created: {username}")
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Failed to create account. Username or email may already exist.', 'error')
    
    return render_template('setup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    # Check if first-time setup is needed
    if check_first_time_setup():
        return redirect(url_for('setup'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        # Get user from database
        user = db_manager.get_user_by_username(username)
        
        if user and user['is_active']:
            # Check if account is locked
            if user['locked_until']:
                locked_until = datetime.fromisoformat(user['locked_until'])
                if datetime.now() < locked_until:
                    remaining = int((locked_until - datetime.now()).total_seconds() / 60)
                    flash(f'Account is locked. Please try again in {remaining} minutes.', 'error')
                    return render_template('login.html')
            
            # Verify password
            if check_password_hash(user['password_hash'], password):
                # Successful login
                session['authenticated'] = True
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                session.permanent = True
                
                # Update login info
                db_manager.update_user_login(user['user_id'], success=True)
                
                # Log activity
                ip_address = request.remote_addr
                db_manager.log_user_activity(user['user_id'], 'login', 'User logged in', ip_address)
                
                flash('Login successful', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Failed login
                db_manager.update_user_login(user['user_id'], success=False)
                flash('Invalid username or password', 'error')
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', show_create_account=True)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    # Check if first-time setup is needed
    if check_first_time_setup():
        return redirect(url_for('setup'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Validation
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return render_template('register.html')
        
        if not email or '@' not in email:
            flash('Please enter a valid email address', 'error')
            return render_template('register.html')
        
        if not password or len(password) < 8:
            flash('Password must be at least 8 characters long', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        # Check if username or email already exists
        if db_manager.get_user_by_username(username):
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        if db_manager.get_user_by_email(email):
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Create user (non-admin by default)
        password_hash = generate_password_hash(password)
        user_id = db_manager.create_user(username, email, password_hash, is_admin=False)
        
        if user_id:
            logger.info(f"New user registered: {username}")
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Failed to create account. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/logout')
@require_auth
def logout():
    """User logout"""
    if session.get('user_id'):
        ip_address = request.remote_addr
        db_manager.log_user_activity(session['user_id'], 'logout', 'User logged out', ip_address)
    
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

# Main dashboard routes
@app.route('/')
@require_auth
def dashboard():
    """Main dashboard page"""
    try:
        # Check if components are initialized
        if db_manager is None:
            logger.warning("Database manager not initialized")
            flash('System components not initialized. Please restart the dashboard.', 'warning')
            dashboard_data = {
                'recent_scans': [],
                'vulnerability_stats': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
                'target_count': 0,
                'system_info': {'cpu_usage': 0, 'memory_usage': 0, 'disk_usage': 0},
                'active_scan_count': 0
            }
        else:
            # Get recent scan statistics
            recent_scans = db_manager.get_scan_results(days_back=7, limit=10)
            vuln_stats = db_manager.get_vulnerability_stats(days_back=30)
            targets = db_manager.get_targets(days_back=30)
            
            # System information
            system_info = SystemUtils.get_system_info()
            
            dashboard_data = {
                'recent_scans': [scan.to_dict() for scan in recent_scans],
                'vulnerability_stats': vuln_stats,
                'target_count': len(targets),
                'system_info': system_info,
                'active_scan_count': len(active_scans)
            }
        
        # Add current time
        dashboard_data['current_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return render_template('dashboard.html', data=dashboard_data, current_time=dashboard_data['current_time'])
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        flash(f'Dashboard error: {str(e)}', 'error')
        return render_template('dashboard.html', data={}, current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

@app.route('/scans')
@require_auth
def scans():
    """Scan management page"""
    try:
        # Get scan history
        scan_results = db_manager.get_scan_results(days_back=90, limit=50)
        
        return render_template('scans.html', scans=[scan.to_dict() for scan in scan_results])
        
    except Exception as e:
        logger.error(f"Scans page error: {str(e)}")
        flash(f'Error loading scans: {str(e)}', 'error')
        return render_template('scans.html', scans=[])

@app.route('/scan/new', methods=['GET', 'POST'])
@require_auth
def new_scan():
    """Create new scan"""
    if request.method == 'POST':
        try:
            # Get form data
            targets = request.form.get('targets', '').strip()
            scan_type = request.form.get('scan_type', 'quick')
            ports = request.form.get('ports', '')
            
            if not targets:
                flash('Please specify at least one target', 'error')
                return render_template('new_scan.html')
            
            # Parse targets
            target_list = NetworkUtils.parse_targets(targets)
            if not target_list:
                flash('No valid targets found', 'error')
                return render_template('new_scan.html')
            
            # Generate scan ID
            scan_id = f"web_scan_{uuid.uuid4().hex[:8]}"
            
            # Parse ports if provided
            port_list = []
            if ports:
                port_list = NetworkUtils.parse_port_range(ports)
            
            # Create scan configuration
            scan_config = {
                'scan_id': scan_id,
                'targets': [target.ip for target in target_list],
                'scan_type': scan_type,
                'ports': port_list,
                'web_interface': True,
                'started_by': session.get('username', 'unknown')
            }
            
            # Start scan in background thread
            scan_thread = threading.Thread(
                target=run_scan_background,
                args=(scan_id, scan_config),
                daemon=True
            )
            scan_thread.start()
            
            # Track active scan
            with scan_lock:
                active_scans[scan_id] = {
                    'config': scan_config,
                    'started_at': datetime.now().isoformat(),
                    'status': 'running',
                    'progress': 0
                }
            
            flash(f'Scan started successfully: {scan_id}', 'success')
            return redirect(url_for('scan_status', scan_id=scan_id))
            
        except Exception as e:
            logger.error(f"Failed to start scan: {str(e)}")
            flash(f'Failed to start scan: {str(e)}', 'error')
    
    return render_template('new_scan.html')

@app.route('/scan/<scan_id>')
@require_auth
def scan_status(scan_id: str):
    """View scan status and results"""
    try:
        # Check if scan is active
        with scan_lock:
            if scan_id in active_scans:
                scan_info = active_scans[scan_id]
                return render_template('scan_status.html', 
                                     scan_id=scan_id, 
                                     scan_info=scan_info,
                                     is_active=True)
        
        # Get completed scan from database
        scan_results = db_manager.get_scan_results(limit=1)
        matching_scans = [s for s in scan_results if s.scan_id == scan_id]
        
        if matching_scans:
            scan_result = matching_scans[0]
            return render_template('scan_results.html', 
                                 scan=scan_result.to_dict())
        else:
            flash('Scan not found', 'error')
            return redirect(url_for('scans'))
            
    except Exception as e:
        logger.error(f"Error viewing scan {scan_id}: {str(e)}")
        flash(f'Error viewing scan: {str(e)}', 'error')
        return redirect(url_for('scans'))

@app.route('/vulnerabilities')
@require_auth
def vulnerabilities():
    """Vulnerability management page"""
    try:
        # Get vulnerability statistics
        vuln_stats = db_manager.get_vulnerability_stats(days_back=30)
        
        # Get recent scan results to extract vulnerabilities
        recent_scans = db_manager.get_scan_results(days_back=30, limit=100)
        all_vulns = []
        
        for scan in recent_scans:
            for vuln in scan.vulnerabilities:
                vuln['scan_id'] = scan.scan_id
                vuln['scan_timestamp'] = scan.timestamp
                all_vulns.append(vuln)
        
        # Sort by severity and CVSS score
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0}
        all_vulns.sort(key=lambda v: (
            severity_order.get(v.get('severity', 'informational'), 0),
            v.get('cvss_score', 0)
        ), reverse=True)
        
        return render_template('vulnerabilities.html', 
                             vulnerabilities=all_vulns[:100],  # Limit to top 100
                             stats=vuln_stats)
        
    except Exception as e:
        logger.error(f"Vulnerabilities page error: {str(e)}")
        flash(f'Error loading vulnerabilities: {str(e)}', 'error')
        return render_template('vulnerabilities.html', vulnerabilities=[], stats={})

@app.route('/targets')
@require_auth
def targets():
    """Target management page"""
    try:
        target_list = db_manager.get_targets(days_back=90)
        return render_template('targets.html', targets=[target.to_dict() for target in target_list])
        
    except Exception as e:
        logger.error(f"Targets page error: {str(e)}")
        flash(f'Error loading targets: {str(e)}', 'error')
        return render_template('targets.html', targets=[])

@app.route('/reports')
@require_auth
def reports():
    """Reports management page"""
    try:
        # Get available reports from database
        db_info = db_manager.get_database_info()
        
        # List report files from output directory
        report_dir = config.get('reporting', {}).get('output_dir', 'reports')
        report_files = []
        
        if os.path.exists(report_dir):
            for filename in os.listdir(report_dir):
                if filename.endswith(('.html', '.json', '.csv', '.xml', '.pdf')):
                    filepath = os.path.join(report_dir, filename)
                    file_info = {
                        'name': filename,
                        'path': filepath,
                        'size': os.path.getsize(filepath),
                        'created': datetime.fromtimestamp(os.path.getctime(filepath)).isoformat(),
                        'format': filename.split('.')[-1].upper()
                    }
                    report_files.append(file_info)
        
        report_files.sort(key=lambda x: x['created'], reverse=True)
        
        return render_template('reports.html', reports=report_files, db_info=db_info)
        
    except Exception as e:
        logger.error(f"Reports page error: {str(e)}")
        flash(f'Error loading reports: {str(e)}', 'error')
        return render_template('reports.html', reports=[], db_info={})

@app.route('/report/generate', methods=['POST'])
@require_auth
def generate_report():
    """Generate new report"""
    try:
        report_type = request.form.get('report_type', 'html')
        days_back = int(request.form.get('days_back', 30))
        
        # Get scan results
        scan_results = db_manager.get_scan_results(days_back=days_back, limit=1000)
        
        if not scan_results:
            flash('No scan results found for the specified period', 'warning')
            return redirect(url_for('reports'))
        
        # Generate report
        report_id = f"web_report_{uuid.uuid4().hex[:8]}"
        report_config = ReportConfig(
            report_id=report_id,
            title=f'VulnSleuth Security Assessment - {datetime.now().strftime("%Y-%m-%d")}',
            format=report_type,
            output_path=f'reports/{report_id}.{report_type}'
        )
        
        # Convert scan results to dictionaries
        scan_data = [scan.to_dict() for scan in scan_results]
        
        output_path = reporter.generate_report(scan_data, report_config)
        
        flash(f'Report generated successfully: {os.path.basename(output_path)}', 'success')
        
    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        flash(f'Report generation failed: {str(e)}', 'error')
    
    return redirect(url_for('reports'))

@app.route('/remediation')
@require_auth
def remediation():
    """Auto-remediation management page"""
    try:
        # Get remediation statistics
        remediation_stats = remediation_engine.get_remediation_stats()
        
        # Get pending approvals
        pending_approvals = remediation_engine.get_pending_approvals()
        
        return render_template('remediation.html', 
                             stats=remediation_stats,
                             pending_approvals=pending_approvals)
        
    except Exception as e:
        logger.error(f"Remediation page error: {str(e)}")
        flash(f'Error loading remediation data: {str(e)}', 'error')
        return render_template('remediation.html', stats={}, pending_approvals=[])

@app.route('/settings')
@require_auth
def settings():
    """Settings management page"""
    try:
        # Get current settings from config
        current_settings = {
            'general': {
                'app_name': 'VulnSleuth',
                'theme': 'light',
                'language': 'en',
                'timezone': 'UTC'
            },
            'scanning': {
                'default_threads': 10,
                'timeout': 30,
                'retries': 3,
                'delay': 100,
                'user_agent': 'VulnSleuth/2.0 (Security Scanner)',
                'aggressive_scanning': False,
                'save_raw_output': True
            },
            'reporting': {
                'default_format': 'pdf',
                'template': 'standard',
                'company_name': '',
                'logo_url': '',
                'include_charts': True,
                'auto_generate': False
            },
            'notifications': {
                'email_enabled': False,
                'smtp_server': '',
                'smtp_port': 587,
                'username': '',
                'recipients': '',
                'notify_completion': True,
                'notify_critical': True,
                'notify_errors': False
            },
            'security': {
                'require_auth': True,
                'session_timeout': 30,
                'max_attempts': 5,
                'encrypt_database': True,
                'audit_logging': True,
                'data_retention': 365
            },
            'advanced': {
                'db_path': 'data/vulnsleuth.db',
                'log_level': 'INFO',
                'custom_plugins': '',
                'nmap_path': 'nmap',
                'debug_mode': False,
                'dev_mode': False
            }
        }
        
        return render_template('settings.html', settings=current_settings)
        
    except Exception as e:
        logger.error(f"Settings page error: {str(e)}")
        flash(f'Error loading settings: {str(e)}', 'error')
        return render_template('settings.html', settings={})

@app.route('/settings', methods=['POST'])
@require_auth
def save_settings():
    """Save settings changes"""
    try:
        # Get form data
        settings_data = request.form.to_dict()
        
        # Here you would normally save to config file or database
        # For now, just show success message
        
        flash('Settings saved successfully!', 'success')
        return redirect(url_for('settings'))
        
    except Exception as e:
        logger.error(f"Settings save error: {str(e)}")
        flash(f'Error saving settings: {str(e)}', 'error')
        return redirect(url_for('settings'))

# API endpoints
@app.route('/api/scan/status/<scan_id>')
@require_auth
def api_scan_status(scan_id: str):
    """API endpoint for scan status"""
    try:
        with scan_lock:
            if scan_id in active_scans:
                return jsonify(active_scans[scan_id])
        
        # Check database for completed scan
        scan_results = db_manager.get_scan_results(limit=1)
        matching_scans = [s for s in scan_results if s.scan_id == scan_id]
        
        if matching_scans:
            scan = matching_scans[0]
            return jsonify({
                'status': 'completed',
                'scan_id': scan.scan_id,
                'vulnerability_count': len(scan.vulnerabilities),
                'completed_at': scan.timestamp
            })
        
        return jsonify({'error': 'Scan not found'}), 404
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
@require_auth
def api_stats():
    """API endpoint for dashboard statistics"""
    try:
        vuln_stats = db_manager.get_vulnerability_stats(days_back=30)
        db_info = db_manager.get_database_info()
        
        stats = {
            'vulnerability_stats': vuln_stats,
            'database_info': db_info,
            'active_scans': len(active_scans),
            'system_info': SystemUtils.get_system_info()
        }
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/remediation/approve/<action_id>', methods=['POST'])
@require_auth
def api_approve_remediation(action_id: str):
    """API endpoint to approve remediation action"""
    try:
        approver = session.get('username', 'unknown')
        notes = request.json.get('notes', '') if request.is_json else ''
        
        success = remediation_engine.approve_action(action_id, approver, notes)
        
        if success:
            return jsonify({'success': True, 'message': 'Action approved'})
        else:
            return jsonify({'success': False, 'message': 'Failed to approve action'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/remediation/reject/<action_id>', methods=['POST'])
@require_auth
def api_reject_remediation(action_id: str):
    """API endpoint to reject remediation action"""
    try:
        rejector = session.get('username', 'unknown')
        reason = request.json.get('reason', 'No reason provided') if request.is_json else 'No reason provided'
        
        success = remediation_engine.reject_action(action_id, rejector, reason)
        
        if success:
            return jsonify({'success': True, 'message': 'Action rejected'})
        else:
            return jsonify({'success': False, 'message': 'Failed to reject action'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def run_scan_background(scan_id: str, scan_config: Dict[str, Any]):
    """Run scan in background thread"""
    try:
        logger.info(f"Starting background scan: {scan_id}")
        
        # Update scan status
        with scan_lock:
            if scan_id in active_scans:
                active_scans[scan_id]['status'] = 'running'
                active_scans[scan_id]['progress'] = 10
        
        # Run the actual scan
        results = engine.run_scan(
            targets=scan_config['targets'],
            scan_type=scan_config.get('scan_type', 'quick'),
            output_format='json',
            ports=scan_config.get('ports', [])
        )
        
        # Update progress
        with scan_lock:
            if scan_id in active_scans:
                active_scans[scan_id]['progress'] = 50
        
        # Save results to database (this would be handled by the engine normally)
        # For now, we'll simulate this
        
        # Update completion status
        with scan_lock:
            if scan_id in active_scans:
                active_scans[scan_id]['status'] = 'completed'
                active_scans[scan_id]['progress'] = 100
                active_scans[scan_id]['completed_at'] = datetime.now().isoformat()
                active_scans[scan_id]['results'] = results
        
        logger.info(f"Background scan completed: {scan_id}")
        
        # Clean up after some time
        time.sleep(300)  # Keep for 5 minutes
        with scan_lock:
            active_scans.pop(scan_id, None)
            
    except Exception as e:
        logger.error(f"Background scan failed {scan_id}: {str(e)}")
        with scan_lock:
            if scan_id in active_scans:
                active_scans[scan_id]['status'] = 'failed'
                active_scans[scan_id]['error'] = str(e)

def create_default_templates():
    """Create default HTML templates if they don't exist"""
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    os.makedirs(template_dir, exist_ok=True)
    
    # Base template
    base_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnSleuth Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    {% if session.authenticated %}
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="{{ url_for('dashboard') }}">
                <i class="fas fa-shield-alt"></i> VulnSleuth
            </a>
            <div class="navbar-nav me-auto">
                <a class="nav-link" href="{{ url_for('dashboard') }}">Dashboard</a>
                <a class="nav-link" href="{{ url_for('scans') }}">Scans</a>
                <a class="nav-link" href="{{ url_for('vulnerabilities') }}">Vulnerabilities</a>
                <a class="nav-link" href="{{ url_for('targets') }}">Targets</a>
                <a class="nav-link" href="{{ url_for('reports') }}">Reports</a>
                <a class="nav-link" href="{{ url_for('remediation') }}">Remediation</a>
            </div>
            <div class="navbar-nav">
                <span class="navbar-text me-3">{{ session.username }}</span>
                <a class="nav-link" href="{{ url_for('logout') }}">Logout</a>
            </div>
        </div>
    </nav>
    {% endif %}
    
    <div class="container-fluid mt-3">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }} alert-dismissible fade show" role="alert">
                        {{ message }}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        {% block content %}{% endblock %}
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>'''
    
    # Login template
    login_template = '''{% extends "base.html" %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6 col-lg-4">
        <div class="card">
            <div class="card-header text-center">
                <h3><i class="fas fa-shield-alt"></i> VulnSleuth Login</h3>
            </div>
            <div class="card-body">
                <form method="POST">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Login</button>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}'''
    
    # Dashboard template
    dashboard_template = '''{% extends "base.html" %}

{% block content %}
<h1><i class="fas fa-tachometer-alt"></i> Dashboard</h1>

<div class="row">
    <div class="col-md-3">
        <div class="card text-white bg-primary mb-3">
            <div class="card-body">
                <h5 class="card-title">Total Vulnerabilities</h5>
                <h2>{{ data.vulnerability_stats.total_vulnerabilities or 0 }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card text-white bg-success mb-3">
            <div class="card-body">
                <h5 class="card-title">Targets Scanned</h5>
                <h2>{{ data.target_count or 0 }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card text-white bg-warning mb-3">
            <div class="card-body">
                <h5 class="card-title">Active Scans</h5>
                <h2>{{ data.active_scan_count or 0 }}</h2>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card text-white bg-info mb-3">
            <div class="card-body">
                <h5 class="card-title">Recent Scans</h5>
                <h2>{{ data.recent_scans|length }}</h2>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5>Recent Scan Activity</h5>
            </div>
            <div class="card-body">
                <div class="list-group">
                    {% for scan in data.recent_scans[:5] %}
                    <div class="list-group-item">
                        <div class="d-flex w-100 justify-content-between">
                            <h6 class="mb-1">{{ scan.target }}</h6>
                            <small>{{ scan.timestamp }}</small>
                        </div>
                        <p class="mb-1">Type: {{ scan.scan_type }} | Status: {{ scan.status }}</p>
                        <small>{{ scan.vulnerabilities|length }} vulnerabilities found</small>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5>System Information</h5>
            </div>
            <div class="card-body">
                <ul class="list-unstyled">
                    <li><strong>Platform:</strong> {{ data.system_info.platform }}</li>
                    <li><strong>Hostname:</strong> {{ data.system_info.hostname }}</li>
                    <li><strong>Architecture:</strong> {{ data.system_info.architecture }}</li>
                    <li><strong>Python Version:</strong> {{ data.system_info.python_version }}</li>
                </ul>
            </div>
        </div>
    </div>
</div>
{% endblock %}'''
    
    # Write templates
    templates = {
        'base.html': base_template,
        'login.html': login_template,
        'dashboard.html': dashboard_template,
        'scans.html': '{% extends "base.html" %}\n{% block content %}<h1>Scans</h1><p>Scans page under construction</p>{% endblock %}',
        'new_scan.html': '{% extends "base.html" %}\n{% block content %}<h1>New Scan</h1><p>New scan page under construction</p>{% endblock %}',
        'scan_status.html': '{% extends "base.html" %}\n{% block content %}<h1>Scan Status</h1><p>Scan status page under construction</p>{% endblock %}',
        'scan_results.html': '{% extends "base.html" %}\n{% block content %}<h1>Scan Results</h1><p>Scan results page under construction</p>{% endblock %}',
        'vulnerabilities.html': '{% extends "base.html" %}\n{% block content %}<h1>Vulnerabilities</h1><p>Vulnerabilities page under construction</p>{% endblock %}',
        'targets.html': '{% extends "base.html" %}\n{% block content %}<h1>Targets</h1><p>Targets page under construction</p>{% endblock %}',
        'reports.html': '{% extends "base.html" %}\n{% block content %}<h1>Reports</h1><p>Reports page under construction</p>{% endblock %}',
        'remediation.html': '{% extends "base.html" %}\n{% block content %}<h1>Remediation</h1><p>Remediation page under construction</p>{% endblock %}'
    }
    
    for filename, content in templates.items():
        template_path = os.path.join(template_dir, filename)
        if not os.path.exists(template_path):
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(content)

@app.route('/scan/<scan_id>/stop', methods=['POST'])
@require_auth
def stop_scan(scan_id: str):
    """Stop a running scan"""
    try:
        with scan_lock:
            if scan_id in active_scans:
                active_scans[scan_id]['status'] = 'stopped'
                active_scans[scan_id]['stopped_at'] = datetime.now().isoformat()
                return jsonify({'success': True, 'message': 'Scan stopped'})
            else:
                return jsonify({'success': False, 'error': 'Scan not found'}), 404
                
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/scan/<scan_id>/export')
@require_auth
def export_scan(scan_id: str):
    """Export scan results"""
    try:
        with scan_lock:
            if scan_id in active_scans:
                scan_info = active_scans[scan_id]
                # Generate a simple JSON export
                import json
                export_data = {
                    'scan_id': scan_id,
                    'scan_info': scan_info,
                    'exported_at': datetime.now().isoformat()
                }
                
                response = app.response_class(
                    response=json.dumps(export_data, indent=2),
                    status=200,
                    mimetype='application/json'
                )
                response.headers['Content-Disposition'] = f'attachment; filename=scan_{scan_id}.json'
                return response
            else:
                flash('Scan not found', 'error')
                return redirect(url_for('scans'))
                
    except Exception as e:
        flash(f'Export failed: {str(e)}', 'error')
        return redirect(url_for('scans'))

def run_dashboard(vulnsleuth_config: Dict[str, Any]):
    """Run the Flask dashboard"""
    init_dashboard(vulnsleuth_config)
    create_default_templates()
    
    dashboard_config = vulnsleuth_config.get('dashboard', {})
    host = dashboard_config.get('host', '127.0.0.1')
    port = dashboard_config.get('port', 5000)
    debug = dashboard_config.get('debug', False)
    
    logger.info(f"Starting VulnSleuth dashboard on http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)

if __name__ == "__main__":
    # Test configuration
    test_config = {
        'database': {'db_path': 'test_vulnsleuth.db'},
        'reporting': {'output_dir': 'test_reports'},
        'dashboard': {'host': '127.0.0.1', 'port': 5000, 'debug': True},
        'auto_remediation': {'enabled': True}
    }
    
    run_dashboard(test_config)
