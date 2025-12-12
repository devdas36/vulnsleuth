"""
VulnSleuth Web Application
Flask-based web interface for vulnerability scanning

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, flash
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import json
import os
import sys
import uuid
import threading
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
import secrets

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from engine import VulnSleuthEngine
from reporter import VulnSleuthReporter
from db import DatabaseManager
from utils import load_config, validate_target, setup_logging
from plugin import PluginManager

app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')
app.secret_key = secrets.token_hex(32)
CORS(app)

# Global variables
config = None
engine = None
db_manager = None
plugin_manager = None
reporter = None
active_scans = {}
scan_lock = threading.Lock()

# User database path
USER_DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'users.db')

def init_user_database():
    """Initialize user authentication database"""
    os.makedirs(os.path.dirname(USER_DB_PATH), exist_ok=True)
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT,
            theme TEXT DEFAULT 'system',
            is_active INTEGER DEFAULT 1
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_user_db():
    """Get user database connection"""
    conn = sqlite3.connect(USER_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def initialize_system():
    """Initialize VulnSleuth components"""
    global config, engine, db_manager, plugin_manager, reporter
    
    try:
        # Load configuration
        config_path = os.path.join(os.path.dirname(__file__), '..', 'vulnsluth.cfg')
        config = load_config(config_path)
        
        # Setup logging
        setup_logging(config)
        
        # Initialize database
        db_manager = DatabaseManager(config)
        
        # Initialize engine
        engine = VulnSleuthEngine(config)
        
        # Initialize plugin manager
        plugin_manager = PluginManager(config)
        plugin_manager.load_plugins()
        
        # Initialize reporter
        reporter = VulnSleuthReporter(config)
        
        # Initialize user database
        init_user_database()
        
        app.logger.info("VulnSleuth system initialized successfully")
        return True
    except Exception as e:
        app.logger.error(f"System initialization failed: {str(e)}")
        return False

# ==================== Authentication Routes ====================

@app.route('/')
def index():
    """Landing page - redirect to login or dashboard"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    if request.method == 'GET':
        # Check if any users exist
        conn = get_user_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM users')
        user_count = cursor.fetchone()['count']
        conn.close()
        
        return render_template('register.html', first_user=(user_count == 0))
    
    # POST request - handle registration
    data = request.get_json() if request.is_json else request.form
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    # Validation
    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
    
    if len(password) < 8:
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
    
    try:
        conn = get_user_db()
        cursor = conn.cursor()
        
        # Check if username or email already exists
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'message': 'Username or email already exists'}), 400
        
        # Create user
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, created_at, theme)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, email, password_hash, datetime.now().isoformat(), 'system'))
        
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        # Log the user in
        session['user_id'] = user_id
        session['username'] = username
        session.permanent = True
        
        return jsonify({
            'success': True, 
            'message': 'Registration successful',
            'redirect': url_for('dashboard')
        })
        
    except Exception as e:
        app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'success': False, 'message': 'Registration failed. Please try again.'}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if request.method == 'GET':
        # Check if any users exist
        conn = get_user_db()
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) as count FROM users')
        user_count = cursor.fetchone()['count']
        conn.close()
        
        if user_count == 0:
            return redirect(url_for('register'))
        
        return render_template('login.html')
    
    # POST request - handle login
    data = request.get_json() if request.is_json else request.form
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'}), 400
    
    try:
        conn = get_user_db()
        cursor = conn.cursor()
        
        # Get user
        cursor.execute('SELECT * FROM users WHERE username = ? AND is_active = 1', (username,))
        user = cursor.fetchone()
        
        if not user or not check_password_hash(user['password_hash'], password):
            conn.close()
            return jsonify({'success': False, 'message': 'Invalid username or password'}), 401
        
        # Update last login
        cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', 
                      (datetime.now().isoformat(), user['id']))
        conn.commit()
        conn.close()
        
        # Set session
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['theme'] = user['theme']
        session.permanent = True
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'redirect': url_for('dashboard')
        })
        
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'success': False, 'message': 'Login failed. Please try again.'}), 500

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('login'))

# ==================== Dashboard Routes ====================

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard"""
    try:
        # Get user theme
        conn = get_user_db()
        cursor = conn.cursor()
        cursor.execute('SELECT theme FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        theme = user['theme'] if user else 'system'
        
        # Get scan statistics
        scans = db_manager.get_all_scans(limit=10) if db_manager else []
        
        # Get vulnerability statistics
        stats = {
            'total_scans': len(scans),
            'active_scans': len(active_scans),
            'total_vulnerabilities': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for scan in scans:
            if scan.get('vulnerabilities'):
                stats['total_vulnerabilities'] += len(scan['vulnerabilities'])
                for vuln in scan['vulnerabilities']:
                    severity = vuln.get('severity', '').lower()
                    if severity in stats:
                        stats[severity] += 1
        
        # Get plugin count
        plugin_count = len(plugin_manager.list_plugins()) if plugin_manager else 0
        
        return render_template('dashboard.html', 
                             username=session['username'],
                             theme=theme,
                             stats=stats,
                             recent_scans=scans[:5],
                             plugin_count=plugin_count)
    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        # Provide default stats on error
        default_stats = {
            'total_scans': 0,
            'active_scans': 0,
            'total_vulnerabilities': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        return render_template('dashboard.html', 
                             username=session.get('username', 'User'),
                             theme='light',
                             stats=default_stats,
                             recent_scans=[],
                             plugin_count=0,
                             error=str(e))

# ==================== Scan Routes ====================

@app.route('/scan')
@login_required
def scan_page():
    """Scan configuration page"""
    plugins = plugin_manager.list_plugins() if plugin_manager else []
    
    # Get user theme
    conn = get_user_db()
    cursor = conn.cursor()
    cursor.execute('SELECT theme FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    theme = user['theme'] if user else 'system'
    
    return render_template('scan.html', 
                         username=session['username'],
                         theme=theme,
                         plugins=plugins)

@app.route('/api/scan/start', methods=['POST'])
@login_required
def start_scan():
    """Start a new vulnerability scan"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        scan_type = data.get('scan_type', 'full')
        plugins = data.get('plugins', [])
        
        # Validate target
        if not target:
            return jsonify({'success': False, 'message': 'Target is required'}), 400
        
        # Validate target format
        if not validate_target(target):
            return jsonify({'success': False, 'message': 'Invalid target format'}), 400
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        
        # Store user info before thread (to avoid session context issues)
        user_id = session['user_id']
        username = session['username']
        
        # Prepare scan configuration (ensure numeric values are integers)
        scan_config = {
            'target': target,
            'scan_type': scan_type,
            'plugins': plugins,
            'user_id': user_id,
            'username': username,
            'threads': int(data.get('threads', 10)),
            'timeout': int(data.get('timeout', 300)),
            'aggressive': bool(data.get('aggressive', False))
        }
        
        # Start scan in background thread
        def run_scan():
            try:
                with scan_lock:
                    active_scans[scan_id] = {
                        'status': 'running',
                        'progress': 0,
                        'target': target,
                        'started_at': datetime.now().isoformat(),
                        'results': []
                    }
                
                # Run scan
                results = engine.scan(scan_config, progress_callback=lambda p: update_scan_progress(scan_id, p))
                
                # Save results to database
                scan_result = {
                    'scan_id': scan_id,
                    'target': target,
                    'scan_type': scan_type,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'completed',
                    'vulnerabilities': results,
                    'metadata': {
                        'user_id': user_id,
                        'username': username,
                        'plugins': plugins
                    }
                }
                
                db_manager.save_scan_result(scan_result)
                
                with scan_lock:
                    active_scans[scan_id]['status'] = 'completed'
                    active_scans[scan_id]['progress'] = 100
                    active_scans[scan_id]['results'] = results
                    active_scans[scan_id]['completed_at'] = datetime.now().isoformat()
                
            except Exception as e:
                app.logger.error(f"Scan error: {str(e)}")
                with scan_lock:
                    active_scans[scan_id]['status'] = 'failed'
                    active_scans[scan_id]['error'] = str(e)
        
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Scan started successfully'
        })
        
    except Exception as e:
        app.logger.error(f"Start scan error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

def update_scan_progress(scan_id, progress):
    """Update scan progress"""
    with scan_lock:
        if scan_id in active_scans:
            active_scans[scan_id]['progress'] = progress

@app.route('/api/scan/status/<scan_id>')
@login_required
def scan_status(scan_id):
    """Get scan status"""
    with scan_lock:
        if scan_id in active_scans:
            return jsonify(active_scans[scan_id])
    
    # Check database for completed scans
    scan = db_manager.get_scan_by_id(scan_id) if db_manager else None
    if scan:
        return jsonify({
            'status': 'completed',
            'progress': 100,
            'target': scan.get('target'),
            'results': scan.get('vulnerabilities', [])
        })
    
    return jsonify({'status': 'not_found'}), 404

@app.route('/api/scan/list')
@login_required
def list_scans():
    """List all scans"""
    try:
        scans = db_manager.get_all_scans() if db_manager else []
        return jsonify({'success': True, 'scans': scans})
    except Exception as e:
        app.logger.error(f"List scans error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/scan/delete/<scan_id>', methods=['DELETE'])
@login_required
def delete_scan(scan_id):
    """Delete a scan"""
    try:
        db_manager.delete_scan(scan_id)
        return jsonify({'success': True, 'message': 'Scan deleted successfully'})
    except Exception as e:
        app.logger.error(f"Delete scan error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ==================== Report Routes ====================

@app.route('/reports')
@login_required
def reports_page():
    """Reports page"""
    scans = db_manager.get_all_scans() if db_manager else []
    
    # Get user theme
    conn = get_user_db()
    cursor = conn.cursor()
    cursor.execute('SELECT theme FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    theme = user['theme'] if user else 'system'
    
    return render_template('reports.html', 
                         username=session['username'],
                         theme=theme,
                         scans=scans)

@app.route('/api/report/generate', methods=['POST'])
@login_required
def generate_report():
    """Generate report for a scan"""
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        format_type = data.get('format', 'html')
        
        if not scan_id:
            return jsonify({'success': False, 'message': 'Scan ID is required'}), 400
        
        # Get scan data
        scan = db_manager.get_scan_by_id(scan_id)
        if not scan:
            return jsonify({'success': False, 'message': 'Scan not found'}), 404
        
        # Import ReportConfig
        from reporter import ReportConfig
        
        # Generate report - create proper ReportConfig object
        report_id = str(uuid.uuid4())
        report_filename = f"{report_id}.{format_type}"
        report_config = ReportConfig(
            report_id=report_id,
            title=f"VulnSleuth Scan Report - {scan.get('target')}",
            format=format_type,
            output_path=os.path.join('reports', report_filename),
            include_summary=True,
            include_details=True,
            include_charts=True,
            include_recommendations=True
        )
        
        # Pass scan_results as list (reporter expects list of dicts)
        scan_results = [scan] if scan else []
        report_path = reporter.generate_report(scan_results, report_config)
        
        # Extract just the filename from the path
        report_file = os.path.basename(report_path)
        
        return jsonify({
            'success': True,
            'message': 'Report generated successfully',
            'report_path': report_path,
            'report_file': report_file,
            'download_url': url_for('download_report', filename=report_file)
        })
        
    except Exception as e:
        app.logger.error(f"Generate report error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/report/download/<filename>')
@login_required
def download_report(filename):
    """Download report file"""
    try:
        # Security: only allow files from reports directory
        safe_filename = os.path.basename(filename)
        
        # Get absolute path to reports directory (project root/reports)
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        report_path = os.path.join(project_root, 'reports', safe_filename)
        
        if os.path.exists(report_path):
            return send_file(report_path, as_attachment=True)
        else:
            return jsonify({'error': 'Report not found'}), 404
    except Exception as e:
        app.logger.error(f"Download report error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ==================== Plugin Routes ====================

@app.route('/plugins')
@login_required
def plugins_page():
    """Plugins management page"""
    plugins = plugin_manager.list_plugins() if plugin_manager else []
    
    # Plugin descriptions
    plugin_descriptions = {
        'AuthenticationBypassPlugin': 'Identifies authentication bypass vulnerabilities, weak credentials, and session management flaws. Tests for default passwords, brute force susceptibility, and authentication logic errors.',
        'CVEIntelligencePlugin': 'Correlates discovered services and software versions with known CVE databases. Provides real-time vulnerability intelligence and severity ratings from NVD and other sources.',
        'DatabaseSecurityPlugin': 'Scans for database security issues including SQL injection, weak database credentials, exposed database ports, and improper access controls. Supports MySQL, PostgreSQL, MongoDB, and more.',
        'InformationDisclosurePlugin': 'Detects information leakage through verbose error messages, debug outputs, exposed configuration files, directory listings, and metadata disclosure.',
        'NetworkReconnaissancePlugin': 'Performs comprehensive network discovery, port scanning, service detection, and OS fingerprinting. Maps network topology and identifies active hosts and services.',
        'SSLTLSAuditPlugin': 'Audits SSL/TLS configurations for weak ciphers, expired certificates, protocol vulnerabilities (POODLE, BEAST, Heartbleed), and cipher suite misconfigurations.',
        'WebSecurityScannerPlugin': 'Comprehensive web application security testing including XSS, CSRF, security headers analysis, clickjacking, and common web vulnerabilities scanning.'
    }
    
    # Add author and detailed descriptions to all plugins
    for plugin in plugins:
        plugin['author'] = 'Devdas'
        plugin_name = plugin.get('name', '')
        if plugin_name in plugin_descriptions:
            plugin['detailed_description'] = plugin_descriptions[plugin_name]
        else:
            plugin['detailed_description'] = plugin.get('description', 'No description available.')
    
    # Get user theme
    conn = get_user_db()
    cursor = conn.cursor()
    cursor.execute('SELECT theme FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    theme = user['theme'] if user else 'system'
    
    return render_template('plugins.html', 
                         username=session['username'],
                         theme=theme,
                         plugins=plugins)

@app.route('/vulnerabilities')
@login_required
def vulnerabilities_page():
    """Vulnerability guide page"""
    # Get user theme
    conn = get_user_db()
    cursor = conn.cursor()
    cursor.execute('SELECT theme FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    theme = user['theme'] if user else 'system'
    
    return render_template('vulnerabilities.html', 
                         username=session['username'],
                         theme=theme)

@app.route('/api/plugins/list')
@login_required
def list_plugins():
    """List all plugins"""
    try:
        plugins = plugin_manager.list_plugins() if plugin_manager else []
        return jsonify({'success': True, 'plugins': plugins})
    except Exception as e:
        app.logger.error(f"List plugins error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/plugins/toggle/<plugin_name>', methods=['POST'])
@login_required
def toggle_plugin(plugin_name):
    """Enable/disable a plugin"""
    try:
        data = request.get_json()
        enabled = data.get('enabled', False)
        
        if enabled:
            plugin_manager.enable_plugin(plugin_name)
        else:
            plugin_manager.disable_plugin(plugin_name)
        
        return jsonify({'success': True, 'message': f'Plugin {plugin_name} {"enabled" if enabled else "disabled"}'})
    except Exception as e:
        app.logger.error(f"Toggle plugin error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ==================== Settings Routes ====================

@app.route('/settings')
@login_required
def settings_page():
    """Settings page"""
    conn = get_user_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    return render_template('settings.html', 
                         username=session['username'],
                         theme=user['theme'] if user else 'system',
                         user=dict(user) if user else {})

@app.route('/api/settings/theme', methods=['POST'])
@login_required
def update_theme():
    """Update user theme preference"""
    try:
        data = request.get_json()
        theme = data.get('theme', 'system')
        
        conn = get_user_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET theme = ? WHERE id = ?', (theme, session['user_id']))
        conn.commit()
        conn.close()
        
        session['theme'] = theme
        
        return jsonify({'success': True, 'message': 'Theme updated successfully'})
    except Exception as e:
        app.logger.error(f"Update theme error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/settings/password', methods=['POST'])
@login_required
def update_password():
    """Update user password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if len(new_password) < 8:
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
        
        conn = get_user_db()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or not check_password_hash(user['password_hash'], current_password):
            conn.close()
            return jsonify({'success': False, 'message': 'Current password is incorrect'}), 401
        
        new_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
        cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, session['user_id']))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Password updated successfully'})
    except Exception as e:
        app.logger.error(f"Update password error: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

# ==================== API Routes ====================

@app.route('/api/stats')
@login_required
def get_stats():
    """Get system statistics"""
    try:
        scans = db_manager.get_all_scans() if db_manager else []
        
        stats = {
            'total_scans': len(scans),
            'active_scans': len(active_scans),
            'plugins': len(plugin_manager.list_plugins()) if plugin_manager else 0,
            'vulnerabilities': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        for scan in scans:
            if scan.get('vulnerabilities'):
                for vuln in scan['vulnerabilities']:
                    severity = vuln.get('severity', '').lower()
                    if severity in stats['vulnerabilities']:
                        stats['vulnerabilities'][severity] += 1
        
        return jsonify(stats)
    except Exception as e:
        app.logger.error(f"Get stats error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    app.logger.error(f"Internal error: {str(error)}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

# ==================== Application Startup ====================

def run_app(host='0.0.0.0', port=5000, debug=False):
    """Run the Flask application"""
    if initialize_system():
        app.logger.info(f"Starting VulnSleuth Web Interface on http://{host}:{port}")
        app.run(host=host, port=port, debug=debug, threaded=True)
    else:
        app.logger.error("Failed to initialize system. Exiting.")
        sys.exit(1)

if __name__ == '__main__':
    run_app(debug=True)
