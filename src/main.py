#!/usr/bin/env python3
"""
VulnSleuth - Advanced Vulnerability Scanner
CLI Entry Point

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import click
import sys
import os
import json
import yaml
from pathlib import Path
from typing import Optional, List
import colorama
from colorama import Fore, Style
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from engine import VulnSleuthEngine
from reporter import VulnSleuthReporter
from db import DatabaseManager
from utils import setup_logging, load_config, validate_target
import plugin

colorama.init()

# ASCII Art Banner
BANNER = f"""{Fore.CYAN}
 ██▒   █▓ █    ██  ██▓     ███▄    █   ██████  ██▓    ▓█████  █    ██ ▄▄▄█████▓ ██░ ██ 
▓██░   █▒ ██  ▓██▒▓██▒     ██ ▀█   █ ▒██    ▒ ▓██▒    ▓█   ▀  ██  ▓██▒▓  ██▒ ▓▒▓██░ ██▒
 ▓██  █▒░▓██  ▒██░▒██░    ▓██  ▀█ ██▒░ ▓██▄   ▒██░    ▒███   ▓██  ▒██░▒ ▓██░ ▒░▒██▀▀██░
  ▒██ █░░▓▓█  ░██░▒██░    ▓██▒  ▐▌██▒  ▒   ██▒▒██░    ▒▓█  ▄ ▓▓█  ░██░░ ▓██▓ ░ ░▓█ ░██ 
   ▒▀█░  ▒▒█████▓ ░██████▒▒██░   ▓██░▒██████▒▒░██████▒░▒████▒▒▒█████▓   ▒██▒ ░ ░▓█▒░██▓
   ░ ▐░  ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░ ▒░▓  ░░░ ▒░ ░░▒▓▒ ▒ ▒   ▒ ░░    ▒ ░░▒░▒
   ░ ░░  ░░▒░ ░ ░ ░ ░ ▒  ░░ ░░   ░ ▒░░ ░▒  ░ ░░ ░ ▒  ░ ░ ░  ░░░▒░ ░ ░     ░     ▒ ░▒░ ░
     ░░   ░░░ ░ ░   ░ ░      ░   ░ ░ ░  ░  ░    ░ ░      ░    ░░░ ░ ░   ░       ░  ░░ ░
      ░     ░         ░  ░         ░       ░      ░  ░   ░  ░   ░               ░  ░  ░
     ░                                                                                  
{Style.RESET_ALL}
{Fore.GREEN}Advanced Vulnerability Scanner & Security Assessment Tool{Style.RESET_ALL}
{Fore.YELLOW}Ethical Hacking Framework{Style.RESET_ALL}
{Fore.MAGENTA}Author: Devdas | GitHub: https://github.com/devdas36{Style.RESET_ALL}
"""

@click.group(invoke_without_command=True)
@click.option('--config', '-c', default='vulnsluth.cfg', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--quiet', '-q', is_flag=True, help='Quiet mode')
@click.pass_context
def cli(ctx, config, verbose, quiet):
    """VulnSleuth - Advanced Vulnerability Scanner for Ethical Hacking"""
    
    if not quiet:
        click.echo(BANNER)
        
    if ctx.invoked_subcommand is None:
        click.echo(f"{Fore.RED}⚠️  ETHICAL USE NOTICE ⚠️{Style.RESET_ALL}")
        click.echo(f"{Fore.YELLOW}This tool is for authorized security testing only.{Style.RESET_ALL}")
        click.echo(f"{Fore.YELLOW}Ensure you have explicit permission before scanning.{Style.RESET_ALL}")
        click.echo()
        click.echo(ctx.get_help())
        return
    
    ctx.ensure_object(dict)
    ctx.obj['config'] = load_config(config)
    ctx.obj['verbose'] = verbose
    ctx.obj['quiet'] = quiet
    
    setup_logging(ctx.obj['config'])

@cli.command()
@click.option('--force', is_flag=True, help='Force reinitialization')
@click.option('--config-file', default='vulnsluth.cfg', help='Configuration file to create')
@click.pass_context
def init(ctx, force, config_file):
    """Initialize VulnSleuth database and configuration"""
    
    click.echo(f"{Fore.BLUE}🚀 Initializing VulnSleuth...{Style.RESET_ALL}")
    
    try:
        # Check if already initialized
        if os.path.exists('vulnsleuth.db') and not force:
            if not click.confirm(f"{Fore.YELLOW}VulnSleuth appears to already be initialized. Reinitialize?{Style.RESET_ALL}"):
                return
        
        # Create default configuration if it doesn't exist
        if not os.path.exists(config_file) or force:
            click.echo(f"{Fore.BLUE}📝 Creating configuration file: {config_file}{Style.RESET_ALL}")
            from utils import get_default_config
            
            default_config = get_default_config()
            with open(config_file, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False, indent=2)
            click.echo(f"{Fore.GREEN}✅ Configuration file created{Style.RESET_ALL}")
        
        # Load configuration
        config = load_config(config_file)
        
        # Initialize database
        click.echo(f"{Fore.BLUE}🗃️  Initializing database...{Style.RESET_ALL}")
        db = DatabaseManager(config)
        db.init_db()
        click.echo(f"{Fore.GREEN}✅ Database initialized{Style.RESET_ALL}")
        
        # Create necessary directories
        directories = ['reports', 'logs', 'plugins', 'backups']
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                click.echo(f"{Fore.GREEN}📁 Created directory: {directory}{Style.RESET_ALL}")
        
        # Initialize plugin system
        click.echo(f"{Fore.BLUE}🔌 Loading plugins...{Style.RESET_ALL}")
        plugin_manager = plugin.PluginManager(config)
        plugin_count = plugin_manager.load_plugins()
        click.echo(f"{Fore.GREEN}✅ Loaded {plugin_count} plugins{Style.RESET_ALL}")
        
        # Setup logging
        setup_logging(config)
        click.echo(f"{Fore.GREEN}✅ Logging configured{Style.RESET_ALL}")
        
        click.echo(f"\n{Fore.GREEN}🎉 VulnSleuth initialization completed successfully!{Style.RESET_ALL}")
        click.echo(f"{Fore.CYAN}You can now run scans with: python src/main.py scan --help{Style.RESET_ALL}")
        
    except Exception as e:
        click.echo(f"\n{Fore.RED}❌ Initialization failed: {str(e)}{Style.RESET_ALL}")
        if ctx.obj.get('verbose'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

@cli.command()
@click.option('--target', '-t', required=True, help='Target to scan (IP, domain, or range)')
@click.option('--ports', '-p', default='1-1000', help='Port range to scan')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', default='html', type=click.Choice(['json', 'html', 'pdf']), help='Output format')
@click.option('--severity', '-s', default='medium', type=click.Choice(['low', 'medium', 'high', 'critical']), help='Minimum severity level')
@click.option('--local', is_flag=True, help='Perform local system checks')
@click.option('--network', is_flag=True, help='Perform network scanning')
@click.option('--webapp', is_flag=True, help='Perform web application scanning')
@click.option('--plugins', help='Comma-separated list of plugins to use')
@click.option('--exclude-plugins', help='Comma-separated list of plugins to exclude')
@click.option('--threads', '-j', default=10, help='Number of scanning threads')
@click.option('--timeout', default=300, help='Scan timeout in seconds')
@click.option('--save-scan', is_flag=True, help='Save scan results to database')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output with detailed error information')
@click.pass_context
def scan(ctx, target, ports, output, format, severity, local, network, webapp, 
         plugins, exclude_plugins, threads, timeout, save_scan, verbose):
    """Perform vulnerability scan on target system"""
    
    config = ctx.obj['config']
    # Use local verbose parameter if provided, otherwise fall back to global
    verbose_mode = verbose or ctx.obj.get('verbose', False)
    
    # Validate target
    if not validate_target(target):
        click.echo(f"{Fore.RED}❌ Invalid target: {target}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Ethical use confirmation for external targets
    if not target.startswith('127.') and not target.startswith('localhost'):
        click.confirm(f"{Fore.YELLOW}⚠️  Scanning external target {target}. Do you have authorization?{Style.RESET_ALL}", abort=True)
    
    click.echo(f"{Fore.GREEN}🔍 Starting VulnSleuth scan...{Style.RESET_ALL}")
    click.echo(f"Target: {Fore.CYAN}{target}{Style.RESET_ALL}")
    click.echo(f"Ports: {Fore.CYAN}{ports}{Style.RESET_ALL}")
    click.echo(f"Severity: {Fore.CYAN}{severity.upper()}{Style.RESET_ALL}")
    
    # Initialize engine
    engine = VulnSleuthEngine(config)
    
    # Configure scan options
    scan_config = {
        'target': target,
        'ports': ports,
        'local_checks': local,
        'network_checks': network or not (local or webapp),
        'webapp_checks': webapp,
        'plugins': plugins.split(',') if plugins else [],
        'exclude_plugins': exclude_plugins.split(',') if exclude_plugins else [],
        'threads': threads,
        'timeout': timeout,
        'severity_threshold': severity
    }
    
    start_time = time.time()
    
    try:
        # Run scan
        with click.progressbar(length=100, label='Scanning') as bar:
            def progress_update(p):
                # Ensure progress is an integer for click progress bar
                progress_value = int(p) if isinstance(p, (int, float)) else 0
                bar.update(progress_value)
            
            results = engine.scan(scan_config, progress_callback=progress_update)
        
        scan_time = time.time() - start_time
        
        # Display results summary
        click.echo(f"\n{Fore.GREEN}✅ Scan completed in {scan_time:.2f} seconds{Style.RESET_ALL}")
        click.echo(f"Found {len(results)} vulnerabilities:")
        
        # Count by severity
        severity_counts = {}
        for result in results:
            sev = result.get('severity', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        for sev, count in severity_counts.items():
            color = {
                'critical': Fore.RED,
                'high': Fore.MAGENTA,
                'medium': Fore.YELLOW,
                'low': Fore.GREEN,
                'info': Fore.CYAN
            }.get(sev, Fore.WHITE)
            click.echo(f"  {color}{sev.upper()}: {count}{Style.RESET_ALL}")
        
        # Generate report if requested
        if output:
            click.echo(f"\n{Fore.BLUE}📄 Generating {format.upper()} report...{Style.RESET_ALL}")
            report_gen = VulnSleuthReporter(config)
            report_path = report_gen.generate_report(results, scan_config, output, format)
            click.echo(f"{Fore.GREEN}✅ Report saved to: {report_path}{Style.RESET_ALL}")
        
        # Save to database if requested
        if save_scan:
            from db import ScanResult
            db = DatabaseManager(config)
            
            # Create a ScanResult object
            scan_result = ScanResult(
                scan_id=f"scan_{int(time.time())}",
                target=target,
                scan_type="network",
                timestamp=datetime.now().isoformat(),
                status="completed",
                vulnerabilities=results,
                metadata=scan_config
            )
            
            # Save the scan result
            success = db.save_scan_result(scan_result)
            if success:
                click.echo(f"{Fore.BLUE}💾 Scan saved to database with ID: {scan_result.scan_id}{Style.RESET_ALL}")
            else:
                click.echo(f"{Fore.YELLOW}⚠️  Failed to save scan to database{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        click.echo(f"\n{Fore.YELLOW}⚠️  Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        import traceback
        click.echo(f"\n{Fore.RED}❌ Scan failed: {str(e)}{Style.RESET_ALL}")
        # Force traceback to show - debug the string/int comparison error
        click.echo(f"\n{Fore.YELLOW}=== FULL ERROR TRACEBACK ==={Style.RESET_ALL}")
        traceback.print_exc(file=sys.stdout)
        click.echo(f"{Fore.YELLOW}=== END TRACEBACK ==={Style.RESET_ALL}")
        if verbose_mode:
            click.echo(f"\n{Fore.CYAN}Verbose mode enabled - error in scan execution{Style.RESET_ALL}")
        sys.exit(1)

@cli.command()
@click.option('--scan-id', help='Specific scan ID to remediate (e.g., scan_1754736588)')
@click.option('--auto-confirm', is_flag=True, help='Auto-confirm remediation actions')
@click.option('--dry-run', is_flag=True, help='Show proposed actions without executing')
@click.option('--backup', is_flag=True, default=True, help='Create backups before changes')
@click.pass_context
def remediate(ctx, scan_id, auto_confirm, dry_run, backup):
    """Auto-remediate vulnerabilities with operator confirmation"""
    
    config = ctx.obj['config']
    
    if not config.get('remediation', {}).get('enabled', False):
        click.echo(f"{Fore.RED}❌ Auto-remediation is disabled in configuration{Style.RESET_ALL}")
        return
    
    click.echo(f"{Fore.BLUE}🔧 VulnSleuth Auto-Remediation Engine{Style.RESET_ALL}")
    
    # Import remediation engine
    from auto_remediation import AutoRemediationEngine
    
    remediation_engine = AutoRemediationEngine(config)
    
    if scan_id:
        # Get vulnerabilities from specific scan
        db = DatabaseManager(config)
        all_scans = db.get_scan_results(days_back=365, limit=1000)
        
        # Find the specific scan
        target_scan = None
        for scan in all_scans:
            if (scan.scan_id == scan_id or 
                scan.scan_id == f"scan_{scan_id}" or
                (scan_id.isdigit() and scan.scan_id == f"scan_{scan_id}")):
                target_scan = scan
                break
        
        if not target_scan:
            click.echo(f"{Fore.RED}❌ Scan ID '{scan_id}' not found{Style.RESET_ALL}")
            return
        
        vulnerabilities = target_scan.vulnerabilities if target_scan.vulnerabilities else []
    else:
        click.echo(f"{Fore.YELLOW}No scan ID provided. Use latest scan results.{Style.RESET_ALL}")
        return
    
    click.echo(f"Found {len(vulnerabilities)} vulnerabilities to analyze")
    
    if not vulnerabilities:
        click.echo(f"{Fore.GREEN}✅ No vulnerabilities found to remediate{Style.RESET_ALL}")
        return
    
    # Analyze and propose remediation
    remediation_plan = remediation_engine.analyze_vulnerabilities(vulnerabilities)
    
    if not remediation_plan:
        click.echo(f"{Fore.GREEN}✅ No automatic remediation available{Style.RESET_ALL}")
        return
    
    click.echo(f"\n{Fore.CYAN}📋 Remediation Plan:{Style.RESET_ALL}")
    for i, action in enumerate(remediation_plan, 1):
        click.echo(f"{i}. {action['description']}")
        click.echo(f"   Risk: {Fore.YELLOW}{action['risk']}{Style.RESET_ALL}")
        click.echo(f"   Impact: {action['impact']}")
        click.echo()
    
    if dry_run:
        click.echo(f"{Fore.BLUE}🔍 Dry run completed. No changes made.{Style.RESET_ALL}")
        return
    
    if not auto_confirm:
        click.confirm(f"{Fore.YELLOW}Proceed with remediation?{Style.RESET_ALL}", abort=True)
    
    # Execute remediation
    results = remediation_engine.execute_remediation(remediation_plan, backup=backup)
    
    success_count = sum(1 for r in results if r['success'])
    click.echo(f"\n{Fore.GREEN}✅ Remediation completed: {success_count}/{len(results)} successful{Style.RESET_ALL}")

@cli.command()
@click.option('--list-scans', is_flag=True, help='List all previous scans')
@click.option('--scan-id', help='Show details for specific scan (e.g., scan_1754736588)')
@click.option('--export', help='Export scan data to file')
@click.option('--cleanup', is_flag=True, help='Cleanup old scan data')
@click.pass_context
def history(ctx, list_scans, scan_id, export, cleanup):
    """Manage scan history and database"""
    
    config = ctx.obj['config']
    db = DatabaseManager(config)
    
    if list_scans:
        # Use get_scan_results to get recent scans
        scan_results = db.get_scan_results(days_back=365, limit=50)  # Get last year's scans
        if not scan_results:
            click.echo("No scan history found")
            return
        
        click.echo(f"{Fore.CYAN}📊 Scan History:{Style.RESET_ALL}")
        click.echo("-" * 80)
        for scan_result in scan_results:
            timestamp = datetime.fromisoformat(scan_result.timestamp)
            vuln_count = len(scan_result.vulnerabilities) if scan_result.vulnerabilities else 0
            click.echo(f"ID: {scan_result.scan_id} | Target: {scan_result.target} | {timestamp.strftime('%Y-%m-%d %H:%M')} | Vulns: {vuln_count}")
    
    elif scan_id:
        # Get scan results for specific scan_id
        all_scans = db.get_scan_results(days_back=365, limit=1000)
        scan_details = None
        for scan in all_scans:
            # Handle both direct string match and numeric suffix match
            if (scan.scan_id == scan_id or 
                scan.scan_id == f"scan_{scan_id}" or
                (scan_id.isdigit() and scan.scan_id == f"scan_{scan_id}")):
                scan_details = {
                    'scan_id': scan.scan_id,
                    'target': scan.target,
                    'scan_type': scan.scan_type,
                    'timestamp': scan.timestamp,
                    'status': scan.status,
                    'vulnerabilities': scan.vulnerabilities,
                    'metadata': scan.metadata
                }
                break
        
        if not scan_details:
            click.echo(f"Scan ID '{scan_id}' not found")
            return
        
        click.echo(f"{Fore.CYAN}📋 Scan Details (ID: {scan_id}){Style.RESET_ALL}")
        click.echo(json.dumps(scan_details, indent=2))
    
    elif cleanup:
        if click.confirm("Delete old scan data?"):
            deleted = db.cleanup_old_data()
            click.echo(f"Deleted {deleted} old scan records")
    
    else:
        # Show database statistics
        stats = db.get_database_info()
        click.echo(f"{Fore.CYAN}📊 Database Statistics:{Style.RESET_ALL}")
        click.echo(f"Database path: {stats.get('db_path', 'Unknown')}")
        click.echo(f"Database size: {stats.get('size_mb', 0):.2f} MB")
        click.echo(f"Tables: {', '.join(stats.get('tables', []))}")

@cli.command()
@click.option('--list', is_flag=True, help='List available plugins')
@click.option('--install', help='Install plugin from path/URL')
@click.option('--remove', help='Remove installed plugin')
@click.option('--info', help='Show plugin information')
@click.pass_context
def plugins(ctx, list, install, remove, info):
    """Manage vulnerability scanning plugins"""
    
    config = ctx.obj['config']
    plugin_manager = plugin.PluginManager(config)
    
    if list:
        plugins_list = plugin_manager.list_plugins()
        click.echo(f"{Fore.CYAN}🔌 Available Plugins:{Style.RESET_ALL}")
        for p in plugins_list:
            status = f"{Fore.GREEN}✅ LOADED{Style.RESET_ALL}" if p['loaded'] else f"{Fore.RED}❌ ERROR{Style.RESET_ALL}"
            click.echo(f"{p['name']} v{p['version']} - {p['description']} [{status}]")
    
    elif install:
        if plugin_manager.install_plugin(install):
            click.echo(f"{Fore.GREEN}✅ Plugin installed successfully{Style.RESET_ALL}")
        else:
            click.echo(f"{Fore.RED}❌ Plugin installation failed{Style.RESET_ALL}")
    
    elif remove:
        if plugin_manager.remove_plugin(remove):
            click.echo(f"{Fore.GREEN}✅ Plugin removed successfully{Style.RESET_ALL}")
        else:
            click.echo(f"{Fore.RED}❌ Plugin removal failed{Style.RESET_ALL}")
    
    elif info:
        plugin_info = plugin_manager.get_plugin_info(info)
        if plugin_info:
            click.echo(json.dumps(plugin_info, indent=2))
        else:
            click.echo(f"Plugin '{info}' not found")

@cli.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=5000, help='Port to bind to')
@click.option('--debug', is_flag=True, help='Enable debug mode')
@click.pass_context
def dashboard(ctx, host, port, debug):
    """Launch web dashboard"""
    
    config = ctx.obj['config']
    
    click.echo(f"{Fore.BLUE}🌐 Starting VulnSleuth Web Dashboard...{Style.RESET_ALL}")
    click.echo(f"URL: http://{host}:{port}")
    
    # Import and start Flask app
    from webapp import app, init_dashboard
    
    # Initialize dashboard components
    init_dashboard(config)
    
    app.config.update(config)
    app.run(host=host, port=port, debug=debug)

@cli.command()
@click.option('--target', help='Update CVE data for specific target')
@click.option('--force', is_flag=True, help='Force update even if cache is fresh')
@click.pass_context
def update_cve(ctx, target, force):
    """Update CVE database"""
    
    config = ctx.obj['config']
    
    click.echo(f"{Fore.BLUE}🔄 Updating CVE database...{Style.RESET_ALL}")
    
    from cve_lookup import CVELookup
    
    cve_lookup = CVELookup(config)
    
    try:
        if target:
            updated = cve_lookup.update_target_cves(target, force)
            click.echo(f"Updated {updated} CVE records for {target}")
        else:
            updated = cve_lookup.update_all_cves(force)
            click.echo(f"Updated {updated} CVE records")
        
        click.echo(f"{Fore.GREEN}✅ CVE database update completed{Style.RESET_ALL}")
        
    except Exception as e:
        click.echo(f"{Fore.RED}❌ CVE update failed: {str(e)}{Style.RESET_ALL}")

@cli.command()
@click.option('--config-file', help='Generate sample configuration file')
@click.option('--plugin-template', help='Generate plugin template')
@click.option('--report-template', help='Generate custom report template')
@click.pass_context
def generate(ctx, config_file, plugin_template, report_template):
    """Generate configuration templates and examples"""
    
    if config_file:
        # Generate sample config
        sample_config = """# VulnSleuth Sample Configuration
[general]
name = VulnSleuth

[database]
db_path = data/vulnsleuth.db

# Add more configuration sections as needed
"""
        with open(config_file, 'w') as f:
            f.write(sample_config)
        click.echo(f"Sample configuration saved to {config_file}")
    
    elif plugin_template:
        # Generate plugin template
        from plugin import generate_plugin_template
        generate_plugin_template(plugin_template)
        click.echo(f"Plugin template saved to {plugin_template}")
    
    elif report_template:
        # Generate report template
        from reporter import generate_report_template
        generate_report_template(report_template)
        click.echo(f"Report template saved to {report_template}")

if __name__ == '__main__':
    try:
        cli()
    except KeyboardInterrupt:
        click.echo(f"\n{Fore.YELLOW}⚠️  Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        click.echo(f"\n{Fore.RED}❌ Unexpected error in main: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
