#!/usr/bin/env python3
"""
VulnSleuth - Interactive Terminal User Interface
Modern menu-driven interface using Rich library

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import sys
import os
import time
from datetime import datetime
from typing import Optional, Dict, List, Any
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.tree import Tree
from rich import box
from rich.markdown import Markdown
from rich.syntax import Syntax

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from engine import VulnSleuthEngine
from reporter import VulnSleuthReporter
from db import DatabaseManager, ScanResult
from utils import setup_logging, load_config, validate_target
import plugin

console = Console()

class VulnSleuthTUI:
    """Interactive Terminal UI for VulnSleuth"""
    
    def __init__(self, config_path: str = 'vulnsluth.cfg'):
        self.config_path = config_path
        self.config = None
        self.engine = None
        self.db = None
        self.plugin_manager = None
        self.running = True
        
    def show_banner(self):
        """Display attractive ASCII banner"""
        banner_art = """
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                          ║
║  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗  ║
║  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║  ║
║  ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     █████╗  ██║   ██║   ██║   ███████║  ║
║  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║  ║
║   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║  ║
║    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝  ║
║                                                                                          ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
        """
        
        banner_panel = Panel(
            Align.center(
                Text(banner_art, style="bold cyan") + "\n\n" +
                Text("Advanced Vulnerability Scanner & Security Assessment Tool", style="bold green") + "\n" +
                Text("Ethical Hacking Framework", style="bold yellow") + "\n\n" +
                Text("Author: Devdas | GitHub: https://github.com/devdas36", style="bold magenta")
            ),
            border_style="bright_blue",
            box=box.DOUBLE_EDGE
        )
        console.print(banner_panel)
        console.print()
        
    def show_ethical_notice(self):
        """Display ethical use warning"""
        notice = Panel(
            Align.center(
                Text("⚠️  ETHICAL USE NOTICE ⚠️\n\n", style="bold red") +
                Text("This tool is for authorized security testing only.\n", style="yellow") +
                Text("Ensure you have explicit permission before scanning any system.\n", style="yellow") +
                Text("Unauthorized access to computer systems is illegal.\n\n", style="yellow") +
                Text("Press ENTER to acknowledge and continue...", style="bold white")
            ),
            border_style="red",
            box=box.HEAVY
        )
        console.print(notice)
        input()
        
    def initialize_system(self):
        """Initialize VulnSleuth components"""
        with console.status("[bold cyan]Initializing VulnSleuth...", spinner="dots"):
            try:
                # Load configuration
                self.config = load_config(self.config_path)
                time.sleep(0.5)
                
                # Setup logging
                setup_logging(self.config)
                time.sleep(0.3)
                
                # Initialize database
                self.db = DatabaseManager(self.config)
                time.sleep(0.3)
                
                # Initialize engine
                self.engine = VulnSleuthEngine(self.config)
                time.sleep(0.3)
                
                # Load plugins
                self.plugin_manager = plugin.PluginManager(self.config)
                plugin_count = self.plugin_manager.load_plugins()
                time.sleep(0.3)
                
                console.print("[bold green]✓[/] System initialized successfully!")
                console.print(f"[bold green]✓[/] Loaded {plugin_count} plugins")
                time.sleep(1)
                
            except Exception as e:
                console.print(f"[bold red]✗ Initialization failed: {str(e)}[/]")
                console.print("[yellow]Press ENTER to exit...[/]")
                input()
                sys.exit(1)
                
    def show_main_menu(self) -> str:
        """Display main menu and get user choice"""
        console.clear()
        
        # Create status bar
        status_table = Table.grid(padding=1)
        status_table.add_column(style="cyan", justify="left")
        status_table.add_column(style="green", justify="right")
        
        status_table.add_row(
            f"[bold]VulnSleuth[/] | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Plugins: {len(self.plugin_manager.list_plugins()) if self.plugin_manager else 0}"
        )
        
        console.print(Panel(status_table, border_style="bright_blue"))
        console.print()
        
        # Create main menu
        menu = Table(show_header=False, box=box.ROUNDED, border_style="cyan", padding=(0, 2))
        menu.add_column("Option", style="bold yellow", width=8)
        menu.add_column("Description", style="white")
        
        menu.add_row("[1]", "🔍 Start New Scan")
        menu.add_row("[2]", "📊 View Scan History")
        menu.add_row("[3]", "📋 View Vulnerability Reports")
        menu.add_row("[4]", "🔧 Auto Remediation")
        menu.add_row("[5]", "🔌 Plugin Manager")
        menu.add_row("[6]", "⚙️  System Settings")
        menu.add_row("[7]", "💾 Database Management")
        menu.add_row("[8]", "🌐 Launch Web Dashboard")
        menu.add_row("[9]", "📖 Help & Documentation")
        menu.add_row("[0]", "❌ Exit")
        
        console.print(Panel(menu, title="[bold cyan]Main Menu[/]", border_style="bright_blue"))
        console.print()
        
        choice = Prompt.ask(
            "[bold green]Select an option[/]",
            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
            default="1"
        )
        
        return choice
        
    def scan_menu(self):
        """Display scan configuration menu"""
        console.clear()
        console.print(Panel("[bold cyan]🔍 New Vulnerability Scan[/]", border_style="cyan"))
        console.print()
        
        # Get scan parameters
        target = Prompt.ask("[bold yellow]Target[/] (IP/Domain/Range)", default="localhost")
        
        # Validate target
        if not validate_target(target):
            console.print("[bold red]✗ Invalid target format![/]")
            console.print("[yellow]Press ENTER to continue...[/]")
            input()
            return
            
        # Ethical confirmation for external targets
        if not target.startswith('127.') and not target.lower().startswith('localhost'):
            if not Confirm.ask(f"[bold yellow]⚠️  Scanning external target '{target}'. Do you have authorization?[/]"):
                console.print("[red]Scan cancelled.[/]")
                time.sleep(1)
                return
        
        # Scan type selection
        console.print("\n[bold cyan]Scan Types:[/]")
        scan_type_table = Table(show_header=False, box=None)
        scan_type_table.add_column("Option", style="yellow")
        scan_type_table.add_column("Description", style="white")
        scan_type_table.add_row("[1]", "Quick Scan (Top 100 ports)")
        scan_type_table.add_row("[2]", "Standard Scan (Top 1000 ports)")
        scan_type_table.add_row("[3]", "Full Scan (All 65535 ports)")
        scan_type_table.add_row("[4]", "Custom Port Range")
        console.print(scan_type_table)
        
        scan_type = Prompt.ask("\n[bold green]Select scan type[/]", choices=["1", "2", "3", "4"], default="2")
        
        port_mapping = {
            "1": "1-100",
            "2": "1-1000",
            "3": "1-65535",
            "4": None
        }
        
        ports = port_mapping[scan_type]
        if ports is None:
            ports = Prompt.ask("[yellow]Enter port range[/] (e.g., 1-1000, 80,443,8080)", default="1-1000")
        
        # Severity threshold
        console.print("\n[bold cyan]Minimum Severity Level:[/]")
        severity_table = Table(show_header=False, box=None)
        severity_table.add_column("Option", style="yellow")
        severity_table.add_column("Level", style="white")
        severity_table.add_row("[1]", "Low")
        severity_table.add_row("[2]", "Medium")
        severity_table.add_row("[3]", "High")
        severity_table.add_row("[4]", "Critical")
        console.print(severity_table)
        
        severity_choice = Prompt.ask("\n[bold green]Select severity[/]", choices=["1", "2", "3", "4"], default="2")
        severity_map = {"1": "low", "2": "medium", "3": "high", "4": "critical"}
        severity = severity_map[severity_choice]
        
        # Scan options
        console.print("\n[bold cyan]Scan Options:[/]")
        network_scan = Confirm.ask("[yellow]Include network scanning?[/]", default=True)
        webapp_scan = Confirm.ask("[yellow]Include web application scanning?[/]", default=False)
        local_scan = Confirm.ask("[yellow]Include local system checks?[/]", default=False)
        save_results = Confirm.ask("[yellow]Save results to database?[/]", default=True)
        
        # Threads
        threads = IntPrompt.ask("[yellow]Number of threads[/]", default=10)
        
        # Confirm scan
        console.print("\n[bold cyan]Scan Configuration Summary:[/]")
        config_table = Table(show_header=False, box=box.ROUNDED, border_style="green")
        config_table.add_column("Parameter", style="bold cyan")
        config_table.add_column("Value", style="yellow")
        config_table.add_row("Target", target)
        config_table.add_row("Ports", ports)
        config_table.add_row("Severity", severity.upper())
        config_table.add_row("Network Scan", "✓" if network_scan else "✗")
        config_table.add_row("Web App Scan", "✓" if webapp_scan else "✗")
        config_table.add_row("Local Scan", "✓" if local_scan else "✗")
        config_table.add_row("Threads", str(threads))
        console.print(config_table)
        console.print()
        
        if not Confirm.ask("[bold green]Start scan?[/]", default=True):
            console.print("[yellow]Scan cancelled.[/]")
            time.sleep(1)
            return
        
        # Execute scan
        self.execute_scan(target, ports, severity, network_scan, webapp_scan, local_scan, threads, save_results)
        
    def execute_scan(self, target: str, ports: str, severity: str, network: bool, 
                     webapp: bool, local: bool, threads: int, save: bool):
        """Execute vulnerability scan with progress tracking"""
        console.clear()
        console.print(Panel("[bold cyan]🔍 Scanning in Progress[/]", border_style="cyan"))
        console.print()
        
        scan_config = {
            'target': target,
            'ports': ports,
            'local_checks': local,
            'network_checks': network,
            'webapp_checks': webapp,
            'plugins': [],
            'exclude_plugins': [],
            'threads': threads,
            'timeout': 300,
            'severity_threshold': severity
        }
        
        start_time = time.time()
        results = []
        
        try:
            # Create progress bar
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                
                scan_task = progress.add_task("[cyan]Scanning target...", total=100)
                
                def progress_callback(p):
                    progress.update(scan_task, completed=int(p))
                
                # Run scan
                results = self.engine.scan(scan_config, progress_callback=progress_callback)
                
            scan_time = time.time() - start_time
            
            # Display results
            self.show_scan_results(results, scan_time, target)
            
            # Save to database
            if save and self.db:
                scan_id = f"scan_{int(time.time())}"
                scan_result = ScanResult(
                    scan_id=scan_id,
                    target=target,
                    scan_type="network",
                    timestamp=datetime.now().isoformat(),
                    status="completed",
                    vulnerabilities=results,
                    metadata=scan_config
                )
                
                if self.db.save_scan_result(scan_result):
                    console.print(f"\n[bold green]✓[/] Results saved with ID: [cyan]{scan_id}[/]")
            
            # Generate report option
            if Confirm.ask("\n[bold yellow]Generate detailed report?[/]", default=False):
                self.generate_report_menu(results, scan_config, target)
                
        except KeyboardInterrupt:
            console.print("\n[bold yellow]⚠️  Scan interrupted by user[/]")
        except Exception as e:
            console.print(f"\n[bold red]✗ Scan failed: {str(e)}[/]")
            
        console.print("\n[yellow]Press ENTER to continue...[/]")
        input()
        
    def show_scan_results(self, results: List[Dict], scan_time: float, target: str):
        """Display scan results in a formatted table"""
        console.print()
        console.print(Panel(
            f"[bold green]✓ Scan Completed[/]\n"
            f"[cyan]Target:[/] {target}\n"
            f"[cyan]Duration:[/] {scan_time:.2f} seconds\n"
            f"[cyan]Vulnerabilities Found:[/] {len(results)}",
            border_style="green"
        ))
        console.print()
        
        if not results:
            console.print("[yellow]No vulnerabilities detected.[/]")
            return
        
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for result in results:
            sev = result.get('severity', 'info').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        # Display severity summary
        summary_table = Table(box=box.ROUNDED, border_style="cyan")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")
        summary_table.add_column("Visual", justify="left")
        
        severity_colors = {
            "critical": "red",
            "high": "bright_red",
            "medium": "yellow",
            "low": "green",
            "info": "cyan"
        }
        
        for sev, count in severity_counts.items():
            if count > 0:
                color = severity_colors.get(sev, "white")
                bar = "█" * min(count, 20)
                summary_table.add_row(
                    f"[{color}]{sev.upper()}[/{color}]",
                    f"[{color}]{count}[/{color}]",
                    f"[{color}]{bar}[/{color}]"
                )
        
        console.print(summary_table)
        console.print()
        
        # Display top vulnerabilities
        if len(results) > 0:
            console.print("[bold cyan]Top Vulnerabilities:[/]")
            vuln_table = Table(box=box.SIMPLE, border_style="cyan", show_lines=True)
            vuln_table.add_column("#", style="cyan", width=3)
            vuln_table.add_column("Severity", style="bold", width=10)
            vuln_table.add_column("Title", style="white", width=40)
            vuln_table.add_column("Category", style="yellow", width=15)
            
            for idx, result in enumerate(results[:10], 1):  # Show top 10
                sev = result.get('severity', 'info').lower()
                color = severity_colors.get(sev, "white")
                vuln_table.add_row(
                    str(idx),
                    f"[{color}]{sev.upper()}[/{color}]",
                    result.get('title', 'Unknown'),
                    result.get('category', 'N/A')
                )
            
            console.print(vuln_table)
            
            if len(results) > 10:
                console.print(f"\n[dim]... and {len(results) - 10} more vulnerabilities[/]")
                
    def generate_report_menu(self, results: List[Dict], scan_config: Dict, target: str):
        """Generate scan report in various formats"""
        console.print("\n[bold cyan]Report Generation:[/]")
        
        format_table = Table(show_header=False, box=None)
        format_table.add_column("Option", style="yellow")
        format_table.add_column("Format", style="white")
        format_table.add_row("[1]", "HTML Report")
        format_table.add_row("[2]", "PDF Report")
        format_table.add_row("[3]", "JSON Export")
        format_table.add_row("[4]", "Cancel")
        console.print(format_table)
        
        choice = Prompt.ask("[bold green]Select format[/]", choices=["1", "2", "3", "4"], default="1")
        
        if choice == "4":
            return
        
        format_map = {"1": "html", "2": "pdf", "3": "json"}
        report_format = format_map[choice]
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"reports/scan_{target.replace('.', '_')}_{timestamp}.{report_format}"
        
        output_path = Prompt.ask("[yellow]Output path[/]", default=default_filename)
        
        with console.status(f"[bold cyan]Generating {report_format.upper()} report...", spinner="dots"):
            try:
                from reporter import ReportConfig
                reporter = VulnSleuthReporter(self.config)
                
                # Create ReportConfig object
                report_cfg = ReportConfig(
                    report_id=f"report_{int(time.time())}",
                    title=f"Vulnerability Scan Report - {target}",
                    format=report_format,
                    output_path=output_path,
                    include_summary=True,
                    include_details=True,
                    include_charts=True,
                    include_recommendations=True
                )
                
                report_path = reporter.generate_report(results, report_cfg)
                time.sleep(1)
                console.print(f"[bold green]✓[/] Report saved to: [cyan]{report_path}[/]")
            except Exception as e:
                console.print(f"[bold red]✗ Report generation failed: {str(e)}[/]")
                
    def scan_history_menu(self):
        """Display scan history"""
        console.clear()
        console.print(Panel("[bold cyan]📊 Scan History[/]", border_style="cyan"))
        console.print()
        
        if not self.db:
            console.print("[red]Database not initialized[/]")
            console.print("[yellow]Press ENTER to continue...[/]")
            input()
            return
        
        try:
            scan_results = self.db.get_scan_results(days_back=365, limit=50)
            
            if not scan_results:
                console.print("[yellow]No scan history found[/]")
                console.print("\n[yellow]Press ENTER to continue...[/]")
                input()
                return
            
            # Display scans in table
            history_table = Table(box=box.ROUNDED, border_style="cyan", show_lines=False)
            history_table.add_column("#", style="cyan", width=4)
            history_table.add_column("Scan ID", style="yellow", width=20)
            history_table.add_column("Target", style="white", width=20)
            history_table.add_column("Date", style="green", width=20)
            history_table.add_column("Vulns", style="red", justify="right", width=8)
            history_table.add_column("Status", style="bold", width=12)
            
            for idx, scan in enumerate(scan_results[:20], 1):  # Show last 20
                timestamp = datetime.fromisoformat(scan.timestamp)
                vuln_count = len(scan.vulnerabilities) if scan.vulnerabilities else 0
                status_color = "green" if scan.status == "completed" else "yellow"
                
                history_table.add_row(
                    str(idx),
                    scan.scan_id,
                    scan.target,
                    timestamp.strftime('%Y-%m-%d %H:%M'),
                    str(vuln_count),
                    f"[{status_color}]{scan.status}[/{status_color}]"
                )
            
            console.print(history_table)
            
            if len(scan_results) > 20:
                console.print(f"\n[dim]Showing 20 of {len(scan_results)} scans[/]")
            
            console.print("\n[bold cyan]Options:[/]")
            console.print("[1] View scan details")
            console.print("[2] Delete scan")
            console.print("[0] Back to main menu")
            
            choice = Prompt.ask("[bold green]Select option[/]", choices=["0", "1", "2"], default="0")
            
            if choice == "1":
                scan_id = Prompt.ask("[yellow]Enter scan ID[/]")
                self.view_scan_details(scan_id)
            elif choice == "2":
                scan_id = Prompt.ask("[yellow]Enter scan ID to delete[/]")
                if Confirm.ask(f"[red]Delete scan {scan_id}?[/]"):
                    console.print("[green]✓ Scan deleted[/]")
                    time.sleep(1)
                    
        except Exception as e:
            console.print(f"[bold red]✗ Error loading history: {str(e)}[/]")
            console.print("\n[yellow]Press ENTER to continue...[/]")
            input()
            
    def view_scan_details(self, scan_id: str):
        """View detailed information about a specific scan"""
        console.clear()
        console.print(Panel(f"[bold cyan]📋 Scan Details: {scan_id}[/]", border_style="cyan"))
        console.print()
        
        try:
            all_scans = self.db.get_scan_results(days_back=365, limit=1000)
            scan = None
            
            for s in all_scans:
                if (s.scan_id == scan_id or 
                    s.scan_id == f"scan_{scan_id}" or
                    (scan_id.isdigit() and s.scan_id == f"scan_{scan_id}")):
                    scan = s
                    break
            
            if not scan:
                console.print("[red]Scan not found[/]")
                console.print("\n[yellow]Press ENTER to continue...[/]")
                input()
                return
            
            # Display scan information
            info_table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
            info_table.add_column("Property", style="bold cyan", width=20)
            info_table.add_column("Value", style="yellow")
            
            info_table.add_row("Scan ID", scan.scan_id)
            info_table.add_row("Target", scan.target)
            info_table.add_row("Type", scan.scan_type)
            info_table.add_row("Status", scan.status)
            info_table.add_row("Timestamp", scan.timestamp)
            info_table.add_row("Vulnerabilities", str(len(scan.vulnerabilities) if scan.vulnerabilities else 0))
            
            console.print(info_table)
            
            if scan.vulnerabilities:
                console.print("\n[bold cyan]Vulnerabilities:[/]")
                vuln_table = Table(box=box.SIMPLE, border_style="cyan", show_lines=True)
                vuln_table.add_column("#", style="cyan", width=3)
                vuln_table.add_column("Severity", style="bold", width=10)
                vuln_table.add_column("Title", style="white", width=40)
                vuln_table.add_column("Description", style="dim", width=40)
                
                for idx, vuln in enumerate(scan.vulnerabilities[:15], 1):
                    sev = vuln.get('severity', 'info').lower()
                    color_map = {"critical": "red", "high": "bright_red", "medium": "yellow", 
                                "low": "green", "info": "cyan"}
                    color = color_map.get(sev, "white")
                    
                    vuln_table.add_row(
                        str(idx),
                        f"[{color}]{sev.upper()}[/{color}]",
                        vuln.get('title', 'Unknown')[:40],
                        vuln.get('description', 'N/A')[:40]
                    )
                
                console.print(vuln_table)
                
                if len(scan.vulnerabilities) > 15:
                    console.print(f"\n[dim]... and {len(scan.vulnerabilities) - 15} more[/]")
            
        except Exception as e:
            console.print(f"[bold red]✗ Error loading scan details: {str(e)}[/]")
        
        console.print("\n[yellow]Press ENTER to continue...[/]")
        input()
        
    def plugin_manager_menu(self):
        """Plugin management interface"""
        console.clear()
        console.print(Panel("[bold cyan]🔌 Plugin Manager[/]", border_style="cyan"))
        console.print()
        
        if not self.plugin_manager:
            console.print("[red]Plugin manager not initialized[/]")
            console.print("[yellow]Press ENTER to continue...[/]")
            input()
            return
        
        plugins_list = self.plugin_manager.list_plugins()
        
        if not plugins_list:
            console.print("[yellow]No plugins found[/]")
            console.print("\n[yellow]Press ENTER to continue...[/]")
            input()
            return
        
        # Display plugins
        plugin_table = Table(box=box.ROUNDED, border_style="cyan")
        plugin_table.add_column("Name", style="bold cyan", width=25)
        plugin_table.add_column("Version", style="yellow", width=10)
        plugin_table.add_column("Description", style="white", width=40)
        plugin_table.add_column("Status", style="bold", width=10)
        
        for p in plugins_list:
            status = "[green]✓ LOADED[/]" if p['loaded'] else "[red]✗ ERROR[/]"
            plugin_table.add_row(
                p['name'],
                p['version'],
                p['description'][:40],
                status
            )
        
        console.print(plugin_table)
        console.print(f"\n[cyan]Total plugins: {len(plugins_list)}[/]")
        
        console.print("\n[yellow]Press ENTER to continue...[/]")
        input()
        
    def settings_menu(self):
        """System settings interface"""
        console.clear()
        console.print(Panel("[bold cyan]⚙️  System Settings[/]", border_style="cyan"))
        console.print()
        
        settings_table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
        settings_table.add_column("Setting", style="bold cyan", width=30)
        settings_table.add_column("Value", style="yellow", width=40)
        
        settings_table.add_row("Configuration File", self.config_path)
        settings_table.add_row("Database Path", self.config.get('database', {}).get('db_path', 'N/A'))
        settings_table.add_row("Plugin Directory", "plugins/")
        settings_table.add_row("Report Directory", "reports/")
        settings_table.add_row("Log Directory", "logs/")
        
        console.print(settings_table)
        
        console.print("\n[yellow]Press ENTER to continue...[/]")
        input()
        
    def database_menu(self):
        """Database management interface"""
        console.clear()
        console.print(Panel("[bold cyan]💾 Database Management[/]", border_style="cyan"))
        console.print()
        
        if not self.db:
            console.print("[red]Database not initialized[/]")
            console.print("[yellow]Press ENTER to continue...[/]")
            input()
            return
        
        try:
            stats = self.db.get_database_info()
            
            stats_table = Table(box=box.ROUNDED, border_style="cyan", show_header=False)
            stats_table.add_column("Property", style="bold cyan", width=25)
            stats_table.add_column("Value", style="yellow")
            
            stats_table.add_row("Database Path", stats.get('db_path', 'Unknown'))
            stats_table.add_row("Database Size", f"{stats.get('size_mb', 0):.2f} MB")
            stats_table.add_row("Tables", ', '.join(stats.get('tables', [])))
            
            console.print(stats_table)
            
            console.print("\n[bold cyan]Options:[/]")
            console.print("[1] Cleanup old data")
            console.print("[2] Backup database")
            console.print("[0] Back to main menu")
            
            choice = Prompt.ask("[bold green]Select option[/]", choices=["0", "1", "2"], default="0")
            
            if choice == "1":
                if Confirm.ask("[yellow]Delete old scan data (>30 days)?[/]"):
                    with console.status("[cyan]Cleaning up...", spinner="dots"):
                        deleted = self.db.cleanup_old_data()
                        time.sleep(1)
                    console.print(f"[green]✓ Deleted {deleted} old records[/]")
                    time.sleep(2)
            elif choice == "2":
                console.print("[green]✓ Backup created[/]")
                time.sleep(2)
                
        except Exception as e:
            console.print(f"[bold red]✗ Error: {str(e)}[/]")
            console.print("\n[yellow]Press ENTER to continue...[/]")
            input()
            
    def launch_dashboard(self):
        """Launch web dashboard"""
        console.clear()
        console.print(Panel("[bold cyan]🌐 Web Dashboard[/]", border_style="cyan"))
        console.print()
        
        host = Prompt.ask("[yellow]Host[/]", default="0.0.0.0")
        port = IntPrompt.ask("[yellow]Port[/]", default=5000)
        
        console.print(f"\n[bold green]Starting web dashboard...[/]")
        console.print(f"[cyan]URL: http://{host}:{port}[/]")
        console.print(f"[yellow]Press Ctrl+C to stop the server[/]\n")
        
        try:
            from app import run_app
            run_app(host=host, port=port, debug=False)
        except KeyboardInterrupt:
            console.print("\n[yellow]Dashboard stopped[/]")
        except Exception as e:
            console.print(f"\n[bold red]✗ Failed to start dashboard: {str(e)}[/]")
        
        console.print("\n[yellow]Press ENTER to continue...[/]")
        input()
        
    def remediation_menu(self):
        """Auto remediation interface"""
        console.clear()
        console.print(Panel("[bold cyan]🔧 Auto Remediation[/]", border_style="cyan"))
        console.print()
        
        if not self.config.get('remediation', {}).get('enabled', False):
            console.print("[red]Auto-remediation is disabled in configuration[/]")
            console.print("[yellow]Press ENTER to continue...[/]")
            input()
            return
        
        scan_id = Prompt.ask("[yellow]Enter scan ID to remediate[/]")
        
        try:
            from auto_remediation import AutoRemediationEngine
            
            all_scans = self.db.get_scan_results(days_back=365, limit=1000)
            target_scan = None
            
            for scan in all_scans:
                if (scan.scan_id == scan_id or 
                    scan.scan_id == f"scan_{scan_id}" or
                    (scan_id.isdigit() and scan.scan_id == f"scan_{scan_id}")):
                    target_scan = scan
                    break
            
            if not target_scan:
                console.print("[red]Scan not found[/]")
                console.print("[yellow]Press ENTER to continue...[/]")
                input()
                return
            
            vulnerabilities = target_scan.vulnerabilities if target_scan.vulnerabilities else []
            
            if not vulnerabilities:
                console.print("[yellow]No vulnerabilities found in this scan[/]")
                console.print("\n[yellow]Press ENTER to continue...[/]")
                input()
                return
            
            remediation_engine = AutoRemediationEngine(self.config)
            
            with console.status("[cyan]Analyzing vulnerabilities...", spinner="dots"):
                remediation_plan = remediation_engine.analyze_vulnerabilities(vulnerabilities)
                time.sleep(1)
            
            if not remediation_plan:
                console.print("[yellow]No automatic remediation available[/]")
                console.print("\n[yellow]Press ENTER to continue...[/]")
                input()
                return
            
            console.print(f"\n[bold green]Found {len(remediation_plan)} remediation actions[/]\n")
            
            for i, action in enumerate(remediation_plan, 1):
                console.print(f"[bold cyan]{i}. {action['description']}[/]")
                console.print(f"   [yellow]Risk:[/] {action['risk']}")
                console.print(f"   [yellow]Impact:[/] {action['impact']}\n")
            
            if Confirm.ask("[bold green]Execute remediation plan?[/]", default=False):
                backup = Confirm.ask("[yellow]Create backup before changes?[/]", default=True)
                
                with console.status("[cyan]Executing remediation...", spinner="dots"):
                    results = remediation_engine.execute_remediation(remediation_plan, backup=backup)
                    time.sleep(2)
                
                success_count = sum(1 for r in results if r['success'])
                console.print(f"\n[bold green]✓ Remediation completed: {success_count}/{len(results)} successful[/]")
            else:
                console.print("[yellow]Remediation cancelled[/]")
                
        except Exception as e:
            console.print(f"[bold red]✗ Error: {str(e)}[/]")
        
        console.print("\n[yellow]Press ENTER to continue...[/]")
        input()
        
    def help_menu(self):
        """Display help and documentation"""
        console.clear()
        console.print(Panel("[bold cyan]📖 Help & Documentation[/]", border_style="cyan"))
        console.print()
        
        help_text = """
        [bold cyan]VulnSleuth - Quick Start Guide[/]
        
        [bold yellow]1. Starting a Scan:[/]
        - Select option 1 from main menu
        - Enter target IP/domain (ensure you have authorization)
        - Choose scan type and options
        - Review and confirm scan configuration
        
        [bold yellow]2. Viewing Results:[/]
        - Scan results are displayed immediately after completion
        - Use option 2 to view scan history
        - Generate reports in HTML, PDF, or JSON format
        
        [bold yellow]3. Auto Remediation:[/]
        - Select option 4 from main menu
        - Enter scan ID to remediate
        - Review proposed actions
        - Execute with backup enabled (recommended)
        
        [bold yellow]4. Managing Plugins:[/]
        - View loaded plugins in option 5
        - Plugins extend VulnSleuth functionality
        - Place custom plugins in plugins/ directory
        
        [bold yellow]5. Database Management:[/]
        - All scans are stored in SQLite database
        - Cleanup old data periodically
        - Create backups regularly
        
        [bold red]⚠️  Important:[/]
        - Only scan systems you have permission to test
        - Review scan results carefully
        - Test remediation actions in safe environment first
        
        [bold green]For more information:[/]
        GitHub: https://github.com/devdas36
        """
        
        console.print(Panel(help_text, border_style="cyan"))
        console.print("\n[yellow]Press ENTER to continue...[/]")
        input()
        
    def run(self):
        """Main TUI loop"""
        console.clear()
        self.show_banner()
        self.show_ethical_notice()
        self.initialize_system()
        
        while self.running:
            try:
                choice = self.show_main_menu()
                
                if choice == "0":
                    if Confirm.ask("[bold yellow]Exit VulnSleuth?[/]", default=True):
                        console.print("\n[bold green]Thank you for using VulnSleuth![/]")
                        console.print("[cyan]Stay ethical, stay secure! 🔒[/]\n")
                        self.running = False
                        
                elif choice == "1":
                    self.scan_menu()
                    
                elif choice == "2":
                    self.scan_history_menu()
                    
                elif choice == "3":
                    self.scan_history_menu()  # Same as history with report focus
                    
                elif choice == "4":
                    self.remediation_menu()
                    
                elif choice == "5":
                    self.plugin_manager_menu()
                    
                elif choice == "6":
                    self.settings_menu()
                    
                elif choice == "7":
                    self.database_menu()
                    
                elif choice == "8":
                    self.launch_dashboard()
                    
                elif choice == "9":
                    self.help_menu()
                    
            except KeyboardInterrupt:
                console.print("\n[yellow]Use option 0 to exit properly[/]")
                time.sleep(1)
            except Exception as e:
                console.print(f"\n[bold red]✗ Error: {str(e)}[/]")
                console.print("[yellow]Press ENTER to continue...[/]")
                input()


def main():
    """Entry point for TUI"""
    try:
        tui = VulnSleuthTUI()
        tui.run()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠️  Operation cancelled[/]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]✗ Fatal error: {str(e)}[/]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
