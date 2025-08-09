"""
VulnSleuth Reporting System
Comprehensive report generation for scan results

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import json
import csv
import xml.etree.ElementTree as ET
from xml.dom import minidom
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, asdict
import uuid
import hashlib
from pathlib import Path
import base64

try:
    from jinja2 import Template, Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.backends.backend_agg import FigureCanvasAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class ReportConfig:
    """Configuration for report generation"""
    report_id: str
    title: str
    format: str  # json, html, csv, xml, pdf
    output_path: str
    include_summary: bool = True
    include_details: bool = True
    include_charts: bool = True
    include_recommendations: bool = True
    template_path: Optional[str] = None
    custom_fields: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.custom_fields is None:
            self.custom_fields = {}

class VulnSleuthReporter:
    """
    Comprehensive reporting system for VulnSleuth scan results
    
    Features:
    - Multiple output formats (JSON, HTML, CSV, XML, PDF)
    - Executive and technical report templates
    - Custom report templates with Jinja2
    - Vulnerability statistics and trends
    - Risk assessment and scoring
    - Remediation prioritization
    - Charts and visualizations
    - Compliance mapping (OWASP, NIST, etc.)
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.report_config = config.get('reporting', {})
        self.logger = logging.getLogger('VulnSleuthReporter')
        
        # Report configuration
        self.output_dir = self.report_config.get('output_dir', 'reports')
        self.template_dir = self.report_config.get('template_dir', 'templates')
        self.include_charts = self.report_config.get('include_charts', True)
        self.chart_format = self.report_config.get('chart_format', 'png')
        
        # Ensure output directories exist
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.template_dir, exist_ok=True)
        
        # Initialize Jinja2 environment
        if JINJA2_AVAILABLE:
            self.jinja_env = Environment(
                loader=FileSystemLoader([self.template_dir, os.path.join(os.path.dirname(__file__), 'templates')])
            )
        else:
            self.jinja_env = None
            self.logger.warning("Jinja2 not available - HTML templates disabled")
        
        # Risk scoring configuration
        self.risk_matrix = {
            'critical': {'score': 10, 'color': '#DC3545'},
            'high': {'score': 8, 'color': '#FD7E14'},
            'medium': {'score': 5, 'color': '#FFC107'},
            'low': {'score': 2, 'color': '#28A745'},
            'informational': {'score': 1, 'color': '#17A2B8'}
        }
        
        # Compliance frameworks
        self.compliance_mapping = {
            'owasp_top10': {
                'name': 'OWASP Top 10',
                'categories': ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10']
            },
            'nist_csf': {
                'name': 'NIST Cybersecurity Framework',
                'categories': ['Identify', 'Protect', 'Detect', 'Respond', 'Recover']
            },
            'cis_controls': {
                'name': 'CIS Critical Security Controls',
                'categories': [f'CIS-{i}' for i in range(1, 21)]
            }
        }
        
        self.logger.info("VulnSleuth Reporter initialized")
    
    def generate_report(self, 
                       scan_results: List[Dict[str, Any]], 
                       report_config: ReportConfig,
                       target_info: List[Dict[str, Any]] = None) -> str:
        """
        Generate comprehensive vulnerability report
        
        Args:
            scan_results: List of scan result dictionaries
            report_config: Report configuration
            target_info: Optional target information
            
        Returns:
            Path to generated report file
        """
        self.logger.info(f"Generating {report_config.format.upper()} report: {report_config.title}")
        
        try:
            # Prepare report data
            report_data = self._prepare_report_data(scan_results, target_info)
            
            # Generate report based on format
            if report_config.format.lower() == 'json':
                output_path = self._generate_json_report(report_data, report_config)
            elif report_config.format.lower() == 'html':
                output_path = self._generate_html_report(report_data, report_config)
            elif report_config.format.lower() == 'csv':
                output_path = self._generate_csv_report(report_data, report_config)
            elif report_config.format.lower() == 'xml':
                output_path = self._generate_xml_report(report_data, report_config)
            elif report_config.format.lower() == 'pdf':
                output_path = self._generate_pdf_report(report_data, report_config)
            else:
                raise ValueError(f"Unsupported report format: {report_config.format}")
            
            self.logger.info(f"Report generated successfully: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"Failed to generate report: {str(e)}")
            raise
    
    def generate_executive_summary(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate executive summary from scan results
        
        Args:
            scan_results: List of scan result dictionaries
            
        Returns:
            Executive summary data
        """
        all_vulnerabilities = []
        targets_scanned = set()
        scan_types = set()
        
        for result in scan_results:
            targets_scanned.add(result.get('target', ''))
            scan_types.add(result.get('scan_type', ''))
            all_vulnerabilities.extend(result.get('vulnerabilities', []))
        
        # Risk statistics
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
        risk_score = 0
        
        for vuln in all_vulnerabilities:
            severity = vuln.get('severity', 'informational').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
                risk_score += self.risk_matrix.get(severity, {'score': 0})['score']
        
        total_vulns = len(all_vulnerabilities)
        avg_risk_score = risk_score / max(total_vulns, 1)
        
        # Risk level determination
        if avg_risk_score >= 8:
            overall_risk = 'Critical'
        elif avg_risk_score >= 6:
            overall_risk = 'High'
        elif avg_risk_score >= 4:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'
        
        return {
            'summary': {
                'total_vulnerabilities': total_vulns,
                'targets_scanned': len(targets_scanned),
                'scan_types_used': list(scan_types),
                'overall_risk_level': overall_risk,
                'average_risk_score': round(avg_risk_score, 2)
            },
            'severity_breakdown': severity_counts,
            'key_findings': self._get_key_findings(all_vulnerabilities),
            'recommendations': self._get_top_recommendations(all_vulnerabilities),
            'compliance_status': self._assess_compliance(all_vulnerabilities)
        }
    
    def _prepare_report_data(self, scan_results: List[Dict[str, Any]], target_info: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Prepare comprehensive report data"""
        
        # Generate executive summary
        executive_summary = self.generate_executive_summary(scan_results)
        
        # Aggregate all vulnerabilities
        all_vulnerabilities = []
        for result in scan_results:
            all_vulnerabilities.extend(result.get('vulnerabilities', []))
        
        # Sort vulnerabilities by risk score
        sorted_vulns = sorted(all_vulnerabilities, 
                            key=lambda v: self.risk_matrix.get(v.get('severity', 'low'), {'score': 0})['score'], 
                            reverse=True)
        
        # Generate statistics
        stats = self._generate_statistics(scan_results, all_vulnerabilities)
        
        # Create report data structure
        report_data = {
            'metadata': {
                'report_id': str(uuid.uuid4()),
                'generated_at': datetime.now().isoformat(),
                'generator': 'VulnSleuth v1.0',
                'report_version': '1.0'
            },
            'executive_summary': executive_summary,
            'scan_results': scan_results,
            'vulnerabilities': {
                'total': len(all_vulnerabilities),
                'by_severity': executive_summary['severity_breakdown'],
                'detailed_list': sorted_vulns
            },
            'targets': {
                'scanned': list(set(r.get('target', '') for r in scan_results)),
                'details': target_info or []
            },
            'statistics': stats,
            'charts': self._prepare_chart_data(all_vulnerabilities) if self.include_charts else {},
            'recommendations': self._generate_detailed_recommendations(sorted_vulns),
            'appendices': {
                'methodology': self._get_methodology_description(),
                'references': self._get_security_references(),
                'glossary': self._get_security_glossary()
            }
        }
        
        return report_data
    
    def _generate_json_report(self, report_data: Dict[str, Any], config: ReportConfig) -> str:
        """Generate JSON format report"""
        output_path = os.path.join(self.output_dir, f"{config.report_id}.json")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)
        
        return output_path
    
    def _generate_html_report(self, report_data: Dict[str, Any], config: ReportConfig) -> str:
        """Generate HTML format report"""
        if not JINJA2_AVAILABLE:
            raise RuntimeError("Jinja2 required for HTML reports")
        
        # Use custom template if specified, otherwise use default
        template_name = config.template_path or 'vulnerability_report.html'
        
        try:
            template = self.jinja_env.get_template(template_name)
        except Exception:
            # Fall back to inline template
            template = Template(self._get_default_html_template())
        
        # Generate charts if enabled
        chart_paths = {}
        if config.include_charts and MATPLOTLIB_AVAILABLE:
            chart_paths = self._generate_charts(report_data['charts'], config.report_id)
        
        # Render template
        html_content = template.render(
            report=report_data,
            config=config,
            charts=chart_paths,
            risk_matrix=self.risk_matrix
        )
        
        output_path = os.path.join(self.output_dir, f"{config.report_id}.html")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _generate_csv_report(self, report_data: Dict[str, Any], config: ReportConfig) -> str:
        """Generate CSV format report"""
        output_path = os.path.join(self.output_dir, f"{config.report_id}.csv")
        
        vulnerabilities = report_data['vulnerabilities']['detailed_list']
        
        # Define CSV headers
        headers = [
            'Target', 'Vulnerability Type', 'Severity', 'CVSS Score', 'Title', 
            'Description', 'Port', 'Service', 'Protocol', 'CVE IDs', 
            'References', 'Solution', 'First Seen', 'Status'
        ]
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for vuln in vulnerabilities:
                row = [
                    vuln.get('target', ''),
                    vuln.get('vulnerability_type', ''),
                    vuln.get('severity', ''),
                    vuln.get('cvss_score', ''),
                    vuln.get('title', ''),
                    vuln.get('description', ''),
                    vuln.get('port', ''),
                    vuln.get('service', ''),
                    vuln.get('protocol', ''),
                    ', '.join(vuln.get('cve_ids', [])),
                    ', '.join(vuln.get('references', [])),
                    vuln.get('solution', ''),
                    vuln.get('first_seen', ''),
                    vuln.get('status', '')
                ]
                writer.writerow(row)
        
        return output_path
    
    def _generate_xml_report(self, report_data: Dict[str, Any], config: ReportConfig) -> str:
        """Generate XML format report"""
        root = ET.Element('VulnSleuthReport')
        root.set('version', '1.0')
        root.set('generated', report_data['metadata']['generated_at'])
        
        # Metadata
        metadata_elem = ET.SubElement(root, 'Metadata')
        for key, value in report_data['metadata'].items():
            elem = ET.SubElement(metadata_elem, key.replace('_', '').title())
            elem.text = str(value)
        
        # Executive Summary
        summary_elem = ET.SubElement(root, 'ExecutiveSummary')
        for key, value in report_data['executive_summary']['summary'].items():
            elem = ET.SubElement(summary_elem, key.replace('_', '').title())
            elem.text = str(value)
        
        # Vulnerabilities
        vulns_elem = ET.SubElement(root, 'Vulnerabilities')
        vulns_elem.set('total', str(report_data['vulnerabilities']['total']))
        
        for vuln in report_data['vulnerabilities']['detailed_list']:
            vuln_elem = ET.SubElement(vulns_elem, 'Vulnerability')
            
            for key, value in vuln.items():
                if key in ['cve_ids', 'references']:
                    # Handle lists
                    list_elem = ET.SubElement(vuln_elem, key.title())
                    for item in value:
                        item_elem = ET.SubElement(list_elem, 'Item')
                        item_elem.text = str(item)
                else:
                    elem = ET.SubElement(vuln_elem, key.replace('_', '').title())
                    elem.text = str(value) if value is not None else ''
        
        # Pretty print XML
        rough_string = ET.tostring(root, encoding='utf-8')
        reparsed = minidom.parseString(rough_string)
        pretty_xml = reparsed.toprettyxml(indent='  ')
        
        output_path = os.path.join(self.output_dir, f"{config.report_id}.xml")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(pretty_xml)
        
        return output_path
    
    def _generate_pdf_report(self, report_data: Dict[str, Any], config: ReportConfig) -> str:
        """Generate PDF format report"""
        if not REPORTLAB_AVAILABLE:
            raise RuntimeError("ReportLab required for PDF reports")
        
        output_path = os.path.join(self.output_dir, f"{config.report_id}.pdf")
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        story.append(Paragraph(config.title, title_style))
        story.append(Spacer(1, 12))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading1']))
        summary = report_data['executive_summary']['summary']
        
        summary_data = [
            ['Metric', 'Value'],
            ['Total Vulnerabilities', str(summary['total_vulnerabilities'])],
            ['Targets Scanned', str(summary['targets_scanned'])],
            ['Overall Risk Level', summary['overall_risk_level']],
            ['Average Risk Score', str(summary['average_risk_score'])]
        ]
        
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 12))
        
        # Severity Breakdown
        story.append(Paragraph("Vulnerability Severity Breakdown", styles['Heading2']))
        severity_data = [['Severity', 'Count']]
        
        for severity, count in report_data['executive_summary']['severity_breakdown'].items():
            if count > 0:
                severity_data.append([severity.title(), str(count)])
        
        severity_table = Table(severity_data)
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(severity_table)
        story.append(Spacer(1, 12))
        
        # Top Vulnerabilities
        story.append(Paragraph("Top 10 Critical Vulnerabilities", styles['Heading2']))
        
        top_vulns = report_data['vulnerabilities']['detailed_list'][:10]
        for i, vuln in enumerate(top_vulns, 1):
            vuln_title = f"{i}. {vuln.get('title', 'Unknown Vulnerability')}"
            story.append(Paragraph(vuln_title, styles['Heading3']))
            
            vuln_details = [
                f"<b>Severity:</b> {vuln.get('severity', 'Unknown').title()}",
                f"<b>Target:</b> {vuln.get('target', 'Unknown')}",
                f"<b>Description:</b> {vuln.get('description', 'No description available')[:200]}..."
            ]
            
            for detail in vuln_details:
                story.append(Paragraph(detail, styles['Normal']))
            
            story.append(Spacer(1, 6))
        
        # Build PDF
        doc.build(story)
        
        return output_path
    
    def _generate_statistics(self, scan_results: List[Dict[str, Any]], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive statistics"""
        
        # Vulnerability statistics
        vuln_by_type = {}
        vuln_by_target = {}
        vuln_by_service = {}
        cvss_scores = []
        
        for vuln in vulnerabilities:
            # By type
            vuln_type = vuln.get('vulnerability_type', 'unknown')
            vuln_by_type[vuln_type] = vuln_by_type.get(vuln_type, 0) + 1
            
            # By target
            target = vuln.get('target', 'unknown')
            vuln_by_target[target] = vuln_by_target.get(target, 0) + 1
            
            # By service
            service = vuln.get('service', 'unknown')
            vuln_by_service[service] = vuln_by_service.get(service, 0) + 1
            
            # CVSS scores
            cvss = vuln.get('cvss_score', 0)
            if cvss > 0:
                cvss_scores.append(cvss)
        
        # Calculate averages
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        avg_vulns_per_target = len(vulnerabilities) / len(set(v.get('target', '') for v in vulnerabilities)) if vulnerabilities else 0
        
        return {
            'vulnerability_by_type': dict(sorted(vuln_by_type.items(), key=lambda x: x[1], reverse=True)[:10]),
            'vulnerability_by_target': dict(sorted(vuln_by_target.items(), key=lambda x: x[1], reverse=True)[:10]),
            'vulnerability_by_service': dict(sorted(vuln_by_service.items(), key=lambda x: x[1], reverse=True)[:10]),
            'average_cvss_score': round(avg_cvss, 2),
            'average_vulnerabilities_per_target': round(avg_vulns_per_target, 2),
            'total_scans_performed': len(scan_results),
            'scan_success_rate': len([r for r in scan_results if r.get('status') == 'completed']) / len(scan_results) * 100 if scan_results else 0
        }
    
    def _prepare_chart_data(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare data for chart generation"""
        
        # Severity distribution
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0}
        
        # Vulnerability types
        type_counts = {}
        
        # CVSS score distribution
        cvss_ranges = {'0-3': 0, '3-6': 0, '6-9': 0, '9-10': 0}
        
        for vuln in vulnerabilities:
            # Severity
            severity = vuln.get('severity', 'informational').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Type
            vuln_type = vuln.get('vulnerability_type', 'unknown')
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
            
            # CVSS
            cvss = vuln.get('cvss_score', 0)
            if cvss < 3:
                cvss_ranges['0-3'] += 1
            elif cvss < 6:
                cvss_ranges['3-6'] += 1
            elif cvss < 9:
                cvss_ranges['6-9'] += 1
            else:
                cvss_ranges['9-10'] += 1
        
        return {
            'severity_distribution': severity_counts,
            'vulnerability_types': dict(sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            'cvss_distribution': cvss_ranges
        }
    
    def _generate_charts(self, chart_data: Dict[str, Any], report_id: str) -> Dict[str, str]:
        """Generate charts for the report"""
        if not MATPLOTLIB_AVAILABLE:
            return {}
        
        chart_paths = {}
        chart_dir = os.path.join(self.output_dir, 'charts')
        os.makedirs(chart_dir, exist_ok=True)
        
        # Severity distribution pie chart
        if chart_data.get('severity_distribution'):
            fig, ax = plt.subplots(figsize=(8, 6))
            
            severity_data = chart_data['severity_distribution']
            sizes = [count for count in severity_data.values() if count > 0]
            labels = [severity.title() for severity, count in severity_data.items() if count > 0]
            colors = [self.risk_matrix[severity.lower()]['color'] for severity, count in severity_data.items() if count > 0]
            
            if sizes:
                ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
                ax.set_title('Vulnerability Severity Distribution')
                
                chart_path = os.path.join(chart_dir, f'{report_id}_severity.{self.chart_format}')
                plt.savefig(chart_path, dpi=150, bbox_inches='tight')
                chart_paths['severity_distribution'] = chart_path
                
                plt.close()
        
        # Vulnerability types bar chart
        if chart_data.get('vulnerability_types'):
            fig, ax = plt.subplots(figsize=(10, 6))
            
            type_data = chart_data['vulnerability_types']
            types = list(type_data.keys())[:10]
            counts = list(type_data.values())[:10]
            
            bars = ax.bar(range(len(types)), counts, color='#1f77b4')
            ax.set_xlabel('Vulnerability Type')
            ax.set_ylabel('Count')
            ax.set_title('Top 10 Vulnerability Types')
            ax.set_xticks(range(len(types)))
            ax.set_xticklabels(types, rotation=45, ha='right')
            
            # Add value labels on bars
            for i, bar in enumerate(bars):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                       f'{counts[i]}', ha='center', va='bottom')
            
            chart_path = os.path.join(chart_dir, f'{report_id}_types.{self.chart_format}')
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            chart_paths['vulnerability_types'] = chart_path
            
            plt.close()
        
        return chart_paths
    
    def _get_key_findings(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Extract key findings from vulnerabilities"""
        findings = []
        
        # Count critical/high severity vulnerabilities
        critical_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'critical')
        high_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'high')
        
        if critical_count > 0:
            findings.append(f"{critical_count} critical severity vulnerabilities requiring immediate attention")
        
        if high_count > 0:
            findings.append(f"{high_count} high severity vulnerabilities requiring prompt remediation")
        
        # Most common vulnerability type
        type_counts = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('vulnerability_type', 'unknown')
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        if type_counts:
            most_common_type = max(type_counts, key=type_counts.get)
            findings.append(f"Most common vulnerability type: {most_common_type} ({type_counts[most_common_type]} instances)")
        
        # Services with vulnerabilities
        service_vulns = set(v.get('service', '') for v in vulnerabilities if v.get('service'))
        if service_vulns:
            findings.append(f"Vulnerable services identified: {', '.join(list(service_vulns)[:5])}")
        
        return findings
    
    def _get_top_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate top-level recommendations"""
        recommendations = [
            "Implement a vulnerability management program with regular scanning",
            "Prioritize remediation based on CVSS scores and business criticality",
            "Deploy security monitoring and incident response capabilities",
            "Conduct regular security awareness training for staff",
            "Maintain an up-to-date asset inventory"
        ]
        
        # Add specific recommendations based on findings
        critical_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'critical']
        if critical_vulns:
            recommendations.insert(0, "Address all critical vulnerabilities immediately")
        
        return recommendations
    
    def _assess_compliance(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess compliance status against frameworks"""
        compliance_status = {}
        
        for framework, details in self.compliance_mapping.items():
            # Simplified compliance assessment
            critical_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'critical')
            high_count = sum(1 for v in vulnerabilities if v.get('severity', '').lower() == 'high')
            
            if critical_count == 0 and high_count == 0:
                status = 'Compliant'
            elif critical_count == 0:
                status = 'Partially Compliant'
            else:
                status = 'Non-Compliant'
            
            compliance_status[framework] = {
                'framework_name': details['name'],
                'status': status,
                'issues': critical_count + high_count
            }
        
        return compliance_status
    
    def _generate_detailed_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Generate detailed remediation recommendations"""
        
        immediate_actions = []
        short_term_actions = []
        long_term_actions = []
        
        # Analyze vulnerabilities and generate recommendations
        critical_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'critical']
        high_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'high']
        
        if critical_vulns:
            immediate_actions.extend([
                f"Patch or mitigate {len(critical_vulns)} critical vulnerabilities",
                "Implement emergency change management for critical fixes",
                "Monitor affected systems closely for exploitation attempts"
            ])
        
        if high_vulns:
            short_term_actions.extend([
                f"Address {len(high_vulns)} high severity vulnerabilities within 30 days",
                "Conduct security testing after remediation",
                "Update security documentation and procedures"
            ])
        
        long_term_actions.extend([
            "Implement automated vulnerability scanning",
            "Establish security metrics and reporting",
            "Regular security architecture reviews",
            "Continuous security monitoring implementation"
        ])
        
        return {
            'immediate': immediate_actions,
            'short_term': short_term_actions,
            'long_term': long_term_actions
        }
    
    def _get_methodology_description(self) -> str:
        """Get methodology description for appendix"""
        return """
        VulnSleuth employs a comprehensive vulnerability assessment methodology combining:
        
        1. Network Discovery and Port Scanning
        2. Service Enumeration and Banner Grabbing
        3. Vulnerability Detection using signature-based checks
        4. CVE correlation and scoring
        5. Risk assessment and prioritization
        6. Compliance mapping against industry frameworks
        """
    
    def _get_security_references(self) -> List[str]:
        """Get security references for appendix"""
        return [
            "NIST Cybersecurity Framework - https://www.nist.gov/cyberframework",
            "OWASP Top 10 - https://owasp.org/www-project-top-ten/",
            "CIS Critical Security Controls - https://www.cisecurity.org/controls/",
            "CVE Database - https://cve.mitre.org/",
            "CVSS Scoring Guide - https://www.first.org/cvss/"
        ]
    
    def _get_security_glossary(self) -> Dict[str, str]:
        """Get security glossary for appendix"""
        return {
            "CVE": "Common Vulnerabilities and Exposures - standardized identifier for security vulnerabilities",
            "CVSS": "Common Vulnerability Scoring System - standardized method for rating vulnerability severity",
            "OWASP": "Open Web Application Security Project - nonprofit focused on improving software security",
            "CIS": "Center for Internet Security - nonprofit that develops cybersecurity best practices",
            "NIST": "National Institute of Standards and Technology - develops cybersecurity guidelines"
        }
    
    def _get_default_html_template(self) -> str:
        """Get default HTML template for reports"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ config.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { background: #f8f9fa; padding: 20px; margin: 20px 0; border-left: 4px solid #007bff; }
        .vulnerability { border: 1px solid #dee2e6; margin: 10px 0; padding: 15px; }
        .critical { border-left: 4px solid #dc3545; }
        .high { border-left: 4px solid #fd7e14; }
        .medium { border-left: 4px solid #ffc107; }
        .low { border-left: 4px solid #28a745; }
        .chart { text-align: center; margin: 20px 0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #dee2e6; padding: 8px; text-align: left; }
        th { background-color: #e9ecef; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ config.title }}</h1>
        <p>Generated: {{ report.metadata.generated_at }}</p>
        <p>Report ID: {{ report.metadata.report_id }}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Vulnerabilities:</strong> {{ report.executive_summary.summary.total_vulnerabilities }}</p>
        <p><strong>Overall Risk Level:</strong> {{ report.executive_summary.summary.overall_risk_level }}</p>
        <p><strong>Targets Scanned:</strong> {{ report.executive_summary.summary.targets_scanned }}</p>
    </div>
    
    <h2>Vulnerability Details</h2>
    {% for vuln in report.vulnerabilities.detailed_list[:20] %}
    <div class="vulnerability {{ vuln.severity }}">
        <h3>{{ vuln.title }}</h3>
        <p><strong>Severity:</strong> {{ vuln.severity }}</p>
        <p><strong>Target:</strong> {{ vuln.target }}</p>
        <p><strong>Description:</strong> {{ vuln.description }}</p>
        {% if vuln.solution %}
        <p><strong>Solution:</strong> {{ vuln.solution }}</p>
        {% endif %}
    </div>
    {% endfor %}
    
    <h2>Recommendations</h2>
    <h3>Immediate Actions</h3>
    <ul>
    {% for action in report.recommendations.immediate %}
        <li>{{ action }}</li>
    {% endfor %}
    </ul>
    
    <h3>Short-term Actions</h3>
    <ul>
    {% for action in report.recommendations.short_term %}
        <li>{{ action }}</li>
    {% endfor %}
    </ul>
</body>
</html>
        """

if __name__ == "__main__":
    # Test report generation
    config = {
        'reporting': {
            'output_dir': 'test_reports',
            'include_charts': True
        }
    }
    
    reporter = VulnSleuthReporter(config)
    
    # Sample data
    sample_scan_results = [
        {
            'scan_id': 'test_scan_001',
            'target': '192.168.1.100',
            'scan_type': 'network',
            'timestamp': datetime.now().isoformat(),
            'status': 'completed',
            'vulnerabilities': [
                {
                    'target': '192.168.1.100',
                    'vulnerability_type': 'open_port',
                    'severity': 'high',
                    'cvss_score': 7.5,
                    'title': 'SSH Service Exposed',
                    'description': 'SSH service running with weak configuration',
                    'solution': 'Configure SSH security settings',
                    'port': 22,
                    'service': 'ssh',
                    'protocol': 'tcp',
                    'cve_ids': ['CVE-2021-28041'],
                    'references': ['https://nvd.nist.gov/vuln/detail/CVE-2021-28041']
                }
            ]
        }
    ]
    
    report_config = ReportConfig(
        report_id='test_report',
        title='VulnSleuth Security Assessment',
        format='html',
        output_path='test_reports/test_report.html'
    )
    
    # Generate report
    output_path = reporter.generate_report(sample_scan_results, report_config)
    print(f"Report generated: {output_path}")
    
    # Generate executive summary
    summary = reporter.generate_executive_summary(sample_scan_results)
    print(f"Executive Summary: {summary}")
