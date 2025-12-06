# VulnSleuth - Advanced Vulnerability Scanner

A comprehensive vulnerability scanner with both CLI and web dashboard interfaces for ethical security testing and automated vulnerability assessment.

## 🚀 Features

- **Dual Interface**: Command-line tool and Flask web dashboard
- **Multi-layered Scanning**: Local system, network, and web application security checks
- **CVE Integration**: Real-time CVE lookup with MITRE and NVD databases
- **Plugin Architecture**: Extensible system with custom vulnerability checks
- **Interactive Web Dashboard**: Real-time monitoring with Bootstrap 5 UI
- **Comprehensive Reporting**: JSON, HTML, CSV, and XML report generation
- **Database Integration**: SQLite backend for persistent scan data
- **Auto-remediation**: Intelligent vulnerability fixing suggestions
- **Docker Support**: Containerized deployment ready

## 📋 Prerequisites

- Python 3.8+
- Nmap (for network scanning)
- Modern web browser (for dashboard)
- Windows/Linux/macOS support

## 🔧 Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/devdas36/vulnsleuth.git
cd vulnsleuth

# Install Python dependencies
pip install -r requirements.txt

# Run CLI scan
python src/main.py scan --target localhost --type basic

# Launch web dashboard
python src/main.py dashboard
# Access at http://localhost:5000 (admin/vulnsleuth123)
```

### Docker Deployment

```bash
# Build and run with Docker
docker-compose up -d
```

## 💻 Usage

### Command Line Interface

```bash
# Basic system scan
python src/main.py scan --target localhost --type local

# Network scan with port range
python src/main.py scan --target 192.168.1.0/24 --type network --ports 1-1000

# Web application scan
python src/main.py scan --target https://example.com --type webapp

# Generate detailed report
python src/main.py report --scan-id 1 --format html --output scan_report.html
```

### Web Dashboard

Launch the web interface:

```bash
python src/main.py dashboard
```

Features available at `http://localhost:5000`:

- **Dashboard**: Real-time scan status and statistics
- **Scan Management**: Create, monitor, and manage vulnerability scans
- **Vulnerability Viewer**: Detailed findings with remediation guidance
- **Reports**: Generate and download comprehensive reports
- **Target Management**: Organize and track scan targets
- **Settings**: Configure scan parameters and preferences

**Login Credentials**: `admin` / `vulnsleuth123`

## ⚙️ Configuration

The `vulnsluth.cfg` file allows customization of:

- **Scan Settings**: Timeout values, thread counts, intensity levels
- **Database**: SQLite configuration and CVE caching options
- **Network Scanning**: Nmap integration and port ranges
- **Web Scanning**: HTTP settings and security checks
- **Reporting**: Output formats and templates
- **Dashboard**: Web interface host, port, and security settings

## 🔌 Plugin Development

Create custom vulnerability checks by extending the plugin system:

```python
from src.plugin import VulnPlugin, VulnerabilityFinding

class CustomPlugin(VulnPlugin):
    def get_metadata(self):
        return {
            'name': 'Custom Security Check',
            'version': '1.0',
            'description': 'Custom vulnerability detection'
        }
    
    def run_check(self, target):
        # Your vulnerability detection logic
        if self.detect_vulnerability(target):
            return VulnerabilityFinding(
                title="Custom Vulnerability",
                severity="High",
                description="Detected custom security issue"
            )
```

## 🛡️ Project Structure

```sh
vulnsleuth/
├── src/                         # Core application source code
│   ├── __init__.py             # Package initialization
│   ├── main.py                 # CLI entry point and command interface
│   ├── webapp.py               # Flask web application and routes
│   ├── engine.py               # Scan orchestration engine
│   ├── db.py                   # SQLite database management
│   ├── utils.py                # Common utility functions
│   ├── reporter.py             # Report generation (HTML, JSON, CSV, XML)
│   ├── plugin.py               # Plugin system architecture
│   ├── cve_lookup.py           # CVE database integration
│   ├── nmap_integration.py     # Network scanning with Nmap
│   ├── auto_remediation.py     # Automated vulnerability fixing
│   ├── checks/                 # Vulnerability detection modules
│   │   ├── __init__.py         # Checks package initialization
│   │   ├── local_checks.py     # Local system security checks
│   │   ├── network_checks.py   # Network-based vulnerability checks
│   │   └── webapp_checks.py    # Web application security testing
│   └── templates/              # Flask web dashboard templates
│       ├── base.html           # Base template with navigation
│       ├── login.html          # Authentication page
│       ├── dashboard.html      # Main dashboard overview
│       ├── scans.html          # Scan management interface
│       ├── new_scan.html       # Create new scan form
│       ├── scan_status.html    # Real-time scan monitoring
│       ├── vulnerabilities.html # Vulnerability findings display
│       ├── reports.html        # Report generation interface
│       ├── targets.html        # Target management
│       ├── settings.html       # Configuration settings
│       └── remediation.html    # Remediation guidance
├── plugins/                    # Extensible plugin system
│   ├── simple_port_scanner.py  # Basic network port scanner plugin
│   └── example_web_plugin.py   # Web application testing plugin
├── tests/                      # Unit and integration tests
│   ├── __init__.py            # Test package initialization
│   ├── conftest.py            # PyTest configuration and fixtures
│   ├── run_tests.py           # Test runner script
│   ├── test_database.py       # Database functionality tests
│   ├── test_engine.py         # Scan engine tests
│   ├── test_plugins.py        # Plugin system tests
│   └── README.md              # Testing documentation
├── vulnsluth.cfg              # Main configuration file
├── requirements.txt           # Python package dependencies
└── README.md                  # Project documentation (this file)
```

### 📁 Key Components

- **CLI Interface** (`src/main.py`): Command-line tool for automated scanning
- **Web Dashboard** (`src/webapp.py` + `templates/`): Interactive web interface
- **Scan Engine** (`src/engine.py`): Core vulnerability detection orchestration
- **Database Layer** (`src/db.py`): SQLite-based data persistence
- **Plugin System** (`plugins/`): Extensible architecture for custom checks
- **Vulnerability Checks** (`src/checks/`): Modular security testing components
- **Reporting System** (`src/reporter.py`): Multi-format report generation

## ⚖️ Ethical Usage

**⚠️ IMPORTANT**: VulnSleuth is designed for **authorized security testing only**.

- Always obtain explicit written permission before scanning systems
- Use only on systems you own or have authorization to test
- Respect rate limits and avoid disrupting production systems
- Follow responsible disclosure practices for any vulnerabilities found

## 📄 License

MIT License - See LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Add tests for new functionality
4. Commit changes (`git commit -am 'Add new feature'`)
5. Push to branch (`git push origin feature/new-feature`)
6. Create a Pull Request

## 📞 Support & Contact

- **Documentation**: Check the `/docs/` directory
- **Issues**: Report bugs via [GitHub Issues](https://github.com/devdas36/vulnsleuth/issues)
- **Security**: Responsible disclosure to [d3vdas36@gmail.com](mailto:d3vdas36@gmail.com)
- **Author**: Devdas - [GitHub Profile](https://github.com/devdas36)
- **Repository**: [VulnSleuth on GitHub](https://github.com/devdas36/vulnsleuth)

---

Made with ❤️ for the cybersecurity community
