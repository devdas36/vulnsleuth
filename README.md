# VulnSleuth - Advanced Vulnerability Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-brightgreen)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A comprehensive vulnerability assessment platform with multiple interfaces (TUI, Web Dashboard, CLI), extensible plugin system, and automated security testing capabilities.

**Author**: Devdas | **Email**: <d3vdas36@gmail.com> | **GitHub**: [@devdas36](https://github.com/devdas36)

---

## 📖 Table of Contents

- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Plugins](#plugins)
- [Project Structure](#project-structure)
- [Security](#security)
- [License](#license)

---

## About

VulnSleuth is a professional security scanning framework for ethical hackers, security professionals, and system administrators. It provides comprehensive vulnerability assessment across local systems, networks, and web applications.

**Purpose**: Security audits, penetration testing, DevSecOps integration, network monitoring, and educational use.

---

## Features

- **🖥️ Multiple Interfaces**: Interactive TUI, Web Dashboard, CLI for automation
- **🔍 Multi-Layer Scanning**: Local system, network, and web application security checks
- **🧩 Plugin System**: Extensible architecture with 7+ built-in plugins
- **🎯 CVE Intelligence**: Real-time CVE lookup, exploit correlation, NVD/MITRE integration
- **📊 Advanced Reporting**: JSON, HTML, CSV, XML, PDF with custom templates
- **💾 Database Management**: SQLite backend with history tracking and analytics
- **🤖 Automation**: Scheduled scans, auto-remediation suggestions, alerts (Email/Slack/Discord)
- **🔐 Security**: User authentication, encryption, audit logging, rate limiting

---

## Installation

### Prerequisites

- Python 3.8+
- Nmap (for network scanning)
- Git

### Quick Install

```bash
# Clone repository
git clone https://github.com/devdas36/vulnsleuth.git
cd vulnsleuth

# Install dependencies
pip install -r requirements.txt

# Verify installation
nmap --version
python src/main.py --help
```

### Optional: Virtual Environment

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Optional: Docker

```bash
docker build -t vulnsleuth .
docker run -p 5000:5000 -v $(pwd)/data:/app/data vulnsleuth
```

---

## Quick Start

### 1. Interactive TUI

```bash
python src/main.py
```

Menu-driven interface with ASCII banner, real-time progress, and interactive navigation.

### 2. Web Dashboard

```bash
python src/app.py
# Access at http://localhost:5000
```

Features: Real-time monitoring, scan management, vulnerability browser, report generation.

---

## Configuration

Edit `vulnsluth.cfg` to customize VulnSleuth behavior.

### Key Configuration Sections

#### General Settings

```ini
[general]
max_threads = 50              # Concurrent threads
scan_intensity = medium       # low, medium, high, aggressive
default_timeout = 300         # Scan timeout (seconds)
verbose_logging = true
```

#### Database

```ini
[database]
db_path = data/vulnsleuth.db
cve_cache_days = 7
auto_backup = true
```

#### CVE Intelligence

```ini
[cve_sources]
nvd_api_key = your_key_here   # Get from nvd.nist.gov
mitre_enabled = true
exploit_db_enabled = true
```

#### Network Scanning

```ini
[network_scanning]
nmap_path = nmap
nmap_timing = -T4             # -T0 to -T5
default_ports = 1-1000,3000,3389,5432,8080,8443
os_detection = true
service_detection = true
```

#### Dashboard

```ini
[dashboard]
host = 127.0.0.1              # Use 0.0.0.0 for external access
port = 5000
```

#### Notifications

```ini
[notifications]
email_enabled = false
smtp_server = smtp.gmail.com
slack_webhook = your_webhook_url
notify_on_critical = true
```

**Important**: Change default credentials in production!

---

## Plugins

### Built-in Plugins

VulnSleuth includes 7 professional security plugins:

1. **Web Security Scanner**: HTTP headers, SSL/TLS, cookies, XSS/SQLi indicators
2. **Network Reconnaissance**: Port scanning, service detection, OS fingerprinting (Nmap)
3. **CVE Intelligence**: Real-time CVE lookup, exploit correlation, NVD/MITRE integration
4. **SSL/TLS Audit**: Certificate validation, cipher analysis, protocol versions
5. **Database Security**: Database service detection, default credentials, misconfigurations
6. **Authentication Bypass**: Default credentials, weak passwords, session issues
7. **Information Disclosure**: Server banners, directory listing, backup files

### Creating Custom Plugins

Example plugin:

```python
# plugins/my_custom_plugin.py
import sys, os
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from plugin import VulnPlugin, VulnerabilityFinding, PluginMetadata

class CustomPlugin(VulnPlugin):
    def __init__(self, config=None):
        super().__init__(config)
        self.metadata = PluginMetadata(
            name="Custom Plugin",
            version="1.0.0",
            author="Your Name",
            description="Custom vulnerability checks",
            category="custom",
            tags=["custom", "security"]
        )
    
    def check(self, target, **kwargs):
        findings = []
        # Your detection logic here
        if self._detect_vulnerability(target):
            finding = self.create_finding(
                title="Vulnerability Found",
                severity="high",
                description="Details...",
                target=target,
                solution="Fix recommendation"
            )
            findings.append(finding)
        return findings
    
    def _detect_vulnerability(self, target):
        # Your custom logic
        return False

__plugin_class__ = CustomPlugin
```

Place in `plugins/` directory. Auto-loaded on startup if `auto_load = true` in config.

---

## Project Structure

```bash
vulnsleuth/
├── LICENSE
├── README.md
├── requirements.txt          # Python dependencies
├── vulnsluth.cfg            # Configuration file
├── src/                     # Core application
│   ├── main.py             # TUI entry point
│   ├── app.py              # Web dashboard (Flask)
│   ├── engine.py           # Scan orchestration
│   ├── db.py               # Database manager
│   ├── reporter.py         # Report generation
│   ├── plugin.py           # Plugin system
│   ├── tui.py              # Terminal UI
│   ├── utils.py            # Utilities
│   ├── auto_remediation.py # Auto-fix suggestions
│   ├── checks/             # Security checks
│   │   ├── local_checks.py
│   │   ├── network_checks.py
│   │   └── webapp_checks.py
│   ├── templates/          # Web UI templates
│   └── static/             # CSS/JS assets
├── plugins/                # Security plugins
│   ├── web_security_scanner_plugin.py
│   ├── network_reconnaissance_plugin.py
│   ├── cve_intelligence_plugin.py
│   ├── ssl_tls_audit_plugin.py
│   ├── database_security_plugin.py
│   ├── authentication_bypass_plugin.py
│   └── information_disclosure_plugin.py
├── data/                   # Databases (created at runtime)
├── logs/                   # Log files
├── reports/                # Generated reports
├── backups/                # Database backups
└── temp/                   # Temporary files
```

---

## Security

### ⚠️ Ethical Use Warning

**VulnSleuth is for authorized security testing ONLY.**

✅ **DO**: Obtain written permission, scan owned systems, follow responsible disclosure  
❌ **DON'T**: Scan without authorization, use for illegal purposes, disrupt production

**Unauthorized access to computer systems is illegal.** Users are solely responsible for their actions.

### Production Security Checklist

- [ ] Change default credentials in `vulnsluth.cfg`
- [ ] Configure IP whitelist
- [ ] Enable database encryption
- [ ] Use HTTPS with reverse proxy
- [ ] Set API rate limits
- [ ] Regular security updates
- [ ] Secure file permissions on data directory

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Nmap not found** | Install: `apt install nmap` (Linux), `brew install nmap` (Mac), or download from nmap.org (Windows) |
| **Permission denied** | Run with `sudo` or fix directory permissions: `chmod 755 data/ logs/` |
| **Module not found** | Reinstall dependencies: `pip install -r requirements.txt` |
| **Database locked** | Stop all instances: `pkill -f vulnsleuth` |
| **Port 5000 in use** | Change port in config or: `python src/app.py --port 8080` |
| **SSL errors** | Set `verify_ssl = false` in `[web_scanning]` (testing only!) |

Enable debug logging:

```ini
[general]
verbose_logging = true
```

View logs: `tail -f logs/vulnsleuth.log`

---

## Contributing

Contributions welcome!

1. Fork repo
2. Create feature branch: `git checkout -b feature/new-feature`
3. Make changes, add tests
4. Commit: `git commit -am 'Add feature'`
5. Push: `git push origin feature/new-feature`
6. Create Pull Request

**Guidelines**: Follow PEP 8, add tests (>80% coverage), update docs, no hardcoded secrets.

---

## License

MIT License - Copyright (c) 2024 Devdas

See [LICENSE](LICENSE) file for details.

---

## Contact

**Devdas** | <d3vdas36@gmail.com> | [@devdas36](https://github.com/devdas36)

- **Bugs/Features**: [GitHub Issues](https://github.com/devdas36/vulnsleuth/issues)
- **Security**: <d3vdas36@gmail.com> (responsible disclosure)

---

<div align="center">

⭐ **Star this repo if you find it useful!**

Made with ❤️ for the cybersecurity community

</div>
