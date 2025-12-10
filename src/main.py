#!/usr/bin/env python3
"""
VulnSleuth - Advanced Vulnerability Scanner
Main Entry Point - Interactive TUI Interface

Author: Devdas
Contact: d3vdas36@gmail.com
GitHub: https://github.com/devdas36
License: MIT
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Launch the interactive TUI
from tui import VulnSleuthTUI

def main():
    """Main entry point - Launch interactive TUI"""
    try:
        tui = VulnSleuthTUI()
        tui.run()
    except KeyboardInterrupt:
        print("\n⚠️  Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
