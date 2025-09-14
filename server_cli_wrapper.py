#!/usr/bin/env python3
"""
GPG Key Server CLI Wrapper Script
"""

import sys
import os
from pathlib import Path

# Add the current directory and lib to Python path for imports
current_dir = Path(__file__).parent.absolute()
sys.path.insert(0, str(current_dir))
sys.path.insert(0, str(current_dir / 'lib'))

# Import and run the CLI
from server.server_cli import main

if __name__ == "__main__":
    sys.exit(main())