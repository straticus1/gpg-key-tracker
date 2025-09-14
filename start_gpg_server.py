#!/usr/bin/env python3
"""
GPG Key Server Startup Script
Handles directory organization and starts the server
"""

import sys
import os
from pathlib import Path

# Add the current directory and lib to Python path for imports
current_dir = Path(__file__).parent.absolute()
sys.path.insert(0, str(current_dir))
sys.path.insert(0, str(current_dir / 'lib'))

# Import and run the server
from server.start_server import main

if __name__ == "__main__":
    sys.exit(main())