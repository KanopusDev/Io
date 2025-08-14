"""
WSGI entry point for production deployment.
For use with Gunicorn, uWSGI, or other WSGI servers.
"""

import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app import create_app, init_database

# Create the application instance
application = create_app()

# Initialize database
init_database(application)

# For Gunicorn compatibility
app = application

if __name__ == "__main__":
    application.run()
