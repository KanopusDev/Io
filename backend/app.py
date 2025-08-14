"""
Main application entry point for Io URL Shortener.
Production-grade Flask application with proper configuration and initialization.
"""

import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from app import create_app, init_database

def main():
    """Main application entry point."""
    # Create Flask application
    app = create_app()
    
    # Initialize database
    init_database(app)
    
    # Get configuration
    host = app.config.get('HOST')
    port = app.config.get('PORT')
    debug = app.config.get('DEBUG')
    
    # Log startup information
    app.logger.info(f"Starting Io URL Shortener on {host}:{port}")
    app.logger.info(f"Debug mode: {debug}")
    app.logger.info(f"Environment: {app.config.get('ENVIRONMENT')}")
    
    # Run the application
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )

if __name__ == '__main__':
    main()
