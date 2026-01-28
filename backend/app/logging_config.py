"""Logging configuration for the application."""

import logging
import sys
from logging.handlers import RotatingFileHandler
import os


def setup_logging(app):
    """
    Configure application logging with both file and console handlers.
    
    Args:
        app: Flask application instance
    """
    # Set log level based on config
    log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO').upper())
    app.logger.setLevel(log_level)
    
    # Remove default handlers
    app.logger.handlers.clear()
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    simple_formatter = logging.Formatter(
        '[%(levelname)s] %(message)s'
    )
    
    # Console handler (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(simple_formatter)
    app.logger.addHandler(console_handler)
    
    # File handler (rotating, 10MB max, keep 5 backups)
    if app.config.get('LOG_TO_FILE', True):
        log_dir = app.config.get('LOG_DIR', os.path.join(app.root_path, '..', 'logs'))
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, app.config.get('LOG_FILE', 'app.log'))
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(detailed_formatter)
        app.logger.addHandler(file_handler)
    
    # Log startup message
    app.logger.info(f'Application started in {app.config.get("ENV", "unknown")} mode')
    app.logger.debug(f'Log level set to {logging.getLevelName(log_level)}')
    
    return app.logger
