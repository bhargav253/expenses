"""
Shared SQLAlchemy instance for the application
This ensures all modules use the same database session
"""

from flask_sqlalchemy import SQLAlchemy

# Create a single SQLAlchemy instance that will be shared across the application
db = SQLAlchemy()
