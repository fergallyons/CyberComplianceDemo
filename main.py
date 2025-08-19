"""
Cohesive Cyber Compliance Platform - Main Application Entry Point

This is the main entry point for the Cohesive Cyber Compliance Platform.
It initializes the application and starts the Streamlit interface.
"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from cybersecurity_agent import main

if __name__ == "__main__":
    main()
