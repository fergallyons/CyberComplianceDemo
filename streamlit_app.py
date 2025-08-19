"""
Cohesive Cyber Compliance Platform - Streamlit Cloud Deployment Entry Point

This file serves as the main entry point for Streamlit Cloud deployment.
It initializes the application and starts the Streamlit interface.
"""

import streamlit as st
import sys
import os
from pathlib import Path

# Add the src directory to the Python path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

# Set page configuration
st.set_page_config(
    page_title="Cohesive Cyber Compliance",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Import and run the main application
try:
    from cybersecurity_agent import CybersecurityAgent
    
    # Initialize the application
    app = CybersecurityAgent()
    
    # Run the main application
    if __name__ == "__main__":
        app.run()
        
except ImportError as e:
    st.error(f"Failed to import application modules: {e}")
    st.info("Please ensure all required files are present in the src/ directory")
    
    # Show directory structure for debugging
    st.subheader("Current Directory Structure:")
    st.code(str(Path(__file__).parent))
    
    st.subheader("Source Directory Contents:")
    if src_path.exists():
        st.code("\n".join([str(p) for p in src_path.rglob("*")]))
    else:
        st.error("src/ directory not found!")
