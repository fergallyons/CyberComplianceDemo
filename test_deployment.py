"""
Test script to verify deployment structure works correctly.
Run this to check if all imports and file paths are working.
"""

import sys
import os
from pathlib import Path

def test_imports():
    """Test that all required modules can be imported."""
    print("🧪 Testing imports...")
    
    # Add src to path
    src_path = Path(__file__).parent / "src"
    sys.path.insert(0, str(src_path))
    
    try:
        # Test core imports
        from core.auth_system import AuthenticationSystem
        print("✅ Core auth_system imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import core.auth_system: {e}")
        return False
    
    try:
        # Test modules imports
        from modules.security_controls import SecurityControlsManager
        print("✅ Security controls module imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import security_controls: {e}")
        return False
    
    try:
        # Test interfaces imports
        from interfaces.user_management import UserManagementInterface
        print("✅ User management interface imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import user_management: {e}")
        return False
    
    try:
        # Test utils imports
        from utils.data_helpers import format_datetime
        print("✅ Utility functions imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import utility functions: {e}")
        return False
    
    try:
        # Test config imports
        from config.settings import get_config
        print("✅ Configuration imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import configuration: {e}")
        return False
    
    return True

def test_file_paths():
    """Test that all required files and directories exist."""
    print("\n📁 Testing file paths...")
    
    base_path = Path(__file__).parent
    
    # Required files
    required_files = [
        "streamlit_app.py",
        "requirements.txt",
        "packages.txt",
        ".streamlit/config.toml"
    ]
    
    # Required directories
    required_dirs = [
        "src",
        "src/core",
        "src/modules", 
        "src/interfaces",
        "src/utils",
        "src/config",
        "src/data",
        "assets",
        "docs"
    ]
    
    all_good = True
    
    # Check files
    for file_path in required_files:
        full_path = base_path / file_path
        if full_path.exists():
            print(f"✅ {file_path} exists")
        else:
            print(f"❌ {file_path} missing")
            all_good = False
    
    # Check directories
    for dir_path in required_dirs:
        full_path = base_path / dir_path
        if full_path.exists() and full_path.is_dir():
            print(f"✅ {dir_path} exists")
        else:
            print(f"❌ {dir_path} missing")
            all_good = False
    
    return all_good

def test_streamlit_app():
    """Test that the streamlit app can be imported."""
    print("\n🚀 Testing Streamlit app...")
    
    try:
        # Test importing the main app
        import streamlit_app
        print("✅ streamlit_app.py imported successfully")
        return True
    except Exception as e:
        print(f"❌ Failed to import streamlit_app.py: {e}")
        return False

def main():
    """Run all tests."""
    print("🚀 Cohesive Cyber Compliance Platform - Deployment Test")
    print("=" * 60)
    
    # Test imports
    imports_ok = test_imports()
    
    # Test file paths
    paths_ok = test_file_paths()
    
    # Test streamlit app
    app_ok = test_streamlit_app()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Results Summary:")
    print(f"Imports: {'✅ PASS' if imports_ok else '❌ FAIL'}")
    print(f"File Paths: {'✅ PASS' if paths_ok else '❌ FAIL'}")
    print(f"Streamlit App: {'✅ PASS' if app_ok else '❌ FAIL'}")
    
    if all([imports_ok, paths_ok, app_ok]):
        print("\n🎉 All tests passed! Ready for Streamlit Cloud deployment!")
        print("\nNext steps:")
        print("1. Commit all changes to GitHub")
        print("2. Go to share.streamlit.io")
        print("3. Deploy your app!")
    else:
        print("\n⚠️ Some tests failed. Please fix issues before deployment.")
    
    return all([imports_ok, paths_ok, app_ok])

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
