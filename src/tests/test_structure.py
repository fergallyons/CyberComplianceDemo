"""
Test the new project structure and imports.

This test file verifies that:
- All packages can be imported correctly
- Configuration works properly
- Utility functions are accessible
"""

import sys
import os
import unittest
from pathlib import Path

# Add the src directory to the path for testing
src_path = Path(__file__).parent.parent
sys.path.insert(0, str(src_path))


class TestProjectStructure(unittest.TestCase):
    """Test the project structure and imports."""
    
    def test_core_imports(self):
        """Test that core modules can be imported."""
        try:
            from core.auth_system import AuthenticationSystem
            self.assertTrue(True, "Core auth_system imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import core.auth_system: {e}")
    
    def test_modules_imports(self):
        """Test that business logic modules can be imported."""
        try:
            from modules.security_controls import SecurityControlsManager
            self.assertTrue(True, "Security controls module imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import security_controls: {e}")
        
        try:
            from modules.incident_reporting import IncidentReportingModule
            self.assertTrue(True, "Incident reporting module imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import incident_reporting: {e}")
    
    def test_interfaces_imports(self):
        """Test that interface modules can be imported."""
        try:
            from interfaces.user_management import UserManagementInterface
            self.assertTrue(True, "User management interface imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import user_management: {e}")
    
    def test_utils_imports(self):
        """Test that utility modules can be imported."""
        try:
            from utils.data_helpers import format_datetime, clean_text, validate_email
            self.assertTrue(True, "Utility functions imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import utility functions: {e}")
    
    def test_config_imports(self):
        """Test that configuration modules can be imported."""
        try:
            from config.settings import get_config, get_database_path
            self.assertTrue(True, "Configuration functions imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import configuration: {e}")
    
    def test_utility_functions(self):
        """Test that utility functions work correctly."""
        from utils.data_helpers import format_datetime, clean_text, validate_email
        
        # Test datetime formatting
        from datetime import datetime
        now = datetime.now()
        formatted = format_datetime(now)
        self.assertIsInstance(formatted, str)
        self.assertGreater(len(formatted), 0)
        
        # Test text cleaning
        dirty_text = "  <p>Hello   World</p>  "
        clean = clean_text(dirty_text)
        self.assertEqual(clean, "Hello World")
        
        # Test email validation
        self.assertTrue(validate_email("test@example.com"))
        self.assertFalse(validate_email("invalid-email"))
    
    def test_configuration(self):
        """Test that configuration works correctly."""
        from config.settings import get_config, get_database_path
        
        config = get_config()
        self.assertIsNotNone(config)
        self.assertIsInstance(config.app_name, str)
        self.assertIsInstance(config.app_version, str)
        
        db_path = get_database_path()
        self.assertIsInstance(db_path, str)
        self.assertGreater(len(db_path), 0)
    
    def test_directory_structure(self):
        """Test that the directory structure is correct."""
        base_path = Path(__file__).parent.parent.parent
        
        # Check main directories exist
        expected_dirs = ['src', 'assets', 'docs', 'tests']
        for dir_name in expected_dirs:
            dir_path = base_path / dir_name
            self.assertTrue(dir_path.exists(), f"Directory {dir_name} should exist")
            self.assertTrue(dir_path.is_dir(), f"{dir_name} should be a directory")
        
        # Check src subdirectories
        src_path = base_path / 'src'
        src_dirs = ['core', 'modules', 'interfaces', 'utils', 'config', 'data']
        for dir_name in src_dirs:
            dir_path = src_path / dir_name
            self.assertTrue(dir_path.exists(), f"src/{dir_name} should exist")
            self.assertTrue(dir_path.is_dir(), f"src/{dir_name} should be a directory")
    
    def test_package_init_files(self):
        """Test that all packages have __init__.py files."""
        base_path = Path(__file__).parent.parent.parent
        src_path = base_path / 'src'
        
        # Check that all package directories have __init__.py files
        package_dirs = ['core', 'modules', 'interfaces', 'utils', 'config']
        for dir_name in package_dirs:
            init_file = src_path / dir_name / '__init__.py'
            self.assertTrue(init_file.exists(), f"__init__.py should exist in src/{dir_name}")
    
    def test_main_entry_point(self):
        """Test that the main entry point exists."""
        base_path = Path(__file__).parent.parent.parent
        main_file = base_path / 'main.py'
        self.assertTrue(main_file.exists(), "main.py should exist in root directory")
    
    def test_requirements_file(self):
        """Test that requirements.txt exists."""
        base_path = Path(__file__).parent.parent.parent
        requirements_file = base_path / 'requirements.txt'
        self.assertTrue(requirements_file.exists(), "requirements.txt should exist")
    
    def test_setup_file(self):
        """Test that setup.py exists."""
        base_path = Path(__file__).parent.parent.parent
        setup_file = base_path / 'setup.py'
        self.assertTrue(setup_file.exists(), "setup.py should exist")


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)
