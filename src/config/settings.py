"""
Configuration settings for the Cohesive Cyber Compliance Platform.

This module provides:
- Environment-based configuration
- Default settings
- Configuration validation
- Feature flags
"""

import os
from typing import Dict, Any, Optional
from pathlib import Path
import json


class Config:
    """Application configuration manager."""
    
    def __init__(self):
        """Initialize configuration with defaults and environment overrides."""
        self.base_dir = Path(__file__).parent.parent.parent
        self.data_dir = self.base_dir / "src" / "data"
        self.assets_dir = self.base_dir / "assets"
        self.docs_dir = self.base_dir / "docs"
        
        # Load environment variables
        self.load_environment()
        
        # Set default values
        self.set_defaults()
        
        # Validate configuration
        self.validate()
    
    def load_environment(self):
        """Load configuration from environment variables."""
        # Database settings
        self.database_path = os.getenv('DATABASE_PATH', str(self.data_dir / "cybersecurity_users.db"))
        
        # Email settings
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_username = os.getenv('SMTP_USERNAME', '')
        self.smtp_password = os.getenv('SMTP_PASSWORD', '')
        self.smtp_use_tls = os.getenv('SMTP_USE_TLS', 'true').lower() == 'true'
        
        # Application settings
        self.app_name = os.getenv('APP_NAME', 'Cohesive Cyber Compliance')
        self.app_version = os.getenv('APP_VERSION', '1.0.0')
        self.debug_mode = os.getenv('DEBUG_MODE', 'false').lower() == 'true'
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        
        # Security settings
        self.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')
        self.session_timeout = int(os.getenv('SESSION_TIMEOUT', '3600'))  # 1 hour
        
        # Feature flags
        self.enable_email_reports = os.getenv('ENABLE_EMAIL_REPORTS', 'true').lower() == 'true'
        self.enable_pdf_export = os.getenv('ENABLE_PDF_EXPORT', 'true').lower() == 'true'
        self.enable_risk_management = os.getenv('ENABLE_RISK_MANAGEMENT', 'true').lower() == 'true'
        self.enable_logo_fetching = os.getenv('ENABLE_LOGO_FETCHING', 'true').lower() == 'true'
        
        # NIS2 specific settings
        self.nis2_compliance_enabled = os.getenv('NIS2_COMPLIANCE_ENABLED', 'true').lower() == 'true'
        self.nis2_reporting_deadline = os.getenv('NIS2_REPORTING_DEADLINE', '2024-10-17')
        
        # Data retention settings
        self.incident_retention_days = int(os.getenv('INCIDENT_RETENTION_DAYS', '2555'))  # 7 years
        self.audit_log_retention_days = int(os.getenv('AUDIT_LOG_RETENTION_DAYS', '1095'))  # 3 years
    
    def set_defaults(self):
        """Set default configuration values."""
        # File paths
        self.security_controls_file = str(self.data_dir / "security_controls.json")
        self.organization_controls_file = str(self.data_dir / "organization_controls.json")
        self.incidents_file = str(self.data_dir / "incidents.json")
        self.scope_assessments_file = str(self.data_dir / "scope_assessments.json")
        self.risk_register_file = str(self.data_dir / "risk_register.json")
        self.reporting_entities_file = str(self.data_dir / "reporting_entities.json")
        
        # UI settings
        self.page_title = "Cohesive Cyber Compliance"
        self.page_icon = str(self.assets_dir / "cohesive_symbol.svg")
        self.layout = "wide"
        self.initial_sidebar_state = "expanded"
        
        # Dashboard settings
        self.dashboard_refresh_interval = 300  # 5 minutes
        self.max_incidents_display = 50
        self.max_controls_display = 100
        
        # Export settings
        self.csv_encoding = 'utf-8'
        self.pdf_page_size = 'A4'
        self.pdf_margin = 20
        
        # Notification settings
        self.enable_notifications = True
        self.notification_email = os.getenv('NOTIFICATION_EMAIL', '')
        self.notification_webhook = os.getenv('NOTIFICATION_WEBHOOK', '')
    
    def validate(self):
        """Validate configuration values."""
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Validate email settings if enabled
        if self.enable_email_reports:
            if not self.smtp_username or not self.smtp_password:
                print("Warning: Email reports enabled but SMTP credentials not configured")
        
        # Validate file paths
        required_files = [
            self.security_controls_file,
            self.organization_controls_file,
            self.incidents_file,
            self.scope_assessments_file,
            self.risk_register_file,
            self.reporting_entities_file
        ]
        
        for file_path in required_files:
            file_dir = Path(file_path).parent
            file_dir.mkdir(parents=True, exist_ok=True)
    
    def get_database_config(self) -> Dict[str, Any]:
        """Get database configuration."""
        return {
            'path': self.database_path,
            'timeout': 30,
            'check_same_thread': False
        }
    
    def get_email_config(self) -> Dict[str, Any]:
        """Get email configuration."""
        return {
            'smtp_server': self.smtp_server,
            'smtp_port': self.smtp_port,
            'smtp_username': self.smtp_username,
            'smtp_password': self.smtp_password,
            'smtp_use_tls': self.smtp_use_tls
        }
    
    def get_export_config(self) -> Dict[str, Any]:
        """Get export configuration."""
        return {
            'csv_encoding': self.csv_encoding,
            'pdf_page_size': self.pdf_page_size,
            'pdf_margin': self.pdf_margin,
            'enable_pdf': self.enable_pdf_export
        }
    
    def get_feature_flags(self) -> Dict[str, bool]:
        """Get feature flags configuration."""
        return {
            'email_reports': self.enable_email_reports,
            'pdf_export': self.enable_pdf_export,
            'risk_management': self.enable_risk_management,
            'logo_fetching': self.enable_logo_fetching,
            'nis2_compliance': self.nis2_compliance_enabled,
            'notifications': self.enable_notifications
        }
    
    def get_ui_config(self) -> Dict[str, Any]:
        """Get UI configuration."""
        return {
            'page_title': self.page_title,
            'page_icon': self.page_icon,
            'layout': self.layout,
            'initial_sidebar_state': self.initial_sidebar_state
        }
    
    def get_nis2_config(self) -> Dict[str, Any]:
        """Get NIS2 compliance configuration."""
        return {
            'enabled': self.nis2_compliance_enabled,
            'reporting_deadline': self.nis2_reporting_deadline,
            'incident_retention_days': self.incident_retention_days,
            'audit_log_retention_days': self.audit_log_retention_days
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'app_name': self.app_name,
            'app_version': self.app_version,
            'debug_mode': self.debug_mode,
            'database_path': self.database_path,
            'data_directory': str(self.data_dir),
            'assets_directory': str(self.assets_dir),
            'feature_flags': self.get_feature_flags(),
            'nis2_config': self.get_nis2_config()
        }
    
    def save_to_file(self, file_path: str):
        """Save configuration to file."""
        config_data = self.to_dict()
        
        with open(file_path, 'w') as f:
            json.dump(config_data, f, indent=2, default=str)
    
    def load_from_file(self, file_path: str):
        """Load configuration from file."""
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                config_data = json.load(f)
                
                # Update configuration with file data
                for key, value in config_data.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
    
    def get_environment_summary(self) -> str:
        """Get a summary of the current configuration environment."""
        summary = f"""
Configuration Summary:
====================
App Name: {self.app_name} v{self.app_version}
Debug Mode: {self.debug_mode}
Log Level: {self.log_level}

Database: {self.database_path}
Data Directory: {self.data_dir}
Assets Directory: {self.assets_dir}

Feature Flags:
- Email Reports: {self.enable_email_reports}
- PDF Export: {self.enable_pdf_export}
- Risk Management: {self.enable_risk_management}
- Logo Fetching: {self.enable_logo_fetching}
- NIS2 Compliance: {self.nis2_compliance_enabled}

NIS2 Settings:
- Compliance Enabled: {self.nis2_compliance_enabled}
- Reporting Deadline: {self.nis2_reporting_deadline}
- Incident Retention: {self.incident_retention_days} days
- Audit Log Retention: {self.audit_log_retention_days} days
"""
        return summary


# Global configuration instance
config = Config()

# Convenience functions
def get_config() -> Config:
    """Get the global configuration instance."""
    return config

def get_database_path() -> str:
    """Get database path from configuration."""
    return config.database_path

def get_data_directory() -> Path:
    """Get data directory from configuration."""
    return config.data_dir

def get_assets_directory() -> Path:
    """Get assets directory from configuration."""
    return config.assets_dir

def is_feature_enabled(feature: str) -> bool:
    """Check if a feature is enabled."""
    return config.get_feature_flags().get(feature, False)

def get_nis2_config() -> Dict[str, Any]:
    """Get NIS2 configuration."""
    return config.get_nis2_config()
