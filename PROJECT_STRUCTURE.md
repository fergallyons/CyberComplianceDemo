# Cohesive Cyber Compliance Platform - Project Structure

## 📁 Directory Structure

```
cybersecurity_reporting_workspace/
├── 📁 src/                          # Source code package
│   ├── 📁 core/                     # Core functionality
│   │   ├── __init__.py
│   │   ├── auth_system.py          # Authentication & user management
│   │   └── models.py               # Data models & schemas
│   │
│   ├── 📁 modules/                  # Business logic modules
│   │   ├── __init__.py
│   │   ├── security_controls.py    # Security controls management
│   │   ├── incident_reporting.py   # Incident reporting system
│   │   ├── risk_management.py      # Risk assessment & management
│   │   ├── nis2_scope_assessment.py # NIS2 scope assessment
│   │   └── nis2_compliance.py      # NIS2 compliance reporting
│   │
│   ├── 📁 interfaces/               # User interface components
│   │   ├── __init__.py
│   │   ├── user_management.py      # User management interface
│   │   └── reporting_entities.py   # Reporting entities interface
│   │
│   ├── 📁 utils/                    # Utility functions
│   │   ├── __init__.py
│   │   ├── data_helpers.py         # Data processing utilities
│   │   ├── file_handlers.py        # File handling helpers
│   │   └── validators.py           # Data validation functions
│   │
│   ├── 📁 config/                   # Configuration management
│   │   ├── __init__.py
│   │   ├── config.py               # Application configuration
│   │   └── env_example.txt         # Environment variables template
│   │
│   └── 📁 data/                     # Data files
│       ├── *.json                   # Configuration & data files
│       └── *.db                     # Database files
│
├── 📁 assets/                       # Static assets
│   ├── cohesive_logo.svg
│   ├── cohesive_logo_dark.svg
│   ├── cohesive_symbol.svg
│   └── favicon.svg
│
├── 📁 docs/                         # Documentation
│   ├── README.md                    # Main project documentation
│   ├── INCIDENT_REPORTING_GUIDE.md  # Incident reporting guide
│   ├── SECURITY_CONTROLS_GUIDE.md   # Security controls guide
│   ├── REPORTING_ENTITIES_GUIDE.md  # Reporting entities guide
│   └── QUICK_START.md              # Quick start guide
│
├── 📁 tests/                        # Test files
│   ├── test_*.py                    # Unit tests
│   └── conftest.py                  # Test configuration
│
├── 📁 scripts/                      # Utility scripts
│   ├── run_app.bat                  # Windows batch file
│   ├── run_app.ps1                  # PowerShell script
│   ├── activate_anaconda.bat        # Anaconda activation
│   └── activate_anaconda.ps1        # Anaconda activation (PowerShell)
│
├── main.py                          # Main application entry point
├── cybersecurity_agent.py           # Main application logic
├── setup.py                         # Package installation script
├── requirements.txt                 # Python dependencies
├── .gitignore                       # Git ignore file
└── PROJECT_STRUCTURE.md             # This file
```

## 🏗️ Architecture Overview

### **Core Layer (`src/core/`)**
- **Authentication System**: User management, roles, permissions
- **Data Models**: Database schemas, data structures
- **Business Logic**: Core application logic and rules

### **Modules Layer (`src/modules/`)**
- **Security Controls**: NIS2 compliance controls management
- **Incident Reporting**: Security incident tracking and reporting
- **Risk Management**: Risk assessment and mitigation
- **NIS2 Compliance**: Regulatory compliance features

### **Interface Layer (`src/interfaces/`)**
- **User Management**: Administrative user interface
- **Reporting Entities**: Compliance reporting interface
- **Dashboard**: Main application dashboard

### **Utility Layer (`src/utils/`)**
- **Data Processing**: Data transformation and analysis
- **File Handling**: File operations and management
- **Validation**: Data validation and sanitization

### **Configuration Layer (`src/config/`)**
- **Application Settings**: Environment-specific configuration
- **Database Config**: Database connection and settings
- **Feature Flags**: Application feature toggles

## 🔧 Key Benefits of This Structure

### **1. Modularity**
- Clear separation of concerns
- Easy to maintain and extend
- Independent module development

### **2. Scalability**
- Add new modules without affecting existing code
- Easy to add new interfaces
- Scalable testing structure

### **3. Maintainability**
- Logical organization of code
- Easy to find specific functionality
- Clear import paths

### **4. Testing**
- Dedicated test directory
- Easy to run specific test suites
- Clear test organization

### **5. Deployment**
- Proper Python package structure
- Easy to install and distribute
- Clear dependency management

## 🚀 Getting Started

### **Development Setup**
```bash
# Clone the repository
git clone <repository-url>
cd cybersecurity_reporting_workspace

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Run the application
python main.py
# or
streamlit run main.py
```

### **Production Setup**
```bash
# Install the package
pip install .

# Run the application
cohesive-cyber
```

## 📝 Import Examples

### **From Core**
```python
from src.core.auth_system import AuthenticationSystem
from src.core.models import User, Organization
```

### **From Modules**
```python
from src.modules.security_controls import SecurityControlsManager
from src.modules.incident_reporting import IncidentReportingModule
```

### **From Interfaces**
```python
from src.interfaces.user_management import UserManagementInterface
from src.interfaces.reporting_entities import ReportingEntitiesInterface
```

### **From Utils**
```python
from src.utils.data_helpers import process_incident_data
from src.utils.validators import validate_email
```

## 🔄 Migration Notes

### **File Moves**
- Core functionality moved to `src/core/`
- Business logic moved to `src/modules/`
- UI components moved to `src/interfaces/`
- Configuration moved to `src/config/`
- Data files moved to `src/data/`
- Assets moved to `assets/`
- Documentation moved to `docs/`

### **Import Updates**
- All imports need to be updated to use new paths
- Main application entry point is now `main.py`
- Package structure follows Python best practices

### **Running the Application**
- Use `python main.py` instead of `python cybersecurity_agent.py`
- Or use `streamlit run main.py` for Streamlit development
- Package can be installed with `pip install -e .`

## 📚 Next Steps

1. **Update Import Statements**: Modify all Python files to use new import paths
2. **Test the Structure**: Ensure all modules can be imported correctly
3. **Update Documentation**: Modify any hardcoded file paths in documentation
4. **Create Additional Utils**: Add utility functions for common operations
5. **Enhance Testing**: Expand test coverage for the new structure
6. **Add CI/CD**: Set up continuous integration for the new structure

This structure provides a solid foundation for scaling the Cohesive Cyber Compliance Platform while maintaining code quality and developer productivity.
