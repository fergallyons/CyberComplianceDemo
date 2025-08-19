#!/usr/bin/env python3
"""
Simple test script for NIS2 Article 23 compliance modules.
"""

import sys
import os

def test_imports():
    """Test basic imports."""
    try:
        from nis2_scope_assessment import NIS2ScopeAssessment
        print("PASS: nis2_scope_assessment imported successfully")
        return True
    except Exception as e:
        print(f"FAIL: nis2_scope_assessment import failed: {e}")
        return False

    try:
        from incident_reporting import IncidentReportingModule
        print("PASS: incident_reporting imported successfully")
        return True
    except Exception as e:
        print(f"FAIL: incident_reporting import failed: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality."""
    try:
        from nis2_scope_assessment import NIS2ScopeAssessment
        tool = NIS2ScopeAssessment()
        print(f"PASS: Scope assessment tool created with {len(tool.essential_sectors)} essential sectors")
        return True
    except Exception as e:
        print(f"FAIL: Scope assessment creation failed: {e}")
        return False

    try:
        from incident_reporting import IncidentReportingModule
        tool = IncidentReportingModule()
        print(f"PASS: Incident reporting tool created with {len(tool.report_templates)} report templates")
        return True
    except Exception as e:
        print(f"FAIL: Incident reporting creation failed: {e}")
        return False

def main():
    """Run tests."""
    print("Testing NIS2 Article 23 Compliance Modules")
    print("=" * 40)
    
    test1 = test_imports()
    test2 = test_basic_functionality()
    
    if test1 and test2:
        print("=" * 40)
        print("ALL TESTS PASSED")
        return 0
    else:
        print("=" * 40)
        print("SOME TESTS FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())

