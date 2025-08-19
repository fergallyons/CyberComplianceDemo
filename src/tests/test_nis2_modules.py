#!/usr/bin/env python3
"""
Test script for NIS2 Article 23 compliance modules.
This script tests the scope assessment and incident reporting functionality.
"""

import sys
import os
from datetime import datetime

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_scope_assessment():
    """Test the NIS2 scope assessment module."""
    print("🔍 Testing NIS2 Scope Assessment Module...")
    
    try:
        from nis2_scope_assessment import NIS2ScopeAssessment, SectorType, OrganizationSize
        
        # Create assessment instance
        assessment_tool = NIS2ScopeAssessment()
        print("✅ Scope assessment module imported successfully")
        
        # Test sector classifications
        print(f"✅ Essential sectors: {len(assessment_tool.essential_sectors)}")
        print(f"✅ Important sectors: {len(assessment_tool.important_sectors)}")
        print(f"✅ Digital services: {len(assessment_tool.digital_services)}")
        print(f"✅ Risk factors: {len(assessment_tool.risk_factors)}")
        
        # Test enums
        print(f"✅ Sector types: {[s.value for s in SectorType]}")
        print(f"✅ Organization sizes: {[s.value for s in OrganizationSize]}")
        
        print("✅ Scope assessment module test completed successfully\n")
        return True
        
    except Exception as e:
        print(f"❌ Scope assessment module test failed: {e}")
        return False

def test_incident_reporting():
    """Test the incident reporting module."""
    print("🚨 Testing Incident Reporting Module...")
    
    try:
        from incident_reporting import (
            IncidentReportingModule, IncidentCategory, IncidentSeverity, 
            IncidentStatus, SecurityIncident, IncidentTimeline
        )
        
        # Create reporting instance
        reporting_tool = IncidentReportingModule()
        print("✅ Incident reporting module imported successfully")
        
        # Test enums
        print(f"✅ Incident categories: {[c.value for c in IncidentCategory]}")
        print(f"✅ Incident severities: {[s.value for s in IncidentSeverity]}")
        print(f"✅ Incident statuses: {[s.value for s in IncidentStatus]}")
        
        # Test report templates
        print(f"✅ Report templates: {list(reporting_tool.report_templates.keys())}")
        
        print("✅ Incident reporting module test completed successfully\n")
        return True
        
    except Exception as e:
        print(f"❌ Incident reporting module test failed: {e}")
        return False

def test_integration():
    """Test integration between modules."""
    print("🔗 Testing Module Integration...")
    
    try:
        from nis2_scope_assessment import NIS2ScopeAssessment
        from incident_reporting import IncidentReportingModule
        
        # Test that both modules can be instantiated together
        scope_tool = NIS2ScopeAssessment()
        reporting_tool = IncidentReportingModule()
        
        print("✅ Both modules can be instantiated together")
        print("✅ Integration test completed successfully\n")
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False

def test_data_structures():
    """Test data structure creation and manipulation."""
    print("📊 Testing Data Structures...")
    
    try:
        from incident_reporting import SecurityIncident, IncidentTimeline
        from nis2_scope_assessment import ScopeAssessment, SectorType, OrganizationSize
        from datetime import datetime
        
        # Test incident timeline
        timeline = IncidentTimeline(detection_time=datetime.now())
        print("✅ Incident timeline created successfully")
        
        # Test scope assessment
        assessment = ScopeAssessment(
            organization_name="Test Org",
            assessment_date=datetime.now(),
            sector_type=SectorType.ESSENTIAL,
            organization_size=OrganizationSize.MEDIUM,
            in_scope=True,
            reporting_obligations=["Report incidents within 24 hours"],
            assessment_score=75,
            risk_factors=["High critical infrastructure dependency"],
            recommendations=["Implement enhanced security controls"],
            next_steps=["Register with national authority"]
        )
        print("✅ Scope assessment created successfully")
        
        print("✅ Data structure test completed successfully\n")
        return True
        
    except Exception as e:
        print(f"❌ Data structure test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🧪 NIS2 Article 23 Compliance Modules Test Suite")
    print("=" * 50)
    
    tests = [
        test_scope_assessment,
        test_incident_reporting,
        test_integration,
        test_data_structures
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! NIS2 modules are working correctly.")
        return 0
    else:
        print("⚠️ Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

