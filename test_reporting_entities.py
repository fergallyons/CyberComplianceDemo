#!/usr/bin/env python3
"""
Test script for the Reporting Entities module.
"""

import sys
import os

def test_imports():
    """Test basic imports."""
    try:
        from reporting_entities import ReportingEntitiesInterface, ReportingEntity, EntityType, Jurisdiction
        print("PASS: reporting_entities imported successfully")
        return True
    except Exception as e:
        print(f"FAIL: reporting_entities import failed: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality."""
    try:
        from reporting_entities import ReportingEntitiesInterface
        
        # Create interface
        interface = ReportingEntitiesInterface()
        print(f"PASS: Interface created successfully")
        
        # Check default entities
        manager = interface.manager
        print(f"PASS: Manager created with {len(manager.entities)} default entities")
        
        # Check entity types
        entity_types = manager.get_entity_types()
        print(f"PASS: Found {len(entity_types)} entity types")
        
        # Check jurisdictions
        jurisdictions = manager.get_jurisdictions()
        print(f"PASS: Found {len(jurisdictions)} jurisdictions")
        
        # Check NIS2 entities
        nis2_entities = manager.get_nis2_entities()
        print(f"PASS: Found {len(nis2_entities)} NIS2 scope entities")
        
        return True
    except Exception as e:
        print(f"FAIL: Basic functionality test failed: {e}")
        return False

def test_entity_operations():
    """Test entity operations."""
    try:
        from reporting_entities import ReportingEntitiesInterface, ReportingEntity, EntityType, Jurisdiction
        
        interface = ReportingEntitiesInterface()
        manager = interface.manager
        
        # Test adding a new entity
        test_entity = ReportingEntity(
            id="test_entity",
            name="Test Entity",
            entity_type=EntityType.OTHER,
            jurisdiction=Jurisdiction.OTHER,
            description="A test entity for testing purposes"
        )
        
        # Add entity
        success = manager.add_entity(test_entity)
        if success:
            print("PASS: Test entity added successfully")
        else:
            print("FAIL: Could not add test entity")
            return False
        
        # Get entity
        retrieved_entity = manager.get_entity("test_entity")
        if retrieved_entity and retrieved_entity.name == "Test Entity":
            print("PASS: Test entity retrieved successfully")
        else:
            print("FAIL: Could not retrieve test entity")
            return False
        
        # Delete test entity
        delete_success = manager.delete_entity("test_entity")
        if delete_success:
            print("PASS: Test entity deleted successfully")
        else:
            print("FAIL: Could not delete test entity")
            return False
        
        return True
    except Exception as e:
        print(f"FAIL: Entity operations test failed: {e}")
        return False

def main():
    """Run tests."""
    print("Testing Reporting Entities Module")
    print("=" * 40)
    
    test1 = test_imports()
    test2 = test_basic_functionality()
    test3 = test_entity_operations()
    
    if test1 and test2 and test3:
        print("=" * 40)
        print("ALL TESTS PASSED")
        return 0
    else:
        print("=" * 40)
        print("SOME TESTS FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())

