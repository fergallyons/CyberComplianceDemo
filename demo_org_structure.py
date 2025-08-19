#!/usr/bin/env python3
"""
Demonstration script for the new organizational hierarchy:
- Cohesive (platform) - manages everything
- Partner organizations (MSPs) - can manage multiple client organizations
- Client organizations - assigned to partners or directly to Cohesive
"""

from auth_system import AuthenticationSystem, UserRole

def demo_organization_structure():
    """Demonstrate the new organizational hierarchy."""
    print("🏢 Cohesive Cybersecurity Platform - Organization Structure Demo\n")
    
    # Initialize the system
    auth = AuthenticationSystem()
    
    print("1️⃣ Creating Partner Organization (MSP): USafety")
    usafety_id = auth.create_organization(
        name="USafety",
        domain="usafety.ie",
        industry="Managed Security Services",
        country="Ireland",
        compliance_framework="NIS2",
        organization_type="partner",
        parent_organization_id=None  # Direct to Cohesive
    )
    print(f"   ✅ USafety created with ID: {usafety_id}")
    
    print("\n2️⃣ Creating Client Organization: CRH")
    crh_id = auth.create_organization(
        name="CRH",
        domain="crh.com",
        industry="Construction",
        country="Ireland",
        compliance_framework="NIS2",
        organization_type="client",
        parent_organization_id=usafety_id  # Managed by USafety
    )
    print(f"   ✅ CRH created with ID: {crh_id}")
    
    print("\n3️⃣ Creating Another Client Organization: Bank of Ireland")
    boi_id = auth.create_organization(
        name="Bank of Ireland",
        domain="boi.com",
        industry="Financial Services",
        country="Ireland",
        compliance_framework="NIS2",
        organization_type="client",
        parent_organization_id=usafety_id  # Also managed by USafety
    )
    print(f"   ✅ Bank of Ireland created with ID: {boi_id}")
    
    print("\n4️⃣ Creating Direct Client Organization: Aer Lingus")
    aerlingus_id = auth.create_organization(
        name="Aer Lingus",
        domain="aerlingus.com",
        industry="Transportation",
        country="Ireland",
        compliance_framework="NIS2",
        organization_type="client",
        parent_organization_id=None  # Direct to Cohesive
    )
    print(f"   ✅ Aer Lingus created with ID: {aerlingus_id}")
    
    print("\n5️⃣ Creating Users for Different Organizations")
    
    # Create USafety partner user
    usafety_user_id = auth.create_user(
        username="usafety_admin",
        email="admin@usafety.ie",
        password="securepass123",
        organization_id=usafety_id,
        role=UserRole.PARTNER
    )
    print(f"   ✅ USafety partner user created: {usafety_user_id}")
    
    # Create CRH reporter user
    crh_user_id = auth.create_user(
        username="crh_reporter",
        email="security@crh.com",
        password="securepass123",
        organization_id=crh_id,
        role=UserRole.REPORTER
    )
    print(f"   ✅ CRH reporter user created: {crh_user_id}")
    
    # Create Aer Lingus reader user
    aerlingus_user_id = auth.create_user(
        username="aerlingus_reader",
        email="security@aerlingus.com",
        password="securepass123",
        organization_id=aerlingus_id,
        role=UserRole.READER
    )
    print(f"   ✅ Aer Lingus reader user created: {aerlingus_user_id}")
    
    print("\n6️⃣ Testing Organization Visibility by Role")
    
    # Test admin visibility (should see all)
    admin_orgs = auth.get_user_organizations(1)  # admin user
    print(f"\n👑 Admin (Cohesive) can see {len(admin_orgs)} organizations:")
    for org in admin_orgs:
        parent = "Cohesive" if org.parent_organization_id is None else f"Parent ID: {org.parent_organization_id}"
        print(f"   • {org.name} ({org.organization_type}) - {parent}")
    
    # Test partner visibility (should see own org + client orgs)
    partner_orgs = auth.get_user_organizations(usafety_user_id)
    print(f"\n🤝 Partner (USafety) can see {len(partner_orgs)} organizations:")
    for org in partner_orgs:
        parent = "Cohesive" if org.parent_organization_id is None else f"Parent ID: {org.parent_organization_id}"
        print(f"   • {org.name} ({org.organization_type}) - {parent}")
    
    # Test client user visibility (should see only own org)
    client_orgs = auth.get_user_organizations(crh_user_id)
    print(f"\n📋 Client (CRH) can see {len(client_orgs)} organizations:")
    for org in client_orgs:
        parent = "Cohesive" if org.parent_organization_id is None else f"Parent ID: {org.parent_organization_id}"
        print(f"   • {org.name} ({org.organization_type}) - {parent}")
    
    print("\n✅ Organization structure demonstration completed!")
    print("\n📊 Summary:")
    print("   • Cohesive (Platform) - manages everything")
    print("   • USafety (Partner/MSP) - manages CRH and Bank of Ireland")
    print("   • CRH, Bank of Ireland, Aer Lingus (Clients) - managed by partners or Cohesive")

if __name__ == "__main__":
    demo_organization_structure()
