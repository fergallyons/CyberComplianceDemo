#!/usr/bin/env python3
"""
Reporting Entities Management System
Manages regulatory bodies, law enforcement agencies, and cyber insurance companies
for NIS2 compliance and cybersecurity incident reporting.
"""

import json
import os
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, List, Optional, Set
import streamlit as st


class EntityType(Enum):
    """Types of reporting entities."""
    REGULATORY_BODY = "Regulatory Body"
    LAW_ENFORCEMENT = "Law Enforcement"
    CYBER_INSURANCE = "Cyber Insurance"
    DATA_PROTECTION = "Data Protection Authority"
    FINANCIAL_REGULATOR = "Financial Regulator"
    SECTOR_SPECIFIC = "Sector-Specific Regulator"
    OTHER = "Other"


class Jurisdiction(Enum):
    """Geographic jurisdictions."""
    IRELAND = "Ireland"
    UK = "United Kingdom"
    BELGIUM = "Belgium"
    EU = "European Union"
    USA = "United States"
    INTERNATIONAL = "International"
    OTHER = "Other"


class ContactMethod(Enum):
    """Available contact methods."""
    EMAIL = "Email"
    PHONE = "Phone"
    WEB_FORM = "Web Form"
    PORTAL = "Online Portal"
    API = "API"
    POSTAL = "Postal Mail"
    OTHER = "Other"


@dataclass
class ContactInfo:
    """Contact information for a reporting entity."""
    method: ContactMethod
    value: str
    primary: bool = False
    notes: str = ""
    last_verified: Optional[str] = None


@dataclass
class ReportingRequirement:
    """Specific reporting requirements for an entity."""
    incident_type: str
    timeframe_hours: int
    required_fields: List[str]
    mandatory: bool = True
    notes: str = ""


@dataclass
class ReportingEntity:
    """A reporting entity (regulatory body, law enforcement, insurance, etc.)."""
    id: str
    name: str
    entity_type: EntityType
    jurisdiction: Jurisdiction
    description: str
    website: str = ""
    contacts: List[ContactInfo] = None
    reporting_requirements: List[ReportingRequirement] = None
    nis2_scope: bool = False
    sectors_covered: List[str] = None
    active: bool = True
    created_date: str = ""
    last_updated: str = ""
    notes: str = ""
    
    def __post_init__(self):
        if self.contacts is None:
            self.contacts = []
        if self.reporting_requirements is None:
            self.reporting_requirements = []
        if self.sectors_covered is None:
            self.sectors_covered = []
        if not self.created_date:
            self.created_date = datetime.now().isoformat()
        if not self.last_updated:
            self.last_updated = datetime.now().isoformat()


class ReportingEntitiesManager:
    """Manages reporting entities for cybersecurity incident reporting."""
    
    def __init__(self):
        """Initialize the reporting entities manager."""
        self.entities_file = "reporting_entities.json"
        self.entities: Dict[str, ReportingEntity] = {}
        
        # Try to load existing entities first
        self.load_entities()
        
        # If no entities were loaded, initialize with defaults
        if not self.entities:
            self._initialize_default_entities()
            self.save_entities()
    
    def _initialize_default_entities(self):
        """Initialize with a comprehensive list of default reporting entities."""
        default_entities = [
            # Regulatory Bodies
            ReportingEntity(
                id="ncsc_ireland",
                name="NCSC Ireland",
                entity_type=EntityType.REGULATORY_BODY,
                jurisdiction=Jurisdiction.IRELAND,
                description="National Cyber Security Centre Ireland - Primary cybersecurity regulator for Ireland",
                website="https://ncsc.gov.ie/",
                nis2_scope=True,
                sectors_covered=["ESSENTIAL", "IMPORTANT", "DIGITAL"],
                contacts=[
                    ContactInfo(ContactMethod.EMAIL, "incidents@ncsc.gov.ie", primary=True),
                    ContactInfo(ContactMethod.PHONE, "+353 1 631 2000"),
                    ContactInfo(ContactMethod.WEB_FORM, "https://ncsc.gov.ie/report-incident/")
                ],
                reporting_requirements=[
                    ReportingRequirement("Significant Incident", 24, ["incident_description", "impact_assessment", "containment_measures"]),
                    ReportingRequirement("Final Report", 72, ["root_cause", "remediation_actions", "lessons_learned"])
                ]
            ),
            
            ReportingEntity(
                id="ncsc_uk",
                name="NCSC UK",
                entity_type=EntityType.REGULATORY_BODY,
                jurisdiction=Jurisdiction.UK,
                description="National Cyber Security Centre United Kingdom",
                website="https://www.ncsc.gov.uk/",
                nis2_scope=True,
                sectors_covered=["ESSENTIAL", "IMPORTANT"],
                contacts=[
                    ContactInfo(ContactMethod.EMAIL, "incidents@ncsc.gov.uk", primary=True),
                    ContactInfo(ContactMethod.WEB_FORM, "https://www.ncsc.gov.uk/report-an-incident")
                ],
                reporting_requirements=[
                    ReportingRequirement("Significant Incident", 24, ["incident_description", "impact_assessment"])
                ]
            ),
            
            ReportingEntity(
                id="ncsc_belgium",
                name="CCB Belgium",
                entity_type=EntityType.REGULATORY_BODY,
                jurisdiction=Jurisdiction.BELGIUM,
                description="Centre for Cybersecurity Belgium",
                website="https://ccb.belgium.be/",
                nis2_scope=True,
                sectors_covered=["ESSENTIAL", "IMPORTANT"],
                contacts=[
                    ContactInfo(ContactMethod.EMAIL, "incidents@ccb.belgium.be", primary=True),
                    ContactInfo(ContactMethod.PHONE, "+32 2 790 33 00")
                ],
                reporting_requirements=[
                    ReportingRequirement("Significant Incident", 24, ["incident_description", "impact_assessment"])
                ]
            ),
            
            # Law Enforcement
            ReportingEntity(
                id="garda_siochana",
                name="Garda Síochána",
                entity_type=EntityType.LAW_ENFORCEMENT,
                jurisdiction=Jurisdiction.IRELAND,
                description="Irish Police Force - Cybercrime Unit",
                website="https://www.garda.ie/",
                nis2_scope=False,
                sectors_covered=["ALL"],
                contacts=[
                    ContactInfo(ContactMethod.EMAIL, "cybercrime@garda.ie", primary=True),
                    ContactInfo(ContactMethod.PHONE, "1800 666 111"),
                    ContactInfo(ContactMethod.WEB_FORM, "https://www.garda.ie/en/contact-us/online-reporting/")
                ],
                reporting_requirements=[
                    ReportingRequirement("Cybercrime", 24, ["crime_description", "evidence_preservation", "victim_details"])
                ]
            ),
            
            ReportingEntity(
                id="fbi_cyber",
                name="FBI Cyber Division",
                entity_type=EntityType.LAW_ENFORCEMENT,
                jurisdiction=Jurisdiction.USA,
                description="Federal Bureau of Investigation Cyber Division",
                website="https://www.fbi.gov/investigate/cyber",
                nis2_scope=False,
                sectors_covered=["ALL"],
                contacts=[
                    ContactInfo(ContactMethod.EMAIL, "cyber@fbi.gov", primary=True),
                    ContactInfo(ContactMethod.WEB_FORM, "https://www.ic3.gov/"),
                    ContactInfo(ContactMethod.PHONE, "1-800-CALL-FBI")
                ],
                reporting_requirements=[
                    ReportingRequirement("Cyber Incident", 24, ["incident_description", "financial_loss", "victim_details"])
                ]
            ),
            
            # EU Agencies
            ReportingEntity(
                id="enisa",
                name="ENISA",
                entity_type=EntityType.REGULATORY_BODY,
                jurisdiction=Jurisdiction.EU,
                description="European Union Agency for Cybersecurity",
                website="https://www.enisa.europa.eu/",
                nis2_scope=True,
                sectors_covered=["ESSENTIAL", "IMPORTANT"],
                contacts=[
                    ContactInfo(ContactMethod.EMAIL, "incidents@enisa.europa.eu", primary=True),
                    ContactInfo(ContactMethod.WEB_FORM, "https://www.enisa.europa.eu/report-incident")
                ],
                reporting_requirements=[
                    ReportingRequirement("Cross-border Incident", 24, ["incident_description", "affected_countries", "coordination_needs"])
                ]
            ),
            
            ReportingEntity(
                id="europol_ec3",
                name="Europol EC3",
                entity_type=EntityType.LAW_ENFORCEMENT,
                jurisdiction=Jurisdiction.EU,
                description="European Cybercrime Centre",
                website="https://www.europol.europa.eu/ec3",
                nis2_scope=False,
                sectors_covered=["ALL"],
                contacts=[
                    ContactInfo(ContactMethod.EMAIL, "ec3@europol.europa.eu", primary=True),
                    ContactInfo(ContactMethod.WEB_FORM, "https://www.europol.europa.eu/report-cybercrime")
                ],
                reporting_requirements=[
                    ReportingRequirement("Cross-border Cybercrime", 24, ["crime_description", "affected_countries", "evidence"])
                ]
            ),
            
            # Data Protection Authorities
            ReportingEntity(
                id="dpc_ireland",
                name="Data Protection Commission Ireland",
                entity_type=EntityType.DATA_PROTECTION,
                jurisdiction=Jurisdiction.IRELAND,
                description="Irish Data Protection Authority",
                website="https://www.dataprotection.ie/",
                nis2_scope=False,
                sectors_covered=["ALL"],
                contacts=[
                    ContactInfo(ContactMethod.EMAIL, "info@dataprotection.ie", primary=True),
                    ContactInfo(ContactMethod.PHONE, "+353 57 868 4800")
                ],
                reporting_requirements=[
                    ReportingRequirement("Data Breach", 72, ["breach_description", "personal_data_affected", "risk_assessment"])
                ]
            ),
            
            # Cyber Insurance Companies
            ReportingEntity(
                id="aig_cyber",
                name="AIG Cyber Insurance",
                entity_type=EntityType.CYBER_INSURANCE,
                jurisdiction=Jurisdiction.INTERNATIONAL,
                description="AIG CyberEdge Cyber Liability Insurance",
                website="https://www.aig.com/cyber-insurance",
                nis2_scope=False,
                sectors_covered=["ALL"],
                contacts=[
                    ContactInfo(ContactMethod.EMAIL, "cyberclaims@aig.com", primary=True),
                    ContactInfo(ContactMethod.PHONE, "1-800-528-3662"),
                    ContactInfo(ContactMethod.PORTAL, "https://www.aig.com/claims")
                ],
                reporting_requirements=[
                    ReportingRequirement("Cyber Incident", 24, ["incident_description", "policy_number", "financial_impact"])
                ]
            ),
            
            ReportingEntity(
                id="chubb_cyber",
                name="Chubb Cyber Insurance",
                entity_type=EntityType.CYBER_INSURANCE,
                jurisdiction=Jurisdiction.INTERNATIONAL,
                description="Chubb Cyber Enterprise Risk Management",
                website="https://www.chubb.com/cyber",
                nis2_scope=False,
                sectors_covered=["ALL"],
                contacts=[
                    ContactInfo(ContactMethod.EMAIL, "cyberclaims@chubb.com", primary=True),
                    ContactInfo(ContactMethod.PHONE, "1-800-252-4670")
                ],
                reporting_requirements=[
                    ReportingRequirement("Cyber Incident", 24, ["incident_description", "policy_number", "damage_assessment"])
                ]
            ),
            
            ReportingEntity(
                id="beazley_cyber",
                name="Beazley Cyber Insurance",
                entity_type=EntityType.CYBER_INSURANCE,
                jurisdiction=Jurisdiction.INTERNATIONAL,
                description="Beazley Breach Response Cyber Insurance",
                website="https://www.beazley.com/cyber",
                nis2_scope=False,
                sectors_covered=["ALL"],
                contacts=[
                    ContactInfo(ContactMethod.EMAIL, "breach@beazley.com", primary=True),
                    ContactInfo(ContactMethod.PHONE, "1-800-409-9511"),
                    ContactInfo(ContactMethod.PORTAL, "https://www.beazley.com/breach-response")
                ],
                reporting_requirements=[
                    ReportingRequirement("Data Breach", 24, ["breach_description", "policy_number", "affected_records"])
                ]
            )
        ]
        
        for entity in default_entities:
            self.entities[entity.id] = entity
        
        self.save_entities()
    
    def load_entities(self):
        """Load entities from JSON file."""
        try:
            if os.path.exists(self.entities_file):
                with open(self.entities_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.entities = {}
                    for entity_id, entity_data in data.items():
                        try:
                            # Convert back to dataclass objects
                            contacts = []
                            for contact_data in entity_data.get('contacts', []):
                                # Handle both string and enum values for method
                                method_value = contact_data['method']
                                if isinstance(method_value, str):
                                    method_enum = ContactMethod(method_value)
                                else:
                                    method_enum = method_value
                                
                                contact = ContactInfo(
                                    method=method_enum,
                                    value=contact_data['value'],
                                    primary=contact_data.get('primary', False),
                                    notes=contact_data.get('notes', ''),
                                    last_verified=contact_data.get('last_verified')
                                )
                                contacts.append(contact)
                            
                            requirements = []
                            for req_data in entity_data.get('reporting_requirements', []):
                                req = ReportingRequirement(
                                    incident_type=req_data['incident_type'],
                                    timeframe_hours=req_data['timeframe_hours'],
                                    required_fields=req_data['required_fields'],
                                    mandatory=req_data.get('mandatory', True),
                                    notes=req_data.get('notes', '')
                                )
                                requirements.append(req)
                            
                            # Handle both string and enum values for entity_type and jurisdiction
                            entity_type_value = entity_data['entity_type']
                            if isinstance(entity_type_value, str):
                                entity_type_enum = EntityType(entity_type_value)
                            else:
                                entity_type_enum = entity_type_value
                            
                            jurisdiction_value = entity_data['jurisdiction']
                            if isinstance(jurisdiction_value, str):
                                jurisdiction_enum = Jurisdiction(jurisdiction_value)
                            else:
                                jurisdiction_enum = jurisdiction_value
                            
                            entity = ReportingEntity(
                                id=entity_data['id'],
                                name=entity_data['name'],
                                entity_type=entity_type_enum,
                                jurisdiction=jurisdiction_enum,
                                description=entity_data['description'],
                                website=entity_data.get('website', ''),
                                contacts=contacts,
                                reporting_requirements=requirements,
                                nis2_scope=entity_data.get('nis2_scope', False),
                                sectors_covered=entity_data.get('sectors_covered', []),
                                active=entity_data.get('active', True),
                                created_date=entity_data.get('created_date', ''),
                                last_updated=entity_data.get('last_updated', ''),
                                notes=entity_data.get('notes', '')
                            )
                            self.entities[entity.id] = entity
                        except Exception as entity_error:
                            st.warning(f"Error loading entity '{entity_id}': {entity_error}. Skipping...")
                            continue
        except Exception as e:
            st.error(f"Error loading reporting entities: {e}")
            # If loading fails, initialize with default entities
            self.entities = {}
            self._initialize_default_entities()
            self.save_entities()
    
    def save_entities(self):
        """Save entities to JSON file."""
        try:
            data = {}
            for entity_id, entity in self.entities.items():
                # Convert dataclass to dict and handle Enum serialization
                entity_dict = asdict(entity)
                # Convert Enum values to strings for JSON serialization
                entity_dict['entity_type'] = entity.entity_type.value
                entity_dict['jurisdiction'] = entity.jurisdiction.value
                
                # Convert contact method enums to strings
                for contact in entity_dict['contacts']:
                    contact['method'] = contact['method'].value
                
                data[entity_id] = entity_dict
            
            with open(self.entities_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            st.error(f"Error saving reporting entities: {e}")
    
    def add_entity(self, entity: ReportingEntity) -> bool:
        """Add a new reporting entity."""
        try:
            if entity.id in self.entities:
                st.error(f"Entity with ID '{entity.id}' already exists.")
                return False
            
            entity.created_date = datetime.now().isoformat()
            entity.last_updated = datetime.now().isoformat()
            self.entities[entity.id] = entity
            self.save_entities()
            st.success(f"Entity '{entity.name}' added successfully.")
            return True
        except Exception as e:
            st.error(f"Error adding entity: {e}")
            return False
    
    def update_entity(self, entity_id: str, updated_entity: ReportingEntity) -> bool:
        """Update an existing reporting entity."""
        try:
            if entity_id not in self.entities:
                st.error(f"Entity with ID '{entity_id}' not found.")
                return False
            
            updated_entity.last_updated = datetime.now().isoformat()
            updated_entity.created_date = self.entities[entity_id].created_date
            self.entities[entity_id] = updated_entity
            self.save_entities()
            st.success(f"Entity '{updated_entity.name}' updated successfully.")
            return True
        except Exception as e:
            st.error(f"Error updating entity: {e}")
            return False
    
    def delete_entity(self, entity_id: str) -> bool:
        """Delete a reporting entity."""
        try:
            if entity_id not in self.entities:
                st.error(f"Entity with ID '{entity_id}' not found.")
                return False
            
            entity_name = self.entities[entity_id].name
            del self.entities[entity_id]
            self.save_entities()
            st.success(f"Entity '{entity_name}' deleted successfully.")
            return True
        except Exception as e:
            st.error(f"Error deleting entity: {e}")
            return False
    
    def get_entity(self, entity_id: str) -> Optional[ReportingEntity]:
        """Get a specific entity by ID."""
        return self.entities.get(entity_id)
    
    def get_entities_by_type(self, entity_type: EntityType) -> List[ReportingEntity]:
        """Get entities filtered by type."""
        return [entity for entity in self.entities.values() if entity.entity_type == entity_type]
    
    def get_entities_by_jurisdiction(self, jurisdiction: Jurisdiction) -> List[ReportingEntity]:
        """Get entities filtered by jurisdiction."""
        return [entity for entity in self.entities.values() if entity.jurisdiction == jurisdiction]
    
    def get_nis2_entities(self) -> List[ReportingEntity]:
        """Get entities that are in scope for NIS2."""
        return [entity for entity in self.entities.values() if entity.nis2_scope]
    
    def search_entities(self, query: str) -> List[ReportingEntity]:
        """Search entities by name, description, or notes."""
        query = query.lower()
        results = []
        for entity in self.entities.values():
            if (query in entity.name.lower() or 
                query in entity.description.lower() or 
                query in entity.notes.lower()):
                results.append(entity)
        return results
    
    def get_entity_types(self) -> List[EntityType]:
        """Get all available entity types."""
        return list(EntityType)
    
    def get_jurisdictions(self) -> List[Jurisdiction]:
        """Get all available jurisdictions."""
        return list(Jurisdiction)
    
    def get_contact_methods(self) -> List[ContactMethod]:
        """Get all available contact methods."""
        return list(ContactMethod)
    
    def reset_to_defaults(self):
        """Reset entities to default values."""
        try:
            self.entities = {}
            self._initialize_default_entities()
            self.save_entities()
            st.success("Entities reset to defaults successfully.")
        except Exception as e:
            st.error(f"Error resetting entities: {e}")
    
    def get_entity_count(self) -> int:
        """Get the total number of entities."""
        return len(self.entities)
    
    def get_active_entity_count(self) -> int:
        """Get the number of active entities."""
        return len([e for e in self.entities.values() if e.active])


class ReportingEntitiesInterface:
    """Streamlit interface for managing reporting entities."""
    
    def __init__(self):
        """Initialize the interface."""
        self.manager = ReportingEntitiesManager()
    
    def display_main_interface(self):
        """Display the main reporting entities interface."""
        st.header("🏛️ Reporting Entities Management")
        st.markdown("""
        Manage regulatory bodies, law enforcement agencies, and cyber insurance companies
        for NIS2 compliance and cybersecurity incident reporting.
        """)
        
        # Display entity statistics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Entities", self.manager.get_entity_count())
        with col2:
            st.metric("Active Entities", self.manager.get_active_entity_count())
        with col3:
            st.metric("NIS2 Scope", len(self.manager.get_nis2_entities()))
        with col4:
            if st.button("🔄 Reset to Defaults", key="entities_reset_defaults", help="Reset all entities to default values"):
                self.manager.reset_to_defaults()
                st.rerun()
        
        # Tabs for different functions
        tab1, tab2, tab3, tab4 = st.tabs([
            "📋 View Entities", 
            "➕ Add Entity", 
            "✏️ Edit Entity", 
            "🗑️ Delete Entity"
        ])
        
        with tab1:
            self.display_entities_view()
        
        with tab2:
            self.display_add_entity_form()
        
        with tab3:
            self.display_edit_entity_form()
        
        with tab4:
            self.display_delete_entity_form()
    
    def display_entities_view(self):
        """Display a view of all entities with filtering options."""
        st.subheader("📋 View Reporting Entities")
        
        # Filtering options
        col1, col2, col3 = st.columns(3)
        
        with col1:
            entity_type_filter = st.selectbox(
                "Filter by Type",
                ["All Types"] + [et.value for et in self.manager.get_entity_types()],
                index=0
            )
        
        with col2:
            jurisdiction_filter = st.selectbox(
                "Filter by Jurisdiction",
                ["All Jurisdictions"] + [j.value for j in self.manager.get_jurisdictions()],
                index=0
            )
        
        with col3:
            search_query = st.text_input("Search entities", placeholder="Search by name, description...")
        
        # Apply filters
        filtered_entities = list(self.manager.entities.values())
        
        if entity_type_filter != "All Types":
            entity_type = EntityType(entity_type_filter)
            filtered_entities = [e for e in filtered_entities if e.entity_type == entity_type]
        
        if jurisdiction_filter != "All Jurisdictions":
            jurisdiction = Jurisdiction(jurisdiction_filter)
            filtered_entities = [e for e in filtered_entities if e.jurisdiction == jurisdiction]
        
        if search_query:
            filtered_entities = self.manager.search_entities(search_query)
        
        # Display entities
        if filtered_entities:
            st.write(f"**Found {len(filtered_entities)} entities:**")
            
            for entity in filtered_entities:
                with st.expander(f"🏛️ {entity.name} ({entity.entity_type.value})"):
                    self.display_entity_details(entity)
        else:
            st.info("No entities found matching the current filters.")
    
    def display_entity_details(self, entity: ReportingEntity):
        """Display detailed information about a specific entity."""
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown(f"**Description:** {entity.description}")
            st.markdown(f"**Jurisdiction:** {entity.jurisdiction.value}")
            st.markdown(f"**Website:** [{entity.website}]({entity.website})" if entity.website else "**Website:** Not provided")
            st.markdown(f"**NIS2 Scope:** {'✅ Yes' if entity.nis2_scope else '❌ No'}")
            
            if entity.sectors_covered:
                st.markdown(f"**Sectors Covered:** {', '.join(entity.sectors_covered)}")
            
            if entity.notes:
                st.markdown(f"**Notes:** {entity.notes}")
        
        with col2:
            st.markdown(f"**Status:** {'🟢 Active' if entity.active else '🔴 Inactive'}")
            st.markdown(f"**Created:** {entity.created_date[:10]}")
            st.markdown(f"**Updated:** {entity.last_updated[:10]}")
        
        # Contacts
        if entity.contacts:
            st.subheader("📞 Contact Information")
            for contact in entity.contacts:
                primary_indicator = "⭐" if contact.primary else ""
                st.markdown(f"{primary_indicator} **{contact.method.value}:** {contact.value}")
                if contact.notes:
                    st.markdown(f"  *{contact.notes}*")
                if contact.last_verified:
                    st.markdown(f"  *Last verified: {contact.last_verified[:10]}*")
        
        # Reporting Requirements
        if entity.reporting_requirements:
            st.subheader("📋 Reporting Requirements")
            for req in entity.reporting_requirements:
                mandatory_indicator = "🔴" if req.mandatory else "🟡"
                st.markdown(f"{mandatory_indicator} **{req.incident_type}** - {req.timeframe_hours}h")
                st.markdown(f"  Required fields: {', '.join(req.required_fields)}")
                if req.notes:
                    st.markdown(f"  *{req.notes}*")
    
    def display_add_entity_form(self):
        """Display form for adding a new entity."""
        st.subheader("➕ Add New Reporting Entity")
        
        with st.form("add_entity_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                entity_id = st.text_input("Entity ID *", placeholder="e.g., ncsc_ireland")
                name = st.text_input("Entity Name *", placeholder="e.g., NCSC Ireland")
                entity_type = st.selectbox("Entity Type *", [et.value for et in self.manager.get_entity_types()])
                jurisdiction = st.selectbox("Jurisdiction *", [j.value for j in self.manager.get_jurisdictions()])
                website = st.text_input("Website", placeholder="https://example.com")
            
            with col2:
                nis2_scope = st.checkbox("In Scope for NIS2")
                active = st.checkbox("Active", value=True)
                sectors_covered = st.multiselect(
                    "Sectors Covered",
                    ["ESSENTIAL", "IMPORTANT", "DIGITAL", "FINANCIAL", "HEALTHCARE", "TRANSPORT", "ENERGY", "WATER", "OTHER"]
                )
            
            description = st.text_area("Description *", placeholder="Brief description of the entity and its role...")
            notes = st.text_area("Additional Notes", placeholder="Any additional information...")
            
            submitted = st.form_submit_button("➕ Add Entity", type="primary")
            
            if submitted:
                if not entity_id or not name or not description:
                    st.error("Please fill in all required fields.")
                    return
                
                # Create entity
                entity = ReportingEntity(
                    id=entity_id,
                    name=name,
                    entity_type=EntityType(entity_type),
                    jurisdiction=Jurisdiction(jurisdiction),
                    description=description,
                    website=website,
                    nis2_scope=nis2_scope,
                    sectors_covered=sectors_covered,
                    active=active,
                    notes=notes
                )
                
                if self.manager.add_entity(entity):
                    st.rerun()
    
    def display_edit_entity_form(self):
        """Display form for editing an existing entity."""
        st.subheader("✏️ Edit Reporting Entity")
        
        # Entity selection
        entity_options = {f"{e.name} ({e.entity_type.value})": e.id for e in self.manager.entities.values()}
        
        if not entity_options:
            st.info("No entities available to edit.")
            return
        
        selected_entity_key = st.selectbox("Select Entity to Edit", list(entity_options.keys()))
        selected_entity_id = entity_options[selected_entity_key]
        entity = self.manager.get_entity(selected_entity_id)
        
        if not entity:
            st.error("Selected entity not found.")
            return
        
        with st.form("edit_entity_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                name = st.text_input("Entity Name *", value=entity.name)
                entity_type = st.selectbox("Entity Type *", [et.value for et in self.manager.get_entity_types()], 
                                         index=[et.value for et in self.manager.get_entity_types()].index(entity.entity_type.value))
                jurisdiction = st.selectbox("Jurisdiction *", [j.value for j in self.manager.get_jurisdictions()],
                                          index=[j.value for j in self.manager.get_jurisdictions()].index(entity.jurisdiction.value))
                website = st.text_input("Website", value=entity.website)
            
            with col2:
                nis2_scope = st.checkbox("In Scope for NIS2", value=entity.nis2_scope)
                active = st.checkbox("Active", value=entity.active)
                sectors_covered = st.multiselect(
                    "Sectors Covered",
                    ["ESSENTIAL", "IMPORTANT", "DIGITAL", "FINANCIAL", "HEALTHCARE", "TRANSPORT", "ENERGY", "WATER", "OTHER"],
                    default=entity.sectors_covered
                )
            
            description = st.text_area("Description *", value=entity.description)
            notes = st.text_area("Additional Notes", value=entity.notes)
            
            submitted = st.form_submit_button("💾 Update Entity", type="primary")
            
            if submitted:
                if not name or not description:
                    st.error("Please fill in all required fields.")
                    return
                
                # Update entity
                updated_entity = ReportingEntity(
                    id=entity.id,
                    name=name,
                    entity_type=EntityType(entity_type),
                    jurisdiction=Jurisdiction(jurisdiction),
                    description=description,
                    website=website,
                    nis2_scope=nis2_scope,
                    sectors_covered=sectors_covered,
                    active=active,
                    notes=notes
                )
                
                if self.manager.update_entity(entity.id, updated_entity):
                    st.rerun()
    
    def display_delete_entity_form(self):
        """Display form for deleting an entity."""
        st.subheader("🗑️ Delete Reporting Entity")
        
        # Entity selection
        entity_options = {f"{e.name} ({e.entity_type.value})": e.id for e in self.manager.entities.values()}
        
        if not entity_options:
            st.info("No entities available to delete.")
            return
        
        selected_entity_key = st.selectbox("Select Entity to Delete", list(entity_options.keys()))
        selected_entity_id = entity_options[selected_entity_key]
        entity = self.manager.get_entity(selected_entity_id)
        
        if not entity:
            st.error("Selected entity not found.")
            return
        
        st.warning(f"⚠️ You are about to delete: **{entity.name}**")
        st.info(f"**Type:** {entity.entity_type.value}")
        st.info(f"**Jurisdiction:** {entity.jurisdiction.value}")
        st.info(f"**Description:** {entity.description}")
        
        if st.button("🗑️ Delete Entity", key="entities_delete_entity", type="secondary"):
            if self.manager.delete_entity(selected_entity_id):
                st.rerun()


if __name__ == "__main__":
    # Test the interface
    interface = ReportingEntitiesInterface()
    interface.display_main_interface()
