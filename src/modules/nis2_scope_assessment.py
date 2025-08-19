"""
NIS2 Scope Assessment Module
Helps organizations determine if they are in scope for NIS2 Article 23 incident reporting requirements.
Based on NCSC Ireland's scope assessment tool and EU NIS2 Directive criteria.
"""

import streamlit as st
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import os

class SectorType(Enum):
    """NIS2 sector types."""
    ESSENTIAL = "essential"
    IMPORTANT = "important"
    DIGITAL = "digital"
    NOT_IN_SCOPE = "not_in_scope"

class OrganizationSize(Enum):
    """Organization size categories."""
    MICRO = "micro"  # < 10 employees
    SMALL = "small"  # 10-49 employees
    MEDIUM = "medium"  # 50-249 employees
    LARGE = "large"  # 250+ employees

@dataclass
class ScopeAssessment:
    """Result of NIS2 scope assessment."""
    organization_id: str  # Add organization ID for proper association
    organization_name: str
    assessment_date: datetime
    sector_type: SectorType
    organization_size: OrganizationSize
    in_scope: bool
    reporting_obligations: List[str]
    assessment_score: int
    risk_factors: List[str]
    recommendations: List[str]
    next_steps: List[str]
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "organization_id": self.organization_id,
            "organization_name": self.organization_name,
            "assessment_date": self.assessment_date.isoformat(),
            "sector_type": self.sector_type.value,
            "organization_size": self.organization_size.value,
            "in_scope": self.in_scope,
            "reporting_obligations": self.reporting_obligations,
            "assessment_score": self.assessment_score,
            "risk_factors": self.risk_factors,
            "recommendations": self.recommendations,
            "next_steps": self.next_steps
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ScopeAssessment':
        """Create from dictionary for JSON deserialization."""
        return cls(
            organization_id=data["organization_id"],
            organization_name=data["organization_name"],
            assessment_date=datetime.fromisoformat(data["assessment_date"]),
            sector_type=SectorType(data["sector_type"]),
            organization_size=OrganizationSize(data["organization_size"]),
            in_scope=data["in_scope"],
            reporting_obligations=data["reporting_obligations"],
            assessment_score=data["assessment_score"],
            risk_factors=data["risk_factors"],
            recommendations=data["recommendations"],
            next_steps=data["next_steps"]
        )

class NIS2ScopeAssessment:
    """NIS2 scope assessment tool for Article 23 compliance."""
    
    def __init__(self):
        """Initialize the scope assessment tool."""
        self.essential_sectors = {
            "Energy": [
                "Electricity", "Oil", "Gas", "District Heating", "Hydrogen"
            ],
            "Transport": [
                "Air", "Rail", "Water", "Road", "Urban Mobility"
            ],
            "Banking": [
                "Credit Institutions", "Financial Market Infrastructure"
            ],
            "Financial Market Infrastructure": [
                "Trading Venues", "Central Counterparties", "Central Securities Depositories"
            ],
            "Digital Infrastructure": [
                "Internet Exchange Points", "DNS Service Providers", "Top-Level Domain Registries"
            ],
            "ICT Service Management": [
                "B2B Cloud Computing", "Data Center Services", "Content Delivery Networks"
            ],
            "Public Electronic Communications Networks": [
                "Telecommunications", "Internet Access", "Voice Services"
            ],
            "Wastewater": [
                "Wastewater Collection", "Wastewater Treatment", "Wastewater Disposal"
            ],
            "Waste Management": [
                "Hazardous Waste", "Medical Waste", "Electronic Waste"
            ],
            "Manufacturing": [
                "Medical Devices", "In Vitro Diagnostics", "Pharmaceuticals"
            ],
            "Digital Providers": [
                "Online Marketplaces", "Online Search Engines", "Social Networking Platforms"
            ]
        }
        
        self.important_sectors = {
            "Postal and Courier Services": [
                "Postal Services", "Courier Services", "Express Delivery"
            ],
            "Waste Management": [
                "Non-hazardous Waste", "Recycling Services"
            ],
            "Manufacturing": [
                "Chemicals", "Food", "Beverages", "Medical Products"
            ],
            "Digital Providers": [
                "Content Delivery Networks", "Data Analytics", "AI Services"
            ]
        }
        
        self.digital_services = [
            "Online Marketplaces",
            "Online Search Engines", 
            "Social Networking Platforms",
            "Cloud Computing Services",
            "Data Center Services",
            "Content Delivery Networks",
            "Trust Services",
            "IoT Services"
        ]
        
        self.risk_factors = [
            "Critical Infrastructure Dependency",
            "Supply Chain Criticality",
            "Geographic Concentration",
            "Market Dominance",
            "Cross-border Services",
            "Essential Service Provision",
            "Data Processing Volume",
            "User Base Size"
        ]
        
        # Store assessments by organization ID
        self.assessments: Dict[str, ScopeAssessment] = {}
        self.assessments_file = "scope_assessments.json"
        self.load_assessments()  # Load existing assessments on startup
    
    def display_main_interface(self, organization_id: str = None):
        """Display the main NIS2 scope assessment interface."""
        st.header("🔍 NIS2 Scope Assessment Tool")
        
        # Check if we have form data to display results
        if 'scope_form_data' in st.session_state:
            form_data = st.session_state.scope_form_data
            
            # Perform the assessment with stored data
            assessment = self.perform_scope_assessment(
                form_data['org_id'], form_data['org_name'], form_data['org_size'], form_data['sector_category'],
                form_data['sector'], form_data['subsector'], form_data['risk_scores'],
                form_data['has_critical_infrastructure'], form_data['has_supply_chain_role'],
                form_data['cross_border_operations'], form_data['data_processing_volume'],
                form_data['user_base_size']
            )
            
            # Display results
            self._display_assessment_results(assessment)
            
            # Clear the form data
            del st.session_state.scope_form_data
            
            # Success message and navigation
            st.success("🎉 **Scope Assessment Completed Successfully!**")
            st.info("💡 **Tip**: The sidebar has been updated with your organization's NIS2 scope information.")
            
            # Set flag to trigger sidebar refresh
            st.session_state.scope_assessment_completed = True
            st.session_state.last_assessment_time = datetime.now().isoformat()
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔄 Start New Assessment", key="scope_start_new", use_container_width=True):
                    st.rerun()
            
            with col2:
                if st.button("🏠 Return to Main Page", key="scope_return_main", use_container_width=True, type="primary"):
                    # Clear any session state and return to main
                    if 'scope_form_data' in st.session_state:
                        del st.session_state.scope_form_data
                    st.switch_page("cybersecurity_agent.py")
            
            return
        
        # Assessment form
        with st.form("scope_assessment_form", clear_on_submit=False):
            st.subheader("🏢 Organization Information")
            
            # Organization information (read-only from current context)
            col1, col2 = st.columns(2)
            with col1:
                st.info(f"**Organization:** {st.session_state.get('current_organization_name', 'Unknown')}")
                st.info(f"**Organization ID:** {st.session_state.get('current_organization_id', 'Unknown')}")
            
            with col2:
                st.info(f"**Current Context:** {st.session_state.get('current_organization_name', 'Unknown')}")
                st.info(f"**Assessment Date:** {datetime.now().strftime('%Y-%m-%d')}")
            
            st.markdown("---")
            st.subheader("📊 Organization Characteristics")
            
            # Organization size
            org_size = st.selectbox(
                "Organization Size *",
                options=[
                    ("micro", "< 10 employees"),
                    ("small", "10-49 employees"),
                    ("medium", "50-249 employees"),
                    ("large", "250+ employees")
                ],
                format_func=lambda x: x[1]
            )
            
            st.subheader("🏭 Sector Classification")
            
            # Sector selection
            sector_category = st.selectbox(
                "Primary Sector Category *",
                ["", "Essential", "Important", "Digital Services", "Other"]
            )
            
            # Initialize variables to prevent UnboundLocalError
            sector = ""
            subsector = ""
            risk_scores = {}
            has_critical_infrastructure = False
            has_supply_chain_role = False
            cross_border_operations = False
            data_processing_volume = "Low"
            user_base_size = "< 1K"
            
            if sector_category == "Essential":
                sector = st.selectbox(
                    "Essential Sector *",
                    options=[""] + list(self.essential_sectors.keys())
                )
                if sector:
                    subsector = st.selectbox(
                        "Subsector",
                        options=[""] + self.essential_sectors[sector]
                    )
            
            elif sector_category == "Important":
                sector = st.selectbox(
                    "Important Sector *",
                    options=[""] + list(self.important_sectors.keys())
                )
                if sector:
                    subsector = st.selectbox(
                        "Subsector",
                        options=[""] + self.important_sectors[sector]
                    )
            
            elif sector_category == "Digital Services":
                sector = st.selectbox(
                    "Digital Service Type *",
                    options=[""] + self.digital_services
                )
                subsector = ""
            
            else:
                sector = st.text_input("Other Sector Description")
                subsector = ""
            
            st.subheader("📊 Risk Assessment Factors")
            
            # Risk factor assessment
            for factor in self.risk_factors:
                risk_scores[factor] = st.slider(
                    f"{factor}",
                    min_value=1,
                    max_value=5,
                    value=3,
                    help=f"Rate your organization's exposure to {factor.lower()} (1=Low, 5=High)"
                )
            
            # Additional questions
            st.subheader("🔐 Additional Security Considerations")
            
            col1, col2 = st.columns(2)
            with col1:
                has_critical_infrastructure = st.checkbox("Provides critical infrastructure services")
                has_supply_chain_role = st.checkbox("Critical role in supply chains")
                cross_border_operations = st.checkbox("Significant cross-border operations")
            
            with col2:
                data_processing_volume = st.selectbox(
                    "Data Processing Volume",
                    ["Low", "Medium", "High", "Very High"]
                )
                user_base_size = st.selectbox(
                    "User Base Size",
                    ["< 1K", "1K-10K", "10K-100K", "100K-1M", "> 1M"]
                )
            
            submitted = st.form_submit_button("🔍 Assess Scope", type="primary")
            
            if submitted and st.session_state.get('current_organization_name') and org_size and sector_category:
                # Store form data in session state to display results outside the form
                st.session_state.scope_form_data = {
                    'org_id': st.session_state.get('current_organization_id'),
                    'org_name': st.session_state.get('current_organization_name'),
                    'org_size': org_size[0],
                    'sector_category': sector_category,
                    'sector': sector,
                    'subsector': subsector,
                    'risk_scores': risk_scores,
                    'has_critical_infrastructure': has_critical_infrastructure,
                    'has_supply_chain_role': has_supply_chain_role,
                    'cross_border_operations': cross_border_operations,
                    'data_processing_volume': data_processing_volume,
                    'user_base_size': user_base_size
                }
                st.rerun()
    
    def perform_scope_assessment(self, org_id: str, org_name: str, org_size: str, sector_category: str,
                               sector: str, subsector: str, risk_scores: Dict[str, int],
                               has_critical_infrastructure: bool, has_supply_chain_role: bool,
                               cross_border_operations: bool, data_processing_volume: str,
                               user_base_size: str) -> ScopeAssessment:
        """Perform the scope assessment and return results."""
        
        # Determine sector type
        if sector_category == "Essential":
            sector_type = SectorType.ESSENTIAL
        elif sector_category == "Important":
            sector_type = SectorType.IMPORTANT
        elif sector_category == "Digital Services":
            sector_type = SectorType.DIGITAL
        else:
            sector_type = SectorType.NOT_IN_SCOPE
        
        # Calculate assessment score
        base_score = sum(risk_scores.values())
        
        # Apply multipliers
        if has_critical_infrastructure:
            base_score *= 1.5
        if has_supply_chain_role:
            base_score *= 1.3
        if cross_border_operations:
            base_score *= 1.2
        
        # Size considerations
        org_size_enum = OrganizationSize(org_size)
        if org_size_enum in [OrganizationSize.MEDIUM, OrganizationSize.LARGE]:
            base_score *= 1.2
        
        # Determine if in scope
        in_scope = self._determine_scope(sector_type, base_score, org_size_enum)
        
        # Generate reporting obligations
        reporting_obligations = self._get_reporting_obligations(sector_type, in_scope)
        
        # Generate risk factors
        risk_factors = self._identify_risk_factors(risk_scores, has_critical_infrastructure,
                                                 has_supply_chain_role, cross_border_operations)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(sector_type, in_scope, risk_factors)
        
        # Generate next steps
        next_steps = self._generate_next_steps(in_scope, sector_type)
        
        # Create assessment result
        assessment = ScopeAssessment(
            organization_id=org_id,
            organization_name=org_name,
            assessment_date=datetime.now(),
            sector_type=sector_type,
            organization_size=org_size_enum,
            in_scope=in_scope,
            reporting_obligations=reporting_obligations,
            assessment_score=int(base_score),
            risk_factors=risk_factors,
            recommendations=recommendations,
            next_steps=next_steps
        )
        
        # Save assessment
        self.save_assessment(assessment)
        
        return assessment
    
    def _determine_scope(self, sector_type: SectorType, score: float, 
                         org_size: OrganizationSize) -> bool:
        """Determine if organization is in scope based on criteria."""
        
        # Essential sectors are always in scope
        if sector_type == SectorType.ESSENTIAL:
            return True
        
        # Important sectors with medium+ size are in scope
        if sector_type == SectorType.IMPORTANT and org_size in [OrganizationSize.MEDIUM, OrganizationSize.LARGE]:
            return True
        
        # Digital services with high risk scores are in scope
        if sector_type == SectorType.DIGITAL and score >= 60:
            return True
        
        # Large organizations in any sector may be in scope
        if org_size == OrganizationSize.LARGE and score >= 50:
            return True
        
        return False
    
    def _get_reporting_obligations(self, sector_type: SectorType, in_scope: bool) -> List[str]:
        """Get reporting obligations based on scope."""
        if not in_scope:
            return ["No mandatory reporting obligations under NIS2"]
        
        obligations = [
            "Report significant incidents within 24 hours of detection",
            "Submit initial incident report",
            "Provide intermediate updates as required",
            "Submit final incident report",
            "Maintain incident records for at least 3 years"
        ]
        
        if sector_type == SectorType.ESSENTIAL:
            obligations.extend([
                "Enhanced reporting requirements",
                "Regular security assessments",
                "Compliance audits"
            ])
        
        return obligations
    
    def _identify_risk_factors(self, risk_scores: Dict[str, int], 
                              has_critical_infrastructure: bool,
                              has_supply_chain_role: bool,
                              cross_border_operations: bool) -> List[str]:
        """Identify key risk factors based on assessment."""
        risk_factors = []
        
        # High risk factors
        for factor, score in risk_scores.items():
            if score >= 4:
                risk_factors.append(f"High {factor.lower()} exposure")
        
        # Additional risk factors
        if has_critical_infrastructure:
            risk_factors.append("Critical infrastructure dependency")
        if has_supply_chain_role:
            risk_factors.append("Supply chain criticality")
        if cross_border_operations:
            risk_factors.append("Cross-border operational complexity")
        
        return risk_factors
    
    def _generate_recommendations(self, sector_type: SectorType, in_scope: bool,
                                risk_factors: List[str]) -> List[str]:
        """Generate recommendations based on assessment."""
        recommendations = []
        
        if in_scope:
            recommendations.extend([
                "Implement NIS2 compliance framework",
                "Establish incident response procedures",
                "Conduct regular security assessments",
                "Train staff on incident reporting",
                "Develop business continuity plans"
            ])
            
            if sector_type == SectorType.ESSENTIAL:
                recommendations.extend([
                    "Implement enhanced security controls",
                    "Establish 24/7 security monitoring",
                    "Conduct penetration testing",
                    "Implement zero-trust architecture"
                ])
        else:
            recommendations.extend([
                "Monitor NIS2 developments",
                "Consider voluntary compliance",
                "Implement security best practices",
                "Regular security assessments"
            ])
        
        # Risk-specific recommendations
        if "High critical infrastructure dependency" in risk_factors:
            recommendations.append("Implement redundant systems and failover procedures")
        if "High supply chain criticality" in risk_factors:
            recommendations.append("Establish supplier security requirements and monitoring")
        
        return recommendations
    
    def _generate_next_steps(self, in_scope: bool, sector_type: SectorType) -> List[str]:
        """Generate next steps for the organization."""
        if in_scope:
            steps = [
                "Register with relevant national authority",
                "Appoint NIS2 compliance officer",
                "Develop incident response plan",
                "Implement security monitoring tools",
                "Conduct gap analysis against NIS2 requirements"
            ]
            
            if sector_type == SectorType.ESSENTIAL:
                steps.extend([
                    "Establish security operations center",
                    "Implement advanced threat detection",
                    "Develop crisis communication plan"
                ])
        else:
            steps = [
                "Continue monitoring NIS2 developments",
                "Implement security best practices",
                "Consider voluntary compliance",
                "Regular security assessments"
            ]
        
        return steps
    
    def _display_assessment_results(self, assessment: ScopeAssessment):
        """Display the assessment results."""
        st.success("✅ Scope Assessment Complete!")
        
        # Results summary
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Scope Status", "In Scope" if assessment.in_scope else "Not In Scope")
        
        with col2:
            st.metric("Sector Type", assessment.sector_type.value.title())
        
        with col3:
            st.metric("Assessment Score", assessment.assessment_score)
        
        # Detailed results
        st.subheader("📋 Assessment Results")
        
        # Scope determination
        scope_color = "🟢" if assessment.in_scope else "🔴"
        st.markdown(f"**Scope Determination:** {scope_color} {assessment.organization_name} is **{'IN SCOPE' if assessment.in_scope else 'NOT IN SCOPE'}** for NIS2 Article 23 reporting requirements.")
        
        # Reporting obligations
        st.subheader("📤 Reporting Obligations")
        for obligation in assessment.reporting_obligations:
            st.markdown(f"• {obligation}")
        
        # Risk factors
        if assessment.risk_factors:
            st.subheader("⚠️ Key Risk Factors")
            for factor in assessment.risk_factors:
                st.markdown(f"• {factor}")
        
        # Recommendations
        st.subheader("💡 Recommendations")
        for rec in assessment.recommendations:
            st.markdown(f"• {rec}")
        
        # Next steps
        st.subheader("🚀 Next Steps")
        for i, step in enumerate(assessment.next_steps, 1):
            st.markdown(f"{i}. {step}")
        
        # Export results
        st.subheader("💾 Export Results")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("📄 Export as PDF", key="scope_export_pdf"):
                st.info("PDF export functionality to be implemented")
        
        with col2:
            if st.button("📊 Export as JSON", key="scope_export_json"):
                assessment_dict = {
                    "organization_id": assessment.organization_id,
                    "organization_name": assessment.organization_name,
                    "assessment_date": assessment.assessment_date.isoformat(),
                    "sector_type": assessment.sector_type.value,
                    "organization_size": assessment.organization_size.value,
                    "in_scope": assessment.in_scope,
                    "reporting_obligations": assessment.reporting_obligations,
                    "assessment_score": assessment.assessment_score,
                    "risk_factors": assessment.risk_factors,
                    "recommendations": assessment.recommendations,
                    "next_steps": assessment.next_steps
                }
                
                st.download_button(
                    label="⬇️ Download JSON",
                    data=json.dumps(assessment_dict, indent=2),
                    file_name=f"nis2_scope_assessment_{assessment.organization_name}_{datetime.now().strftime('%Y%m%d')}.json",
                    mime="application/json"
                )
        
        # Save to session state for later use
        if 'scope_assessments' not in st.session_state:
            st.session_state.scope_assessments = []
        
        st.session_state.scope_assessments.append(assessment)
        
        # Save the assessment to persistent storage immediately
        self.save_assessment(assessment)
    
    def save_assessment(self, assessment: ScopeAssessment):
        """Save an assessment to storage."""
        # For now, save to session state
        # In production, this would save to a database
        if 'scope_assessments' not in st.session_state:
            st.session_state.scope_assessments = []
        
        # Store by organization name for now (in production, use organization_id)
        self.assessments[assessment.organization_id] = assessment
        
        # Also save to session state
        if 'scope_assessments' not in st.session_state:
            st.session_state.scope_assessments = []
        
        # Update or add to session state
        existing_index = None
        for i, existing in enumerate(st.session_state.scope_assessments):
            if existing.organization_id == assessment.organization_id:
                existing_index = i
                break
        
        if existing_index is not None:
            st.session_state.scope_assessments[existing_index] = assessment
        else:
            st.session_state.scope_assessments.append(assessment)
        
        # Save to persistent storage
        self.save_assessments()
        
        return assessment
    
    def save_assessments(self):
        """Save all scope assessments to JSON file."""
        try:
            assessments_data = {}
            for org_id, assessment in self.assessments.items():
                assessments_data[org_id] = assessment.to_dict()
            
            with open(self.assessments_file, 'w', encoding='utf-8') as f:
                json.dump(assessments_data, f, indent=2, ensure_ascii=False)
            
            print(f"✅ Scope assessments saved to {self.assessments_file}")
        except Exception as e:
            print(f"❌ Error saving scope assessments: {e}")
    
    def load_assessments(self):
        """Load scope assessments from JSON file."""
        try:
            if os.path.exists(self.assessments_file):
                with open(self.assessments_file, 'r', encoding='utf-8') as f:
                    assessments_data = json.load(f)
                
                self.assessments = {}
                for org_id, data in assessments_data.items():
                    try:
                        assessment = ScopeAssessment.from_dict(data)
                        self.assessments[org_id] = assessment
                    except Exception as e:
                        print(f"⚠️ Error loading assessment for {org_id}: {e}")
                        continue
                
                print(f"✅ Loaded {len(self.assessments)} scope assessments from {self.assessments_file}")
            else:
                print(f"ℹ️ No existing scope assessments file found: {self.assessments_file}")
        except Exception as e:
            print(f"❌ Error loading scope assessments: {e}")
    
    def get_organization_scope(self, organization_id: str) -> Optional[ScopeAssessment]:
        """Get the scope assessment for a specific organization."""
        return self.assessments.get(organization_id)
    
    def get_organization_scope_by_name(self, organization_name: str) -> Optional[ScopeAssessment]:
        """Get the scope assessment for a specific organization by name."""
        for assessment in self.assessments.values():
            if assessment.organization_name == organization_name:
                return assessment
        return None
