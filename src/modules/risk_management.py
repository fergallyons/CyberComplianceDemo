"""
Risk Assessment & Management Module for NIS2 Compliance
Provides comprehensive risk management capabilities including risk registers,
assessment matrices, treatment plans, and monitoring.
"""

import json
import streamlit as st
from datetime import datetime, date
from dataclasses import dataclass, asdict
from enum import Enum
from typing import List, Optional, Dict, Any
import uuid

# Risk Management Enums
class RiskCategory(Enum):
    TECHNICAL = "Technical"
    OPERATIONAL = "Operational"
    STRATEGIC = "Strategic"
    COMPLIANCE = "Compliance"
    SUPPLY_CHAIN = "Supply Chain"
    PHYSICAL = "Physical"
    HUMAN = "Human"
    FINANCIAL = "Financial"

class RiskLikelihood(Enum):
    VERY_LOW = "Very Low"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    VERY_HIGH = "Very High"

class RiskImpact(Enum):
    VERY_LOW = "Very Low"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    VERY_HIGH = "Very High"

class RiskStatus(Enum):
    IDENTIFIED = "Identified"
    ASSESSED = "Assessed"
    TREATMENT_PLANNED = "Treatment Planned"
    TREATMENT_IN_PROGRESS = "Treatment In Progress"
    TREATMENT_COMPLETED = "Treatment Completed"
    MONITORING = "Monitoring"
    CLOSED = "Closed"

class TreatmentStatus(Enum):
    NOT_STARTED = "Not Started"
    IN_PROGRESS = "In Progress"
    COMPLETED = "Completed"
    ON_HOLD = "On Hold"
    CANCELLED = "Cancelled"

class TreatmentType(Enum):
    AVOID = "Avoid"
    TRANSFER = "Transfer"
    MITIGATE = "Mitigate"
    ACCEPT = "Accept"

# Risk Management Data Classes
@dataclass
class RiskTreatment:
    id: str
    risk_id: str
    treatment_type: TreatmentType
    description: str
    responsible_person: str
    start_date: date
    target_completion_date: date
    actual_completion_date: Optional[date]
    status: TreatmentStatus
    cost: Optional[float]
    effectiveness: Optional[int]  # 1-10 scale
    notes: str
    created_date: date
    updated_date: date

@dataclass
class RiskAssessment:
    id: str
    risk_id: str
    likelihood: RiskLikelihood
    impact: RiskImpact
    risk_score: int  # Calculated field
    assessment_date: date
    assessor: str
    methodology: str
    notes: str
    created_date: date

@dataclass
class Risk:
    id: str
    organization_id: str
    title: str
    description: str
    category: RiskCategory
    status: RiskStatus
    identified_date: date
    last_assessed_date: Optional[date]
    current_likelihood: RiskLikelihood
    current_impact: RiskImpact
    current_risk_score: int
    inherent_likelihood: RiskLikelihood
    inherent_impact: RiskImpact
    inherent_risk_score: int
    residual_likelihood: Optional[RiskLikelihood]
    residual_impact: Optional[RiskImpact]
    residual_risk_score: Optional[int]
    owner: str
    stakeholders: List[str]
    business_impact: str
    compliance_impact: str
    financial_impact: Optional[float]
    created_date: date
    updated_date: date

@dataclass
class RiskRegister:
    organization_id: str
    risks: List[Risk]
    last_updated: date

class RiskManagementSystem:
    def __init__(self, data_file: str = "risk_register.json"):
        self.data_file = data_file
        self.risk_register = self.load_risk_register()
    
    def load_risk_register(self) -> RiskRegister:
        """Load risk register from JSON file."""
        try:
            with open(self.data_file, 'r') as f:
                data = json.load(f)
                
                # Convert risk data back to proper Risk objects with enum conversion
                risks = []
                for risk_data in data.get('risks', []):
                    # Convert string enum values back to enum objects
                    if 'category' in risk_data and isinstance(risk_data['category'], str):
                        category_str = risk_data['category']
                        # Handle both 'RiskCategory.OPERATIONAL' and 'OPERATIONAL' formats
                        if '.' in category_str:
                            category_str = category_str.split('.')[-1]
                        try:
                            risk_data['category'] = RiskCategory(category_str)
                        except ValueError:
                            # Fallback to default if invalid
                            risk_data['category'] = RiskCategory.TECHNICAL
                    
                    if 'status' in risk_data and isinstance(risk_data['status'], str):
                        status_str = risk_data['status']
                        if '.' in status_str:
                            status_str = status_str.split('.')[-1]
                        try:
                            risk_data['status'] = RiskStatus(status_str)
                        except ValueError:
                            risk_data['status'] = RiskStatus.IDENTIFIED
                    
                    if 'current_likelihood' in risk_data and isinstance(risk_data['current_likelihood'], str):
                        likelihood_str = risk_data['current_likelihood']
                        if '.' in likelihood_str:
                            likelihood_str = likelihood_str.split('.')[-1]
                        try:
                            risk_data['current_likelihood'] = RiskLikelihood(likelihood_str)
                        except ValueError:
                            risk_data['current_likelihood'] = RiskLikelihood.MEDIUM
                    
                    if 'current_impact' in risk_data and isinstance(risk_data['current_impact'], str):
                        impact_str = risk_data['current_impact']
                        if '.' in impact_str:
                            impact_str = impact_str.split('.')[-1]
                        try:
                            risk_data['current_impact'] = RiskImpact(impact_str)
                        except ValueError:
                            risk_data['current_impact'] = RiskImpact.MEDIUM
                    
                    if 'inherent_likelihood' in risk_data and isinstance(risk_data['inherent_likelihood'], str):
                        likelihood_str = risk_data['inherent_likelihood']
                        if '.' in likelihood_str:
                            likelihood_str = likelihood_str.split('.')[-1]
                        try:
                            risk_data['inherent_likelihood'] = RiskLikelihood(likelihood_str)
                        except ValueError:
                            risk_data['inherent_likelihood'] = RiskLikelihood.MEDIUM
                    
                    if 'inherent_impact' in risk_data and isinstance(risk_data['inherent_impact'], str):
                        impact_str = risk_data['inherent_impact']
                        if '.' in impact_str:
                            impact_str = impact_str.split('.')[-1]
                        try:
                            risk_data['inherent_impact'] = RiskImpact(impact_str)
                        except ValueError:
                            risk_data['inherent_impact'] = RiskImpact.MEDIUM
                    
                    if 'residual_likelihood' in risk_data and risk_data['residual_likelihood'] and isinstance(risk_data['residual_likelihood'], str):
                        likelihood_str = risk_data['residual_likelihood']
                        if '.' in likelihood_str:
                            likelihood_str = likelihood_str.split('.')[-1]
                        try:
                            risk_data['residual_likelihood'] = RiskLikelihood(likelihood_str)
                        except ValueError:
                            risk_data['residual_likelihood'] = None
                    
                    if 'residual_impact' in risk_data and risk_data['residual_impact'] and isinstance(risk_data['residual_impact'], str):
                        impact_str = risk_data['residual_impact']
                        if '.' in impact_str:
                            impact_str = impact_str.split('.')[-1]
                        try:
                            risk_data['residual_impact'] = RiskImpact(impact_str)
                        except ValueError:
                            risk_data['residual_impact'] = None
                    
                    # Convert date strings back to date objects
                    if 'identified_date' in risk_data and isinstance(risk_data['identified_date'], str):
                        risk_data['identified_date'] = datetime.strptime(risk_data['identified_date'], '%Y-%m-%d').date()
                    if 'last_assessed_date' in risk_data and risk_data['last_assessed_date'] and isinstance(risk_data['last_assessed_date'], str):
                        risk_data['last_assessed_date'] = datetime.strptime(risk_data['last_assessed_date'], '%Y-%m-%d').date()
                    if 'created_date' in risk_data and isinstance(risk_data['created_date'], str):
                        risk_data['created_date'] = datetime.strptime(risk_data['created_date'], '%Y-%m-%d').date()
                    if 'updated_date' in risk_data and isinstance(risk_data['updated_date'], str):
                        risk_data['updated_date'] = datetime.strptime(risk_data['updated_date'], '%Y-%m-%d').date()
                    
                    risks.append(Risk(**risk_data))
                
                return RiskRegister(
                    organization_id=data.get('organization_id', ''),
                    risks=risks,
                    last_updated=datetime.strptime(data['last_updated'], '%Y-%m-%d').date()
                )
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            # Return empty risk register if file doesn't exist or is invalid
            return RiskRegister(
                organization_id='',
                risks=[],
                last_updated=date.today()
            )
    
    def save_risk_register(self) -> bool:
        """Save risk register to JSON file."""
        try:
            data = {
                'organization_id': self.risk_register.organization_id,
                'risks': [asdict(risk) for risk in self.risk_register.risks],
                'last_updated': self.risk_register.last_updated.isoformat()
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            st.error(f"Error saving risk register: {e}")
            return False
    
    def calculate_risk_score(self, likelihood: RiskLikelihood, impact: RiskImpact) -> int:
        """Calculate risk score based on likelihood and impact."""
        likelihood_scores = {
            RiskLikelihood.VERY_LOW: 1,
            RiskLikelihood.LOW: 2,
            RiskLikelihood.MEDIUM: 3,
            RiskLikelihood.HIGH: 4,
            RiskLikelihood.VERY_HIGH: 5
        }
        impact_scores = {
            RiskImpact.VERY_LOW: 1,
            RiskImpact.LOW: 2,
            RiskImpact.MEDIUM: 3,
            RiskImpact.HIGH: 4,
            RiskImpact.VERY_HIGH: 5
        }
        return likelihood_scores[likelihood] * impact_scores[impact]
    
    def get_risk_level(self, risk_score: int) -> str:
        """Get risk level based on risk score."""
        if risk_score <= 4:
            return "Low"
        elif risk_score <= 8:
            return "Medium"
        elif risk_score <= 15:
            return "High"
        else:
            return "Critical"
    
    def add_risk(self, risk: Risk) -> bool:
        """Add a new risk to the register."""
        try:
            # Calculate risk scores
            risk.inherent_risk_score = self.calculate_risk_score(risk.inherent_likelihood, risk.inherent_impact)
            risk.current_risk_score = self.calculate_risk_score(risk.current_likelihood, risk.current_impact)
            
            self.risk_register.risks.append(risk)
            self.risk_register.last_updated = date.today()
            return self.save_risk_register()
        except Exception as e:
            st.error(f"Error adding risk: {e}")
            return False
    
    def update_risk(self, risk_id: str, updated_risk: Risk) -> bool:
        """Update an existing risk."""
        try:
            for i, risk in enumerate(self.risk_register.risks):
                if risk.id == risk_id:
                    # Recalculate risk scores
                    updated_risk.inherent_risk_score = self.calculate_risk_score(updated_risk.inherent_likelihood, updated_risk.inherent_impact)
                    updated_risk.current_risk_score = self.calculate_risk_score(updated_risk.current_likelihood, updated_risk.current_impact)
                    updated_risk.updated_date = date.today()
                    
                    self.risk_register.risks[i] = updated_risk
                    self.risk_register.last_updated = date.today()
                    return self.save_risk_register()
            return False
        except Exception as e:
            st.error(f"Error updating risk: {e}")
            return False
    
    def delete_risk(self, risk_id: str) -> bool:
        """Delete a risk from the register."""
        try:
            self.risk_register.risks = [risk for risk in self.risk_register.risks if risk.id != risk_id]
            self.risk_register.last_updated = date.today()
            return self.save_risk_register()
        except Exception as e:
            st.error(f"Error deleting risk: {e}")
            return False
    
    def get_risk_by_id(self, risk_id: str) -> Optional[Risk]:
        """Get a risk by its ID."""
        for risk in self.risk_register.risks:
            if risk.id == risk_id:
                return risk
        return None
    
    def get_risks_by_organization(self, organization_id: str) -> List[Risk]:
        """Get all risks for a specific organization."""
        return [risk for risk in self.risk_register.risks if risk.organization_id == organization_id]
    
    def get_risks_by_status(self, status: RiskStatus) -> List[Risk]:
        """Get risks by status."""
        return [risk for risk in self.risk_register.risks if risk.status == status]
    
    def get_risks_by_category(self, category: RiskCategory) -> List[Risk]:
        """Get risks by category."""
        return [risk for risk in self.risk_register.risks if risk.category == category]
    
    def get_high_priority_risks(self, threshold: int = 12) -> List[Risk]:
        """Get high priority risks above a certain threshold."""
        return [risk for risk in self.risk_register.risks if risk.current_risk_score >= threshold]
    
    def get_risk_statistics(self, organization_id: str) -> Dict[str, Any]:
        """Get risk statistics for an organization."""
        org_risks = self.get_risks_by_organization(organization_id)
        
        if not org_risks:
            return {
                'total_risks': 0,
                'risk_by_status': {},
                'risk_by_category': {},
                'risk_by_level': {},
                'average_risk_score': 0,
                'high_priority_count': 0
            }
        
        # Count by status
        status_counts = {}
        for status in RiskStatus:
            status_counts[status.value] = len([r for r in org_risks if r.status == status])
        
        # Count by category
        category_counts = {}
        for category in RiskCategory:
            category_counts[category.value] = len([r for r in org_risks if r.category == category])
        
        # Count by risk level
        level_counts = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
        for risk in org_risks:
            level = self.get_risk_level(risk.current_risk_score)
            level_counts[level] += 1
        
        # Calculate average risk score
        total_score = sum(risk.current_risk_score for risk in org_risks)
        avg_score = total_score / len(org_risks)
        
        # Count high priority risks
        high_priority = len([r for r in org_risks if r.current_risk_score >= 12])
        
        return {
            'total_risks': len(org_risks),
            'risk_by_status': status_counts,
            'risk_by_category': category_counts,
            'risk_by_level': level_counts,
            'average_risk_score': round(avg_score, 2),
            'high_priority_count': high_priority
        }

class RiskManagementInterface:
    def __init__(self, risk_system: RiskManagementSystem):
        self.risk_system = risk_system
    
    def display_main_interface(self, organization_id: str, organization_name: str):
        """Display the main risk management interface."""
        st.header("🛡️ Risk Assessment & Management")
        st.info(f"Managing risks for **{organization_name}**")
        
        # Create tabs for different risk management functions
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📊 Risk Dashboard",
            "➕ Add New Risk", 
            "📋 Risk Register",
            "✏️ Edit Risks",
            "📈 Risk Analytics"
        ])
        
        with tab1:
            self.display_risk_dashboard(organization_id)
        
        with tab2:
            self.display_add_risk_form(organization_id)
        
        with tab3:
            self.display_risk_register(organization_id)
        
        with tab4:
            self.display_edit_risks(organization_id)
        
        with tab5:
            self.display_risk_analytics(organization_id)
    
    def display_risk_dashboard(self, organization_id: str):
        """Display risk management dashboard."""
        st.subheader("📊 Risk Management Dashboard")
        
        # Get risk statistics
        stats = self.risk_system.get_risk_statistics(organization_id)
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Risks", stats['total_risks'])
        with col2:
            st.metric("High Priority", stats['high_priority_count'], delta=f"{stats['high_priority_count']} require attention")
        with col3:
            st.metric("Average Risk Score", stats['average_risk_score'])
        with col4:
            st.metric("Active Risks", stats['risk_by_status'].get('Treatment In Progress', 0) + 
                     stats['risk_by_status'].get('Monitoring', 0))
        
        st.markdown("---")
        
        # Risk distribution charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Risk Distribution by Status")
            if stats['risk_by_status']:
                status_data = {k: v for k, v in stats['risk_by_status'].items() if v > 0}
                if status_data:
                    st.bar_chart(status_data)
                else:
                    st.info("No risks found")
            else:
                st.info("No risks found")
        
        with col2:
            st.subheader("Risk Distribution by Category")
            if stats['risk_by_category']:
                category_data = {k: v for k, v in stats['risk_by_category'].items() if v > 0}
                if category_data:
                    st.bar_chart(category_data)
                else:
                    st.info("No risks found")
            else:
                st.info("No risks found")
        
        # High priority risks
        st.markdown("---")
        st.subheader("🚨 High Priority Risks")
        high_priority_risks = self.risk_system.get_high_priority_risks()
        org_high_priority = [r for r in high_priority_risks if r.organization_id == organization_id]
        
        if org_high_priority:
            for risk in org_high_priority[:5]:  # Show top 5
                with st.expander(f"🚨 {risk.title} (Score: {risk.current_risk_score})", expanded=False):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"**Category:** {risk.category.value}")
                        st.markdown(f"**Status:** {risk.status.value}")
                        st.markdown(f"**Owner:** {risk.owner}")
                    with col2:
                        st.markdown(f"**Current Likelihood:** {risk.current_likelihood.value}")
                        st.markdown(f"**Current Impact:** {risk.current_impact.value}")
                        st.markdown(f"**Risk Level:** {self.risk_system.get_risk_level(risk.current_risk_score)}")
                    st.markdown(f"**Description:** {risk.description}")
        else:
            st.success("✅ No high priority risks found!")
    
    def display_add_risk_form(self, organization_id: str):
        """Display form to add a new risk."""
        st.subheader("➕ Add New Risk")
        
        with st.form("add_risk_form", clear_on_submit=True):
            col1, col2 = st.columns(2)
            
            with col1:
                title = st.text_input("Risk Title", placeholder="Enter risk title")
                description = st.text_area("Risk Description", placeholder="Describe the risk in detail")
                category = st.selectbox("Risk Category", options=[cat.value for cat in RiskCategory])
                owner = st.text_input("Risk Owner", placeholder="Person responsible for managing this risk")
                business_impact = st.text_area("Business Impact", placeholder="Describe potential business impact")
            
            with col2:
                compliance_impact = st.text_area("Compliance Impact", placeholder="Describe compliance implications")
                financial_impact = st.number_input("Financial Impact (€)", min_value=0.0, value=0.0, step=1000.0)
                stakeholders = st.text_input("Stakeholders", placeholder="Comma-separated list of stakeholders")
                
                # Inherent risk assessment
                st.markdown("**🔍 Inherent Risk Assessment**")
                inherent_likelihood = st.selectbox("Inherent Likelihood", options=[lik.value for lik in RiskLikelihood])
                inherent_impact = st.selectbox("Inherent Impact", options=[imp.value for imp in RiskImpact])
                
                # Current risk assessment
                st.markdown("**📊 Current Risk Assessment**")
                current_likelihood = st.selectbox("Current Likelihood", options=[lik.value for lik in RiskLikelihood])
                current_impact = st.selectbox("Current Impact", options=[imp.value for imp in RiskImpact])
            
            if st.form_submit_button("➕ Add Risk", use_container_width=True, type="primary"):
                if title and description and owner:
                    # Create new risk
                    new_risk = Risk(
                        id=str(uuid.uuid4()),
                        organization_id=organization_id,
                        title=title,
                        description=description,
                        category=RiskCategory(category),
                        status=RiskStatus.IDENTIFIED,
                        identified_date=date.today(),
                        last_assessed_date=None,
                        current_likelihood=RiskLikelihood(current_likelihood),
                        current_impact=RiskImpact(current_impact),
                        current_risk_score=0,  # Will be calculated
                        inherent_likelihood=RiskLikelihood(inherent_likelihood),
                        inherent_impact=RiskImpact(inherent_impact),
                        inherent_risk_score=0,  # Will be calculated
                        residual_likelihood=None,
                        residual_impact=None,
                        residual_risk_score=None,
                        owner=owner,
                        stakeholders=[s.strip() for s in stakeholders.split(',') if s.strip()] if stakeholders else [],
                        business_impact=business_impact,
                        compliance_impact=compliance_impact,
                        financial_impact=financial_impact if financial_impact > 0 else None,
                        created_date=date.today(),
                        updated_date=date.today()
                    )
                    
                    if self.risk_system.add_risk(new_risk):
                        st.success("✅ Risk added successfully!")
                        st.rerun()
                    else:
                        st.error("❌ Failed to add risk")
                else:
                    st.error("❌ Please fill in all required fields")
    
    def display_risk_register(self, organization_id: str):
        """Display the risk register."""
        st.subheader("📋 Risk Register")
        
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            status_filter = st.selectbox("Filter by Status", options=["All"] + [status.value for status in RiskStatus])
        with col2:
            category_filter = st.selectbox("Filter by Category", options=["All"] + [cat.value for cat in RiskCategory])
        with col3:
            level_filter = st.selectbox("Filter by Risk Level", options=["All", "Low", "Medium", "High", "Critical"])
        
        # Get filtered risks
        risks = self.risk_system.get_risks_by_organization(organization_id)
        
        if status_filter != "All":
            risks = [r for r in risks if r.status.value == status_filter]
        if category_filter != "All":
            risks = [r for r in risks if r.category.value == category_filter]
        if level_filter != "All":
            risks = [r for r in risks if self.risk_system.get_risk_level(r.current_risk_score) == level_filter]
        
        if risks:
            # Sort by risk score (highest first)
            risks.sort(key=lambda x: x.current_risk_score, reverse=True)
            
            for risk in risks:
                risk_level = self.risk_system.get_risk_level(risk.current_risk_score)
                level_color = {
                    "Low": "🟢",
                    "Medium": "🟡", 
                    "High": "🟠",
                    "Critical": "🔴"
                }
                
                with st.expander(f"{level_color[risk_level]} {risk.title} (Score: {risk.current_risk_score})", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**Category:** {risk.category.value}")
                        st.markdown(f"**Status:** {risk.status.value}")
                        st.markdown(f"**Owner:** {risk.owner}")
                        st.markdown(f"**Identified:** {risk.identified_date}")
                        if risk.last_assessed_date:
                            st.markdown(f"**Last Assessed:** {risk.last_assessed_date}")
                    
                    with col2:
                        st.markdown(f"**Current Likelihood:** {risk.current_likelihood.value}")
                        st.markdown(f"**Current Impact:** {risk.current_impact.value}")
                        st.markdown(f"**Risk Level:** {risk_level}")
                        if risk.financial_impact:
                            st.markdown(f"**Financial Impact:** €{risk.financial_impact:,.2f}")
                    
                    st.markdown("**Description:**")
                    st.info(risk.description)
                    
                    if risk.business_impact:
                        st.markdown("**Business Impact:**")
                        st.warning(risk.business_impact)
                    
                    if risk.compliance_impact:
                        st.markdown("**Compliance Impact:**")
                        st.error(risk.compliance_impact)
                    
                    if risk.stakeholders:
                        st.markdown("**Stakeholders:**")
                        st.markdown(", ".join(risk.stakeholders))
        else:
            st.info("📝 No risks found matching the selected filters.")
    
    def display_edit_risks(self, organization_id: str):
        """Display interface to edit existing risks."""
        st.subheader("✏️ Edit Risks")
        
        risks = self.risk_system.get_risks_by_organization(organization_id)
        
        if not risks:
            st.info("📝 No risks found to edit.")
            return
        
        # Risk selection
        selected_risk_id = st.selectbox(
            "Select Risk to Edit",
            options=[risk.id for risk in risks],
            format_func=lambda x: next((risk.title for risk in risks if risk.id == x), x)
        )
        
        if selected_risk_id:
            risk = self.risk_system.get_risk_by_id(selected_risk_id)
            if risk:
                self.display_edit_risk_form(risk)
    
    def display_edit_risk_form(self, risk: Risk):
        """Display form to edit a risk."""
        st.markdown(f"**Editing Risk: {risk.title}**")
        
        with st.form(f"edit_risk_form_{risk.id}"):
            col1, col2 = st.columns(2)
            
            with col1:
                title = st.text_input("Risk Title", value=risk.title, key=f"edit_title_{risk.id}")
                description = st.text_area("Risk Description", value=risk.description, key=f"edit_desc_{risk.id}")
                category = st.selectbox("Risk Category", options=[cat.value for cat in RiskCategory], 
                                      index=[cat.value for cat in RiskCategory].index(risk.category.value),
                                      key=f"edit_cat_{risk.id}")
                status = st.selectbox("Risk Status", options=[status.value for status in RiskStatus],
                                    index=[status.value for status in RiskStatus].index(risk.status.value),
                                    key=f"edit_status_{risk.id}")
                owner = st.text_input("Risk Owner", value=risk.owner, key=f"edit_owner_{risk.id}")
            
            with col2:
                business_impact = st.text_area("Business Impact", value=risk.business_impact, key=f"edit_biz_{risk.id}")
                compliance_impact = st.text_area("Compliance Impact", value=risk.compliance_impact, key=f"edit_comp_{risk.id}")
                financial_impact = st.number_input("Financial Impact (€)", value=risk.financial_impact or 0.0, 
                                                min_value=0.0, step=1000.0, key=f"edit_fin_{risk.id}")
                stakeholders = st.text_input("Stakeholders", value=", ".join(risk.stakeholders), key=f"edit_stake_{risk.id}")
                
                # Current risk assessment
                st.markdown("**📊 Current Risk Assessment**")
                current_likelihood = st.selectbox("Current Likelihood", options=[lik.value for lik in RiskLikelihood],
                                                index=[lik.value for lik in RiskLikelihood].index(risk.current_likelihood.value),
                                                key=f"edit_cur_lik_{risk.id}")
                current_impact = st.selectbox("Current Impact", options=[imp.value for imp in RiskImpact],
                                            index=[imp.value for imp in RiskImpact].index(risk.current_impact.value),
                                            key=f"edit_cur_imp_{risk.id}")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.form_submit_button("💾 Save Changes", use_container_width=True, type="primary"):
                    # Update risk
                    updated_risk = Risk(
                        id=risk.id,
                        organization_id=risk.organization_id,
                        title=title,
                        description=description,
                        category=RiskCategory(category),
                        status=RiskStatus(status),
                        identified_date=risk.identified_date,
                        last_assessed_date=date.today() if status != risk.status.value else risk.last_assessed_date,
                        current_likelihood=RiskLikelihood(current_likelihood),
                        current_impact=RiskImpact(current_impact),
                        current_risk_score=0,  # Will be calculated
                        inherent_likelihood=risk.inherent_likelihood,
                        inherent_impact=risk.inherent_impact,
                        inherent_risk_score=risk.inherent_risk_score,
                        residual_likelihood=risk.residual_likelihood,
                        residual_impact=risk.residual_impact,
                        residual_risk_score=risk.residual_risk_score,
                        owner=owner,
                        stakeholders=[s.strip() for s in stakeholders.split(',') if s.strip()] if stakeholders else [],
                        business_impact=business_impact,
                        compliance_impact=compliance_impact,
                        financial_impact=financial_impact if financial_impact > 0 else None,
                        created_date=risk.created_date,
                        updated_date=date.today()
                    )
                    
                    if self.risk_system.update_risk(risk.id, updated_risk):
                        st.success("✅ Risk updated successfully!")
                        st.rerun()
                    else:
                        st.error("❌ Failed to update risk")
            
            with col2:
                if st.form_submit_button("🗑️ Delete Risk", use_container_width=True, type="secondary"):
                    if st.button("⚠️ Confirm Delete", key=f"confirm_delete_{risk.id}"):
                        if self.risk_system.delete_risk(risk.id):
                            st.success("✅ Risk deleted successfully!")
                            st.rerun()
                        else:
                            st.error("❌ Failed to delete risk")
    
    def display_risk_analytics(self, organization_id: str):
        """Display risk analytics and trends."""
        st.subheader("📈 Risk Analytics")
        
        stats = self.risk_system.get_risk_statistics(organization_id)
        
        if stats['total_risks'] == 0:
            st.info("📊 No risk data available for analysis.")
            return
        
        # Risk trend analysis
        st.markdown("**📊 Risk Distribution Analysis**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Risk Status Distribution**")
            if stats['risk_by_status']:
                status_data = {k: v for k, v in stats['risk_by_status'].items() if v > 0}
                if status_data:
                    st.bar_chart(status_data)
                else:
                    st.info("No status data")
        
        with col2:
            st.markdown("**Risk Category Distribution**")
            if stats['risk_by_category']:
                category_data = {k: v for k, v in stats['risk_by_category'].items() if v > 0}
                if category_data:
                    st.bar_chart(category_data)
                else:
                    st.info("No category data")
        
        # Risk level analysis
        st.markdown("---")
        st.markdown("**🚨 Risk Level Analysis**")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Risk Level Distribution**")
            if stats['risk_by_level']:
                level_data = {k: v for k, v in stats['risk_by_level'].items() if v > 0}
                if level_data:
                    st.bar_chart(level_data)
                else:
                    st.info("No level data")
        
        with col2:
            st.markdown("**Risk Level Summary**")
            for level, count in stats['risk_by_level'].items():
                if count > 0:
                    color = {
                        "Low": "🟢",
                        "Medium": "🟡",
                        "High": "🟠",
                        "Critical": "🔴"
                    }.get(level, "⚪")
                    st.metric(f"{color} {level} Risks", count)
        
        # Recommendations
        st.markdown("---")
        st.markdown("**💡 Risk Management Recommendations**")
        
        recommendations = []
        
        if stats['high_priority_count'] > 0:
            recommendations.append(f"🚨 **{stats['high_priority_count']} high priority risks** require immediate attention")
        
        if stats['risk_by_status'].get('Identified', 0) > 0:
            recommendations.append(f"📋 **{stats['risk_by_status']['Identified']} identified risks** need assessment")
        
        if stats['risk_by_status'].get('Treatment Planned', 0) > 0:
            recommendations.append(f"📝 **{stats['risk_by_status']['Treatment Planned']} risks** have treatment plans ready")
        
        if stats['average_risk_score'] > 8:
            recommendations.append("⚠️ **Average risk score is high** - consider additional mitigation measures")
        
        if recommendations:
            for rec in recommendations:
                st.info(rec)
        else:
            st.success("✅ Risk profile looks healthy!")
