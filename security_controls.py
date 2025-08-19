"""
Security Controls Module for NIS2 Compliance
Provides NIST and Cyber Fundamentals controls as organization-level checklists
with recommendations on mandatory and recommended controls.
"""

import streamlit as st
from dataclasses import dataclass, asdict
from enum import Enum
from typing import List, Dict, Optional, Set
import json
import os
from datetime import datetime, timedelta
import uuid


class ControlCategory(Enum):
    """Categories of security controls."""
    IDENTIFY = "Identify"
    PROTECT = "Protect"
    DETECT = "Detect"
    RESPOND = "Respond"
    RECOVER = "Recover"


class ControlPriority(Enum):
    """Priority levels for security controls."""
    MANDATORY = "Mandatory"
    RECOMMENDED = "Recommended"
    OPTIONAL = "Optional"


class ControlStatus(Enum):
    """Implementation status of controls."""
    NOT_IMPLEMENTED = "Not Implemented"
    PARTIALLY_IMPLEMENTED = "Partially Implemented"
    FULLY_IMPLEMENTED = "Fully Implemented"
    NOT_APPLICABLE = "Not Applicable"


class ControlFramework(Enum):
    """Source frameworks for controls."""
    NIST_CSF = "NIST Cybersecurity Framework"
    CYBER_ESSENTIALS = "Cyber Essentials (UK NCSC)"
    NIS2 = "NIS2 Directive"
    ISO_27001 = "ISO 27001"


@dataclass
class SecurityControl:
    """Individual security control definition."""
    id: str
    name: str
    description: str
    category: ControlCategory
    framework: ControlFramework
    priority: ControlPriority
    nis2_requirement: bool
    implementation_guidance: str
    assessment_criteria: List[str]
    related_controls: List[str]
    created_date: str
    last_updated: str


@dataclass
class OrganizationControlAssessment:
    """Organization's assessment of a specific control."""
    control_id: str
    status: ControlStatus
    implementation_date: Optional[str]
    responsible_person: str
    notes: str
    evidence: str
    next_review_date: str
    last_assessed: str


@dataclass
class OrganizationControls:
    """Complete organization security controls assessment."""
    organization_id: str
    organization_name: str
    controls: Dict[str, OrganizationControlAssessment]
    overall_score: float
    last_assessment: str
    next_review: str
    created_date: str
    last_updated: str


class SecurityControlsManager:
    """Manages security controls and organization assessments."""
    
    def __init__(self):
        self.controls: Dict[str, SecurityControl] = {}
        self.organization_assessments: Dict[str, OrganizationControls] = {}
        self.controls_file = "security_controls.json"
        self.assessments_file = "organization_controls.json"
        self._initialize_default_controls()
        self.load_data()
    
    def _initialize_default_controls(self):
        """Initialize with default NIST and Cyber Essentials controls."""
        default_controls = [
            # IDENTIFY Category
            SecurityControl(
                id="ID-AM-1",
                name="Asset Inventory Management",
                description="Maintain an inventory of all assets including hardware, software, and data",
                category=ControlCategory.IDENTIFY,
                framework=ControlFramework.NIST_CSF,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Document all IT assets, assign ownership, and maintain regular updates",
                assessment_criteria=[
                    "Complete asset inventory exists",
                    "Asset ownership is assigned",
                    "Inventory is updated regularly",
                    "Critical assets are identified"
                ],
                related_controls=["ID-AM-2", "ID-AM-3"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            SecurityControl(
                id="ID-AM-2",
                name="Business Environment Understanding",
                description="Understand the organization's mission, objectives, and stakeholders",
                category=ControlCategory.IDENTIFY,
                framework=ControlFramework.NIST_CSF,
                priority=ControlPriority.RECOMMENDED,
                nis2_requirement=False,
                implementation_guidance="Document business objectives and identify critical business processes",
                assessment_criteria=[
                    "Business objectives documented",
                    "Critical processes identified",
                    "Stakeholder analysis completed"
                ],
                related_controls=["ID-AM-1"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            
            # PROTECT Category
            SecurityControl(
                id="PR-AC-1",
                name="Access Control Management",
                description="Implement and maintain access control policies and procedures",
                category=ControlCategory.PROTECT,
                framework=ControlFramework.NIST_CSF,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Implement role-based access control, least privilege principle, and regular access reviews",
                assessment_criteria=[
                    "Access control policy exists",
                    "User accounts are managed",
                    "Access reviews are conducted",
                    "Privileged access is controlled"
                ],
                related_controls=["PR-AC-2", "PR-AC-3"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            SecurityControl(
                id="PR-AC-2",
                name="Identity Management",
                description="Establish and maintain identity management processes",
                category=ControlCategory.PROTECT,
                framework=ControlFramework.NIST_CSF,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Implement user lifecycle management, authentication, and authorization",
                assessment_criteria=[
                    "User lifecycle processes exist",
                    "Multi-factor authentication implemented",
                    "Password policies enforced",
                    "Account provisioning/deprovisioning automated"
                ],
                related_controls=["PR-AC-1"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            SecurityControl(
                id="PR-DS-1",
                name="Data Security",
                description="Protect data at rest and in transit",
                category=ControlCategory.PROTECT,
                framework=ControlFramework.NIST_CSF,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Implement encryption, data classification, and secure data handling procedures",
                assessment_criteria=[
                    "Data classification scheme exists",
                    "Encryption implemented for sensitive data",
                    "Secure data transmission protocols",
                    "Data backup and recovery procedures"
                ],
                related_controls=["PR-DS-2", "PR-DS-3"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            
            # DETECT Category
            SecurityControl(
                id="DE-AE-1",
                name="Security Monitoring",
                description="Implement continuous security monitoring and detection capabilities",
                category=ControlCategory.DETECT,
                framework=ControlFramework.NIST_CSF,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Deploy SIEM, log monitoring, and threat detection tools",
                assessment_criteria=[
                    "Security monitoring tools deployed",
                    "Log collection and analysis",
                    "Threat detection rules configured",
                    "Incident detection procedures"
                ],
                related_controls=["DE-AE-2", "DE-CM-1"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            SecurityControl(
                id="DE-CM-1",
                name="Continuous Monitoring",
                description="Monitor security controls and system configurations",
                category=ControlCategory.DETECT,
                framework=ControlFramework.NIST_CSF,
                priority=ControlPriority.RECOMMENDED,
                nis2_requirement=False,
                implementation_guidance="Implement automated monitoring of security configurations and control effectiveness",
                assessment_criteria=[
                    "Configuration monitoring implemented",
                    "Control effectiveness measured",
                    "Regular security assessments",
                    "Vulnerability scanning"
                ],
                related_controls=["DE-AE-1"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            
            # RESPOND Category
            SecurityControl(
                id="RS-RP-1",
                name="Incident Response Planning",
                description="Develop and maintain incident response plans and procedures",
                category=ControlCategory.RESPOND,
                framework=ControlFramework.NIST_CSF,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Create incident response plan, establish response team, and conduct regular exercises",
                assessment_criteria=[
                    "Incident response plan exists",
                    "Response team established",
                    "Communication procedures defined",
                    "Regular exercises conducted"
                ],
                related_controls=["RS-RP-2", "RS-CO-1"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            SecurityControl(
                id="RS-CO-1",
                name="Incident Communication",
                description="Establish communication procedures for incident response",
                category=ControlCategory.RESPOND,
                framework=ControlFramework.NIST_CSF,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Define communication channels, stakeholders, and reporting procedures",
                assessment_criteria=[
                    "Communication procedures defined",
                    "Stakeholder contacts identified",
                    "Reporting templates available",
                    "Escalation procedures"
                ],
                related_controls=["RS-RP-1"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            
            # RECOVER Category
            SecurityControl(
                id="RC-RP-1",
                name="Recovery Planning",
                description="Develop and maintain business continuity and disaster recovery plans",
                category=ControlCategory.RECOVER,
                framework=ControlFramework.NIST_CSF,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Create recovery plans, establish recovery teams, and conduct regular testing",
                assessment_criteria=[
                    "Recovery plans exist",
                    "Recovery teams established",
                    "Recovery procedures documented",
                    "Regular testing conducted"
                ],
                related_controls=["RC-RP-2", "RC-IM-1"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            
            # Cyber Essentials Controls
            SecurityControl(
                id="CE-1",
                name="Secure Configuration",
                description="Ensure systems are configured securely",
                category=ControlCategory.PROTECT,
                framework=ControlFramework.CYBER_ESSENTIALS,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Implement secure baseline configurations and regular security updates",
                assessment_criteria=[
                    "Secure baseline configurations",
                    "Regular security updates",
                    "Unnecessary services disabled",
                    "Default passwords changed"
                ],
                related_controls=["PR-AC-1", "PR-DS-1"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            SecurityControl(
                id="CE-2",
                name="Boundary Firewalls and Internet Gateways",
                description="Protect networks with firewalls and secure gateways",
                category=ControlCategory.PROTECT,
                framework=ControlFramework.CYBER_ESSENTIALS,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Deploy network firewalls, configure rules, and monitor traffic",
                assessment_criteria=[
                    "Firewalls deployed and configured",
                    "Traffic rules defined",
                    "Regular monitoring",
                    "Configuration reviews"
                ],
                related_controls=["PR-AC-1", "DE-AE-1"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            SecurityControl(
                id="CE-3",
                name="Access Control and Administrative Privilege Management",
                description="Manage user access and administrative privileges",
                category=ControlCategory.PROTECT,
                framework=ControlFramework.CYBER_ESSENTIALS,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Implement user access controls and limit administrative privileges",
                assessment_criteria=[
                    "User access controls implemented",
                    "Administrative privileges limited",
                    "Regular access reviews",
                    "Privileged account management"
                ],
                related_controls=["PR-AC-1", "PR-AC-2"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            SecurityControl(
                id="CE-4",
                name="Patch Management",
                description="Keep systems updated with security patches",
                category=ControlCategory.PROTECT,
                framework=ControlFramework.CYBER_ESSENTIALS,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Establish patch management process and apply security updates promptly",
                assessment_criteria=[
                    "Patch management process exists",
                    "Regular security updates",
                    "Critical patches applied promptly",
                    "Patch testing procedures"
                ],
                related_controls=["CE-1", "DE-CM-1"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            ),
            SecurityControl(
                id="CE-5",
                name="Malware Protection",
                description="Implement anti-malware protection",
                category=ControlCategory.PROTECT,
                framework=ControlFramework.CYBER_ESSENTIALS,
                priority=ControlPriority.MANDATORY,
                nis2_requirement=True,
                implementation_guidance="Deploy anti-malware solutions and keep them updated",
                assessment_criteria=[
                    "Anti-malware deployed",
                    "Regular updates applied",
                    "Real-time protection enabled",
                    "Regular scans scheduled"
                ],
                related_controls=["DE-AE-1", "RS-RP-1"],
                created_date=datetime.now().isoformat(),
                last_updated=datetime.now().isoformat()
            )
        ]
        
        for control in default_controls:
            self.controls[control.id] = control
    
    def get_controls_by_category(self, category: ControlCategory) -> List[SecurityControl]:
        """Get all controls for a specific category."""
        return [control for control in self.controls.values() if control.category == category]
    
    def get_controls_by_framework(self, framework: ControlFramework) -> List[SecurityControl]:
        """Get all controls for a specific framework."""
        return [control for control in self.controls.values() if control.framework == framework]
    
    def get_mandatory_controls(self) -> List[SecurityControl]:
        """Get all mandatory controls."""
        return [control for control in self.controls.values() if control.priority == ControlPriority.MANDATORY]
    
    def get_nis2_controls(self) -> List[SecurityControl]:
        """Get all controls that are NIS2 requirements."""
        return [control for control in self.controls.values() if control.nis2_requirement]
    
    def get_control(self, control_id: str) -> Optional[SecurityControl]:
        """Get a specific control by ID."""
        return self.controls.get(control_id)
    
    def create_organization_assessment(self, organization_id: str, organization_name: str) -> OrganizationControls:
        """Create a new organization controls assessment."""
        assessment = OrganizationControls(
            organization_id=organization_id,
            organization_name=organization_name,
            controls={},
            overall_score=0.0,
            last_assessment=datetime.now().isoformat(),
            next_review=(datetime.now() + timedelta(days=30)).isoformat(),
            created_date=datetime.now().isoformat(),
            last_updated=datetime.now().isoformat()
        )
        
        # Initialize all controls as not implemented
        for control_id in self.controls:
            assessment.controls[control_id] = OrganizationControlAssessment(
                control_id=control_id,
                status=ControlStatus.NOT_IMPLEMENTED,
                implementation_date=None,
                responsible_person="",
                notes="",
                evidence="",
                next_review_date=(datetime.now() + timedelta(days=90)).isoformat(),
                last_assessed=datetime.now().isoformat()
            )
        
        self.organization_assessments[organization_id] = assessment
        self.save_data()
        return assessment
    
    def get_organization_assessment(self, organization_id: str) -> Optional[OrganizationControls]:
        """Get organization controls assessment."""
        return self.organization_assessments.get(organization_id)
    
    def update_control_assessment(self, organization_id: str, control_id: str, status: ControlStatus, 
                                 responsible_person: str, notes: str, evidence: str) -> bool:
        """Update a control assessment for an organization."""
        try:
            # Get or create organization assessment
            assessment = self.get_organization_assessment(organization_id)
            if not assessment:
                return False
            
            # Get or create control assessment
            if control_id not in assessment.controls:
                assessment.controls[control_id] = OrganizationControlAssessment(
                    control_id=control_id,
                    status=status,
                    implementation_date=datetime.now().strftime("%Y-%m-%d"),
                    responsible_person=responsible_person,
                    notes=notes,
                    evidence=evidence,
                    next_review_date=(datetime.now() + timedelta(days=90)).strftime("%Y-%m-%d"),
                    last_assessed=datetime.now().strftime("%Y-%m-%d")
                )
            else:
                control_assessment = assessment.controls[control_id]
                control_assessment.status = status
                control_assessment.responsible_person = responsible_person
                control_assessment.notes = notes
                control_assessment.evidence = evidence
                control_assessment.last_assessed = datetime.now().strftime("%Y-%m-%d")
                
                # Update implementation date if status changed to implemented
                if status in [ControlStatus.FULLY_IMPLEMENTED, ControlStatus.PARTIALLY_IMPLEMENTED]:
                    if not control_assessment.implementation_date:
                        control_assessment.implementation_date = datetime.now().strftime("%Y-%m-%d")
            
            # Update overall score
            self._calculate_overall_score(assessment)
            
            # Save data
            self.save_data()
            return True
            
        except Exception as e:
            return False
    
    def _calculate_overall_score(self, assessment: OrganizationControls):
        """Calculate overall implementation score."""
        if not assessment.controls:
            assessment.overall_score = 0.0
            return
        
        total_controls = len(assessment.controls)
        implemented_controls = 0
        
        for control_assessment in assessment.controls.values():
            if control_assessment.status == ControlStatus.FULLY_IMPLEMENTED:
                implemented_controls += 1
            elif control_assessment.status == ControlStatus.PARTIALLY_IMPLEMENTED:
                implemented_controls += 0.5
        
        assessment.overall_score = (implemented_controls / total_controls) * 100
    
    def get_implementation_summary(self, organization_id: str) -> Dict[str, int]:
        """Get implementation summary for an organization."""
        if organization_id not in self.organization_assessments:
            return {}
        
        assessment = self.organization_assessments[organization_id]
        summary = {
            "total": len(assessment.controls),
            "fully_implemented": 0,
            "partially_implemented": 0,
            "not_implemented": 0,
            "not_applicable": 0
        }
        
        for control_assessment in assessment.controls.values():
            if control_assessment.status == ControlStatus.FULLY_IMPLEMENTED:
                summary["fully_implemented"] += 1
            elif control_assessment.status == ControlStatus.PARTIALLY_IMPLEMENTED:
                summary["partially_implemented"] += 1
            elif control_assessment.status == ControlStatus.NOT_IMPLEMENTED:
                summary["not_implemented"] += 1
            elif control_assessment.status == ControlStatus.NOT_APPLICABLE:
                summary["not_applicable"] += 1
        
        return summary
    
    def save_data(self):
        """Save security controls and organization assessments to JSON files."""
        try:
            # Save controls with enum values serialized to strings
            controls_data: Dict[str, Dict] = {}
            for control_id, control in self.controls.items():
                control_dict = asdict(control)
                # Convert enums to their values
                control_dict["category"] = control.category.value
                control_dict["framework"] = control.framework.value
                control_dict["priority"] = control.priority.value
                controls_data[control_id] = control_dict
            
            tmp_controls = f"{self.controls_file}.tmp"
            with open(tmp_controls, "w", encoding="utf-8") as f:
                json.dump(controls_data, f, indent=2, ensure_ascii=False)
            os.replace(tmp_controls, self.controls_file)
            
            # Save organization assessments with enum values serialized to strings
            assessments_data: Dict[str, Dict] = {}
            for org_id, assessment in self.organization_assessments.items():
                assessment_dict = asdict(assessment)
                # Convert nested control assessment enums
                serialized_controls: Dict[str, Dict] = {}
                for cid, ca in assessment.controls.items():
                    ca_dict = asdict(ca)
                    ca_dict["status"] = ca.status.value
                    serialized_controls[cid] = ca_dict
                assessment_dict["controls"] = serialized_controls
                assessments_data[org_id] = assessment_dict
            
            tmp_assess = f"{self.assessments_file}.tmp"
            with open(tmp_assess, "w", encoding="utf-8") as f:
                json.dump(assessments_data, f, indent=2, ensure_ascii=False)
            os.replace(tmp_assess, self.assessments_file)
                
        except Exception as e:
            # Handle error without requiring Streamlit context
            try:
                st.error(f"Error saving security controls data: {e}")
            except:
                print(f"Error saving security controls data: {e}")

    def load_data(self):
        """Load security controls and organization assessments from JSON files."""
        try:
            # Load controls
            if os.path.exists(self.controls_file):
                try:
                    with open(self.controls_file, "r", encoding="utf-8") as f:
                        controls_data = json.load(f)
                except json.JSONDecodeError:
                    # Backup corrupt file and regenerate from defaults
                    try:
                        os.replace(self.controls_file, f"{self.controls_file}.bak")
                    except Exception:
                        pass
                    # Reinitialize defaults and save
                    self.controls.clear()
                    self._initialize_default_controls()
                    self.save_data()
                    with open(self.controls_file, "r", encoding="utf-8") as f:
                        controls_data = json.load(f)
                
                self.controls.clear()
                for control_id, data in controls_data.items():
                    try:
                        # Convert enum values back to enum objects
                        data['category'] = ControlCategory(data['category'])
                        data['framework'] = ControlFramework(data['framework'])
                        data['priority'] = ControlPriority(data['priority'])
                        
                        control = SecurityControl(**data)
                        self.controls[control_id] = control
                    except Exception:
                        # Skip invalid controls
                        continue
            else:
                # Use default controls if file doesn't exist
                self.controls.clear()
                self._initialize_default_controls()
                self.save_data()
            
            # Load organization assessments
            if os.path.exists(self.assessments_file):
                try:
                    with open(self.assessments_file, "r", encoding="utf-8") as f:
                        assessments_data = json.load(f)
                except json.JSONDecodeError:
                    try:
                        os.replace(self.assessments_file, f"{self.assessments_file}.bak")
                    except Exception:
                        pass
                    # Start fresh assessments file
                    self.organization_assessments = {}
                    self.save_data()
                    assessments_data = {}
                
                for org_id, assessment_data in assessments_data.items():
                    try:
                        # Convert enum values back to enum objects
                        controls: Dict[str, OrganizationControlAssessment] = {}
                        for control_id, control_data in assessment_data.get('controls', {}).items():
                            try:
                                control_data['status'] = ControlStatus(control_data['status'])
                                control_assessment = OrganizationControlAssessment(**control_data)
                                controls[control_id] = control_assessment
                            except Exception:
                                # Skip invalid control assessments
                                continue
                        
                        assessment_data['controls'] = controls
                        assessment = OrganizationControls(**assessment_data)
                        self.organization_assessments[org_id] = assessment
                        
                    except Exception:
                        # Skip invalid assessments
                        continue
                        
        except Exception as e:
            # Handle error without requiring Streamlit context
            try:
                st.error(f"Error loading security controls data: {e}")
            except:
                print(f"Error loading security controls data: {e}")


class SecurityControlsInterface:
    """Streamlit interface for security controls management."""
    
    def __init__(self):
        self.manager = SecurityControlsManager()
    
    def display_main_interface(self, organization_id: int, organization_name: str):
        """Display the main security controls interface."""
        st.header("🛡️ Security Controls Assessment")
        st.markdown("Comprehensive security controls assessment based on NIST Cybersecurity Framework and Cyber Essentials")
        
        # Convert organization_id to string for consistency with JSON storage
        org_id_str = str(organization_id)
        
        # Reload data to ensure we have the latest
        self.manager.load_data()
        
        # Ensure organization assessment exists
        if not self.manager.get_organization_assessment(org_id_str):
            st.info(f"🔄 Creating new assessment for {organization_name}...")
            self.manager.create_organization_assessment(org_id_str, organization_name)
            st.success(f"✅ Created new assessment for {organization_name}")
            # Reload to get the newly created assessment
            self.manager.load_data()
        
        # Display overview metrics
        self._display_overview_metrics(org_id_str)
        
        # Create tabs for different views
        tab1, tab2, tab3, tab4 = st.tabs([
            "📊 Controls Overview", 
            "🔍 Control Details", 
            "📋 Assessment Form",
            "📈 Implementation Progress"
        ])
        
        with tab1:
            self._display_controls_overview(org_id_str)
        
        with tab2:
            self._display_control_details(org_id_str)
        
        with tab3:
            self._display_assessment_form(org_id_str)
        
        with tab4:
            self._display_implementation_progress(org_id_str)
    
    def _display_overview_metrics(self, organization_id: str):
        """Display overview metrics."""
        summary = self.manager.get_implementation_summary(organization_id)
        assessment = self.manager.get_organization_assessment(organization_id)
        
        if not summary or not assessment:
            return
        
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Overall Score", f"{assessment.overall_score:.1f}%")
        
        with col2:
            st.metric("Total Controls", summary["total"])
        
        with col3:
            st.metric("Implemented", summary["fully_implemented"])
        
        with col4:
            st.metric("Partially Implemented", summary["partially_implemented"])
        
        with col5:
            st.metric("Not Implemented", summary["not_implemented"])
        
        st.markdown("---")
    
    def _display_controls_overview(self, organization_id: str):
        """Display controls overview by category."""
        st.subheader("Controls by Category")
        
        for category in ControlCategory:
            st.markdown(f"### {category.value}")
            
            controls = self.manager.get_controls_by_category(category)
            assessment = self.manager.get_organization_assessment(organization_id)
            
            if not assessment:
                continue
            
            # Create columns for each control
            cols = st.columns(3)
            for i, control in enumerate(controls):
                col_idx = i % 3
                with cols[col_idx]:
                    control_assessment = assessment.controls.get(control.id)
                    if control_assessment:
                        status_color = {
                            ControlStatus.FULLY_IMPLEMENTED: "🟢",
                            ControlStatus.PARTIALLY_IMPLEMENTED: "🟡",
                            ControlStatus.NOT_IMPLEMENTED: "🔴",
                            ControlStatus.NOT_APPLICABLE: "⚪"
                        }.get(control_assessment.status, "⚪")
                        
                        priority_icon = "🔴" if control.priority == ControlPriority.MANDATORY else "🟡"
                        nis2_icon = "✅" if control.nis2_requirement else "ℹ️"
                        
                        st.markdown(f"""
                        **{control.id}**: {control.name}
                        - {status_color} {control_assessment.status.value}
                        - {priority_icon} {control.priority.value}
                        - {nis2_icon} NIS2: {'Yes' if control.nis2_requirement else 'No'}
                        """)
            
            st.markdown("---")
    
    def _display_control_details(self, organization_id: str):
        """Display detailed control information."""
        st.subheader("Control Details")
        
        # Filter controls
        col1, col2 = st.columns(2)
        with col1:
            selected_framework = st.selectbox(
                "Framework",
                options=[f.value for f in ControlFramework],
                index=0
            )
        
        with col2:
            selected_category = st.selectbox(
                "Category",
                options=[c.value for c in ControlCategory],
                index=0
            )
        
        # Filter controls
        filtered_controls = []
        for control in self.manager.controls.values():
            if (control.framework.value == selected_framework and 
                control.category.value == selected_category):
                filtered_controls.append(control)
        
        if not filtered_controls:
            st.info("No controls found for the selected criteria.")
            return
        
        # Display filtered controls
        for control in filtered_controls:
            with st.expander(f"{control.id}: {control.name}"):
                st.markdown(f"**Description:** {control.description}")
                st.markdown(f"**Framework:** {control.framework.value}")
                st.markdown(f"**Category:** {control.category.value}")
                st.markdown(f"**Priority:** {control.priority.value}")
                st.markdown(f"**NIS2 Requirement:** {'Yes' if control.nis2_requirement else 'No'}")
                
                st.markdown("**Implementation Guidance:**")
                st.markdown(control.implementation_guidance)
                
                st.markdown("**Assessment Criteria:**")
                for i, criterion in enumerate(control.assessment_criteria, 1):
                    st.markdown(f"{i}. {criterion}")
                
                if control.related_controls:
                    st.markdown("**Related Controls:**")
                    st.markdown(", ".join(control.related_controls))
    
    def _display_assessment_form(self, organization_id: str):
        """Display assessment form for updating control status."""
        st.subheader("Update Control Assessment")
        
        assessment = self.manager.get_organization_assessment(organization_id)
        if not assessment:
            st.error("No assessment found for this organization.")
            return
        
        # Select control to assess
        control_options = [(control.id, f"{control.id}: {control.name}") 
                          for control in self.manager.controls.values()]
        selected_control = st.selectbox(
            "Select Control to Assess",
            options=[opt[0] for opt in control_options],
            format_func=lambda x: next(opt[1] for opt in control_options if opt[0] == x)
        )
        
        if selected_control:
            control = self.manager.get_control(selected_control)
            control_assessment = assessment.controls.get(selected_control)
            
            if control and control_assessment:
                st.markdown(f"**Control:** {control.name}")
                st.markdown(f"**Description:** {control.description}")
                st.markdown(f"**Priority:** {control.priority.value}")
                st.markdown(f"**NIS2 Requirement:** {'Yes' if control.nis2_requirement else 'No'}")
                
                # Show current status
                st.info(f"**Current Status:** {control_assessment.status.value}")
                if control_assessment.responsible_person:
                    st.info(f"**Responsible Person:** {control_assessment.responsible_person}")
                if control_assessment.notes:
                    st.info(f"**Current Notes:** {control_assessment.notes}")
                if control_assessment.evidence:
                    st.info(f"**Current Evidence:** {control_assessment.evidence}")
                
                # Create a unique key for this form to prevent conflicts
                form_key = f"assessment_form_{organization_id}_{selected_control}"
                
                with st.form(form_key):
                    st.info(f"Form key: {form_key}")
                    st.info(f"Current control status: {control_assessment.status.value}")
                    
                    new_status = st.selectbox(
                        "Implementation Status",
                        options=[status.value for status in ControlStatus],
                        index=[status.value for status in ControlStatus].index(control_assessment.status.value)
                    )
                    
                    responsible_person = st.text_input(
                        "Responsible Person",
                        value=control_assessment.responsible_person,
                        key=f"resp_{form_key}"
                    )
                    
                    notes = st.text_area(
                        "Notes",
                        value=control_assessment.notes,
                        help="Additional notes about implementation status",
                        key=f"notes_{form_key}"
                    )
                    
                    evidence = st.text_area(
                        "Evidence",
                        value=control_assessment.evidence,
                        help="Evidence of implementation (documents, screenshots, etc.)",
                        key=f"evidence_{form_key}"
                    )
                    
                    # Show form values before submission
                    st.info(f"Form values - Status: {new_status}, Person: {responsible_person}, Notes: {notes}")
                    
                    submitted = st.form_submit_button("Update Assessment")
                    
                    if submitted:
                        st.info("🎯 Form submitted!")
                        # Debug information
                        st.info(f"Updating control {selected_control} for organization {organization_id}")
                        st.info(f"New status: {new_status}")
                        st.info(f"Responsible person: {responsible_person}")
                        st.info(f"Notes: {notes}")
                        st.info(f"Evidence: {evidence}")
                        
                        # Check if the form data is valid
                        if not new_status:
                            st.error("Status is required!")
                            return
                        
                        try:
                            status_enum = ControlStatus(new_status)
                        except ValueError as e:
                            st.error(f"Invalid status: {e}")
                            return
                        
                        st.info(f"Status enum created: {status_enum.value}")
                        
                        success = self.manager.update_control_assessment(
                            organization_id, selected_control, status_enum,
                            responsible_person, notes, evidence
                        )
                        
                        if success:
                            st.success("Assessment updated successfully!")
                            st.info("Data saved to file. Refreshing page...")
                            
                            # Verify the data was actually saved
                            st.info("Verifying data persistence...")
                            self.manager.load_data()
                            verification_assessment = self.manager.get_organization_assessment(organization_id)
                            if verification_assessment and selected_control in verification_assessment.controls:
                                verification_control = verification_assessment.controls[selected_control]
                                st.success(f"✅ Verification successful - Status: {verification_control.status.value}")
                                st.success(f"✅ Notes: {verification_control.notes}")
                                st.success(f"✅ Evidence: {verification_control.evidence}")
                            else:
                                st.error("❌ Verification failed - data not found after reload")
                            
                            # Use st.rerun() to refresh the page
                            st.rerun()
                        else:
                            st.error("Failed to update assessment. Please try again.")
                    else:
                        st.info("⏳ Form not submitted yet...")
    
    def _display_implementation_progress(self, organization_id: str):
        """Display implementation progress charts and trends."""
        st.subheader("Implementation Progress")
        
        assessment = self.manager.get_organization_assessment(organization_id)
        if not assessment:
            st.error("No assessment found for this organization.")
            return
        
        # Progress by category
        st.markdown("### Progress by Category")
        category_progress = {}
        
        for category in ControlCategory:
            category_controls = self.manager.get_controls_by_category(category)
            if not category_controls:
                continue
            
            implemented = 0
            total = len(category_controls)
            
            for control in category_controls:
                control_assessment = assessment.controls.get(control.id)
                if control_assessment and control_assessment.status == ControlStatus.FULLY_IMPLEMENTED:
                    implemented += 1
            
            category_progress[category.value] = (implemented / total) * 100
        
        # Display category progress bars
        for category, progress in category_progress.items():
            st.markdown(f"**{category}:** {progress:.1f}%")
            st.progress(progress / 100)
        
        st.markdown("---")
        
        # Priority breakdown
        st.markdown("### Progress by Priority")
        priority_progress = {}
        
        for priority in ControlPriority:
            priority_controls = [c for c in self.manager.controls.values() if c.priority == priority]
            if not priority_controls:
                continue
            
            implemented = 0
            total = len(priority_controls)
            
            for control in priority_controls:
                control_assessment = assessment.controls.get(control.id)
                if control_assessment and control_assessment.status == ControlStatus.FULLY_IMPLEMENTED:
                    implemented += 1
            
            priority_progress[priority.value] = (implemented / total) * 100
        
        # Display priority progress bars
        for priority, progress in priority_progress.items():
            st.markdown(f"**{priority}:** {progress:.1f}%")
            st.progress(progress / 100)
        
        st.markdown("---")
        
        # NIS2 compliance
        st.markdown("### NIS2 Compliance Progress")
        nis2_controls = self.manager.get_nis2_controls()
        if nis2_controls:
            implemented = 0
            total = len(nis2_controls)
            
            for control in nis2_controls:
                control_assessment = assessment.controls.get(control.id)
                if control_assessment and control_assessment.status == ControlStatus.FULLY_IMPLEMENTED:
                    implemented += 1
            
            nis2_progress = (implemented / total) * 100
            st.markdown(f"**NIS2 Controls:** {nis2_progress:.1f}%")
            st.progress(nis2_progress / 100)
            
            if nis2_progress == 100:
                st.success("🎉 All NIS2 controls are fully implemented!")
            elif nis2_progress >= 80:
                st.warning("⚠️ Most NIS2 controls implemented. Review remaining controls.")
            else:
                st.error("🚨 Significant NIS2 controls not implemented. Prioritize implementation.")
