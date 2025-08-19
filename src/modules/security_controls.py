"""
Security Controls Module for NIS2 Compliance
Provides NIST and Cyber Fundamentals controls as organization-level checklists
with recommendations on mandatory and recommended controls.
"""

import streamlit as st
from dataclasses import dataclass, asdict
from enum import Enum
from typing import List, Dict, Optional, Set, Any
import json
import os
from datetime import datetime, timedelta, date
import uuid


# Security Controls Enums
class ControlCategory(Enum):
    GOVERNANCE = "Governance"
    TECHNICAL = "Technical"
    OPERATIONAL = "Operational"
    PHYSICAL = "Physical"
    SUPPLY_CHAIN = "Supply Chain"

class ControlPriority(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

class ControlStatus(Enum):
    NOT_IMPLEMENTED = "Not Implemented"
    PARTIALLY_IMPLEMENTED = "Partially Implemented"
    IMPLEMENTED = "Implemented"
    VERIFIED = "Verified"
    EXEMPT = "Exempt"

class ControlFramework(Enum):
    NIS2 = "NIS2"
    ISO27001 = "ISO27001"
    SOC2 = "SOC2"
    GDPR = "GDPR"
    CUSTOM = "Custom"

class ImplementationLevel(Enum):
    BASIC = "Basic"
    INTERMEDIATE = "Intermediate"
    ADVANCED = "Advanced"
    ENTERPRISE = "Enterprise"

class ComplianceStatus(Enum):
    COMPLIANT = "Compliant"
    PARTIALLY_COMPLIANT = "Partially Compliant"
    NON_COMPLIANT = "Non-Compliant"
    NOT_APPLICABLE = "Not Applicable"

# Enhanced Security Control Data Classes
@dataclass
class SubControl:
    id: str
    title: str
    description: str
    implementation_guidance: str
    testing_procedures: str
    priority: ControlPriority
    implementation_level: ImplementationLevel
    status: ControlStatus
    notes: str
    last_assessed: Optional[date]
    assessor: str
    evidence: str
    remediation_plan: str
    target_completion: Optional[date]
    cost_estimate: Optional[float]
    effort_estimate: str  # e.g., "2 weeks", "1 month"
    dependencies: List[str]  # IDs of other controls this depends on
    risk_mitigation: str
    compliance_impact: str

@dataclass
class SecurityControl:
    id: str
    title: str
    description: str
    category: ControlCategory
    priority: ControlPriority
    framework: ControlFramework
    reference_id: str  # e.g., "NIS2-1.1", "ISO-5.1"
    nis2_requirement: bool  # Whether this control is required for NIS2 compliance
    sub_controls: List[SubControl]
    overall_status: ControlStatus
    implementation_level: ImplementationLevel
    compliance_status: ComplianceStatus
    last_assessed: Optional[date]
    assessor: str
    notes: str
    risk_score: int  # Calculated based on priority and status
    business_impact: str
    technical_complexity: str  # "Low", "Medium", "High"
    resource_requirements: str
    timeline: str
    success_criteria: List[str]
    key_metrics: List[str]
    audit_evidence: List[str]
    exceptions: List[str]
    waivers: List[str]


@dataclass
class OrganizationControlAssessment:
    """Assessment of a specific control for an organization."""
    organization_id: str
    control_id: str
    control_title: str
    control_category: ControlCategory
    control_priority: ControlPriority
    control_framework: ControlFramework
    reference_id: str
    overall_status: ControlStatus
    implementation_level: ImplementationLevel
    compliance_status: ComplianceStatus
    sub_controls_assessment: List[SubControl]
    last_assessed: Optional[date]
    assessor: str
    notes: str
    risk_score: int
    business_impact: str
    technical_complexity: str
    resource_requirements: str
    timeline: str
    success_criteria: List[str]
    key_metrics: List[str]
    audit_evidence: List[str]
    exceptions: List[str]
    waivers: List[str]
    remediation_priority: str
    estimated_cost: Optional[float]
    estimated_effort: str
    dependencies: List[str]
    next_review_date: Optional[date]
    review_frequency: str  # e.g., "Monthly", "Quarterly", "Annually"

@dataclass
class OrganizationControls:
    """Complete security controls assessment for an organization."""
    organization_id: str
    organization_name: str
    assessment_date: date
    assessor: str
    framework_version: str
    overall_compliance_score: float  # 0-100
    risk_level: str  # "Low", "Medium", "High", "Critical"
    controls_assessed: List[OrganizationControlAssessment]
    summary_by_category: Dict[str, Dict[str, int]]  # category -> status -> count
    summary_by_priority: Dict[str, Dict[str, int]]  # priority -> status -> count
    summary_by_framework: Dict[str, Dict[str, int]]  # framework -> status -> count
    critical_gaps: List[str]
    high_priority_remediations: List[str]
    compliance_deadlines: List[Dict[str, Any]]
    next_assessment_date: date
    assessment_methodology: str
    evidence_repository: str
    stakeholder_approval: str
    audit_trail: List[Dict[str, Any]]


class SecurityControlsManager:
    """Manages security controls and organization assessments."""
    
    def __init__(self):
        """Initialize the security controls manager with predefined controls."""
        self.controls = {
            "GOV-001": SecurityControl(
                id="GOV-001",
                title="Information Security Policy",
                description="Establish and maintain comprehensive information security policies",
                category=ControlCategory.GOVERNANCE,
                priority=ControlPriority.CRITICAL,
                framework=ControlFramework.NIS2,
                reference_id="NIS2-1.1",
                nis2_requirement=True,
                sub_controls=[
                    SubControl(
                        id="GOV-001-001",
                        title="Policy Development",
                        description="Develop comprehensive information security policy",
                        implementation_guidance="Create policy covering all aspects of information security",
                        testing_procedures="Review policy document and stakeholder approval",
                        priority=ControlPriority.CRITICAL,
                        implementation_level=ImplementationLevel.BASIC,
                        status=ControlStatus.NOT_IMPLEMENTED,
                        notes="",
                        last_assessed=None,
                        assessor="",
                        evidence="",
                        remediation_plan="",
                        target_completion=None,
                        cost_estimate=None,
                        effort_estimate="2 weeks",
                        dependencies=[],
                        risk_mitigation="Reduces security incidents through clear guidance",
                        compliance_impact="Required for NIS2 compliance"
                    ),
                    SubControl(
                        id="GOV-001-002",
                        title="Policy Communication",
                        description="Communicate policy to all stakeholders",
                        implementation_guidance="Distribute policy and provide training",
                        testing_procedures="Verify policy acknowledgment and understanding",
                        priority=ControlPriority.HIGH,
                        implementation_level=ImplementationLevel.BASIC,
                        status=ControlStatus.NOT_IMPLEMENTED,
                        notes="",
                        last_assessed=None,
                        assessor="",
                        evidence="",
                        remediation_plan="",
                        target_completion=None,
                        cost_estimate=None,
                        effort_estimate="1 week",
                        dependencies=["GOV-001-001"],
                        risk_mitigation="Ensures policy awareness and compliance",
                        compliance_impact="Required for NIS2 compliance"
                    ),
                    SubControl(
                        id="GOV-001-003",
                        title="Policy Review and Updates",
                        description="Regular review and update of security policies",
                        implementation_guidance="Annual review with stakeholder input",
                        testing_procedures="Document review process and update history",
                        priority=ControlPriority.MEDIUM,
                        implementation_level=ImplementationLevel.INTERMEDIATE,
                        status=ControlStatus.NOT_IMPLEMENTED,
                        notes="",
                        last_assessed=None,
                        assessor="",
                        evidence="",
                        remediation_plan="",
                        target_completion=None,
                        cost_estimate=None,
                        effort_estimate="1 week annually",
                        dependencies=["GOV-001-001"],
                        risk_mitigation="Keeps policies current and relevant",
                        compliance_impact="Maintains NIS2 compliance"
                    )
                ],
                overall_status=ControlStatus.NOT_IMPLEMENTED,
                implementation_level=ImplementationLevel.BASIC,
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                last_assessed=None,
                assessor="",
                notes="",
                risk_score=0,
                business_impact="Critical for business operations and compliance",
                technical_complexity="Low",
                resource_requirements="Policy writer, legal review, stakeholder input",
                timeline="4 weeks",
                success_criteria=["Policy approved by management", "All staff trained", "Regular review process established"],
                key_metrics=["Policy coverage", "Staff awareness", "Review frequency"],
                audit_evidence=["Policy document", "Training records", "Review logs"],
                exceptions=[],
                waivers=[]
            ),
            "TECH-001": SecurityControl(
                id="TECH-001",
                title="Access Control Management",
                description="Implement comprehensive access control mechanisms",
                category=ControlCategory.TECHNICAL,
                priority=ControlPriority.CRITICAL,
                framework=ControlFramework.NIS2,
                reference_id="NIS2-2.1",
                nis2_requirement=True,
                sub_controls=[
                    SubControl(
                        id="TECH-001-001",
                        title="User Authentication",
                        description="Implement strong user authentication",
                        implementation_guidance="Multi-factor authentication for all users",
                        testing_procedures="Test authentication mechanisms and password policies",
                        priority=ControlPriority.CRITICAL,
                        implementation_level=ImplementationLevel.BASIC,
                        status=ControlStatus.NOT_IMPLEMENTED,
                        notes="",
                        last_assessed=None,
                        assessor="",
                        evidence="",
                        remediation_plan="",
                        target_completion=None,
                        cost_estimate=None,
                        effort_estimate="3 weeks",
                        dependencies=[],
                        risk_mitigation="Prevents unauthorized access",
                        compliance_impact="Required for NIS2 compliance"
                    ),
                    SubControl(
                        id="TECH-001-002",
                        title="Role-Based Access Control",
                        description="Implement role-based access control system",
                        implementation_guidance="Define roles and assign permissions",
                        testing_procedures="Verify role assignments and access rights",
                        priority=ControlPriority.HIGH,
                        implementation_level=ImplementationLevel.INTERMEDIATE,
                        status=ControlStatus.NOT_IMPLEMENTED,
                        notes="",
                        last_assessed=None,
                        assessor="",
                        evidence="",
                        remediation_plan="",
                        target_completion=None,
                        cost_estimate=None,
                        effort_estimate="4 weeks",
                        dependencies=["TECH-001-001"],
                        risk_mitigation="Limits access to necessary resources",
                        compliance_impact="Required for NIS2 compliance"
                    ),
                    SubControl(
                        id="TECH-001-003",
                        title="Access Monitoring",
                        description="Monitor and log access activities",
                        implementation_guidance="Implement comprehensive logging and monitoring",
                        testing_procedures="Verify log generation and retention",
                        priority=ControlPriority.MEDIUM,
                        implementation_level=ImplementationLevel.ADVANCED,
                        status=ControlStatus.NOT_IMPLEMENTED,
                        notes="",
                        last_assessed=None,
                        assessor="",
                        evidence="",
                        remediation_plan="",
                        target_completion=None,
                        cost_estimate=None,
                        effort_estimate="2 weeks",
                        dependencies=["TECH-001-001", "TECH-001-002"],
                        risk_mitigation="Detects unauthorized access attempts",
                        compliance_impact="Required for NIS2 compliance"
                    )
                ],
                overall_status=ControlStatus.NOT_IMPLEMENTED,
                implementation_level=ImplementationLevel.BASIC,
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                last_assessed=None,
                assessor="",
                notes="",
                risk_score=0,
                business_impact="Critical for protecting sensitive data and systems",
                technical_complexity="High",
                resource_requirements="Security engineers, system administrators, training",
                timeline="8 weeks",
                success_criteria=["MFA implemented", "RBAC system operational", "Monitoring active"],
                key_metrics=["Authentication success rate", "Access violations", "System availability"],
                audit_evidence=["Access logs", "User accounts", "Role definitions"],
                exceptions=[],
                waivers=[]
            ),
            "OPS-001": SecurityControl(
                id="OPS-001",
                title="Security Operations Center",
                description="Establish security operations center for monitoring and response",
                category=ControlCategory.OPERATIONAL,
                priority=ControlPriority.HIGH,
                framework=ControlFramework.NIS2,
                reference_id="NIS2-3.1",
                nis2_requirement=True,
                sub_controls=[
                    SubControl(
                        id="OPS-001-001",
                        title="24/7 Monitoring",
                        description="Implement 24/7 security monitoring",
                        implementation_guidance="Continuous monitoring of security events",
                        testing_procedures="Test monitoring systems and alert mechanisms",
                        priority=ControlPriority.HIGH,
                        implementation_level=ImplementationLevel.ENTERPRISE,
                        status=ControlStatus.NOT_IMPLEMENTED,
                        notes="",
                        last_assessed=None,
                        assessor="",
                        evidence="",
                        remediation_plan="",
                        target_completion=None,
                        cost_estimate=None,
                        effort_estimate="6 weeks",
                        dependencies=[],
                        risk_mitigation="Early detection of security threats",
                        compliance_impact="Required for NIS2 compliance"
                    ),
                    SubControl(
                        id="OPS-001-002",
                        title="Incident Response",
                        description="Establish incident response procedures",
                        implementation_guidance="Define response procedures and escalation",
                        testing_procedures="Conduct incident response exercises",
                        priority=ControlPriority.HIGH,
                        implementation_level=ImplementationLevel.INTERMEDIATE,
                        status=ControlStatus.NOT_IMPLEMENTED,
                        notes="",
                        last_assessed=None,
                        assessor="",
                        evidence="",
                        remediation_plan="",
                        target_completion=None,
                        cost_estimate=None,
                        effort_estimate="4 weeks",
                        dependencies=["OPS-001-001"],
                        risk_mitigation="Reduces impact of security incidents",
                        compliance_impact="Required for NIS2 compliance"
                    )
                ],
                overall_status=ControlStatus.NOT_IMPLEMENTED,
                implementation_level=ImplementationLevel.BASIC,
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                last_assessed=None,
                assessor="",
                notes="",
                risk_score=0,
                business_impact="Critical for business continuity and incident response",
                technical_complexity="High",
                resource_requirements="Security analysts, monitoring tools, procedures",
                timeline="10 weeks",
                success_criteria=["24/7 monitoring active", "Response procedures tested", "Team trained"],
                key_metrics=["Response time", "False positive rate", "Incident resolution time"],
                audit_evidence=["Monitoring logs", "Response procedures", "Exercise results"],
                exceptions=[],
                waivers=[]
            )
        }
        self.organization_assessments: Dict[str, OrganizationControls] = {}
        self.controls_file = "security_controls.json"
        self.assessments_file = "organization_controls.json"
        self._initialize_default_controls()
        self.load_data()
    
    def _initialize_default_controls(self):
        """Initialize default security controls."""
        # The controls are now defined in the __init__ method with the new structure
        # This method is kept for backward compatibility but no longer needed
        pass
    
    def get_controls_by_category(self, category: ControlCategory) -> List[SecurityControl]:
        """Get all controls for a specific category."""
        return [control for control in self.controls.values() if control.category == category]
    
    def get_controls_by_framework(self, framework: ControlFramework) -> List[SecurityControl]:
        """Get all controls for a specific framework."""
        return [control for control in self.controls.values() if control.framework == framework]
    
    def get_mandatory_controls(self) -> List[SecurityControl]:
        """Get all mandatory controls."""
        return [control for control in self.controls.values() if control.priority == ControlPriority.CRITICAL]
    
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
            assessment_date=datetime.now().date(),
            assessor="",
            framework_version="",
            overall_compliance_score=0.0,
            risk_level="",
            controls_assessed=[],
            summary_by_category={},
            summary_by_priority={},
            summary_by_framework={},
            critical_gaps=[],
            high_priority_remediations=[],
            compliance_deadlines=[],
            next_assessment_date=datetime.now().date() + timedelta(days=30),
            assessment_methodology="",
            evidence_repository="",
            stakeholder_approval="",
            audit_trail=[]
        )
        
        # Initialize all controls as not implemented
        for control_id in self.controls:
            control = self.controls[control_id]
            assessment.controls_assessed.append(OrganizationControlAssessment(
                organization_id=organization_id,
                control_id=control.id,
                control_title=control.title,
                control_category=control.category,
                control_priority=control.priority,
                control_framework=control.framework,
                reference_id=control.reference_id,
                overall_status=ControlStatus.NOT_IMPLEMENTED,
                implementation_level=ImplementationLevel.BASIC,
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                sub_controls_assessment=[],
                last_assessed=datetime.now().date(),
                assessor="",
                notes="",
                risk_score=0,
                business_impact="",
                technical_complexity="",
                resource_requirements="",
                timeline="",
                success_criteria=[],
                key_metrics=[],
                audit_evidence=[],
                exceptions=[],
                waivers=[],
                remediation_priority="",
                estimated_cost=None,
                estimated_effort="",
                dependencies=[],
                next_review_date=datetime.now().date() + timedelta(days=90),
                review_frequency="Monthly"
            ))
        
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
            
            # Find the control assessment to update
            control_assessment_to_update = None
            for ca in assessment.controls_assessed:
                if ca.control_id == control_id:
                    control_assessment_to_update = ca
                    break
            
            if not control_assessment_to_update:
                return False # Control not found in assessment
            
            # Update control assessment details
            control_assessment_to_update.overall_status = status
            control_assessment_to_update.last_assessed = datetime.now().date()
            control_assessment_to_update.assessor = responsible_person
            control_assessment_to_update.notes = notes
            control_assessment_to_update.risk_score = 0 # Placeholder, needs actual calculation
            control_assessment_to_update.business_impact = "" # Placeholder
            control_assessment_to_update.technical_complexity = "" # Placeholder
            control_assessment_to_update.resource_requirements = "" # Placeholder
            control_assessment_to_update.timeline = "" # Placeholder
            control_assessment_to_update.success_criteria = [] # Placeholder
            control_assessment_to_update.key_metrics = [] # Placeholder
            control_assessment_to_update.audit_evidence = [] # Placeholder
            control_assessment_to_update.exceptions = [] # Placeholder
            control_assessment_to_update.waivers = [] # Placeholder
            control_assessment_to_update.remediation_priority = "" # Placeholder
            control_assessment_to_update.estimated_cost = None # Placeholder
            control_assessment_to_update.estimated_effort = "" # Placeholder
            control_assessment_to_update.dependencies = [] # Placeholder
            control_assessment_to_update.next_review_date = datetime.now().date() + timedelta(days=90) # Placeholder
            control_assessment_to_update.review_frequency = "Monthly" # Placeholder

            # Update sub-control assessments if they exist
            for sub_control_assessment in control_assessment_to_update.sub_controls_assessment:
                if sub_control_assessment.id == control_id: # This logic needs refinement if sub_controls_assessment is a list of SubControl objects
                    sub_control_assessment.status = status
                    sub_control_assessment.last_assessed = datetime.now().date()
                    sub_control_assessment.assessor = responsible_person
                    sub_control_assessment.notes = notes
                    sub_control_assessment.risk_score = 0 # Placeholder
                    sub_control_assessment.business_impact = "" # Placeholder
                    sub_control_assessment.technical_complexity = "" # Placeholder
                    sub_control_assessment.resource_requirements = "" # Placeholder
                    sub_control_assessment.timeline = "" # Placeholder
                    sub_control_assessment.success_criteria = [] # Placeholder
                    sub_control_assessment.key_metrics = [] # Placeholder
                    sub_control_assessment.audit_evidence = [] # Placeholder
                    sub_control_assessment.exceptions = [] # Placeholder
                    sub_control_assessment.waivers = [] # Placeholder
                    sub_control_assessment.remediation_plan = "" # Placeholder
                    sub_control_assessment.target_completion = datetime.now().date() + timedelta(days=30) # Placeholder
                    sub_control_assessment.cost_estimate = None # Placeholder
                    sub_control_assessment.effort_estimate = "" # Placeholder
                    sub_control_assessment.dependencies = [] # Placeholder
                    sub_control_assessment.risk_mitigation = "" # Placeholder
                    sub_control_assessment.compliance_impact = "" # Placeholder

            # Re-calculate overall compliance score and update summary
            self._calculate_overall_compliance_score(assessment)
            self._update_summary_by_category(assessment)
            self._update_summary_by_priority(assessment)
            self._update_summary_by_framework(assessment)

            # Save data
            self.save_data()
            return True
            
        except Exception as e:
            return False
    
    def _calculate_overall_compliance_score(self, assessment: OrganizationControls):
        """Calculate overall compliance score."""
        if not assessment.controls_assessed:
            assessment.overall_compliance_score = 0.0
            return
        
        total_controls = len(assessment.controls_assessed)
        compliant_controls = 0
        
        for control_assessment in assessment.controls_assessed:
            if control_assessment.overall_status == ControlStatus.IMPLEMENTED:
                compliant_controls += 1
            elif control_assessment.overall_status == ControlStatus.PARTIALLY_IMPLEMENTED:
                compliant_controls += 0.5
        
        assessment.overall_compliance_score = (compliant_controls / total_controls) * 100
    
    def _update_summary_by_category(self, assessment: OrganizationControls):
        """Update summary by category."""
        assessment.summary_by_category = {}
        for control_assessment in assessment.controls_assessed:
            category_name = control_assessment.control_category.value
            if category_name not in assessment.summary_by_category:
                assessment.summary_by_category[category_name] = {}
            
            status_count = assessment.summary_by_category[category_name]
            if control_assessment.overall_status == ControlStatus.IMPLEMENTED:
                status_count["Fully Implemented"] = status_count.get("Fully Implemented", 0) + 1
            elif control_assessment.overall_status == ControlStatus.PARTIALLY_IMPLEMENTED:
                status_count["Partially Implemented"] = status_count.get("Partially Implemented", 0) + 1
            elif control_assessment.overall_status == ControlStatus.NOT_IMPLEMENTED:
                status_count["Not Implemented"] = status_count.get("Not Implemented", 0) + 1
            elif control_assessment.overall_status == ControlStatus.NOT_APPLICABLE:
                status_count["Not Applicable"] = status_count.get("Not Applicable", 0) + 1
    
    def _update_summary_by_priority(self, assessment: OrganizationControls):
        """Update summary by priority."""
        assessment.summary_by_priority = {}
        for control_assessment in assessment.controls_assessed:
            priority_name = control_assessment.control_priority.value
            if priority_name not in assessment.summary_by_priority:
                assessment.summary_by_priority[priority_name] = {}
            
            status_count = assessment.summary_by_priority[priority_name]
            if control_assessment.overall_status == ControlStatus.IMPLEMENTED:
                status_count["Fully Implemented"] = status_count.get("Fully Implemented", 0) + 1
            elif control_assessment.overall_status == ControlStatus.PARTIALLY_IMPLEMENTED:
                status_count["Partially Implemented"] = status_count.get("Partially Implemented", 0) + 1
            elif control_assessment.overall_status == ControlStatus.NOT_IMPLEMENTED:
                status_count["Not Implemented"] = status_count.get("Not Implemented", 0) + 1
            elif control_assessment.overall_status == ControlStatus.NOT_APPLICABLE:
                status_count["Not Applicable"] = status_count.get("Not Applicable", 0) + 1
    
    def _update_summary_by_framework(self, assessment: OrganizationControls):
        """Update summary by framework."""
        assessment.summary_by_framework = {}
        for control_assessment in assessment.controls_assessed:
            framework_name = control_assessment.control_framework.value
            if framework_name not in assessment.summary_by_framework:
                assessment.summary_by_framework[framework_name] = {}
            
            status_count = assessment.summary_by_framework[framework_name]
            if control_assessment.overall_status == ControlStatus.IMPLEMENTED:
                status_count["Fully Implemented"] = status_count.get("Fully Implemented", 0) + 1
            elif control_assessment.overall_status == ControlStatus.PARTIALLY_IMPLEMENTED:
                status_count["Partially Implemented"] = status_count.get("Partially Implemented", 0) + 1
            elif control_assessment.overall_status == ControlStatus.NOT_IMPLEMENTED:
                status_count["Not Implemented"] = status_count.get("Not Implemented", 0) + 1
            elif control_assessment.overall_status == ControlStatus.NOT_APPLICABLE:
                status_count["Not Applicable"] = status_count.get("Not Applicable", 0) + 1
    
    def get_implementation_summary(self, organization_id: str) -> Dict[str, int]:
        """Get implementation summary for an organization."""
        if organization_id not in self.organization_assessments:
            return {}
        
        assessment = self.organization_assessments[organization_id]
        summary = {
            "total": len(assessment.controls_assessed),
            "fully_implemented": 0,
            "partially_implemented": 0,
            "not_implemented": 0,
            "not_applicable": 0
        }
        
        for control_assessment in assessment.controls_assessed:
            if control_assessment.overall_status == ControlStatus.IMPLEMENTED:
                summary["fully_implemented"] += 1
            elif control_assessment.overall_status == ControlStatus.PARTIALLY_IMPLEMENTED:
                summary["partially_implemented"] += 1
            elif control_assessment.overall_status == ControlStatus.NOT_IMPLEMENTED:
                summary["not_implemented"] += 1
            elif control_assessment.overall_status == ControlStatus.NOT_APPLICABLE:
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
                serialized_controls: List[Dict] = []
                for ca in assessment.controls_assessed:
                    ca_dict = asdict(ca)
                    # Convert enum values back to enum objects for sub_controls_assessment
                    for sub_ca in ca_dict.get('sub_controls_assessment', []):
                        sub_ca['status'] = ControlStatus(sub_ca['status'])
                        sub_ca['priority'] = ControlPriority(sub_ca['priority'])
                        sub_ca['implementation_level'] = ImplementationLevel(sub_ca['implementation_level'])
                        sub_ca['compliance_status'] = ComplianceStatus(sub_ca['compliance_status'])
                    ca_dict['sub_controls_assessment'] = [SubControl(**sub_ca) for sub_ca in ca_dict['sub_controls_assessment']]

                    # Convert enum values back to enum objects for summary_by_category, etc.
                    ca_dict['control_category'] = ControlCategory(ca_dict['control_category'])
                    ca_dict['control_priority'] = ControlPriority(ca_dict['control_priority'])
                    ca_dict['control_framework'] = ControlFramework(ca_dict['control_framework'])
                    ca_dict['overall_status'] = ControlStatus(ca_dict['overall_status'])
                    ca_dict['implementation_level'] = ImplementationLevel(ca_dict['implementation_level'])
                    ca_dict['compliance_status'] = ComplianceStatus(ca_dict['compliance_status'])
                    ca_dict['next_review_date'] = datetime.strptime(ca_dict['next_review_date'], "%Y-%m-%d").date() if ca_dict['next_review_date'] else None
                    ca_dict['last_assessed'] = datetime.strptime(ca_dict['last_assessed'], "%Y-%m-%d").date() if ca_dict['last_assessed'] else None

                    serialized_controls.append(ca_dict)
                assessment_dict["controls_assessed"] = serialized_controls
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
                        controls_assessed: List[OrganizationControlAssessment] = []
                        for control_data in assessment_data.get('controls_assessed', []):
                            try:
                                # Convert enum values back to enum objects for sub_controls_assessment
                                sub_controls_assessment: List[SubControl] = []
                                for sub_control_data in control_data.get('sub_controls_assessment', []):
                                    sub_control_data['status'] = ControlStatus(sub_control_data['status'])
                                    sub_control_data['priority'] = ControlPriority(sub_control_data['priority'])
                                    sub_control_data['implementation_level'] = ImplementationLevel(sub_control_data['implementation_level'])
                                    sub_control_data['compliance_status'] = ComplianceStatus(sub_control_data['compliance_status'])
                                    sub_controls_assessment.append(SubControl(**sub_control_data))
                                control_data['sub_controls_assessment'] = sub_controls_assessment

                                # Convert enum values back to enum objects for summary_by_category, etc.
                                control_data['control_category'] = ControlCategory(control_data['control_category'])
                                control_data['control_priority'] = ControlPriority(control_data['control_priority'])
                                control_data['control_framework'] = ControlFramework(control_data['control_framework'])
                                control_data['overall_status'] = ControlStatus(control_data['overall_status'])
                                control_data['implementation_level'] = ImplementationLevel(control_data['implementation_level'])
                                control_data['compliance_status'] = ComplianceStatus(control_data['compliance_status'])
                                control_data['next_review_date'] = datetime.strptime(control_data['next_review_date'], "%Y-%m-%d").date() if control_data['next_review_date'] else None
                                control_data['last_assessed'] = datetime.strptime(control_data['last_assessed'], "%Y-%m-%d").date() if control_data['last_assessed'] else None

                                control_assessment = OrganizationControlAssessment(**control_data)
                                controls_assessed.append(control_assessment)
                            except Exception:
                                # Skip invalid control assessments
                                continue
                        
                        assessment_data['controls_assessed'] = controls_assessed
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

    def get_sub_control(self, control_id: str, sub_control_id: str) -> Optional[SubControl]:
        """Get a specific sub-control by ID."""
        if control_id in self.controls:
            control = self.controls[control_id]
            for sub_control in control.sub_controls:
                if sub_control.id == sub_control_id:
                    return sub_control
        return None
    
    def update_sub_control_assessment(self, organization_id: str, control_id: str, sub_control_id: str,
                                   status: ControlStatus, assessor: str, notes: str, evidence: str,
                                   remediation_plan: str, target_completion: Optional[date] = None,
                                   cost_estimate: Optional[float] = None, effort_estimate: str = "") -> bool:
        """Update assessment of a specific sub-control."""
        try:
            assessment = self.get_organization_assessment(organization_id)
            if not assessment:
                return False
            
            # Find the control assessment
            control_assessment = None
            for ca in assessment.controls_assessed:
                if ca.control_id == control_id:
                    control_assessment = ca
                    break
            
            if not control_assessment:
                return False
            
            # Find and update the sub-control assessment
            sub_control_updated = False
            for sub_ca in control_assessment.sub_controls_assessment:
                if sub_ca.id == sub_control_id:
                    sub_ca.status = status
                    sub_ca.last_assessed = datetime.now().date()
                    sub_ca.assessor = assessor
                    sub_ca.notes = notes
                    sub_ca.evidence = evidence
                    sub_ca.remediation_plan = remediation_plan
                    if target_completion:
                        sub_ca.target_completion = target_completion
                    if cost_estimate:
                        sub_ca.cost_estimate = cost_estimate
                    if effort_estimate:
                        sub_ca.effort_estimate = effort_estimate
                    sub_control_updated = True
                    break
            
            if not sub_control_updated:
                return False
            
            # Update overall control status based on sub-controls
            self._update_control_overall_status(control_assessment)
            
            # Recalculate overall compliance score
            self._calculate_overall_compliance_score(assessment)
            self._update_summary_by_category(assessment)
            self._update_summary_by_priority(assessment)
            self._update_summary_by_framework(assessment)
            
            # Save data
            self.save_data()
            return True
            
        except Exception as e:
            st.error(f"Error updating sub-control assessment: {e}")
            return False
    
    def _update_control_overall_status(self, control_assessment: OrganizationControlAssessment):
        """Update the overall status of a control based on its sub-controls."""
        if not control_assessment.sub_controls_assessment:
            return
        
        # Count sub-control statuses
        status_counts = {}
        for sub_control in control_assessment.sub_controls_assessment:
            status = sub_control.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        total_sub_controls = len(control_assessment.sub_controls_assessment)
        
        # Determine overall status based on sub-control statuses
        if status_counts.get(ControlStatus.IMPLEMENTED.value, 0) == total_sub_controls:
            control_assessment.overall_status = ControlStatus.IMPLEMENTED
            control_assessment.compliance_status = ComplianceStatus.COMPLIANT
        elif status_counts.get(ControlStatus.IMPLEMENTED.value, 0) > 0:
            control_assessment.overall_status = ControlStatus.PARTIALLY_IMPLEMENTED
            control_assessment.compliance_status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            control_assessment.overall_status = ControlStatus.NOT_IMPLEMENTED
            control_assessment.compliance_status = ComplianceStatus.NON_COMPLIANT
        
        # Calculate risk score based on priority and status
        priority_scores = {
            ControlPriority.CRITICAL: 5,
            ControlPriority.HIGH: 4,
            ControlPriority.MEDIUM: 3,
            ControlPriority.LOW: 2
        }
        
        status_scores = {
            ControlStatus.IMPLEMENTED: 1,
            ControlStatus.PARTIALLY_IMPLEMENTED: 3,
            ControlStatus.NOT_IMPLEMENTED: 5
        }
        
        base_score = priority_scores.get(control_assessment.control_priority, 3)
        status_multiplier = status_scores.get(control_assessment.overall_status, 5)
        control_assessment.risk_score = base_score * status_multiplier
    
    def get_control_dependencies(self, control_id: str) -> List[str]:
        """Get list of control dependencies."""
        if control_id in self.controls:
            control = self.controls[control_id]
            dependencies = []
            for sub_control in control.sub_controls:
                dependencies.extend(sub_control.dependencies)
            return list(set(dependencies))  # Remove duplicates
        return []
    
    def get_control_roadmap(self, organization_id: str) -> Dict[str, Any]:
        """Generate implementation roadmap for an organization."""
        assessment = self.get_organization_assessment(organization_id)
        if not assessment:
            return {}
        
        roadmap = {
            "immediate_actions": [],
            "short_term": [],
            "medium_term": [],
            "long_term": [],
            "estimated_total_cost": 0.0,
            "estimated_total_effort": "",
            "critical_path": [],
            "dependencies": {}
        }
        
        for control_assessment in assessment.controls_assessed:
            if control_assessment.overall_status == ControlStatus.NOT_IMPLEMENTED:
                control = self.controls.get(control_assessment.control_id)
                if control:
                    # Determine timeline based on complexity and dependencies
                    if control.technical_complexity == "Low" and not control_assessment.dependencies:
                        timeline = "immediate_actions"
                    elif control.technical_complexity == "Medium":
                        timeline = "short_term"
                    else:
                        timeline = "medium_term"
                    
                    roadmap[timeline].append({
                        "control_id": control.id,
                        "title": control.title,
                        "priority": control_assessment.control_priority.value,
                        "complexity": control.technical_complexity,
                        "estimated_cost": control_assessment.estimated_cost or 0.0,
                        "estimated_effort": control_assessment.estimated_effort,
                        "dependencies": control_assessment.dependencies
                    })
                    
                    if control_assessment.estimated_cost:
                        roadmap["estimated_total_cost"] += control_assessment.estimated_cost
        
        return roadmap
    
    def get_compliance_gap_analysis(self, organization_id: str) -> Dict[str, Any]:
        """Generate compliance gap analysis."""
        assessment = self.get_organization_assessment(organization_id)
        if not assessment:
            return {}
        
        gap_analysis = {
            "critical_gaps": [],
            "high_priority_gaps": [],
            "medium_priority_gaps": [],
            "low_priority_gaps": [],
            "nis2_compliance": {
                "compliant": 0,
                "partially_compliant": 0,
                "non_compliant": 0,
                "total": 0
            },
            "framework_compliance": {},
            "category_compliance": {}
        }
        
        for control_assessment in assessment.controls_assessed:
            # Categorize gaps by priority
            if control_assessment.overall_status == ControlStatus.NOT_IMPLEMENTED:
                gap_info = {
                    "control_id": control_assessment.control_id,
                    "title": control_assessment.control_title,
                    "category": control_assessment.control_category.value,
                    "framework": control_assessment.control_framework.value,
                    "risk_score": control_assessment.risk_score,
                    "business_impact": control_assessment.business_impact
                }
                
                if control_assessment.control_priority == ControlPriority.CRITICAL:
                    gap_analysis["critical_gaps"].append(gap_info)
                elif control_assessment.control_priority == ControlPriority.HIGH:
                    gap_analysis["high_priority_gaps"].append(gap_info)
                elif control_assessment.control_priority == ControlPriority.MEDIUM:
                    gap_analysis["medium_priority_gaps"].append(gap_info)
                else:
                    gap_analysis["low_priority_gaps"].append(gap_info)
            
            # Count NIS2 compliance
            if control_assessment.control_framework == ControlFramework.NIS2:
                gap_analysis["nis2_compliance"]["total"] += 1
                if control_assessment.compliance_status == ComplianceStatus.COMPLIANT:
                    gap_analysis["nis2_compliance"]["compliant"] += 1
                elif control_assessment.compliance_status == ComplianceStatus.PARTIALLY_COMPLIANT:
                    gap_analysis["nis2_compliance"]["partially_compliant"] += 1
                else:
                    gap_analysis["nis2_compliance"]["non_compliant"] += 1
        
        return gap_analysis


class SecurityControlsInterface:
    """Streamlit interface for security controls management."""
    
    def __init__(self):
        self.manager = SecurityControlsManager()
    
    def display_main_interface(self, organization_id: str, organization_name: str):
        """Display the main security controls interface."""
        st.header("🛡️ Security Controls Assessment")
        st.info(f"Assessing security controls for **{organization_name}**")
        
        # Initialize session state for selected control
        if 'selected_control' not in st.session_state:
            st.session_state.selected_control = None
        
        # Create tabs for different functions
        tab1, tab2, tab3, tab4 = st.tabs([
            "📊 Enhanced Dashboard",
            "🔍 Control Assessment",
            "📋 Control Register",
            "⚙️ Settings"
        ])
        
        with tab1:
            # Enhanced Dashboard
            self.display_enhanced_dashboard(organization_id)
        
        with tab2:
            # Control Assessment
            if st.session_state.selected_control:
                # Display selected control details
                self.display_control_details(organization_id, st.session_state.selected_control)
                
                # Back button
                if st.button("← Back to Dashboard", key="controls_back_to_dashboard"):
                    st.session_state.selected_control = None
                    st.rerun()
            else:
                # Control selection
                st.subheader("🔍 Select Control to Assess")
                
                # Filter options
                col1, col2 = st.columns(2)
                with col1:
                    selected_framework = st.selectbox(
                        "Framework",
                        options=[f.value for f in ControlFramework],
                        index=0,
                        key="control_framework_filter"
                    )
                
                with col2:
                    selected_category = st.selectbox(
                        "Category",
                        options=[c.value for c in ControlCategory],
                        index=0,
                        key="control_category_filter"
                    )
                
                # Filter controls
                filtered_controls = []
                for control in self.manager.controls.values():
                    if (control.framework.value == selected_framework and 
                        control.category.value == selected_category):
                        filtered_controls.append(control)
                
                if not filtered_controls:
                    st.info("No controls found for the selected criteria.")
                else:
                    # Display filtered controls
                    for control in filtered_controls:
                        with st.expander(f"{control.id}: {control.title}", expanded=False):
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown(f"**Description:** {control.description}")
                                st.markdown(f"**Framework:** {control.framework.value}")
                                st.markdown(f"**Category:** {control.category.value}")
                                st.markdown(f"**Priority:** {control.priority.value}")
                                st.markdown(f"**Reference ID:** {control.reference_id}")
                            
                            with col2:
                                st.markdown(f"**Business Impact:** {control.business_impact}")
                                st.markdown(f"**Technical Complexity:** {control.technical_complexity}")
                                st.markdown(f"**Resource Requirements:** {control.resource_requirements}")
                                st.markdown(f"**Timeline:** {control.timeline}")
                            
                            # Sub-controls preview
                            if control.sub_controls:
                                st.markdown("**Sub-Controls:**")
                                for sub_control in control.sub_controls:
                                    st.markdown(f"- **{sub_control.title}** ({sub_control.priority.value}): {sub_control.description}")
                            
                            # Assess button
                            if st.button(f"📝 Assess {control.title}", key=f"select_{control.id}"):
                                st.session_state.selected_control = control.id
                                st.rerun()
        
        with tab3:
            # Control Register
            self._display_control_register(organization_id)
        
        with tab4:
            # Settings
            st.subheader("⚙️ Security Controls Settings")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔄 Refresh Data", use_container_width=True):
                    self.manager.load_data()
                    st.success("✅ Data refreshed successfully!")
                    st.rerun()
            
            with col2:
                if st.button("📊 Generate Report", use_container_width=True):
                    st.info("Report generation functionality coming soon!")
            
            # Assessment settings
            st.markdown("---")
            st.subheader("📋 Assessment Configuration")
            
            # Get current assessment
            assessment = self.manager.get_organization_assessment(organization_id)
            if assessment:
                with st.form("assessment_settings"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        next_assessment = st.date_input(
                            "Next Assessment Date",
                            value=assessment.next_assessment_date,
                            key="next_assessment_date"
                        )
                        
                        assessment_methodology = st.text_input(
                            "Assessment Methodology",
                            value=assessment.assessment_methodology,
                            key="assessment_methodology"
                        )
                    
                    with col2:
                        evidence_repository = st.text_input(
                            "Evidence Repository",
                            value=assessment.evidence_repository,
                            key="evidence_repository"
                        )
                        
                        stakeholder_approval = st.text_input(
                            "Stakeholder Approval",
                            value=assessment.stakeholder_approval,
                            key="stakeholder_approval"
                        )
                    
                    if st.form_submit_button("💾 Save Settings", use_container_width=True):
                        assessment.next_assessment_date = next_assessment
                        assessment.assessment_methodology = assessment_methodology
                        assessment.evidence_repository = evidence_repository
                        assessment.stakeholder_approval = stakeholder_approval
                        
                        if self.manager.save_data():
                            st.success("✅ Assessment settings updated successfully!")
                            st.rerun()
    
    def display_enhanced_dashboard(self, organization_id: str):
        """Display enhanced security controls dashboard with granular insights."""
        assessment = self.manager.get_organization_assessment(organization_id)
        if not assessment:
            st.info("No assessment data available. Please complete an assessment first.")
            return
        
        st.subheader("📊 Enhanced Security Controls Dashboard")
        
        # Key metrics row
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Overall Compliance", f"{assessment.overall_compliance_score:.1f}%")
        with col2:
            st.metric("Controls Assessed", len(assessment.controls_assessed))
        with col3:
            st.metric("Risk Level", assessment.risk_level)
        with col4:
            st.metric("Next Assessment", assessment.next_assessment_date.strftime("%Y-%m-%d"))
        
        st.markdown("---")
        
        # Compliance by category
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("📈 Compliance by Category")
            if assessment.summary_by_category:
                category_data = {}
                for category, status_counts in assessment.summary_by_category.items():
                    total = sum(status_counts.values())
                    if total > 0:
                        compliant = status_counts.get("Fully Implemented", 0)
                        category_data[category] = (compliant / total) * 100
                
                if category_data:
                    st.bar_chart(category_data)
                else:
                    st.info("No category data available")
            else:
                st.info("No category data available")
        
        with col2:
            st.subheader("📊 Compliance by Priority")
            if assessment.summary_by_priority:
                priority_data = {}
                for priority, status_counts in assessment.summary_by_priority.items():
                    total = sum(status_counts.values())
                    if total > 0:
                        compliant = status_counts.get("Fully Implemented", 0)
                        priority_data[priority] = (compliant / total) * 100
                
                if priority_data:
                    st.bar_chart(priority_data)
                else:
                    st.info("No priority data available")
            else:
                st.info("No priority data available")
        
        # Gap analysis
        st.markdown("---")
        st.subheader("🚨 Compliance Gap Analysis")
        
        gap_analysis = self.manager.get_compliance_gap_analysis(organization_id)
        
        if gap_analysis:
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Critical Gaps:**")
                if gap_analysis["critical_gaps"]:
                    for gap in gap_analysis["critical_gaps"]:
                        st.error(f"🔴 {gap['title']} (Risk Score: {gap['risk_score']})")
                else:
                    st.success("✅ No critical gaps found")
                
                st.markdown("**High Priority Gaps:**")
                if gap_analysis["high_priority_gaps"]:
                    for gap in gap_analysis["high_priority_gaps"]:
                        st.warning(f"🟠 {gap['title']} (Risk Score: {gap['risk_score']})")
                else:
                    st.success("✅ No high priority gaps found")
            
            with col2:
                st.markdown("**NIS2 Compliance Status:**")
                nis2_stats = gap_analysis["nis2_compliance"]
                if nis2_stats["total"] > 0:
                    compliant_pct = (nis2_stats["compliant"] / nis2_stats["total"]) * 100
                    st.metric("NIS2 Compliance", f"{compliant_pct:.1f}%")
                    st.info(f"Compliant: {nis2_stats['compliant']}, Partially: {nis2_stats['partially_compliant']}, Non-compliant: {nis2_stats['non_compliant']}")
                else:
                    st.info("No NIS2 controls assessed")
        
        # Implementation roadmap
        st.markdown("---")
        st.subheader("🗺️ Implementation Roadmap")
        
        roadmap = self.manager.get_control_roadmap(organization_id)
        
        if roadmap:
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Immediate Actions (Next 30 days):**")
                if roadmap["immediate_actions"]:
                    for action in roadmap["immediate_actions"]:
                        st.info(f"⚡ {action['title']} - {action['estimated_effort']}")
                else:
                    st.success("✅ No immediate actions required")
                
                st.markdown("**Short Term (1-3 months):**")
                if roadmap["short_term"]:
                    for action in roadmap["short_term"]:
                        st.info(f"📅 {action['title']} - {action['estimated_effort']}")
                else:
                    st.success("✅ No short term actions required")
            
            with col2:
                st.markdown("**Medium Term (3-6 months):**")
                if roadmap["medium_term"]:
                    for action in roadmap["medium_term"]:
                        st.info(f"📅 {action['title']} - {action['estimated_effort']}")
                else:
                    st.success("✅ No medium term actions required")
                
                if roadmap["estimated_total_cost"] > 0:
                    st.metric("Estimated Total Cost", f"€{roadmap['estimated_total_cost']:,.2f}")
        
        # Control details table
        st.markdown("---")
        st.subheader("🔍 Control Assessment Details")
        
        # Filter options
        col1, col2, col3 = st.columns(3)
        with col1:
            status_filter = st.selectbox(
                "Filter by Status",
                options=["All"] + [status.value for status in ControlStatus],
                key="dashboard_status_filter"
            )
        with col2:
            category_filter = st.selectbox(
                "Filter by Category",
                options=["All"] + [cat.value for cat in ControlCategory],
                key="dashboard_category_filter"
            )
        with col3:
            priority_filter = st.selectbox(
                "Filter by Priority",
                options=["All"] + [pri.value for pri in ControlPriority],
                key="dashboard_priority_filter"
            )
        
        # Filter controls
        filtered_controls = []
        for control_assessment in assessment.controls_assessed:
            include = True
            
            if status_filter != "All" and control_assessment.overall_status.value != status_filter:
                include = False
            if category_filter != "All" and control_assessment.control_category.value != category_filter:
                include = False
            if priority_filter != "All" and control_assessment.control_priority.value != priority_filter:
                include = False
            
            if include:
                filtered_controls.append(control_assessment)
        
        # Display filtered controls
        if filtered_controls:
            for control_assessment in filtered_controls:
                with st.expander(f"🔒 {control_assessment.control_title} ({control_assessment.control_id})", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**Status:** {control_assessment.overall_status.value}")
                        st.markdown(f"**Compliance:** {control_assessment.compliance_status.value}")
                        st.markdown(f"**Category:** {control_assessment.control_category.value}")
                        st.markdown(f"**Priority:** {control_assessment.control_priority.value}")
                    
                    with col2:
                        st.markdown(f"**Risk Score:** {control_assessment.risk_score}")
                        st.markdown(f"**Implementation Level:** {control_assessment.implementation_level.value}")
                        st.markdown(f"**Last Assessed:** {control_assessment.last_assessed or 'Never'}")
                        st.markdown(f"**Next Review:** {control_assessment.next_review_date}")
                    
                    # Sub-controls summary
                    if control_assessment.sub_controls_assessment:
                        st.markdown("**Sub-Controls:**")
                        sub_control_summary = {}
                        for sub_control in control_assessment.sub_controls_assessment:
                            status = sub_control.status.value
                            sub_control_summary[status] = sub_control_summary.get(status, 0) + 1
                        
                        for status, count in sub_control_summary.items():
                            st.markdown(f"- {status}: {count}")
                    
                    # Action button
                    if st.button(f"📝 Assess {control_assessment.control_title}", key=f"assess_{control_assessment.control_id}"):
                        st.session_state.selected_control = control_assessment.control_id
                        st.rerun()
        else:
            st.info("No controls match the selected filters.")
        
        # Quick actions
        st.markdown("---")
        st.subheader("⚡ Quick Actions")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("🔄 Refresh Assessment", use_container_width=True):
                st.rerun()
        
        with col2:
            if st.button("📊 Export Report", use_container_width=True):
                st.info("Export functionality coming soon!")
        
        with col3:
            if st.button("📅 Schedule Review", use_container_width=True):
                st.info("Scheduling functionality coming soon!")

    def _display_control_register(self, organization_id: str):
        """Display the control register with filtering and search capabilities."""
        st.subheader("📋 Security Controls Register")
        
        # Get current assessment
        assessment = self.manager.get_organization_assessment(organization_id)
        if not assessment:
            st.info("No assessment data available. Please complete an assessment first.")
            return
        
        # Search and filter options
        col1, col2, col3 = st.columns(3)
        with col1:
            search_term = st.text_input("🔍 Search Controls", placeholder="Search by title or description", key="control_search")
        with col2:
            status_filter = st.selectbox(
                "Filter by Status",
                options=["All"] + [status.value for status in ControlStatus],
                key="register_status_filter"
            )
        with col3:
            category_filter = st.selectbox(
                "Filter by Category",
                options=["All"] + [cat.value for cat in ControlCategory],
                key="register_category_filter"
            )
        
        # Filter controls based on search and filters
        filtered_controls = []
        for control_assessment in assessment.controls_assessed:
            include = True
            
            # Search filter
            if search_term:
                search_lower = search_term.lower()
                if (search_lower not in control_assessment.control_title.lower() and 
                    search_lower not in control_assessment.notes.lower()):
                    include = False
            
            # Status filter
            if status_filter != "All" and control_assessment.overall_status.value != status_filter:
                include = False
            
            # Category filter
            if category_filter != "All" and control_assessment.control_category.value != category_filter:
                include = False
            
            if include:
                filtered_controls.append(control_assessment)
        
        # Display filtered controls
        if filtered_controls:
            # Sort by priority and status
            priority_order = {ControlPriority.CRITICAL: 1, ControlPriority.HIGH: 2, ControlPriority.MEDIUM: 3, ControlPriority.LOW: 4}
            filtered_controls.sort(key=lambda x: (priority_order.get(x.control_priority, 5), x.overall_status.value))
            
            for control_assessment in filtered_controls:
                # Get the control definition
                control = self.manager.get_control(control_assessment.control_id)
                if not control:
                    continue
                
                # Determine status color and icon
                status_color = {
                    ControlStatus.IMPLEMENTED: "🟢",
                    ControlStatus.PARTIALLY_IMPLEMENTED: "🟡",
                    ControlStatus.NOT_IMPLEMENTED: "🔴",
                    ControlStatus.VERIFIED: "✅",
                    ControlStatus.EXEMPT: "⚪"
                }.get(control_assessment.overall_status, "⚪")
                
                priority_icon = {
                    ControlPriority.CRITICAL: "🔴",
                    ControlPriority.HIGH: "🟠",
                    ControlPriority.MEDIUM: "🟡",
                    ControlPriority.LOW: "🟢"
                }.get(control_assessment.control_priority, "⚪")
                
                with st.expander(f"{status_color} {control_assessment.control_title} ({control_assessment.control_id})", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**Status:** {control_assessment.overall_status.value}")
                        st.markdown(f"**Compliance:** {control_assessment.compliance_status.value}")
                        st.markdown(f"**Category:** {control_assessment.control_category.value}")
                        st.markdown(f"**Priority:** {priority_icon} {control_assessment.control_priority.value}")
                        st.markdown(f"**Framework:** {control_assessment.control_framework.value}")
                        st.markdown(f"**Reference ID:** {control.reference_id}")
                    
                    with col2:
                        st.markdown(f"**Risk Score:** {control_assessment.risk_score}")
                        st.markdown(f"**Implementation Level:** {control_assessment.implementation_level.value}")
                        st.markdown(f"**Last Assessed:** {control_assessment.last_assessed or 'Never'}")
                        st.markdown(f"**Next Review:** {control_assessment.next_review_date}")
                        st.markdown(f"**Assessor:** {control_assessment.assessor or 'Not assigned'}")
                    
                    # Control description
                    st.markdown("**Description:**")
                    st.info(control.description)
                    
                    # Sub-controls summary
                    if control.sub_controls:
                        st.markdown("**Sub-Controls:**")
                        sub_control_summary = {}
                        for sub_control in control.sub_controls:
                            status = sub_control.status.value
                            sub_control_summary[status] = sub_control_summary.get(status, 0) + 1
                        
                        for status, count in sub_control_summary.items():
                            st.markdown(f"- {status}: {count}")
                    
                    # Notes and evidence
                    if control_assessment.notes:
                        st.markdown("**Assessment Notes:**")
                        st.warning(control_assessment.notes)
                    
                    # Action buttons
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button(f"📝 Assess {control_assessment.control_title}", key=f"assess_register_{control_assessment.control_id}"):
                            st.session_state.selected_control = control_assessment.control_id
                            st.rerun()
                    
                    with col2:
                        if st.button(f"🔍 View Details", key=f"view_register_{control_assessment.control_id}"):
                            st.session_state.selected_control = control_assessment.control_id
                            st.rerun()
        else:
            st.info("No controls match the selected filters.")
        
        # Summary statistics
        st.markdown("---")
        st.subheader("📊 Register Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_controls = len(assessment.controls_assessed)
            st.metric("Total Controls", total_controls)
        
        with col2:
            implemented_controls = len([c for c in assessment.controls_assessed if c.overall_status == ControlStatus.IMPLEMENTED])
            st.metric("Implemented", implemented_controls)
        
        with col3:
            partially_implemented = len([c for c in assessment.controls_assessed if c.overall_status == ControlStatus.PARTIALLY_IMPLEMENTED])
            st.metric("Partially Implemented", partially_implemented)
        
        with col4:
            not_implemented = len([c for c in assessment.controls_assessed if c.overall_status == ControlStatus.NOT_IMPLEMENTED])
            st.metric("Not Implemented", not_implemented)
        
        # Export options
        st.markdown("---")
        st.subheader("📤 Export Options")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("📊 Export to CSV", use_container_width=True):
                st.info("CSV export functionality coming soon!")
        
        with col2:
            if st.button("📋 Export to PDF", use_container_width=True):
                st.info("PDF export functionality coming soon!")
        
        with col3:
            if st.button("🔄 Refresh Register", use_container_width=True):
                st.rerun()
    
    def _display_control_register(self, organization_id: str):
        """Display the control register with filtering and search capabilities."""
        st.subheader("📋 Security Controls Register")

        # Get current assessment
        assessment = self.manager.get_organization_assessment(organization_id)
        if not assessment:
            st.info("No assessment data available. Please complete an assessment first.")
            return

        # Search and filter options
        col1, col2, col3 = st.columns(3)
        with col1:
            search_term = st.text_input("🔍 Search Controls", placeholder="Search by title or description", key="control_search")
        with col2:
            status_filter = st.selectbox(
                "Filter by Status",
                options=["All"] + [status.value for status in ControlStatus],
                key="register_status_filter"
            )
        with col3:
            category_filter = st.selectbox(
                "Filter by Category",
                options=["All"] + [cat.value for cat in ControlCategory],
                key="register_category_filter"
            )

        # Filter controls based on search and filters
        filtered_controls = []
        for control_assessment in assessment.controls_assessed:
            include = True

            # Search filter
            if search_term:
                search_lower = search_term.lower()
                if (search_lower not in control_assessment.control_title.lower() and
                    search_lower not in control_assessment.notes.lower()):
                    include = False

            # Status filter
            if status_filter != "All" and control_assessment.overall_status.value != status_filter:
                include = False

            # Category filter
            if category_filter != "All" and control_assessment.control_category.value != category_filter:
                include = False

            if include:
                filtered_controls.append(control_assessment)

        # Display filtered controls
        if filtered_controls:
            # Sort by priority and status
            priority_order = {ControlPriority.CRITICAL: 1, ControlPriority.HIGH: 2, ControlPriority.MEDIUM: 3, ControlPriority.LOW: 4}
            filtered_controls.sort(key=lambda x: (priority_order.get(x.control_priority, 5), x.overall_status.value))

            for control_assessment in filtered_controls:
                # Get the control definition
                control = self.manager.get_control(control_assessment.control_id)
                if not control:
                    continue

                # Determine status color and icon
                status_color = {
                    ControlStatus.IMPLEMENTED: "🟢",
                    ControlStatus.PARTIALLY_IMPLEMENTED: "🟡",
                    ControlStatus.NOT_IMPLEMENTED: "🔴",
                    ControlStatus.VERIFIED: "✅",
                    ControlStatus.EXEMPT: "⚪"
                }.get(control_assessment.overall_status, "⚪")

                priority_icon = {
                    ControlPriority.CRITICAL: "🔴",
                    ControlPriority.HIGH: "🟠",
                    ControlPriority.MEDIUM: "🟡",
                    ControlPriority.LOW: "🟢"
                }.get(control_assessment.control_priority, "⚪")

                with st.expander(f"{status_color} {control_assessment.control_title} ({control_assessment.control_id})", expanded=False):
                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown(f"**Status:** {control_assessment.overall_status.value}")
                        st.markdown(f"**Compliance:** {control_assessment.compliance_status.value}")
                        st.markdown(f"**Category:** {control_assessment.control_category.value}")
                        st.markdown(f"**Priority:** {priority_icon} {control_assessment.control_priority.value}")
                        st.markdown(f"**Framework:** {control_assessment.control_framework.value}")
                        st.markdown(f"**Reference ID:** {control.reference_id}")

                    with col2:
                        st.markdown(f"**Risk Score:** {control_assessment.risk_score}")
                        st.markdown(f"**Implementation Level:** {control_assessment.implementation_level.value}")
                        st.markdown(f"**Last Assessed:** {control_assessment.last_assessed or 'Never'}")
                        st.markdown(f"**Next Review:** {control_assessment.next_review_date}")
                        st.markdown(f"**Assessor:** {control_assessment.assessor or 'Not assigned'}")

                    # Control description
                    st.markdown("**Description:**")
                    st.info(control.description)

                    # Sub-controls summary
                    if control.sub_controls:
                        st.markdown("**Sub-Controls:**")
                        sub_control_summary = {}
                        for sub_control in control.sub_controls:
                            status = sub_control.status.value
                            sub_control_summary[status] = sub_control_summary.get(status, 0) + 1

                        for status, count in sub_control_summary.items():
                            st.markdown(f"- {status}: {count}")

                    # Notes and evidence
                    if control_assessment.notes:
                        st.markdown("**Assessment Notes:**")
                        st.warning(control_assessment.notes)

                    # Action buttons
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button(f"📝 Assess {control_assessment.control_title}", key=f"assess_register_{control_assessment.control_id}"):
                            st.session_state.selected_control = control_assessment.control_id
                            st.rerun()

                    with col2:
                        if st.button(f"🔍 View Details", key=f"view_register_{control_assessment.control_id}"):
                            st.session_state.selected_control = control_assessment.control_id
                            st.rerun()
        else:
            st.info("No controls match the selected filters.")

        # Summary statistics
        st.markdown("---")
        st.subheader("📊 Register Summary")

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            total_controls = len(assessment.controls_assessed)
            st.metric("Total Controls", total_controls)

        with col2:
            implemented_controls = len([c for c in assessment.controls_assessed if c.overall_status == ControlStatus.IMPLEMENTED])
            st.metric("Implemented", implemented_controls)

        with col3:
            partially_implemented = len([c for c in assessment.controls_assessed if c.overall_status == ControlStatus.PARTIALLY_IMPLEMENTED])
            st.metric("Partially Implemented", partially_implemented)

        with col4:
            not_implemented = len([c for c in assessment.controls_assessed if c.overall_status == ControlStatus.NOT_IMPLEMENTED])
            st.metric("Not Implemented", not_implemented)

        # Export options
        st.markdown("---")
        st.subheader("📤 Export Options")

        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("📊 Export to CSV", use_container_width=True):
                st.info("CSV export functionality coming soon!")

        with col2:
            if st.button("📋 Export to PDF", use_container_width=True):
                st.info("PDF export functionality coming soon!")

        with col3:
            if st.button("🔄 Refresh Register", use_container_width=True):
                st.rerun()
