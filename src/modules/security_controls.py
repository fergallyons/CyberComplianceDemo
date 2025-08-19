"""
Simplified Security Controls Module for NIS2 Compliance
Provides NIS2 and CyberFundamentals controls as organization-level checklists.
"""

import streamlit as st
import json
import os
from datetime import datetime, date
from typing import Dict, List, Optional, Any


class SecurityControlsManager:
    """Simplified security controls manager focusing on NIS2 and CyberFundamentals."""
    
    def __init__(self):
        """Initialize with predefined NIS2 and CyberFundamentals controls."""
        self.controls_file = "security_controls.json"
        self.assessments_file = "organization_controls.json"
        
        # Define core NIS2 and CyberFundamentals controls
        self.default_controls = {
            "GOV-001": {
                "id": "GOV-001",
                "title": "Information Security Policy",
                "description": "Establish and maintain comprehensive information security policies",
                "category": "Governance",
                "priority": "Critical",
                "framework": "NIS2",
                "reference": "NIS2-1.1",
                "nis2_required": True,
                "sub_controls": [
                    {
                        "id": "GOV-001-001",
                        "title": "Policy Development",
                        "description": "Develop comprehensive information security policy",
                        "status": "Not Implemented"
                    },
                    {
                        "id": "GOV-001-002", 
                        "title": "Policy Communication",
                        "description": "Communicate policy to all stakeholders",
                        "status": "Not Implemented"
                    },
                    {
                        "id": "GOV-001-003",
                        "title": "Policy Review and Updates", 
                        "description": "Regular review and update of security policies",
                        "status": "Not Implemented"
                    }
                ]
            },
            "GOV-002": {
                "id": "GOV-002",
                "title": "Risk Management",
                "description": "Implement comprehensive risk management framework",
                "category": "Governance", 
                "priority": "Critical",
                "framework": "NIS2",
                "reference": "NIS2-1.2",
                "nis2_required": True,
                "sub_controls": [
                    {
                        "id": "GOV-002-001",
                        "title": "Risk Assessment",
                        "description": "Conduct regular risk assessments",
                        "status": "Not Implemented"
                    },
                    {
                        "id": "GOV-002-002",
                        "title": "Risk Treatment",
                        "description": "Implement risk treatment measures",
                        "status": "Not Implemented"
                    }
                ]
            },
            "TECH-001": {
                "id": "TECH-001",
                "title": "Access Control Management",
                "description": "Implement comprehensive access control mechanisms",
                "category": "Technical",
                "priority": "Critical", 
                "framework": "NIS2",
                "reference": "NIS2-2.1",
                "nis2_required": True,
                "sub_controls": [
                    {
                        "id": "TECH-001-001",
                        "title": "User Authentication",
                        "description": "Implement strong user authentication",
                        "status": "Not Implemented"
                    },
                    {
                        "id": "TECH-001-002",
                        "title": "Role-Based Access Control",
                        "description": "Implement role-based access control system",
                        "status": "Not Implemented"
                    },
                    {
                        "id": "TECH-001-003",
                        "title": "Access Monitoring",
                        "description": "Monitor and log access activities",
                        "status": "Not Implemented"
                    }
                ]
            },
            "TECH-002": {
                "id": "TECH-002",
                "title": "Network Security",
                "description": "Implement network security controls",
                "category": "Technical",
                "priority": "High",
                "framework": "NIS2", 
                "reference": "NIS2-2.2",
                "nis2_required": True,
                "sub_controls": [
                    {
                        "id": "TECH-002-001",
                        "title": "Network Segmentation",
                        "description": "Implement network segmentation",
                        "status": "Not Implemented"
                    },
                    {
                        "id": "TECH-002-002",
                        "title": "Firewall Configuration",
                        "description": "Configure and maintain firewalls",
                        "status": "Not Implemented"
                    }
                ]
            },
            "OPS-001": {
                "id": "OPS-001",
                "title": "Security Operations",
                "description": "Establish security operations center",
                "category": "Operational",
                "priority": "High",
                "framework": "NIS2",
                "reference": "NIS2-3.1", 
                "nis2_required": True,
                "sub_controls": [
                    {
                        "id": "OPS-001-001",
                        "title": "24/7 Monitoring",
                        "description": "Implement 24/7 security monitoring",
                        "status": "Not Implemented"
                    },
                    {
                        "id": "OPS-001-002",
                        "title": "Incident Response",
                        "description": "Establish incident response procedures",
                        "status": "Not Implemented"
                    }
                ]
            },
            "OPS-002": {
                "id": "OPS-002",
                "title": "Business Continuity",
                "description": "Implement business continuity planning",
                "category": "Operational",
                "priority": "High",
                "framework": "NIS2",
                "reference": "NIS2-3.2",
                "nis2_required": True,
                "sub_controls": [
                    {
                        "id": "OPS-002-001",
                        "title": "BCP Development",
                        "description": "Develop business continuity plan",
                        "status": "Not Implemented"
                    },
                    {
                        "id": "OPS-002-002",
                        "title": "BCP Testing",
                        "description": "Test business continuity procedures",
                        "status": "Not Implemented"
                    }
                ]
            },
            "PHYS-001": {
                "id": "PHYS-001",
                "title": "Physical Security",
                "description": "Implement physical security controls",
                "category": "Physical",
                "priority": "Medium",
                "framework": "CyberFundamentals",
                "reference": "CF-1.1",
                "nis2_required": False,
                "sub_controls": [
                    {
                        "id": "PHYS-001-001",
                        "title": "Access Control",
                        "description": "Control physical access to facilities",
                        "status": "Not Implemented"
                    },
                    {
                        "id": "PHYS-001-002",
                        "title": "Environmental Controls",
                        "description": "Implement environmental security controls",
                        "status": "Not Implemented"
                    }
                ]
            },
            "SUPPLY-001": {
                "id": "SUPPLY-001",
                "title": "Supply Chain Security",
                "description": "Implement supply chain security controls",
                "category": "Supply Chain",
                "priority": "Medium",
                "framework": "NIS2",
                "reference": "NIS2-4.1",
                "nis2_required": True,
                "sub_controls": [
                    {
                        "id": "SUPPLY-001-001",
                        "title": "Vendor Assessment",
                        "description": "Assess vendor security posture",
                        "status": "Not Implemented"
                    },
                    {
                        "id": "SUPPLY-001-002",
                        "title": "Contract Security",
                        "description": "Include security requirements in contracts",
                        "status": "Not Implemented"
                    }
                ]
            }
        }
        
        self.controls = self.default_controls.copy()
        self.organization_assessments = {}
        self.load_data()
    
    def get_controls_by_category(self, category: str) -> List[Dict]:
        """Get all controls for a specific category."""
        return [control for control in self.controls.values() if control["category"] == category]
    
    def get_controls_by_framework(self, framework: str) -> List[Dict]:
        """Get all controls for a specific framework."""
        return [control for control in self.controls.values() if control["framework"] == framework]
    
    def get_nis2_controls(self) -> List[Dict]:
        """Get all NIS2 required controls."""
        return [control for control in self.controls.values() if control["nis2_required"]]
    
    def get_control(self, control_id: str) -> Optional[Dict]:
        """Get a specific control by ID."""
        return self.controls.get(control_id)
    
    def create_organization_assessment(self, organization_id: str, organization_name: str) -> Dict:
        """Create a new organization controls assessment."""
        assessment = {
            "organization_id": organization_id,
            "organization_name": organization_name,
            "assessment_date": datetime.now().strftime("%Y-%m-%d"),
            "assessor": "",
            "overall_compliance_score": 0.0,
            "controls_assessed": []
        }
        
        # Initialize all controls as not implemented
        for control_id, control in self.controls.items():
            control_assessment = {
                "control_id": control_id,
                "title": control["title"],
                "category": control["category"],
                "priority": control["priority"],
                "framework": control["framework"],
                "reference": control["reference"],
                "nis2_required": control["nis2_required"],
                "overall_status": "Not Implemented",
                "last_assessed": None,
                "assessor": "",
                "notes": "",
                "sub_controls_assessment": []
            }
            
            # Initialize sub-controls
            for sub_control in control["sub_controls"]:
                sub_assessment = {
                    "id": sub_control["id"],
                    "title": sub_control["title"],
                    "status": "Not Implemented",
                    "notes": "",
                    "evidence": "",
                    "last_assessed": None,
                    "assessor": ""
                }
                control_assessment["sub_controls_assessment"].append(sub_assessment)
            
            assessment["controls_assessed"].append(control_assessment)
        
        self.organization_assessments[organization_id] = assessment
        self.save_data()
        return assessment
    
    def get_organization_assessment(self, organization_id: str) -> Optional[Dict]:
        """Get organization controls assessment."""
        return self.organization_assessments.get(organization_id)
    
    def update_control_assessment(self, organization_id: str, control_id: str, status: str, 
                                 assessor: str, notes: str) -> bool:
        """Update a control assessment for an organization."""
        try:
            assessment = self.get_organization_assessment(organization_id)
            if not assessment:
                return False
            
            # Find and update the control assessment
            for control_assessment in assessment["controls_assessed"]:
                if control_assessment["control_id"] == control_id:
                    control_assessment["overall_status"] = status
                    control_assessment["last_assessed"] = datetime.now().strftime("%Y-%m-%d")
                    control_assessment["assessor"] = assessor
                    control_assessment["notes"] = notes
                    
                    # Update sub-controls to match overall status
                    for sub_control in control_assessment["sub_controls_assessment"]:
                        sub_control["status"] = status
                        sub_control["last_assessed"] = datetime.now().strftime("%Y-%m-%d")
                        sub_control["assessor"] = assessor
                    
                    break
            
            # Recalculate compliance score
            self._calculate_compliance_score(assessment)
            
            # Save data
            self.save_data()
            return True
            
        except Exception as e:
            print(f"Error updating control assessment: {e}")
            return False
    
    def update_sub_control_assessment(self, organization_id: str, control_id: str, sub_control_id: str,
                                   status: str, assessor: str, notes: str, evidence: str) -> bool:
        """Update assessment of a specific sub-control."""
        try:
            assessment = self.get_organization_assessment(organization_id)
            if not assessment:
                return False
            
            # Find the control assessment
            for control_assessment in assessment["controls_assessed"]:
                if control_assessment["control_id"] == control_id:
                    # Find and update the sub-control assessment
                    for sub_control in control_assessment["sub_controls_assessment"]:
                        if sub_control["id"] == sub_control_id:
                            sub_control["status"] = status
                            sub_control["notes"] = notes
                            sub_control["evidence"] = evidence
                            sub_control["last_assessed"] = datetime.now().strftime("%Y-%m-%d")
                            sub_control["assessor"] = assessor
                            break
                    
                    # Update overall control status based on sub-controls
                    self._update_control_overall_status(control_assessment)
                    break
            
            # Recalculate compliance score
            self._calculate_compliance_score(assessment)
            
            # Save data
            self.save_data()
            return True
            
        except Exception as e:
            print(f"Error updating sub-control assessment: {e}")
            return False
    
    def _update_control_overall_status(self, control_assessment: Dict):
        """Update the overall status of a control based on its sub-controls."""
        if not control_assessment["sub_controls_assessment"]:
            return
        
        # Count sub-control statuses
        status_counts = {}
        for sub_control in control_assessment["sub_controls_assessment"]:
            status = sub_control["status"]
            status_counts[status] = status_counts.get(status, 0) + 1
        
        total_sub_controls = len(control_assessment["sub_controls_assessment"])
        
        # Determine overall status based on sub-control statuses
        if status_counts.get("Implemented", 0) == total_sub_controls:
            control_assessment["overall_status"] = "Implemented"
        elif status_counts.get("Implemented", 0) > 0:
            control_assessment["overall_status"] = "Partially Implemented"
        else:
            control_assessment["overall_status"] = "Not Implemented"
    
    def _calculate_compliance_score(self, assessment: Dict):
        """Calculate overall compliance score."""
        if not assessment["controls_assessed"]:
            assessment["overall_compliance_score"] = 0.0
            return
        
        total_controls = len(assessment["controls_assessed"])
        compliant_controls = 0
        
        for control_assessment in assessment["controls_assessed"]:
            if control_assessment["overall_status"] == "Implemented":
                compliant_controls += 1
            elif control_assessment["overall_status"] == "Partially Implemented":
                compliant_controls += 0.5
        
        assessment["overall_compliance_score"] = (compliant_controls / total_controls) * 100
    
    def get_implementation_summary(self, organization_id: str) -> Dict[str, int]:
        """Get implementation summary for an organization."""
        assessment = self.get_organization_assessment(organization_id)
        if not assessment:
            return {}
        
        summary = {
            "total": len(assessment["controls_assessed"]),
            "implemented": 0,
            "partially_implemented": 0,
            "not_implemented": 0
        }
        
        for control_assessment in assessment["controls_assessed"]:
            if control_assessment["overall_status"] == "Implemented":
                summary["implemented"] += 1
            elif control_assessment["overall_status"] == "Partially Implemented":
                summary["partially_implemented"] += 1
            else:
                summary["not_implemented"] += 1
        
        return summary
    
    def save_data(self):
        """Save security controls and organization assessments to JSON files."""
        try:
            # Save controls
            with open(self.controls_file, "w", encoding="utf-8") as f:
                json.dump(self.controls, f, indent=2, ensure_ascii=False)
            
            # Save organization assessments
            with open(self.assessments_file, "w", encoding="utf-8") as f:
                json.dump(self.organization_assessments, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            print(f"Error saving security controls data: {e}")

    def load_data(self):
        """Load security controls and organization assessments from JSON files."""
        try:
            # Load controls
            if os.path.exists(self.controls_file):
                with open(self.controls_file, "r", encoding="utf-8") as f:
                    loaded_controls = json.load(f)
                    # Only update if we actually loaded valid controls
                    if loaded_controls and isinstance(loaded_controls, dict):
                        self.controls = loaded_controls
                    else:
                        # If file is empty or invalid, use defaults
                        self.controls = self.default_controls.copy()
                        self.save_data()
            else:
                # Use default controls if file doesn't exist
                self.controls = self.default_controls.copy()
                self.save_data()
            
            # Load organization assessments
            if os.path.exists(self.assessments_file):
                with open(self.assessments_file, "r", encoding="utf-8") as f:
                    self.organization_assessments = json.load(f)
            else:
                self.organization_assessments = {}
                
        except Exception as e:
            print(f"Error loading security controls data: {e}")
            # Reset to defaults on error
            self.controls = self.default_controls.copy()
            self.organization_assessments = {}


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
        tab1, tab2, tab3 = st.tabs([
            "📊 Dashboard",
            "🔍 Control Assessment", 
            "📋 Control Register"
        ])
        
        with tab1:
            self.display_dashboard(organization_id)
        
        with tab2:
            if st.session_state.selected_control:
                self.display_control_details(organization_id, st.session_state.selected_control)
                
                # Back button
                if st.button("← Back to Dashboard", key="controls_back_to_dashboard"):
                    st.session_state.selected_control = None
                    st.rerun()
            else:
                self.display_control_selection(organization_id)
        
        with tab3:
            self.display_control_register(organization_id)
    
    def display_dashboard(self, organization_id: str):
        """Display the security controls dashboard."""
        st.subheader("📊 Security Controls Dashboard")
        
        # Get or create assessment
        assessment = self.manager.get_organization_assessment(organization_id)
        if not assessment:
            if st.button("🚀 Start Assessment", use_container_width=True):
                assessment = self.manager.create_organization_assessment(organization_id, "Demo Organization")
                st.success("✅ Assessment created successfully!")
                st.rerun()
            return
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Overall Compliance", f"{assessment['overall_compliance_score']:.1f}%")
        with col2:
            st.metric("Controls Assessed", len(assessment["controls_assessed"]))
        with col3:
            nis2_controls = [c for c in assessment["controls_assessed"] if c["nis2_required"]]
            st.metric("NIS2 Controls", len(nis2_controls))
        with col4:
            implemented = [c for c in assessment["controls_assessed"] if c["overall_status"] == "Implemented"]
            st.metric("Implemented", len(implemented))
        
        st.markdown("---")
        
        # Compliance by category
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("📈 Compliance by Category")
            category_data = {}
            for control in assessment["controls_assessed"]:
                category = control["category"]
                if category not in category_data:
                    category_data[category] = {"total": 0, "implemented": 0}
                
                category_data[category]["total"] += 1
                if control["overall_status"] == "Implemented":
                    category_data[category]["implemented"] += 1
            
            # Calculate percentages
            category_percentages = {}
            for category, counts in category_data.items():
                if counts["total"] > 0:
                    category_percentages[category] = (counts["implemented"] / counts["total"]) * 100
            
            if category_percentages:
                st.bar_chart(category_percentages)
            else:
                st.info("No category data available")
        
        with col2:
            st.subheader("📊 Compliance by Priority")
            priority_data = {}
            for control in assessment["controls_assessed"]:
                priority = control["priority"]
                if priority not in priority_data:
                    priority_data[priority] = {"total": 0, "implemented": 0}
                
                priority_data[priority]["total"] += 1
                if control["overall_status"] == "Implemented":
                    priority_data[priority]["implemented"] += 1
            
            # Calculate percentages
            priority_percentages = {}
            for priority, counts in priority_data.items():
                if counts["total"] > 0:
                    priority_percentages[priority] = (counts["implemented"] / counts["total"]) * 100
            
            if priority_percentages:
                st.bar_chart(priority_percentages)
            else:
                st.info("No priority data available")
        
        # Gap analysis
        st.markdown("---")
        st.subheader("🚨 Compliance Gap Analysis")
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Critical Gaps:**")
            critical_gaps = [c for c in assessment["controls_assessed"] 
                           if c["priority"] == "Critical" and c["overall_status"] != "Implemented"]
            if critical_gaps:
                for gap in critical_gaps:
                    st.error(f"🔴 {gap['title']}")
            else:
                st.success("✅ No critical gaps found")
            
            st.markdown("**High Priority Gaps:**")
            high_gaps = [c for c in assessment["controls_assessed"] 
                        if c["priority"] == "High" and c["overall_status"] != "Implemented"]
            if high_gaps:
                for gap in high_gaps:
                    st.warning(f"🟠 {gap['title']}")
            else:
                st.success("✅ No high priority gaps found")
        
        with col2:
            st.markdown("**NIS2 Compliance Status:**")
            nis2_controls = [c for c in assessment["controls_assessed"] if c["nis2_required"]]
            if nis2_controls:
                implemented_nis2 = [c for c in nis2_controls if c["overall_status"] == "Implemented"]
                partially_nis2 = [c for c in nis2_controls if c["overall_status"] == "Partially Implemented"]
                
                nis2_compliance = (len(implemented_nis2) / len(nis2_controls)) * 100
                st.metric("NIS2 Compliance", f"{nis2_compliance:.1f}%")
                st.info(f"Implemented: {len(implemented_nis2)}, Partially: {len(partially_nis2)}, Total: {len(nis2_controls)}")
            else:
                st.info("No NIS2 controls assessed")
        
        # Control summary table
        st.markdown("---")
        st.subheader("🔍 Control Assessment Summary")
        
        # Filter options
        col1, col2, col3 = st.columns(3)
        with col1:
            status_filter = st.selectbox(
                "Filter by Status",
                options=["All", "Implemented", "Partially Implemented", "Not Implemented"],
                key="dashboard_status_filter"
            )
        with col2:
            category_filter = st.selectbox(
                "Filter by Category",
                options=["All"] + list(set(c["category"] for c in assessment["controls_assessed"])),
                key="dashboard_category_filter"
            )
        with col3:
            priority_filter = st.selectbox(
                "Filter by Priority",
                options=["All", "Critical", "High", "Medium", "Low"],
                key="dashboard_priority_filter"
            )
        
        # Filter controls
        filtered_controls = []
        for control in assessment["controls_assessed"]:
            include = True
            
            if status_filter != "All" and control["overall_status"] != status_filter:
                include = False
            if category_filter != "All" and control["category"] != category_filter:
                include = False
            if priority_filter != "All" and control["priority"] != priority_filter:
                include = False
            
            if include:
                filtered_controls.append(control)
        
        # Display filtered controls
        if filtered_controls:
            for control in filtered_controls:
                status_icon = {
                    "Implemented": "🟢",
                    "Partially Implemented": "🟡",
                    "Not Implemented": "🔴"
                }.get(control["overall_status"], "⚪")
                
                priority_icon = {
                    "Critical": "🔴",
                    "High": "🟠", 
                    "Medium": "🟡",
                    "Low": "🟢"
                }.get(control["priority"], "⚪")
                
                with st.expander(f"{status_icon} {control['title']} ({control['control_id']})", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**Status:** {control['overall_status']}")
                        st.markdown(f"**Category:** {control['category']}")
                        st.markdown(f"**Priority:** {priority_icon} {control['priority']}")
                        st.markdown(f"**Framework:** {control['framework']}")
                    
                    with col2:
                        st.markdown(f"**Reference:** {control['reference']}")
                        st.markdown(f"**NIS2 Required:** {'Yes' if control['nis2_required'] else 'No'}")
                        st.markdown(f"**Last Assessed:** {control['last_assessed'] or 'Never'}")
                        st.markdown(f"**Assessor:** {control['assessor'] or 'Not assigned'}")
                    
                    # Sub-controls summary
                    if control["sub_controls_assessment"]:
                        st.markdown("**Sub-Controls:**")
                        sub_control_summary = {}
                        for sub_control in control["sub_controls_assessment"]:
                            status = sub_control["status"]
                            sub_control_summary[status] = sub_control_summary.get(status, 0) + 1
                        
                        for status, count in sub_control_summary.items():
                            st.markdown(f"- {status}: {count}")
                    
                    # Action button
                    if st.button(f"📝 Assess {control['title']}", key=f"assess_{control['control_id']}"):
                        st.session_state.selected_control = control['control_id']
                        st.rerun()
        else:
            st.info("No controls match the selected filters.")
    
    def display_control_selection(self, organization_id: str):
        """Display control selection interface."""
        st.subheader("🔍 Select Control to Assess")
        
        # Filter options
        col1, col2 = st.columns(2)
        with col1:
            selected_framework = st.selectbox(
                "Framework",
                options=["All", "NIS2", "CyberFundamentals"],
                key="control_framework_filter"
            )
        
        with col2:
            selected_category = st.selectbox(
                "Category",
                options=["All", "Governance", "Technical", "Operational", "Physical", "Supply Chain"],
                key="control_category_filter"
            )
        
        # Filter controls
        filtered_controls = []
        for control in self.manager.controls.values():
            include = True
            
            if selected_framework != "All" and control["framework"] != selected_framework:
                include = False
            if selected_category != "All" and control["category"] != selected_category:
                include = False
            
            if include:
                filtered_controls.append(control)
        
        if not filtered_controls:
            st.info("No controls found for the selected criteria.")
        else:
            # Display filtered controls
            for control in filtered_controls:
                with st.expander(f"{control['id']}: {control['title']}", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**Description:** {control['description']}")
                        st.markdown(f"**Framework:** {control['framework']}")
                        st.markdown(f"**Category:** {control['category']}")
                        st.markdown(f"**Priority:** {control['priority']}")
                    
                    with col2:
                        st.markdown(f"**Reference:** {control['reference']}")
                        st.markdown(f"**NIS2 Required:** {'Yes' if control['nis2_required'] else 'No'}")
                        st.markdown(f"**Sub-Controls:** {len(control['sub_controls'])}")
                    
                    # Sub-controls preview
                    if control["sub_controls"]:
                        st.markdown("**Sub-Controls:**")
                        for sub_control in control["sub_controls"]:
                            st.markdown(f"- **{sub_control['title']}**: {sub_control['description']}")
                    
                    # Assess button
                    if st.button(f"📝 Assess {control['title']}", key=f"select_{control['id']}"):
                        st.session_state.selected_control = control['id']
                        st.rerun()
    
    def display_control_details(self, organization_id: str, control_id: str):
        """Display detailed control assessment interface."""
        control = self.manager.get_control(control_id)
        assessment = self.manager.get_organization_assessment(organization_id)
        
        if not control or not assessment:
            st.error("Control or assessment not found.")
            return
        
        # Find control assessment
        control_assessment = None
        for ca in assessment["controls_assessed"]:
            if ca["control_id"] == control_id:
                control_assessment = ca
                break
        
        if not control_assessment:
            st.error("Control assessment not found.")
            return
        
        st.subheader(f"🔍 {control['title']} Assessment")
        
        # Control overview
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Control ID:** {control['id']}")
            st.markdown(f"**Category:** {control['category']}")
            st.markdown(f"**Priority:** {control['priority']}")
            st.markdown(f"**Framework:** {control['framework']}")
        
        with col2:
            st.markdown(f"**Reference:** {control['reference']}")
            st.markdown(f"**NIS2 Required:** {'Yes' if control['nis2_required'] else 'No'}")
            st.markdown(f"**Current Status:** {control_assessment['overall_status']}")
            st.markdown(f"**Last Assessed:** {control_assessment['last_assessed'] or 'Never'}")
        
        st.markdown("---")
        st.markdown(f"**Description:** {control['description']}")
        
        # Sub-controls assessment
        st.markdown("---")
        st.subheader("📋 Sub-Controls Assessment")
        
        for i, sub_control in enumerate(control["sub_controls"]):
            # Find sub-control assessment
            sub_assessment = None
            for sa in control_assessment["sub_controls_assessment"]:
                if sa["id"] == sub_control["id"]:
                    sub_assessment = sa
                    break
            
            if not sub_assessment:
                continue
            
            with st.expander(f"{sub_control['title']} ({sub_control['id']})", expanded=True):
                col1, col2 = st.columns(2)
                
                with col1:
                    status = st.selectbox(
                        "Status",
                        options=["Not Implemented", "Partially Implemented", "Implemented"],
                        index=["Not Implemented", "Partially Implemented", "Implemented"].index(sub_assessment["status"]),
                        key=f"status_{sub_control['id']}"
                    )
                    
                    assessor = st.text_input(
                        "Assessor",
                        value=sub_assessment["assessor"],
                        key=f"assessor_{sub_control['id']}"
                    )
                
                with col2:
                    notes = st.text_area(
                        "Notes",
                        value=sub_assessment["notes"],
                        key=f"notes_{sub_control['id']}"
                    )
                    
                    evidence = st.text_area(
                        "Evidence",
                        value=sub_assessment["evidence"],
                        key=f"evidence_{sub_control['id']}"
                    )
                
                # Update button
                if st.button(f"💾 Update {sub_control['title']}", key=f"update_{sub_control['id']}"):
                    if self.manager.update_sub_control_assessment(
                        organization_id, control_id, sub_control["id"], 
                        status, assessor, notes, evidence
                    ):
                        st.success("✅ Sub-control updated successfully!")
                        st.rerun()
                    else:
                        st.error("❌ Failed to update sub-control.")
        
        # Overall control assessment
        st.markdown("---")
        st.subheader("📊 Overall Control Assessment")
        
        col1, col2 = st.columns(2)
        with col1:
            overall_status = st.selectbox(
                "Overall Status",
                options=["Not Implemented", "Partially Implemented", "Implemented"],
                index=["Not Implemented", "Partially Implemented", "Implemented"].index(control_assessment["overall_status"]),
                key="overall_status"
            )
            
            overall_assessor = st.text_input(
                "Overall Assessor",
                value=control_assessment["assessor"],
                key="overall_assessor"
            )
        
        with col2:
            overall_notes = st.text_area(
                "Overall Notes",
                value=control_assessment["notes"],
                key="overall_notes"
            )
        
        # Update overall control
        if st.button("💾 Update Overall Control", key="update_overall"):
            if self.manager.update_control_assessment(
                organization_id, control_id, overall_status, 
                overall_assessor, overall_notes
            ):
                st.success("✅ Overall control updated successfully!")
                st.rerun()
            else:
                st.error("❌ Failed to update overall control.")
    
    def display_control_register(self, organization_id: str):
        """Display the control register."""
        st.subheader("📋 Security Controls Register")
        
        assessment = self.manager.get_organization_assessment(organization_id)
        if not assessment:
            st.info("No assessment data available. Please complete an assessment first.")
            return
        
        # Search and filter
        col1, col2 = st.columns(2)
        with col1:
            search_term = st.text_input("🔍 Search Controls", placeholder="Search by title", key="control_search")
        with col2:
            status_filter = st.selectbox(
                "Filter by Status",
                options=["All", "Implemented", "Partially Implemented", "Not Implemented"],
                key="register_status_filter"
            )
        
        # Filter controls
        filtered_controls = []
        for control_assessment in assessment["controls_assessed"]:
            include = True
            
            if search_term and search_term.lower() not in control_assessment["title"].lower():
                include = False
            
            if status_filter != "All" and control_assessment["overall_status"] != status_filter:
                include = False
            
            if include:
                filtered_controls.append(control_assessment)
        
        # Display controls
        if filtered_controls:
            for control_assessment in filtered_controls:
                status_icon = {
                    "Implemented": "🟢",
                    "Partially Implemented": "🟡",
                    "Not Implemented": "🔴"
                }.get(control_assessment["overall_status"], "⚪")
                
                priority_icon = {
                    "Critical": "🔴",
                    "High": "🟠",
                    "Medium": "🟡",
                    "Low": "🟢"
                }.get(control_assessment["priority"], "⚪")
                
                with st.expander(f"{status_icon} {control_assessment['title']} ({control_assessment['control_id']})", expanded=False):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**Status:** {control_assessment['overall_status']}")
                        st.markdown(f"**Category:** {control_assessment['category']}")
                        st.markdown(f"**Priority:** {priority_icon} {control_assessment['priority']}")
                        st.markdown(f"**Framework:** {control_assessment['framework']}")
                    
                    with col2:
                        st.markdown(f"**Reference:** {control_assessment['reference']}")
                        st.markdown(f"**NIS2 Required:** {'Yes' if control_assessment['nis2_required'] else 'No'}")
                        st.markdown(f"**Last Assessed:** {control_assessment['last_assessed'] or 'Never'}")
                        st.markdown(f"**Assessor:** {control_assessment['assessor'] or 'Not assigned'}")
                    
                    # Sub-controls summary
                    if control_assessment["sub_controls_assessment"]:
                        st.markdown("**Sub-Controls:**")
                        sub_control_summary = {}
                        for sub_control in control_assessment["sub_controls_assessment"]:
                            status = sub_control["status"]
                            sub_control_summary[status] = sub_control_summary.get(status, 0) + 1
                        
                        for status, count in sub_control_summary.items():
                            st.markdown(f"- {status}: {count}")
                    
                    # Notes
                    if control_assessment["notes"]:
                        st.markdown("**Notes:**")
                        st.info(control_assessment["notes"])
                    
                    # Action button
                    if st.button(f"📝 Assess {control_assessment['title']}", key=f"assess_register_{control_assessment['control_id']}"):
                        st.session_state.selected_control = control_assessment['control_id']
                        st.rerun()
        else:
            st.info("No controls match the selected filters.")
        
        # Summary statistics
        st.markdown("---")
        st.subheader("📊 Register Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_controls = len(assessment["controls_assessed"])
            st.metric("Total Controls", total_controls)
        
        with col2:
            implemented_controls = len([c for c in assessment["controls_assessed"] if c["overall_status"] == "Implemented"])
            st.metric("Implemented", implemented_controls)
        
        with col3:
            partially_implemented = len([c for c in assessment["controls_assessed"] if c["overall_status"] == "Partially Implemented"])
            st.metric("Partially Implemented", partially_implemented)
        
        with col4:
            not_implemented = len([c for c in assessment["controls_assessed"] if c["overall_status"] == "Not Implemented"])
            st.metric("Not Implemented", not_implemented)
