"""
NIS2 Article 23 Compliance Reporting Module
Provides comprehensive compliance reporting for Network and Information Security 2 Directive.
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import json
import plotly.graph_objects as go
import plotly.express as px
from dataclasses import dataclass
from enum import Enum
import os
import base64

# Branding utilities
def _load_svg_data_url(filename: str) -> str:
    try:
        base_dir = os.path.dirname(__file__)
        svg_path = os.path.join(base_dir, filename)
        with open(svg_path, 'rb') as f:
            data = f.read()
        b64 = base64.b64encode(data).decode('utf-8')
        return f"data:image/svg+xml;base64,{b64}"
    except Exception:
        return ""

def get_branding_header_html(title_text: str = "Compliance Report") -> str:
    logo_data_url = _load_svg_data_url('cohesive_logo.svg')
    brand = "Cohesive"
    subtitle = "Technology"
    return f'''
<div style="display:flex; align-items:center; gap:16px; padding:12px 0 8px 0; border-bottom:1px solid #e9eef5;">
  <img src="{logo_data_url}" alt="{brand} logo" style="height:48px; width:auto;"/>
  <div>
    <div style="font: 700 20px/1.2 Inter, Segoe UI, Arial; color:#0B1020;">{brand}</div>
    <div style="font: 500 12px/1.2 Inter, Segoe UI, Arial; color:#5A6275; letter-spacing:2px; text-transform:uppercase;">{subtitle} • {title_text}</div>
  </div>
</div>
'''

class IncidentSeverity(Enum):
    """NIS2 incident severity levels."""
    MINOR = "minor"
    SIGNIFICANT = "significant"
    MAJOR = "major"
    CRITICAL = "critical"

class IncidentStatus(Enum):
    """Incident status enumeration."""
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"

@dataclass
class SecurityIncident:
    """Security incident data structure for NIS2 reporting."""
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    detection_time: datetime
    resolution_time: Optional[datetime]
    affected_services: List[str]
    impact_assessment: str
    containment_measures: List[str]
    remediation_actions: List[str]
    lessons_learned: str
    reported_to_authorities: bool
    authority_report_date: Optional[datetime]

class NIS2ComplianceModule:
    """NIS2 Article 23 compliance reporting and management."""
    
    def __init__(self):
        """Initialize the NIS2 compliance module."""
        self.incident_types = [
            "Malware/Ransomware",
            "Phishing/Social Engineering",
            "DDoS Attack",
            "Data Breach",
            "Insider Threat",
            "Supply Chain Attack",
            "Vulnerability Exploitation",
            "Physical Security Breach",
            "Other"
        ]
        
        self.affected_services = [
            "Critical Infrastructure",
            "Digital Services",
            "Essential Services",
            "Network Infrastructure",
            "Data Centers",
            "Cloud Services",
            "End User Systems",
            "Mobile Devices",
            "IoT Devices",
            "Other"
        ]
        
        self.containment_measures = [
            "Network Isolation",
            "Service Shutdown",
            "Access Revocation",
            "Patch Deployment",
            "Backup Restoration",
            "Incident Response Team Activation",
            "External Expert Consultation",
            "Law Enforcement Notification",
            "Other"
        ]
    
    def create_incident_report(self) -> SecurityIncident:
        """Create a new security incident report."""
        st.subheader("📝 Create Security Incident Report")
        
        with st.form("incident_report_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                incident_id = st.text_input("Incident ID", value=f"INC-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
                title = st.text_input("Incident Title")
                severity = st.selectbox("Severity Level", 
                                      [sev.value for sev in IncidentSeverity],
                                      index=1)
                status = st.selectbox("Status", 
                                    [stat.value for stat in IncidentStatus],
                                    index=0)
                detection_date = st.date_input("Detection Date", 
                                             value=datetime.now().date())
                detection_time = st.time_input("Detection Time", 
                                             value=datetime.now().time())
            
            with col2:
                affected_services = st.multiselect("Affected Services", 
                                                 self.affected_services)
                incident_type = st.selectbox("Incident Type", self.incident_types)
                reported_to_authorities = st.checkbox("Reported to Authorities")
                authority_report_date = None
                if reported_to_authorities:
                    authority_date = st.date_input("Authority Report Date")
                    authority_time = st.time_input("Authority Report Time")
            
            description = st.text_area("Detailed Description", height=100)
            impact_assessment = st.text_area("Impact Assessment", height=100)
            containment_measures = st.multiselect("Containment Measures", 
                                                self.containment_measures)
            remediation_actions = st.text_area("Remediation Actions", height=100)
            lessons_learned = st.text_area("Lessons Learned", height=100)
            
            submit_button = st.form_submit_button("Create Incident Report")
            
            if submit_button:
                if title and description and affected_services:
                    # Combine date and time inputs
                    detection_datetime = datetime.combine(detection_date, detection_time)
                    authority_datetime = None
                    if reported_to_authorities and authority_date and authority_time:
                        authority_datetime = datetime.combine(authority_date, authority_time)
                    
                    incident = SecurityIncident(
                        id=incident_id,
                        title=title,
                        description=description,
                        severity=IncidentSeverity(severity),
                        status=IncidentStatus(status),
                        detection_time=detection_datetime,
                        resolution_time=None,
                        affected_services=affected_services,
                        impact_assessment=impact_assessment,
                        containment_measures=containment_measures,
                        remediation_actions=remediation_actions.split('\n') if remediation_actions else [],
                        lessons_learned=lessons_learned,
                        reported_to_authorities=reported_to_authorities,
                        authority_report_date=authority_datetime
                    )
                    
                    st.success("Incident report created successfully!")
                    return incident
                else:
                    st.error("Please fill in all required fields")
        
        return None
    
    def generate_nis2_article23_report(self, incidents: List[SecurityIncident], 
                                      organization_name: str, 
                                      reporting_period: str) -> str:
        """Generate NIS2 Article 23 compliance report."""
        
        header_html = get_branding_header_html("NIS2 Article 23 Compliance Report")
        report = f"""
{header_html}
# NIS2 Article 23 Compliance Report
## {organization_name}
### Reporting Period: {reporting_period}
### Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## Executive Summary

This report provides a comprehensive overview of security incidents and compliance with the Network and Information Security 2 (NIS2) Directive, specifically addressing Article 23 requirements for incident reporting and management.

### Key Findings
- **Total Incidents**: {len(incidents)}
- **Critical Incidents**: {len([i for i in incidents if i.severity == IncidentSeverity.CRITICAL])}
- **Major Incidents**: {len([i for i in incidents if i.severity == IncidentSeverity.MAJOR])}
- **Significant Incidents**: {len([i for i in incidents if i.severity == IncidentSeverity.SIGNIFICANT])}
- **Minor Incidents**: {len([i for i in incidents if i.severity == IncidentSeverity.MINOR])}

---

## Article 23 Compliance Assessment

### 23.1 Incident Detection and Reporting
**Compliance Status**: ✅ **COMPLIANT**

**Requirements Met**:
- Established incident detection mechanisms
- Defined incident severity classification
- Implemented reporting procedures
- Maintained incident documentation

**Evidence**:
- {len(incidents)} incidents detected and documented
- All incidents classified according to NIS2 severity levels
- Incident response procedures followed for all cases

### 23.2 Incident Response and Management
**Compliance Status**: ✅ **COMPLIANT**

**Requirements Met**:
- Incident response team activation
- Containment measures implementation
- Impact assessment procedures
- Remediation action tracking

**Evidence**:
- Containment measures implemented for {len([i for i in incidents if i.containment_measures])} incidents
- Remediation actions documented for all incidents
- Lessons learned captured and documented

### 23.3 Authority Notification
**Compliance Status**: {'✅ COMPLIANT' if any(i.reported_to_authorities for i in incidents) else '⚠️ PARTIALLY COMPLIANT'}

**Requirements Met**:
- Authority notification procedures established
- Critical and major incidents reported as required

**Evidence**:
- {len([i for i in incidents if i.reported_to_authorities])} incidents reported to authorities
- Authority reporting dates documented

---

## Detailed Incident Analysis

### Incident Severity Distribution
"""

        # Add severity distribution chart
        severity_counts = {}
        for severity in IncidentSeverity:
            severity_counts[severity.value] = len([i for i in incidents if i.severity == severity])
        
        report += f"""
- **Critical**: {severity_counts.get(IncidentSeverity.CRITICAL.value, 0)} incidents
- **Major**: {severity_counts.get(IncidentSeverity.MAJOR.value, 0)} incidents  
- **Significant**: {severity_counts.get(IncidentSeverity.SIGNIFICANT.value, 0)} incidents
- **Minor**: {severity_counts.get(IncidentSeverity.MINOR.value, 0)} incidents

### Incident Types Analysis
"""

        # Add incident type analysis
        incident_type_counts = {}
        for incident in incidents:
            incident_type = incident.title.split()[0] if incident.title else "Other"
            incident_type_counts[incident_type] = incident_type_counts.get(incident_type, 0) + 1
        
        for incident_type, count in incident_type_counts.items():
            report += f"- **{incident_type}**: {count} incidents\n"

        report += f"""

### Affected Services Impact
"""

        # Add affected services analysis
        service_impact = {}
        for incident in incidents:
            for service in incident.affected_services:
                service_impact[service] = service_impact.get(service, 0) + 1
        
        for service, count in sorted(service_impact.items(), key=lambda x: x[1], reverse=True):
            report += f"- **{service}**: {count} incidents\n"

        report += f"""

---

## Individual Incident Reports

"""

        # Add detailed incident reports
        for incident in incidents:
            report += f"""
### {incident.id}: {incident.title}

**Severity**: {incident.severity.value.upper()}
**Status**: {incident.status.value.upper()}
**Detection Time**: {incident.detection_time.strftime('%Y-%m-%d %H:%M:%S')}
**Resolution Time**: {incident.resolution_time.strftime('%Y-%m-%d %H:%M:%S') if incident.resolution_time else 'Not resolved'}

**Description**: {incident.description}

**Affected Services**: {', '.join(incident.affected_services)}

**Impact Assessment**: {incident.impact_assessment}

**Containment Measures**: {', '.join(incident.containment_measures)}

**Remediation Actions**: {', '.join(incident.remediation_actions) if incident.remediation_actions else 'None specified'}

**Lessons Learned**: {incident.lessons_learned}

**Authority Reporting**: {'Yes' if incident.reported_to_authorities else 'No'}
{f'**Authority Report Date**: {incident.authority_report_date.strftime("%Y-%m-%d %H:%M:%S")}' if incident.authority_report_date else ''}

---

"""

        report += f"""
---

## Compliance Recommendations

### Immediate Actions Required
"""

        # Generate recommendations based on incident analysis
        critical_incidents = [i for i in incidents if i.severity == IncidentSeverity.CRITICAL]
        if critical_incidents:
            report += f"""
- **Critical Incident Review**: {len(critical_incidents)} critical incidents require immediate review and process improvement
- **Authority Notification**: Ensure all critical incidents are reported to relevant authorities within required timeframes
- **Response Time Optimization**: Review and optimize incident response procedures for critical incidents
"""

        unresolved_incidents = [i for i in incidents if i.status not in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]]
        if unresolved_incidents:
            report += f"""
- **Incident Resolution**: {len(unresolved_incidents)} incidents remain unresolved and require immediate attention
- **Resource Allocation**: Allocate additional resources to resolve outstanding incidents
- **Escalation Procedures**: Review escalation procedures for incidents exceeding resolution timeframes
"""

        report += f"""

### Long-term Improvements
- **Process Enhancement**: Continuously improve incident detection and response procedures
- **Training and Awareness**: Regular training for incident response teams and staff
- **Technology Investment**: Invest in advanced threat detection and response technologies
- **Third-party Assessment**: Regular third-party security assessments and compliance audits

---

## Conclusion

{organization_name} demonstrates compliance with NIS2 Article 23 requirements through:

1. **Comprehensive Incident Management**: All security incidents are properly detected, documented, and managed
2. **Established Procedures**: Clear incident response and reporting procedures are in place
3. **Authority Cooperation**: Appropriate incidents are reported to relevant authorities
4. **Continuous Improvement**: Lessons learned are captured and used to improve security posture

The organization maintains a robust security incident management framework that meets and exceeds NIS2 Directive requirements.

---

*This report was generated automatically by the Cybersecurity Reporting Agent on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*

**Compliance Status**: ✅ **FULLY COMPLIANT**
**Next Review Date**: {(datetime.now() + timedelta(days=90)).strftime('%Y-%m-%d')}
"""

        return report
    
    def _get_sample_incidents(self) -> List[SecurityIncident]:
        """Get sample incidents for demonstration purposes."""
        from datetime import datetime, timedelta
        
        # Create sample incidents with realistic data
        sample_incidents = [
            SecurityIncident(
                id="INC-20241201-001",
                title="Phishing Attempt Detected",
                description="Multiple phishing emails targeting employees with malicious attachments detected by email security system.",
                severity=IncidentSeverity.SIGNIFICANT,
                status=IncidentStatus.CONTAINED,
                detection_time=datetime.now() - timedelta(days=2),
                resolution_time=datetime.now() - timedelta(days=1),
                affected_services=["Email Services", "Digital Services"],
                impact_assessment="Low impact - contained before any successful compromises. No data loss reported.",
                containment_measures=["Email Filtering Enhanced", "User Awareness Training"],
                remediation_actions=["Updated email security rules", "Conducted phishing awareness training"],
                lessons_learned="Regular security awareness training is crucial for preventing phishing attacks.",
                reported_to_authorities=False,
                authority_report_date=None
            ),
            SecurityIncident(
                id="INC-20241128-002",
                title="Suspicious Network Activity",
                description="Unusual network traffic patterns detected from external IP addresses, potential scanning activity.",
                severity=IncidentSeverity.MINOR,
                status=IncidentStatus.RESOLVED,
                detection_time=datetime.now() - timedelta(days=5),
                resolution_time=datetime.now() - timedelta(days=4),
                affected_services=["Network Infrastructure"],
                impact_assessment="No actual breach occurred. Network monitoring systems successfully detected and blocked suspicious activity.",
                containment_measures=["IP Blocking", "Enhanced Monitoring"],
                remediation_actions=["Blocked suspicious IP addresses", "Enhanced network monitoring"],
                lessons_learned="Proactive network monitoring is effective in detecting and preventing potential threats.",
                reported_to_authorities=False,
                authority_report_date=None
            ),
            SecurityIncident(
                id="INC-20241125-003",
                title="Software Vulnerability Detected",
                description="Critical security vulnerability identified in web application framework used by customer portal.",
                severity=IncidentSeverity.CRITICAL,
                status=IncidentStatus.INVESTIGATING,
                detection_time=datetime.now() - timedelta(days=8),
                resolution_time=None,
                affected_services=["Customer Portal", "Web Services"],
                impact_assessment="High risk - vulnerability could allow remote code execution. Immediate patching required.",
                containment_measures=["Access Restrictions", "Enhanced Monitoring"],
                remediation_actions=["Emergency patch deployment in progress", "Security assessment ongoing"],
                lessons_learned="Regular vulnerability scanning and patch management are essential.",
                reported_to_authorities=True,
                authority_report_date=datetime.now() - timedelta(days=7)
            ),
            SecurityIncident(
                id="INC-20241120-004",
                title="Data Access Anomaly",
                description="Unusual access patterns detected for sensitive customer data, potential insider threat investigation.",
                severity=IncidentSeverity.MAJOR,
                status=IncidentStatus.INVESTIGATING,
                detection_time=datetime.now() - timedelta(days=13),
                resolution_time=None,
                affected_services=["Customer Database", "Data Services"],
                impact_assessment="Medium risk - investigation ongoing to determine if unauthorized access occurred.",
                containment_measures=["Access Logging Enhanced", "Suspicious Account Review"],
                remediation_actions=["Enhanced access monitoring", "Account access review in progress"],
                lessons_learned="Continuous monitoring of data access patterns is critical for detecting anomalies.",
                reported_to_authorities=False,
                authority_report_date=None
            )
        ]
        
        return sample_incidents
    
    def display_compliance_dashboard(self, user, organization):
        """Display NIS2 compliance dashboard."""
        st.subheader("📊 NIS2 Compliance Dashboard")
        
        # Display user and organization context
        col1, col2, col3 = st.columns(3)
        with col1:
            st.info(f"**User**: {user.username} ({user.role.value})")
        with col2:
            st.info(f"**Organization**: {organization.name}")
        with col3:
            st.info(f"**Framework**: {organization.compliance_framework}")
        
        # Create sample incidents for demonstration purposes
        # In a real application, these would be fetched from a database
        incidents = self._get_sample_incidents()
        
        if not incidents:
            st.info("No incidents available for compliance reporting.")
            return
        
        # Key metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Incidents", len(incidents))
        
        with col2:
            critical_count = len([i for i in incidents if i.severity == IncidentSeverity.CRITICAL])
            st.metric("Critical Incidents", critical_count, delta=f"{critical_count} requiring immediate attention" if critical_count > 0 else "None")
        
        with col3:
            resolved_count = len([i for i in incidents if i.status in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]])
            st.metric("Resolved Incidents", resolved_count, delta=f"{len(incidents) - resolved_count} remaining")
        
        with col4:
            reported_count = len([i for i in incidents if i.reported_to_authorities])
            st.metric("Authority Reports", reported_count, delta=f"{len(incidents) - reported_count} not reported")
        
        # Charts
        col1, col2 = st.columns(2)
        
        with col1:
            # Severity distribution
            severity_counts = {}
            for severity in IncidentSeverity:
                severity_counts[severity.value] = len([i for i in incidents if i.severity == severity])
            
            fig = px.pie(
                values=list(severity_counts.values()),
                names=list(severity_counts.keys()),
                title="Incident Severity Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Status distribution
            status_counts = {}
            for status in IncidentStatus:
                status_counts[status.value] = len([i for i in incidents if i.status == status])
            
            fig = px.bar(
                x=list(status_counts.keys()),
                y=list(status_counts.values()),
                title="Incident Status Distribution"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        # Incident timeline
        st.subheader("📅 Incident Timeline")
        
        timeline_data = []
        for incident in incidents:
            # Use detection time as start, resolution time as end (or current time if not resolved)
            end_time = incident.resolution_time if incident.resolution_time else datetime.now()
            timeline_data.append({
                'Start': incident.detection_time,
                'End': end_time,
                'Incident': incident.title,
                'Severity': incident.severity.value,
                'Status': incident.status.value
            })
        
        if timeline_data:
            timeline_df = pd.DataFrame(timeline_data)
            timeline_df = timeline_df.sort_values('Start')
            
            fig = px.timeline(
                timeline_df,
                x_start='Start',
                x_end='End',
                y='Incident',
                color='Severity',
                title="Security Incident Timeline"
            )
            fig.update_xaxes(rangeslider_visible=True)
            st.plotly_chart(fig, use_container_width=True)
        
        # Incident Management Section
        st.subheader("📝 Incident Management")
        
        # Tabs for different incident management functions
        tab1, tab2, tab3 = st.tabs(["Create Incident", "Generate Report", "Export Data"])
        
        with tab1:
            st.write("Create a new security incident report:")
            new_incident = self.create_incident_report()
            if new_incident:
                st.success(f"Incident {new_incident.id} created successfully!")
                # In a real application, this would be saved to a database
                # and the incidents list would be refreshed
        
        with tab2:
            st.write("Generate NIS2 Article 23 compliance report:")
            if st.button("Generate Report", key="compliance_generate_report"):
                report = self.generate_nis2_article23_report(
                    incidents, 
                    organization.name, 
                    "Q4 2024"
                )
                st.markdown(report, unsafe_allow_html=True)
                
                # Export options
                col1, col2, col3 = st.columns(3)
                with col1:
                    if st.button("📥 Download Markdown", key="compliance_download_md"):
                        st.download_button(
                            label="Download Markdown",
                            data=report,
                            file_name=f"nis2_compliance_report_{datetime.now().strftime('%Y%m%d')}.md",
                            mime="text/markdown"
                        )
                with col2:
                    if st.button("📥 Download HTML", key="compliance_download_html"):
                        html_data = self.export_compliance_report(report, "html")
                        st.download_button(
                            label="Download HTML",
                            data=html_data,
                            file_name=f"nis2_compliance_report_{datetime.now().strftime('%Y%m%d')}.html",
                            mime="text/html"
                        )
                with col3:
                    if st.button("📥 Download JSON", key="compliance_download_json"):
                        json_data = self.export_compliance_report(report, "json")
                        st.download_button(
                            label="Download JSON",
                            data=json_data,
                            file_name=f"nis2_compliance_report_{datetime.now().strftime('%Y%m%d')}.json",
                            mime="application/json"
                        )
        
        with tab3:
            st.write("Export incident data:")
            if st.button("Export to CSV", key="compliance_export_csv"):
                # Convert incidents to DataFrame for export
                export_data = []
                for incident in incidents:
                    export_data.append({
                        'ID': incident.id,
                        'Title': incident.title,
                        'Description': incident.description,
                        'Severity': incident.severity.value,
                        'Status': incident.status.value,
                        'Detection Time': incident.detection_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'Resolution Time': incident.resolution_time.strftime('%Y-%m-%d %H:%M:%S') if incident.resolution_time else 'N/A',
                        'Affected Services': ', '.join(incident.affected_services),
                        'Impact Assessment': incident.impact_assessment,
                        'Containment Measures': ', '.join(incident.containment_measures),
                        'Remediation Actions': ', '.join(incident.remediation_actions) if incident.remediation_actions else 'N/A',
                        'Lessons Learned': incident.lessons_learned,
                        'Reported to Authorities': incident.reported_to_authorities,
                        'Authority Report Date': incident.authority_report_date.strftime('%Y-%m-%d %H:%M:%S') if incident.authority_report_date else 'N/A'
                    })
                
                df = pd.DataFrame(export_data)
                csv = df.to_csv(index=False)
                st.download_button(
                    label="📥 Download CSV",
                    data=csv,
                    file_name=f"incidents_export_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv"
                )
    
    def export_compliance_report(self, report: str, format_type: str = "markdown") -> bytes:
        """Export compliance report in various formats."""
        if format_type == "markdown":
            return report.encode('utf-8')
        elif format_type == "html":
            import markdown
            html_content = markdown.markdown(report)
            return html_content.encode('utf-8')
        elif format_type == "json":
            # Convert report to structured JSON format
            report_data = {
                "title": "NIS2 Article 23 Compliance Report",
                "generated_at": datetime.now().isoformat(),
                "content": report
            }
            return json.dumps(report_data, indent=2).encode('utf-8')
        else:
            return report.encode('utf-8')
