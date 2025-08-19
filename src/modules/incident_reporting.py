"""
NIS2 Article 23 Incident Reporting Module
Provides comprehensive incident reporting with timeline management for NIS2 compliance.
Enhanced with professional PDF report generation and email distribution.
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import json
import uuid
from pathlib import Path
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import os
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import requests
import re

class ReportType(Enum):
    """NIS2 incident report types."""
    INITIAL = "initial"
    INTERMEDIATE = "intermediate"
    FINAL = "final"
    UPDATE = "update"

class IncidentCategory(Enum):
    """NIS2 incident categories."""
    MALWARE_RANSOMWARE = "malware_ransomware"
    PHISHING_SOCIAL_ENGINEERING = "phishing_social_engineering"
    DDOS_ATTACK = "ddos_attack"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN_ATTACK = "supply_chain_attack"
    VULNERABILITY_EXPLOITATION = "vulnerability_exploitation"
    PHYSICAL_SECURITY_BREACH = "physical_security_breach"
    SYSTEM_FAILURE = "system_failure"
    OTHER = "other"

class IncidentSeverity(Enum):
    """NIS2 incident severity levels."""
    MINOR = "minor"
    SIGNIFICANT = "significant"
    MAJOR = "major"
    CRITICAL = "critical"

class IncidentStatus(Enum):
    """Incident status for timeline tracking."""
    DETECTED = "detected"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"

@dataclass
class ThreatIntelligence:
    """Threat intelligence data for incident reports."""
    indicators: List[str] = field(default_factory=list)  # IPs, domains, hashes, URLs
    malware_families: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    ioc_sources: Dict[str, str] = field(default_factory=dict)  # Source -> URL mapping
    risk_score: int = 0  # 0-100
    confidence_level: str = "Low"  # Low, Medium, High
    last_updated: Optional[datetime] = None
    
    def add_indicator(self, indicator: str, source: str, url: str):
        """Add a new threat indicator with source information."""
        if indicator not in self.indicators:
            self.indicators.append(indicator)
        self.ioc_sources[source] = url

@dataclass
class Vulnerability:
    """Vulnerability information for incident reports."""
    cve_id: str  # CVE-YYYY-NNNNN format
    description: str
    severity: str  # Critical, High, Medium, Low
    cvss_score: Optional[float] = None
    affected_products: List[str] = field(default_factory=list)
    exploitation_status: str = "Unknown"  # Unknown, POC, Exploited, Patched
    patch_available: bool = False
    references: List[str] = field(default_factory=list)
    
    @property
    def enisa_url(self) -> str:
        """Generate ENISA Vulnerability Database URL."""
        return f"https://vulnerability-database.enisa.europa.eu/vulnerability/{self.cve_id}"
    
    @property
    def nvd_url(self) -> str:
        """Generate NVD CVE URL."""
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "affected_products": self.affected_products,
            "exploitation_status": self.exploitation_status,
            "patch_available": self.patch_available,
            "references": self.references
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Vulnerability':
        """Create from dictionary for JSON deserialization."""
        return cls(
            cve_id=data["cve_id"],
            description=data["description"],
            severity=data["severity"],
            cvss_score=data.get("cvss_score"),
            affected_products=data.get("affected_products", []),
            exploitation_status=data.get("exploitation_status", "Unknown"),
            patch_available=data.get("patch_available", False),
            references=data.get("references", [])
        )

@dataclass
class EmailConfig:
    """Email configuration for incident report distribution."""
    smtp_server: str
    smtp_port: int
    username: str
    password: str
    use_tls: bool = True
    use_ssl: bool = False
    sender_name: str = "NIS2 Incident Reporting System"
    sender_email: str = ""
    
    def __post_init__(self):
        if not self.sender_email:
            self.sender_email = self.username

@dataclass
class ReportRecipient:
    """Recipient configuration for incident reports."""
    entity_name: str
    email_address: str
    report_types: List[ReportType] = field(default_factory=lambda: [ReportType.INITIAL, ReportType.FINAL])
    priority: str = "Normal"  # Low, Normal, High, Critical
    contact_person: str = ""
    phone: str = ""
    
    def should_receive_report(self, report_type: ReportType, severity: IncidentSeverity) -> bool:
        """Determine if this recipient should receive a specific report type."""
        if report_type not in self.report_types:
            return False
        
        # Critical incidents go to all recipients
        if severity == IncidentSeverity.CRITICAL:
            return True
        
        # High priority recipients get all reports
        if self.priority in ["High", "Critical"]:
            return True
        
        # Normal priority recipients get initial and final reports
        if self.priority == "Normal" and report_type in [ReportType.INITIAL, ReportType.FINAL]:
            return True
        
        return False

@dataclass
class IncidentTimeline:
    """Timeline tracking for incident reporting."""
    detection_time: datetime
    initial_report_time: Optional[datetime] = None
    intermediate_reports: List[datetime] = field(default_factory=list)
    final_report_time: Optional[datetime] = None
    resolution_time: Optional[datetime] = None
    closure_time: Optional[datetime] = None
    
    def add_intermediate_report(self):
        """Add an intermediate report timestamp."""
        self.intermediate_reports.append(datetime.now())
    
    def get_next_report_deadline(self) -> Optional[datetime]:
        """Get the next reporting deadline based on NIS2 requirements."""
        if not self.initial_report_time:
            return self.detection_time + timedelta(hours=24)
        
        # For significant+ incidents, intermediate reports every 72 hours
        if len(self.intermediate_reports) == 0:
            return self.initial_report_time + timedelta(hours=72)
        
        last_report = max(self.intermediate_reports)
        return last_report + timedelta(hours=72)
    
    def is_overdue(self) -> bool:
        """Check if any reporting deadlines are overdue."""
        deadline = self.get_next_report_deadline()
        if deadline:
            return datetime.now() > deadline
        return False

@dataclass
class SecurityIncident:
    """Security incident for NIS2 reporting."""
    id: str
    title: str
    description: str
    category: IncidentCategory
    severity: IncidentSeverity
    status: IncidentStatus
    timeline: IncidentTimeline
    affected_services: List[str]
    affected_entities: List[str]  # Internal IP addresses
    threat_intelligence_input: str  # Raw threat intelligence input
    impact_assessment: str
    containment_measures: List[str]
    remediation_actions: List[str]
    lessons_learned: str
    reported_to_authorities: bool
    authority_report_date: Optional[datetime]
    organization_id: str
    assigned_to: Optional[str]
    threat_intelligence: ThreatIntelligence = field(default_factory=ThreatIntelligence)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)  # CVE information
    report_recipients: List[ReportRecipient] = field(default_factory=list)
    email_sent: bool = False
    email_sent_date: Optional[datetime] = None

class IncidentReportingModule:
    """NIS2 Article 23 incident reporting module with enhanced capabilities."""
    
    def __init__(self):
        self.incidents: Dict[str, SecurityIncident] = {}
        self.report_templates = self._load_report_templates()
        self.email_config = self._load_email_config()
        self.report_recipients = self._load_report_recipients()
        self.load_incidents()
    
    def _load_report_templates(self) -> Dict[str, str]:
        """Load report templates for different report types."""
        return {
            "initial": """
# Initial Incident Report - {incident_title}

## Incident Details
- **Incident ID**: {incident_id}
- **Detection Time**: {detection_time}
- **Category**: {category}
- **Severity**: {severity}
- **Status**: {status}

## Description
{description}

## Impact Assessment
{impact_assessment}

## Immediate Response
{containment_measures}

## Next Steps
- Continue investigation
- Implement additional containment measures
- Prepare for intermediate reporting
            """,
            "intermediate": """
# Intermediate Incident Report - {incident_title}

## Incident Progress
- **Incident ID**: {incident_id}
- **Report Time**: {report_time}
- **Status**: {status}

## Investigation Update
{investigation_update}

## Containment Status
{containment_status}

## Remediation Progress
{remediation_progress}

## Next Steps
{next_steps}
            """,
            "final": """
# Final Incident Report - {incident_title}

## Incident Resolution
- **Incident ID**: {incident_id}
- **Resolution Time**: {resolution_time}
- **Total Duration**: {duration}

## Root Cause Analysis
{root_cause}

## Remediation Actions Taken
{remediation_actions}

## Lessons Learned
{lessons_learned}

## Prevention Measures
{prevention_measures}

## Closure
This incident is now resolved and closed.
            """
        }
    
    def _load_email_config(self) -> EmailConfig:
        """Load email configuration from environment or defaults."""
        return EmailConfig(
            smtp_server=os.getenv("SMTP_SERVER", "smtp.gmail.com"),
            smtp_port=int(os.getenv("SMTP_PORT", "587")),
            username=os.getenv("SMTP_USERNAME", ""),
            password=os.getenv("SMTP_PASSWORD", ""),
            use_tls=os.getenv("SMTP_USE_TLS", "true").lower() == "true",
            use_ssl=os.getenv("SMTP_USE_SSL", "false").lower() == "true",
            sender_name=os.getenv("SENDER_NAME", "NIS2 Incident Reporting System"),
            sender_email=os.getenv("SENDER_EMAIL", "")
        )
    
    def _load_report_recipients(self) -> List[ReportRecipient]:
        """Load report recipients from configuration."""
        default_recipients = [
            ReportRecipient(
                entity_name="National Cyber Security Centre (Ireland)",
                email_address="incidents@ncsc.gov.ie",
                report_types=[ReportType.INITIAL, ReportType.INTERMEDIATE, ReportType.FINAL],
                priority="High",
                contact_person="NCSC Incident Response Team"
            ),
            ReportRecipient(
                entity_name="Garda Cyber Crime Unit",
                email_address="cybercrime@garda.ie",
                report_types=[ReportType.INITIAL, ReportType.FINAL],
                priority="High",
                contact_person="Cyber Crime Investigation Team"
            ),
            ReportRecipient(
                entity_name="Data Protection Commission",
                email_address="info@dataprotection.ie",
                report_types=[ReportType.INITIAL, ReportType.FINAL],
                priority="Normal",
                contact_person="Data Protection Officer"
            ),
            ReportRecipient(
                entity_name="ENISA",
                email_address="incidents@enisa.europa.eu",
                report_types=[ReportType.INITIAL, ReportType.FINAL],
                priority="Normal",
                contact_person="ENISA Incident Response"
            )
        ]
        
        # Load custom recipients from file if available
        recipients_file = "incident_report_recipients.json"
        if os.path.exists(recipients_file):
            try:
                with open(recipients_file, 'r') as f:
                    custom_recipients = json.load(f)
                    for recipient_data in custom_recipients:
                        recipient = ReportRecipient(
                            entity_name=recipient_data["entity_name"],
                            email_address=recipient_data["email_address"],
                            report_types=[ReportType(rt) for rt in recipient_data.get("report_types", [])],
                            priority=recipient_data.get("priority", "Normal"),
                            contact_person=recipient_data.get("contact_person", ""),
                            phone=recipient_data.get("phone", "")
                        )
                        default_recipients.append(recipient)
            except Exception as e:
                st.warning(f"Could not load custom recipients: {e}")
        
        return default_recipients
    
    def enrich_threat_intelligence(self, incident: SecurityIncident):
        """Enrich threat intelligence with external sources and analysis."""
        # Extract indicators from description and threat intelligence input
        description_indicators = self._extract_indicators(incident.description)
        ti_indicators = self._extract_indicators(incident.threat_intelligence_input)
        
        # Combine all indicators
        all_indicators = []
        for indicator_type, indicators in description_indicators.items():
            all_indicators.extend(indicators)
        for indicator_type, indicators in ti_indicators.items():
            all_indicators.extend(indicators)
        
        # Remove duplicates
        all_indicators = list(set(all_indicators))
        
        # Add indicators to threat intelligence
        for indicator in all_indicators:
            if self._is_ip_address(indicator):
                incident.threat_intelligence.add_indicator(indicator, "AbuseIPDB", f"https://www.abuseipdb.com/check/{indicator}")
                incident.threat_intelligence.add_indicator(indicator, "Shodan", f"https://shodan.io/host/{indicator}")
            elif self._is_domain(indicator):
                incident.threat_intelligence.add_indicator(indicator, "VirusTotal", f"https://www.virustotal.com/gui/domain/{indicator}")
                incident.threat_intelligence.add_indicator(indicator, "AbuseIPDB", f"https://www.abuseipdb.com/check/{indicator}")
            elif self._is_hash(indicator):
                incident.threat_intelligence.add_indicator(indicator, "VirusTotal", f"https://www.virustotal.com/gui/file/{indicator}")
            elif self._is_url(indicator):
                incident.threat_intelligence.add_indicator(indicator, "VirusTotal", f"https://www.virustotal.com/gui/url/{indicator}")
        
        # Process vulnerabilities if present
        if incident.vulnerabilities:
            for vulnerability in incident.vulnerabilities:
                # Add ENISA and NVD references
                vulnerability.references.extend([
                    vulnerability.enisa_url,
                    vulnerability.nvd_url
                ])
        
        # Calculate risk score and confidence level
        incident.threat_intelligence.risk_score = self._calculate_risk_score(incident)
        incident.threat_intelligence.confidence_level = self._calculate_confidence_level(incident)
        incident.threat_intelligence.last_updated = datetime.now()
    
    def _extract_indicators(self, text: str) -> Dict[str, List[str]]:
        """Extract indicators of compromise from text."""
        indicators = {
            'ips': [],
            'domains': [],
            'hashes': [],
            'urls': []
        }
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        indicators['ips'] = re.findall(ip_pattern, text)
        
        # Extract domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        indicators['domains'] = re.findall(domain_pattern, text)
        
        # Extract hashes (MD5, SHA1, SHA256)
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b'   # SHA256
        ]
        for pattern in hash_patterns:
            indicators['hashes'].extend(re.findall(pattern, text))
        
        # Extract URLs
        url_pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
        indicators['urls'] = re.findall(url_pattern, text)
        
        return indicators
    
    def _validate_cve_id(self, cve_id: str) -> bool:
        """Validate CVE ID format."""
        cve_pattern = r'^CVE-\d{4}-\d{4,7}$'
        return bool(re.match(cve_pattern, cve_id.strip()))
    
    def _parse_cve_input(self, cve_input: str) -> List[Vulnerability]:
        """Parse CVE input and create Vulnerability objects."""
        vulnerabilities = []
        
        # Split by newlines, commas, or semicolons
        cve_lines = re.split(r'[\n,;]', cve_input.strip())
        
        for line in cve_lines:
            line = line.strip()
            if not line:
                continue
            
            # Check if it's a valid CVE ID
            if self._validate_cve_id(line):
                # Create a basic vulnerability object
                vulnerability = Vulnerability(
                    cve_id=line.upper(),
                    description=f"Vulnerability identified: {line}",
                    severity="Unknown",
                    exploitation_status="Unknown"
                )
                vulnerabilities.append(vulnerability)
            else:
                # Try to extract CVE ID from text
                cve_match = re.search(r'CVE-\d{4}-\d{4,7}', line, re.IGNORECASE)
                if cve_match:
                    cve_id = cve_match.group().upper()
                    vulnerability = Vulnerability(
                        cve_id=cve_id,
                        description=line.strip(),
                        severity="Unknown",
                        exploitation_status="Unknown"
                    )
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _is_ip_address(self, text: str) -> bool:
        """Check if text is a valid IP address."""
        try:
            parts = text.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def _is_domain(self, text: str) -> bool:
        """Check if text is a valid domain."""
        return '.' in text and not text.startswith('http') and not self._is_ip_address(text)
    
    def _is_hash(self, text: str) -> bool:
        """Check if text is a hash."""
        return len(text) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in text)
    
    def _is_url(self, text: str) -> bool:
        """Check if text is a URL."""
        return text.startswith(('http://', 'https://', 'www.'))
    
    def _calculate_risk_score(self, incident: SecurityIncident) -> int:
        """Calculate threat intelligence risk score."""
        base_score = 0
        
        # Base score from incident severity
        severity_scores = {
            IncidentSeverity.MINOR: 10,
            IncidentSeverity.SIGNIFICANT: 30,
            IncidentSeverity.MAJOR: 60,
            IncidentSeverity.CRITICAL: 90
        }
        base_score += severity_scores.get(incident.severity, 0)
        
        # Add points for threat indicators
        base_score += len(incident.threat_intelligence.indicators) * 5
        
        # Add points for malware families
        base_score += len(incident.threat_intelligence.malware_families) * 10
        
        # Add points for threat actors
        base_score += len(incident.threat_intelligence.threat_actors) * 15
        
        return min(base_score, 100)  # Cap at 100
    
    def _calculate_confidence_level(self, incident: SecurityIncident) -> str:
        """Calculate confidence level based on available intelligence."""
        if len(incident.threat_intelligence.indicators) >= 5 and len(incident.threat_intelligence.ioc_sources) >= 3:
            return "High"
        elif len(incident.threat_intelligence.indicators) >= 2 and len(incident.threat_intelligence.ioc_sources) >= 2:
            return "Medium"
        else:
            return "Low"
    
    def display_incident_reporting_interface(self):
        """Display the main incident reporting interface."""
        st.header("🚨 NIS2 Security Incident Reporting")
        
        
        # Navigation tabs
        tab1, tab2, tab3, tab4, tab5 = st.tabs([
            "📝 Report New Incident",
            "📊 Active Incidents", 
            "📋 Report Timeline",
            "📈 Analytics",
            "⚙️ Configuration"
        ])
        
        with tab1:
            self.display_new_incident_form()
        
        with tab2:
            self.display_active_incidents()
        
        with tab3:
            self.display_report_timeline()
        
        with tab4:
            self.display_incident_analytics()
        
        with tab5:
            self.display_configuration_interface()
    
    def display_new_incident_form(self):
        """Display form for reporting new incidents."""
        st.subheader("📝 Report New Security Incident")
        
        with st.form("new_incident_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                title = st.text_input("Incident Title *")
                category = st.selectbox(
                    "Incident Category *",
                    options=[cat.value for cat in IncidentCategory],
                    format_func=lambda x: x.replace('_', ' ').title()
                )
                severity = st.selectbox(
                    "Incident Severity *",
                    options=[sev.value for sev in IncidentSeverity],
                    format_func=lambda x: x.title()
                )
            
            with col2:
                detection_time = st.date_input(
                    "Detection Date *",
                    value=datetime.now().date(),
                    help="When was the incident first detected?"
                )
                
                # Show current time for reference
                current_time = datetime.now().time().replace(second=0, microsecond=0)
                st.info(f"🕐 Current time: {current_time.strftime('%H:%M')}")
                
                detection_time_only = st.time_input(
                    "Detection Time *",
                    value=current_time,
                    help="Time when the incident was first detected (use the time picker or type HH:MM)",
                    step=300  # 5-minute intervals for easier selection
                )
                
                affected_services = st.multiselect(
                    "Affected Services",
                    ["Critical Infrastructure", "Digital Services", "Essential Services", 
                     "Network Infrastructure", "Data Centers", "Cloud Services", "Other"]
                )
                
                # Affected Entities (Internal IP Addresses)
                affected_entities = st.text_area(
                    "Affected Entities (Internal IP Addresses) *",
                    height=80,
                    help="Enter internal IP addresses of affected systems, one per line or comma-separated (e.g., 192.168.1.100, 10.0.0.50)"
                )
                
                # Threat Intelligence (Observed Attack Addresses)
                threat_intelligence_input = st.text_area(
                    "Threat Intelligence - Observed Attack Addresses *",
                    height=80,
                    help="Enter external IP addresses, domains, URLs, or file hashes observed in the attack, one per line or comma-separated"
                )
                
                # Vulnerabilities (CVE IDs)
                vulnerabilities_input = st.text_area(
                    "Vulnerabilities (CVE IDs)",
                    height=80,
                    help="Enter CVE IDs (e.g., CVE-2023-1234, CVE-2024-5678) or vulnerability descriptions. One per line or comma-separated."
                )
            
            description = st.text_area(
                "Incident Description *",
                height=100,
                help="Provide a detailed description of the incident"
            )
            
            impact_assessment = st.text_area(
                "Impact Assessment *",
                height=100,
                help="Describe the impact on services, users, and operations"
            )
            
            containment_measures = st.text_area(
                "Immediate Containment Measures *",
                height=100,
                help="What immediate actions were taken to contain the incident?"
            )
            
            # Organization and assignment
            col1, col2 = st.columns(2)
            with col1:
                # Get organization ID from current context (read-only)
                current_org_id = st.session_state.get('current_organization_id', 'Unknown')
                st.info(f"**Organization ID:** {current_org_id}")
            with col2:
                assigned_to = st.text_input("Assigned To")
            
            submitted = st.form_submit_button("🚨 Report Incident", type="primary")
            
            if submitted and title and category and severity and description:
                # Validate all required fields
                if not title.strip():
                    st.error("Please enter an incident title.")
                    return
                if not description.strip():
                    st.error("Please provide an incident description.")
                    return
                
                # Get organization ID from current context
                current_org_id = st.session_state.get('current_organization_id')
                if not current_org_id:
                    st.error("Unable to determine organization context. Please refresh the page.")
                    return
                
                # Validate time input
                if not detection_time_only:
                    st.error("Please select a detection time.")
                    return
                
                # Validate affected services (ensure it's a list)
                if not affected_services:
                    affected_services = []
                
                # Parse affected entities (internal IP addresses)
                affected_entities_list = []
                if affected_entities.strip():
                    # Split by newlines, commas, or semicolons
                    entities = re.split(r'[\n,;]', affected_entities.strip())
                    for entity in entities:
                        entity = entity.strip()
                        if entity and self._is_ip_address(entity):
                            affected_entities_list.append(entity)
                        elif entity:
                            st.warning(f"⚠️ Invalid IP address format: {entity}")
                
                # Parse vulnerabilities (CVE IDs)
                vulnerabilities_list = []
                if vulnerabilities_input and vulnerabilities_input.strip():
                    vulnerabilities_list = self._parse_cve_input(vulnerabilities_input)
                    if vulnerabilities_list:
                        st.success(f"✅ Parsed {len(vulnerabilities_list)} vulnerability(ies)")
                    else:
                        st.warning("⚠️ No valid CVE IDs found in vulnerability input")
                
                # Validate threat intelligence input
                if not threat_intelligence_input.strip():
                    st.error("Please provide threat intelligence information.")
                    return
                
                # Combine date and time
                detection_datetime = datetime.combine(detection_time, detection_time_only)
                
                # Show confirmation of the combined date and time
                st.success(f" 📅 Incident will be recorded for: {detection_datetime:%Y-%m-%d %H:%M}")
                
                # Create incident
                incident = SecurityIncident(
                    id=str(uuid.uuid4())[:8],
                    title=title,
                    description=description,
                    category=IncidentCategory(category),
                    severity=IncidentSeverity(severity),
                    status=IncidentStatus.DETECTED,
                    timeline=IncidentTimeline(detection_time=detection_datetime),
                    affected_services=affected_services,
                    affected_entities=affected_entities_list,
                    threat_intelligence_input=threat_intelligence_input,
                    impact_assessment=impact_assessment,
                    containment_measures=[containment_measures],
                    remediation_actions=[],
                    lessons_learned="",
                    reported_to_authorities=False,
                    authority_report_date=None,
                    organization_id=current_org_id,
                    assigned_to=assigned_to,
                    vulnerabilities=vulnerabilities_list
                )
                
                self.create_new_incident(incident)
    
    def create_new_incident(self, incident: SecurityIncident):
        """Create a new security incident."""
        
        # Generate unique incident ID
        incident_id = str(uuid.uuid4())[:8]
        incident.id = incident_id
        
        # Save incident
        self.incidents[incident_id] = incident
        self.save_incidents()
        
        st.success(f"✅ Incident {incident_id} created successfully!")
        st.info(f"⚠️ **Initial report due by:** {incident.timeline.detection_time + timedelta(hours=24):%Y-%m-%d %H:%M}")
        
        # Auto-generate initial report
        self.generate_initial_report(incident)
    
    def display_active_incidents(self):
        """Display active incidents with status and timeline."""
        st.subheader("📊 Active Incidents")
        
        if not self.incidents:
            st.info("No incidents reported yet.")
            return
        
        # Get current organization context from session state
        current_org_id = st.session_state.get('current_organization_id')
        if not current_org_id:
            st.error("Unable to determine organization context.")
            return
        
        # Filter incidents by current organization
        organization_incidents = [
            incident for incident in self.incidents.values() 
            if str(incident.organization_id) == str(current_org_id)
        ]
        
        if not organization_incidents:
            st.info(f"No incidents found for the current organization.")
            return
        
        # Filter options
        col1, col2, col3 = st.columns(3)
        with col1:
            status_filter = st.selectbox(
                "Filter by Status",
                ["All"] + [status.name.title() for status in IncidentStatus]
            )
        with col2:
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["All"] + [sev.name.title() for sev in IncidentSeverity]
            )
        with col3:
            overdue_filter = st.checkbox("Show Overdue Reports Only")
        
        # Apply additional filters
        filtered_incidents = []
        for incident in organization_incidents:
            if status_filter != "All" and incident.status.name.title() != status_filter:
                continue
            if severity_filter != "All" and incident.severity.name.title() != severity_filter:
                continue
            if overdue_filter and not incident.timeline.is_overdue():
                continue
            filtered_incidents.append(incident)
        
        if not filtered_incidents:
            st.info("No incidents match the selected filters.")
            return
        
        # Display incidents
        for incident in filtered_incidents:
            with st.expander(f"🚨 {incident.title} (ID: {incident.id})"):
                self.display_incident_details(incident)
    
    def display_incident_details(self, incident: SecurityIncident):
        """Display detailed incident information."""
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"**Status:** {incident.status.name.title()}")
            st.markdown(f"**Severity:** {incident.severity.name.title()}")
            st.markdown(f"**Category:** {incident.category.name.replace('_', ' ').title()}")
            st.markdown(f"**Detection Time:** {incident.timeline.detection_time:%Y-%m-%d %H:%M}")
        
        with col2:
            st.markdown(f"**Organization:** {incident.organization_id}")
            st.markdown(f"**Assigned To:** {incident.assigned_to or 'Unassigned'}")
        
        # Affected Entities
        if incident.affected_entities:
            st.markdown("**Affected Entities (Internal IP Addresses):**")
            for entity in incident.affected_entities:
                st.markdown(f"• {entity}")
        
        # Threat Intelligence Input
        if incident.threat_intelligence_input:
            st.markdown("**Observed Attack Indicators:**")
            st.text_area("Raw Threat Intelligence", value=incident.threat_intelligence_input, height=100, disabled=True)
        
        # Description
        st.markdown("**Description:**")
        st.text_area("Incident Description", value=incident.description, height=100, disabled=True)
        
        # Impact Assessment
        st.markdown("**Impact Assessment:**")
        st.text_area("Impact Assessment", value=incident.impact_assessment, height=100, disabled=True)
        
        # Containment Measures
        if incident.containment_measures:
            st.markdown("**Containment Measures:**")
            for measure in incident.containment_measures:
                st.markdown(f"• {measure}")
        
        # Timeline Information
        st.markdown("**Timeline:**")
        timeline_col1, timeline_col2 = st.columns(2)
        
        with timeline_col1:
            st.markdown(f"**Detection:** {incident.timeline.detection_time:%Y-%m-%d %H:%M}")
            if incident.timeline.initial_report_time:
                st.markdown(f"**Initial Report:** {incident.timeline.initial_report_time:%Y-%m-%d %H:%M}")
            if incident.timeline.resolution_time:
                st.markdown(f"**Resolution:** {incident.timeline.resolution_time:%Y-%m-%d %H:%M}")
        
        with timeline_col2:
            if incident.timeline.intermediate_reports:
                st.markdown(f"**Intermediate Reports:** {len(incident.timeline.intermediate_reports)}")
            if incident.timeline.final_report_time:
                st.markdown(f"**Final Report:** {incident.timeline.final_report_time:%Y-%m-%d %H:%M}")
            if incident.timeline.closure_time:
                st.markdown(f"**Closure:** {incident.timeline.closure_time:%Y-%m-%d %H:%M}")
        
        # Threat Intelligence Summary
        if incident.threat_intelligence.indicators:
            st.markdown("**Threat Intelligence Summary:**")
            ti_col1, ti_col2 = st.columns(2)
            
            with ti_col1:
                st.metric("Risk Score", f"{incident.threat_intelligence.risk_score}/100")
                st.metric("Confidence Level", incident.threat_intelligence.confidence_level)
            
            with ti_col2:
                st.metric("Indicators Found", len(incident.threat_intelligence.indicators))
                if incident.threat_intelligence.last_updated:
                    st.metric("Last Updated", incident.threat_intelligence.last_updated.strftime("%Y-%m-%d %H:%M"))
            
            # Show indicators with source links
            st.markdown("**Threat Indicators & Sources:**")
            for i, indicator in enumerate(incident.threat_intelligence.indicators):
                st.markdown(f"**🔍 {indicator}**")
                st.markdown("**Available Sources:**")
                for source, url in incident.threat_intelligence.ioc_sources.items():
                    if indicator in url:  # Only show sources relevant to this indicator
                        st.markdown(f"• [{source}]({url})")
                if i < len(incident.threat_intelligence.indicators) - 1:
                    st.markdown("---")
        
        # Vulnerabilities Section
        if incident.vulnerabilities:
            st.markdown("**🔓 Vulnerabilities Identified:**")
            for i, vulnerability in enumerate(incident.vulnerabilities):
                st.markdown(f"**🛡️ {vulnerability.cve_id} - {vulnerability.severity.title()}**")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**CVE ID:** {vulnerability.cve_id}")
                    st.markdown(f"**Severity:** {vulnerability.severity.title()}")
                    if vulnerability.cvss_score:
                        st.markdown(f"**CVSS Score:** {vulnerability.cvss_score}")
                    st.markdown(f"**Status:** {vulnerability.exploitation_status.title()}")
                    st.markdown(f"**Patch Available:** {'✅ Yes' if vulnerability.patch_available else '❌ No'}")
                
                with col2:
                    st.markdown("**External References:**")
                    st.markdown(f"• [🔍 ENISA Database]({vulnerability.enisa_url})")
                    st.markdown(f"• [📋 NVD CVE]({vulnerability.nvd_url})")
                    
                    if vulnerability.references:
                        st.markdown("**Additional References:**")
                        for ref in vulnerability.references:
                            if ref not in [vulnerability.enisa_url, vulnerability.nvd_url]:
                                st.markdown(f"• {ref}")
                
                st.markdown("**Description:**")
                st.text_area("Vulnerability Description", value=vulnerability.description, height=80, disabled=True, key=f"vuln_desc_{i}")
                
                if vulnerability.affected_products:
                    st.markdown("**Affected Products:**")
                    for product in vulnerability.affected_products:
                        st.markdown(f"• {product}")
                
                if i < len(incident.vulnerabilities) - 1:
                    st.markdown("---")
        else:
            st.info("ℹ️ No vulnerabilities identified in this incident.")
        
        # Action buttons
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button(f"📝 Update Status", key=f"update_{incident.id}"):
                st.session_state.editing_incident = incident.id
        
        with col2:
            if st.button(f"📋 Generate Report", key=f"report_{incident.id}"):
                st.session_state.generating_report = incident.id
        
        with col3:
            if st.button(f"🔒 Close Incident", key=f"close_{incident.id}"):
                self.close_incident(incident.id)
        
        # Show report generation if requested
        if st.session_state.get('generating_report') == incident.id:
            self.display_report_generation(incident)
            if st.button("❌ Close Report Generation", key=f"close_report_{incident.id}"):
                st.session_state.generating_report = None
                st.rerun()
        
        # Status update form
        if st.session_state.get('editing_incident') == incident.id:
            self.display_status_update_form(incident)
    
    def display_status_update_form(self, incident: SecurityIncident):
        """Display form for updating incident status."""
        st.subheader("📝 Update Incident Status")
        
        with st.form(f"status_update_{incident.id}"):
            new_status = st.selectbox(
                "New Status",
                options=[status.name.title() for status in IncidentStatus],
                index=list(IncidentStatus).index(incident.status)
            )
            
            update_notes = st.text_area("Update Notes", height=100)
            
            if st.form_submit_button("Update Status"):
                incident.status = IncidentStatus[new_status.upper()]
                
                # Update timeline
                if incident.status == IncidentStatus.RESOLVED:
                    incident.timeline.resolution_time = datetime.now()
                elif incident.status == IncidentStatus.CLOSED:
                    incident.timeline.closure_time = datetime.now()
                
                # Add remediation action if provided
                if update_notes:
                    incident.remediation_actions.append(update_notes)
                
                self.save_incidents()
                st.success("✅ Status updated successfully!")
                st.session_state.editing_incident = None
                st.rerun()
    
    def display_report_generation(self, incident: SecurityIncident):
        """Display report generation interface."""
        st.subheader("📋 Generate Incident Report")
        
        report_type = st.selectbox(
            "Report Type",
            ["Initial Report", "Intermediate Report", "Final Report"]
        )
        
        if report_type == "Initial Report":
            if incident.timeline.initial_report_time:
                st.warning("Initial report already submitted.")
                return
            
            with st.form(f"initial_report_{incident.id}"):
                if st.form_submit_button("Generate Initial Report"):
                    self.generate_initial_report(incident)
        
        elif report_type == "Intermediate Report":
            if not incident.timeline.initial_report_time:
                st.error("Initial report must be submitted first.")
                return
            
            with st.form(f"intermediate_report_{incident.id}"):
                investigation_update = st.text_area("Investigation Update", height=100)
                containment_status = st.text_area("Containment Status", height=100)
                next_steps = st.text_area("Next Steps", height=100)
                
                if st.form_submit_button("Generate Intermediate Report"):
                    self.generate_intermediate_report(incident, investigation_update, 
                                                   containment_status, next_steps)
        
        elif report_type == "Final Report":
            if incident.status != IncidentStatus.RESOLVED:
                st.error("Incident must be resolved before generating final report.")
                return
            
            with st.form(f"final_report_{incident.id}"):
                root_cause = st.text_area("Root Cause Analysis", height=100)
                prevention_measures = st.text_area("Prevention Measures", height=100)
                
                if st.form_submit_button("Generate Final Report"):
                    self.generate_final_report(incident, root_cause, prevention_measures)
    
    def generate_initial_report(self, incident: SecurityIncident):
        """Generate and submit initial incident report."""
        incident.timeline.initial_report_time = datetime.now()
        incident.reported_to_authorities = True
        incident.authority_report_date = datetime.now()
        
        # Enrich with threat intelligence
        self.enrich_threat_intelligence(incident)
        
        # Generate PDF report
        pdf_filepath = self.generate_pdf_report(incident, ReportType.INITIAL)
        
        # Send email with PDF attachment
        email_sent = self.send_incident_report_email(incident, ReportType.INITIAL, pdf_filepath)
        
        # Save report content for display
        report_content = self.report_templates["initial"].format(
            incident_title=incident.title,
            incident_id=incident.id,
            detection_time=incident.timeline.detection_time.strftime("%Y-%m-%d %H:%M"),
            category=incident.category.name.replace('_', ' ').title(),
            severity=incident.severity.name.title(),
            status=incident.status.name.title(),
            description=incident.description,
            impact_assessment=incident.impact_assessment,
            containment_measures="\n".join([f"- {measure}" for measure in incident.containment_measures])
        )
        
        # Save report
        self.save_report(incident.id, "initial", report_content)
        
        if email_sent:
            st.success("✅ Initial report generated, PDF created, and email sent!")
        else:
            st.success("✅ Initial report generated and PDF created!")
            st.warning("⚠️ Email delivery failed - check configuration")
        
        st.info("📅 Next intermediate report due in 72 hours (if incident is significant or higher)")
        
        self.save_incidents()
    
    def generate_intermediate_report(self, incident: SecurityIncident, 
                                   investigation_update: str, containment_status: str, 
                                   next_steps: str):
        """Generate intermediate incident report."""
        incident.timeline.add_intermediate_report()
        
        # Update threat intelligence
        self.enrich_threat_intelligence(incident)
        
        # Prepare additional data for PDF
        additional_data = {
            "investigation_update": investigation_update,
            "containment_status": containment_status,
            "next_steps": next_steps
        }
        
        # Generate PDF report
        pdf_filepath = self.generate_pdf_report(incident, ReportType.INTERMEDIATE, additional_data)
        
        # Send email with PDF attachment
        email_sent = self.send_incident_report_email(incident, ReportType.INTERMEDIATE, pdf_filepath, additional_data)
        
        # Save report content for display
        report_content = self.report_templates["intermediate"].format(
            incident_title=incident.title,
            incident_id=incident.id,
            report_time=datetime.now().strftime("%Y-%m-%d %H:%M"),
            status=incident.status.name.title(),
            investigation_update=investigation_update,
            containment_status=containment_status,
            next_steps=next_steps
        )
        
        # Save report
        self.save_report(incident.id, "intermediate", report_content)
        
        if email_sent:
            st.success("✅ Intermediate report generated, PDF created, and email sent!")
        else:
            st.success("✅ Intermediate report generated and PDF created!")
            st.warning("⚠️ Email delivery failed - check configuration")
        
        st.info("📅 Next intermediate report due in 72 hours")
        
        self.save_incidents()
    
    def generate_final_report(self, incident: SecurityIncident, root_cause: str, 
                             prevention_measures: str):
        """Generate final incident report."""
        incident.timeline.final_report_time = datetime.now()
        incident.lessons_learned = "Final report generated"
        
        # Calculate duration
        duration = incident.timeline.resolution_time - incident.timeline.detection_time if incident.timeline.resolution_time else timedelta(0)
        
        # Update threat intelligence
        self.enrich_threat_intelligence(incident)
        
        # Prepare additional data for PDF
        additional_data = {
            "root_cause": root_cause,
            "prevention_measures": prevention_measures,
            "total_duration": str(duration).split('.')[0]  # Remove microseconds
        }
        
        # Generate PDF report
        pdf_filepath = self.generate_pdf_report(incident, ReportType.FINAL, additional_data)
        
        # Send email with PDF attachment
        email_sent = self.send_incident_report_email(incident, ReportType.FINAL, pdf_filepath, additional_data)
        
        # Save report content for display
        report_content = self.report_templates["final"].format(
            incident_title=incident.title,
            incident_id=incident.id,
            resolution_time=incident.timeline.resolution_time.strftime("%Y-%m-%d %H:%M") if incident.timeline.resolution_time else "Pending",
            duration=str(duration).split('.')[0],  # Remove microseconds
            root_cause=root_cause,
            remediation_actions="\n".join([f"- {action}" for action in incident.remediation_actions]),
            lessons_learned=incident.lessons_learned,
            prevention_measures=prevention_measures
        )
        
        # Save report
        self.save_report(incident.id, "final", report_content)
        
        if email_sent:
            st.success("✅ Final report generated, PDF created, and email sent!")
        else:
            st.success("✅ Final report generated and PDF created!")
            st.warning("⚠️ Email delivery failed - check configuration")
        
        self.save_incidents()
    
    def generate_pdf_report(self, incident: SecurityIncident, report_type: ReportType, 
                           additional_data: Dict[str, str] = None) -> str:
        """Generate a professional PDF report for the incident."""
        # Create reports directory if it doesn't exist
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"incident_{incident.id}_{report_type.value}_{timestamp}.pdf"
        filepath = reports_dir / filename
        
        # Create PDF document
        doc = SimpleDocTemplate(str(filepath), pagesize=A4)
        story = []
        
        # Define styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.darkred
        )
        
        normal_style = styles['Normal']
        
        # Add header
        story.append(Paragraph("NIS2 Article 23 Security Incident Report", title_style))
        story.append(Spacer(1, 20))
        
        # Add incident summary table
        summary_data = [
            ['Incident ID', incident.id],
            ['Title', incident.title],
            ['Category', incident.category.name.replace('_', ' ').title()],
            ['Severity', incident.severity.name.title()],
            ['Status', incident.status.name.title()],
            ['Detection Time', incident.timeline.detection_time.strftime("%Y-%m-%d %H:%M")],
            ['Organization ID', incident.organization_id],
            ['Assigned To', incident.assigned_to or 'Unassigned']
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(Paragraph("Incident Summary", heading_style))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Add affected entities
        if incident.affected_entities:
            story.append(Paragraph("Affected Entities (Internal IP Addresses)", heading_style))
            for entity in incident.affected_entities:
                story.append(Paragraph(f"• {entity}", normal_style))
            story.append(Spacer(1, 20))
        
        # Add description
        story.append(Paragraph("Incident Description", heading_style))
        story.append(Paragraph(incident.description, normal_style))
        story.append(Spacer(1, 20))
        
        # Add threat intelligence input
        if incident.threat_intelligence_input:
            story.append(Paragraph("Observed Attack Indicators", heading_style))
            story.append(Paragraph(incident.threat_intelligence_input, normal_style))
            story.append(Spacer(1, 20))
        
        # Add impact assessment
        story.append(Paragraph("Impact Assessment", heading_style))
        story.append(Paragraph(incident.impact_assessment, normal_style))
        story.append(Spacer(1, 20))
        
        # Add containment measures
        story.append(Paragraph("Immediate Response & Containment", heading_style))
        for measure in incident.containment_measures:
            story.append(Paragraph(f"• {measure}", normal_style))
        story.append(Spacer(1, 20))
        
        # Add threat intelligence if available
        if incident.threat_intelligence.indicators:
            story.append(Paragraph("Threat Intelligence", heading_style))
            
            # Add threat intelligence summary
            ti_summary = [
                ['Risk Score', f"{incident.threat_intelligence.risk_score}/100"],
                ['Confidence Level', incident.threat_intelligence.confidence_level],
                ['Indicators Found', str(len(incident.threat_intelligence.indicators))],
                ['Last Updated', incident.threat_intelligence.last_updated.strftime("%Y-%m-%d %H:%M") if incident.threat_intelligence.last_updated else 'N/A']
            ]
            
            ti_table = Table(ti_summary, colWidths=[2*inch, 4*inch])
            ti_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(ti_table)
            story.append(Spacer(1, 15))
            
            # Add threat indicators
            story.append(Paragraph("Threat Indicators:", normal_style))
            for indicator in incident.threat_intelligence.indicators:
                story.append(Paragraph(f"• {indicator}", normal_style))
            story.append(Spacer(1, 20))
        
        # Add vulnerabilities if available
        if incident.vulnerabilities:
            story.append(Paragraph("Vulnerabilities Identified", heading_style))
            
            for vulnerability in incident.vulnerabilities:
                # Create vulnerability summary table
                vuln_data = [
                    ['CVE ID', vulnerability.cve_id],
                    ['Severity', vulnerability.severity.title()],
                    ['CVSS Score', str(vulnerability.cvss_score) if vulnerability.cvss_score else 'N/A'],
                    ['Exploitation Status', vulnerability.exploitation_status.title()],
                    ['Patch Available', 'Yes' if vulnerability.patch_available else 'No']
                ]
                
                vuln_table = Table(vuln_data, colWidths=[2*inch, 4*inch])
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightcoral),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 10))
                
                # Add vulnerability description
                story.append(Paragraph("Description:", normal_style))
                story.append(Paragraph(vulnerability.description, normal_style))
                story.append(Spacer(1, 10))
                
                # Add external references
                story.append(Paragraph("External References:", normal_style))
                story.append(Paragraph(f"• ENISA Vulnerability Database: {vulnerability.enisa_url}", normal_style))
                story.append(Paragraph(f"• NVD CVE Database: {vulnerability.nvd_url}", normal_style))
                
                if vulnerability.affected_products:
                    story.append(Paragraph("Affected Products:", normal_style))
                    for product in vulnerability.affected_products:
                        story.append(Paragraph(f"• {product}", normal_style))
                
                story.append(Spacer(1, 20))
        
        # Add timeline
        story.append(Paragraph("Incident Timeline", heading_style))
        timeline_data = [
            ['Event', 'Date/Time'],
            ['Detection', incident.timeline.detection_time.strftime("%Y-%m-%d %H:%M")],
            ['Initial Report', incident.timeline.initial_report_time.strftime("%Y-%m-%d %H:%M") if incident.timeline.initial_report_time else 'Pending'],
            ['Resolution', incident.timeline.resolution_time.strftime("%Y-%m-%d %H:%M") if incident.timeline.resolution_time else 'Pending'],
            ['Closure', incident.timeline.closure_time.strftime("%Y-%m-%d %H:%M") if incident.timeline.closure_time else 'Pending']
        ]
        
        timeline_table = Table(timeline_data, colWidths=[3*inch, 3*inch])
        timeline_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(timeline_table)
        story.append(Spacer(1, 20))
        
        # Add footer
        story.append(Paragraph("Report Generated", heading_style))
        story.append(Paragraph(f"This report was automatically generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        story.append(Paragraph("NIS2 Compliance - Security Incident Reporting System", normal_style))
        
        # Build PDF
        doc.build(story)
        
        return str(filepath)
    
    def send_incident_report_email(self, incident: SecurityIncident, report_type: ReportType, 
                                 pdf_filepath: str, additional_data: Dict[str, str] = None) -> bool:
        """Send incident report via email to relevant recipients."""
        try:
            # Determine recipients based on report type and incident severity
            recipients = []
            for recipient in self.report_recipients:
                if recipient.should_receive_report(report_type, incident.severity):
                    recipients.append(recipient)
            
            if not recipients:
                st.warning("No recipients configured for this report type and severity level.")
                return False
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = f"{self.email_config.sender_name} <{self.email_config.sender_email}>"
            msg['Subject'] = f"NIS2 Incident Report - {incident.id} - {report_type.value.title()}"
            
            # Create email body
            body = self._create_email_body(incident, report_type, additional_data)
            msg.attach(MIMEText(body, 'html'))
            
            # Attach PDF
            with open(pdf_filepath, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {os.path.basename(pdf_filepath)}'
            )
            msg.attach(part)
            
            # Send email to each recipient
            success_count = 0
            for recipient in recipients:
                try:
                    msg['To'] = recipient.email_address
                    
                    # Connect to SMTP server
                    if self.email_config.use_ssl:
                        server = smtplib.SMTP_SSL(self.email_config.smtp_server, self.email_config.smtp_port)
                    else:
                        server = smtplib.SMTP(self.email_config.smtp_server, self.email_config.smtp_port)
                    
                    if self.email_config.use_tls:
                        server.starttls()
                    
                    # Login
                    server.login(self.email_config.username, self.email_config.password)
                    
                    # Send email
                    server.send_message(msg)
                    server.quit()
                    
                    success_count += 1
                    st.success(f"✅ Report sent to {recipient.entity_name} ({recipient.email_address})")
                    
                except Exception as e:
                    st.error(f"❌ Failed to send to {recipient.entity_name}: {e}")
            
            # Update incident status
            if success_count > 0:
                incident.email_sent = True
                incident.email_sent_date = datetime.now()
                self.save_incidents()
                
                return True
            
            return False
            
        except Exception as e:
            st.error(f"❌ Email sending failed: {e}")
            return False
    
    def _create_email_body(self, incident: SecurityIncident, report_type: ReportType, 
                          additional_data: Dict[str, str] = None) -> str:
        """Create HTML email body for incident report."""
        body = f"""
        <html>
        <body>
            <h2 style="color: #2c3e50;">NIS2 Security Incident Report</h2>
            
            <h3 style="color: #e74c3c;">Incident Summary</h3>
            <table style="border-collapse: collapse; width: 100%; margin-bottom: 20px;">
                <tr style="background-color: #ecf0f1;">
                    <td style="padding: 8px; border: 1px solid #bdc3c7;"><strong>Incident ID:</strong></td>
                    <td style="padding: 8px; border: 1px solid #bdc3c7;">{incident.id}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #bdc3c7;"><strong>Title:</strong></td>
                    <td style="padding: 8px; border: 1px solid #bdc3c7;">{incident.title}</td>
                </tr>
                <tr style="background-color: #ecf0f1;">
                    <td style="padding: 8px; border: 1px solid #bdc3c7;"><strong>Category:</strong></td>
                    <td style="padding: 8px; border: 1px solid #bdc3c7;">{incident.category.name.replace('_', ' ').title()}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #bdc3c7;"><strong>Severity:</strong></td>
                    <td style="padding: 8px; border: 1px solid #bdc3c7;">{incident.severity.name.title()}</td>
                </tr>
                <tr style="background-color: #ecf0f1;">
                    <td style="padding: 8px; border: 1px solid #bdc3c7;"><strong>Status:</strong></td>
                    <td style="padding: 8px; border: 1px solid #bdc3c7;">{incident.status.name.title()}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #bdc3c7;"><strong>Detection Time:</strong></td>
                    <td style="padding: 8px; border: 1px solid #bdc3c7;">{incident.timeline.detection_time.strftime("%Y-%m-%d %H:%M")}</td>
                </tr>
            </table>
            
            <h3 style="color: #e74c3c;">Affected Entities</h3>
            <p style="background-color: #f8f9fa; padding: 15px; border-left: 4px solid #e67e22;">
                <strong>Internal IP Addresses:</strong><br>
                {', '.join(incident.affected_entities) if incident.affected_entities else 'None specified'}
            </p>
            
            <h3 style="color: #e74c3c;">Description</h3>
            <p style="background-color: #f8f9fa; padding: 15px; border-left: 4px solid #3498db;">
                {incident.description}
            </p>
            
            <h3 style="color: #e74c3c;">Observed Attack Indicators</h3>
            <p style="background-color: #f8f9fa; padding: 15px; border-left: 4px solid #e74c3c;">
                {incident.threat_intelligence_input}
            </p>
            
            <h3 style="color: #e74c3c;">Impact Assessment</h3>
            <p style="background-color: #f8f9fa; padding: 15px; border-left: 4px solid #e74c3c;">
                {incident.impact_assessment}
            </p>
        """
        
        # Add threat intelligence if available
        if incident.threat_intelligence.indicators:
            body += f"""
            <h3 style="color: #e74c3c;">Threat Intelligence</h3>
            <p><strong>Risk Score:</strong> {incident.threat_intelligence.risk_score}/100</p>
            <p><strong>Confidence Level:</strong> {incident.threat_intelligence.confidence_level}</p>
            <p><strong>Indicators Found:</strong> {len(incident.threat_intelligence.indicators)}</p>
            
            <h4 style="color: #2c3e50;">Threat Indicators:</h4>
            <ul>
            """
            
            for indicator in incident.threat_intelligence.indicators:
                body += f"<li><strong>{indicator}</strong></li>"
            
            body += "</ul>"
        
        # Add vulnerabilities if available
        if incident.vulnerabilities:
            body += f"""
            <h3 style="color: #e74c3c;">Vulnerabilities Identified</h3>
            <p><strong>Total Vulnerabilities:</strong> {len(incident.vulnerabilities)}</p>
            """
            
            for vulnerability in incident.vulnerabilities:
                body += f"""
                <div style="background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 10px 0;">
                    <h4 style="color: #856404; margin-top: 0;">{vulnerability.cve_id}</h4>
                    <p><strong>Severity:</strong> {vulnerability.severity.title()}</p>
                    <p><strong>Status:</strong> {vulnerability.exploitation_status.title()}</p>
                    <p><strong>Patch Available:</strong> {'Yes' if vulnerability.patch_available else 'No'}</p>
                    <p><strong>Description:</strong> {vulnerability.description}</p>
                    <p><strong>External References:</strong></p>
                    <ul>
                        <li><a href="{vulnerability.enisa_url}" style="color: #007bff;">🔍 ENISA Vulnerability Database</a></li>
                        <li><a href="{vulnerability.nvd_url}" style="color: #007bff;">📋 NVD CVE Database</a></li>
                    </ul>
                </div>
                """
        
        # Add additional data if provided
        if additional_data:
            body += "<h3 style='color: #e74c3c;'>Additional Information</h3>"
            for key, value in additional_data.items():
                if value and value.strip():
                    body += f"<p><strong>{key.replace('_', ' ').title()}:</strong> {value}</p>"
        
        body += """
            <hr style="margin: 30px 0;">
            <p style="color: #7f8c8d; font-size: 12px;">
                This report was automatically generated by the NIS2 Incident Reporting System.<br>
                Please refer to the attached PDF for complete details and threat intelligence links.
            </p>
        </body>
        </html>
        """
        
        return body
    
    def display_configuration_interface(self):
        """Display configuration interface for email settings and recipients."""
        st.subheader("⚙️ Incident Reporting Configuration")
        
        # Email Configuration
        st.markdown("### 📧 Email Configuration")
        
        with st.expander("SMTP Settings", expanded=True):
            col1, col2 = st.columns(2)
            
            with col1:
                smtp_server = st.text_input(
                    "SMTP Server",
                    value=self.email_config.smtp_server,
                    help="SMTP server address (e.g., smtp.gmail.com)"
                )
                smtp_port = st.number_input(
                    "SMTP Port",
                    value=self.email_config.smtp_port,
                    min_value=1,
                    max_value=65535,
                    help="SMTP server port"
                )
                username = st.text_input(
                    "Username/Email",
                    value=self.email_config.username,
                    help="SMTP username or email address"
                )
            
            with col2:
                password = st.text_input(
                    "Password/App Password",
                    value=self.email_config.password,
                    type="password",
                    help="SMTP password or app password"
                )
                use_tls = st.checkbox(
                    "Use TLS",
                    value=self.email_config.use_tls,
                    help="Enable TLS encryption"
                )
                use_ssl = st.checkbox(
                    "Use SSL",
                    value=self.email_config.use_ssl,
                    help="Enable SSL encryption (mutually exclusive with TLS)"
                )
                sender_name = st.text_input(
                    "Sender Name",
                    value=self.email_config.sender_name,
                    help="Display name for outgoing emails"
                )
            
            if st.button("💾 Save Email Configuration", key="incident_save_email_config"):
                # Update email configuration
                self.email_config.smtp_server = smtp_server
                self.email_config.smtp_port = smtp_port
                self.email_config.username = username
                self.email_config.password = password
                self.email_config.use_tls = use_tls
                self.email_config.use_ssl = use_ssl
                self.email_config.sender_name = sender_name
                
                # Save to environment variables (for persistence)
                os.environ["SMTP_SERVER"] = smtp_server
                os.environ["SMTP_PORT"] = str(smtp_port)
                os.environ["SMTP_USERNAME"] = username
                os.environ["SMTP_PASSWORD"] = password
                os.environ["SMTP_USE_TLS"] = str(use_tls).lower()
                os.environ["SMTP_USE_SSL"] = str(use_ssl).lower()
                os.environ["SENDER_NAME"] = sender_name
                
                st.success("✅ Email configuration saved!")
        
        # Test Email Configuration
        st.markdown("### 🧪 Test Email Configuration")
        
        test_email = st.text_input(
            "Test Email Address",
            placeholder="Enter email address to send test message",
            help="Send a test email to verify configuration"
        )
        
        if st.button("📧 Send Test Email", key="incident_send_test_email") and test_email:
            if self._send_test_email(test_email):
                st.success("✅ Test email sent successfully!")
            else:
                st.error("❌ Test email failed - check configuration")
        
        # Report Recipients Management
        st.markdown("### 📋 Report Recipients")
        
        # Display current recipients
        st.markdown("#### Current Recipients")
        for i, recipient in enumerate(self.report_recipients):
            with st.expander(f"{recipient.entity_name} ({recipient.email_address})"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Priority:** {recipient.priority}")
                    st.write(f"**Contact Person:** {recipient.contact_person or 'Not specified'}")
                    st.write(f"**Phone:** {recipient.phone or 'Not specified'}")
                
                with col2:
                    st.write("**Report Types:**")
                    for rt in recipient.report_types:
                        st.write(f"• {rt.value.title()}")
                
                # Edit recipient
                if st.button(f"✏️ Edit {recipient.entity_name}", key=f"edit_{i}"):
                    st.session_state.editing_recipient = i
                
                # Delete recipient
                if st.button(f"🗑️ Delete {recipient.entity_name}", key=f"delete_{i}"):
                    if st.button(f"⚠️ Confirm Delete {recipient.entity_name}", key=f"confirm_delete_{i}"):
                        del self.report_recipients[i]
                        st.success(f"✅ {recipient.entity_name} removed")
                        st.rerun()
        
        # Add new recipient
        st.markdown("#### Add New Recipient")
        
        with st.form("add_recipient_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                new_entity_name = st.text_input("Entity Name *")
                new_email_address = st.text_input("Email Address *")
                new_priority = st.selectbox(
                    "Priority",
                    options=["Low", "Normal", "High", "Critical"],
                    index=1
                )
            
            with col2:
                new_contact_person = st.text_input("Contact Person")
                new_phone = st.text_input("Phone Number")
                new_report_types = st.multiselect(
                    "Report Types",
                    options=[rt.value for rt in ReportType],
                    default=[ReportType.INITIAL.value, ReportType.FINAL.value]
                )
            
            if st.form_submit_button("➕ Add Recipient"):
                if new_entity_name and new_email_address:
                    new_recipient = ReportRecipient(
                        entity_name=new_entity_name,
                        email_address=new_email_address,
                        report_types=[ReportType(rt) for rt in new_report_types],
                        priority=new_priority,
                        contact_person=new_contact_person,
                        phone=new_phone
                    )
                    
                    self.report_recipients.append(new_recipient)
                    st.success(f"✅ {new_entity_name} added as recipient")
                    st.rerun()
                else:
                    st.error("Please provide entity name and email address")
        
        # Export/Import Configuration
        st.markdown("### 💾 Export/Import Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📤 Export Configuration"):
                config_data = {
                    "email_config": {
                        "smtp_server": self.email_config.smtp_server,
                        "smtp_port": self.email_config.smtp_port,
                        "username": self.email_config.username,
                        "use_tls": self.email_config.use_tls,
                        "use_ssl": self.email_config.use_ssl,
                        "sender_name": self.email_config.sender_name
                    },
                    "recipients": [
                        {
                            "entity_name": r.entity_name,
                            "email_address": r.email_address,
                            "report_types": [rt.value for rt in r.report_types],
                            "priority": r.priority,
                            "contact_person": r.contact_person,
                            "phone": r.phone
                        }
                        for r in self.report_recipients
                    ]
                }
                
                st.download_button(
                    label="⬇️ Download Configuration",
                    data=json.dumps(config_data, indent=2),
                    file_name=f"incident_reporting_config_{datetime.now().strftime('%Y%m%d')}.json",
                    mime="application/json"
                )
        
        with col2:
            uploaded_file = st.file_uploader(
                "Import Configuration",
                type=["json"],
                help="Upload a previously exported configuration file"
            )
            
            if uploaded_file is not None:
                try:
                    config_data = json.load(uploaded_file)
                    
                    if st.button("📥 Import Configuration"):
                        # Update email config
                        if "email_config" in config_data:
                            ec = config_data["email_config"]
                            self.email_config.smtp_server = ec.get("smtp_server", self.email_config.smtp_server)
                            self.email_config.smtp_port = ec.get("smtp_port", self.email_config.smtp_port)
                            self.email_config.username = ec.get("username", self.email_config.username)
                            self.email_config.use_tls = ec.get("use_tls", self.email_config.use_tls)
                            self.email_config.use_ssl = ec.get("use_ssl", self.email_config.use_ssl)
                            self.email_config.sender_name = ec.get("sender_name", self.email_config.sender_name)
                        
                        # Update recipients
                        if "recipients" in config_data:
                            self.report_recipients = []
                            for r_data in config_data["recipients"]:
                                recipient = ReportRecipient(
                                    entity_name=r_data["entity_name"],
                                    email_address=r_data["email_address"],
                                    report_types=[ReportType(rt) for rt in r_data.get("report_types", [])],
                                    priority=r_data.get("priority", "Normal"),
                                    contact_person=r_data.get("contact_person", ""),
                                    phone=r_data.get("phone", "")
                                )
                                self.report_recipients.append(recipient)
                        
                        st.success("✅ Configuration imported successfully!")
                        st.rerun()
                        
                except Exception as e:
                    st.error(f"❌ Failed to import configuration: {e}")
    
    def _send_test_email(self, test_email: str) -> bool:
        """Send a test email to verify configuration."""
        try:
            msg = MIMEMultipart()
            msg['From'] = f"{self.email_config.sender_name} <{self.email_config.username}>"
            msg['To'] = test_email
            msg['Subject'] = "NIS2 Incident Reporting System - Test Email"
            
            body = """
            <html>
            <body>
                <h2>NIS2 Incident Reporting System - Test Email</h2>
                <p>This is a test email to verify your email configuration is working correctly.</p>
                <p>If you received this email, your incident reporting system is properly configured for email distribution.</p>
                <hr>
                <p style="color: #7f8c8d; font-size: 12px;">
                    Sent on: {timestamp}<br>
                    System: NIS2 Incident Reporting System
                </p>
            </body>
            </html>
            """.format(timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            msg.attach(MIMEText(body, 'html'))
            
            # Connect to SMTP server
            if self.email_config.use_ssl:
                server = smtplib.SMTP_SSL(self.email_config.smtp_server, self.email_config.smtp_port)
            else:
                server = smtplib.SMTP(self.email_config.smtp_server, self.email_config.smtp_port)
            
            if self.email_config.use_tls:
                server.starttls()
            
            # Login
            server.login(self.email_config.username, self.email_config.password)
            
            # Send email
            server.send_message(msg)
            server.quit()
            
            return True
            
        except Exception as e:
            st.error(f"Test email failed: {e}")
            return False
    
    def display_report_timeline(self):
        """Display incident reporting timeline and deadlines."""
        st.subheader("📋 Report Timeline & Deadlines")
        
        if not self.incidents:
            st.info("No incidents to display timeline for.")
            return
        
        # Get current organization context from session state
        current_org_id = st.session_state.get('current_organization_id')
        if not current_org_id:
            st.error("Unable to determine organization context.")
            return
        
        # Filter incidents by current organization
        organization_incidents = [
            incident for incident in self.incidents.values() 
            if str(incident.organization_id) == str(current_org_id)
        ]
        
        if not organization_incidents:
            st.info(f"No incidents found for the current organization.")
            return
        
        # Get upcoming deadlines
        upcoming_deadlines = []
        overdue_reports = []
        
        for incident in organization_incidents:
            if incident.status in [IncidentStatus.CLOSED]:
                continue
                
            deadline = incident.timeline.get_next_report_deadline()
            if deadline:
                if incident.timeline.is_overdue():
                    overdue_reports.append((incident, deadline))
                else:
                    upcoming_deadlines.append((incident, deadline))
        
        # Sort by deadline
        upcoming_deadlines.sort(key=lambda x: x[1])
        overdue_reports.sort(key=lambda x: x[1])
        
        # Display overdue reports
        if overdue_reports:
            st.error("🚨 **OVERDUE REPORTS**")
            for incident, deadline in overdue_reports:
                st.markdown(f"**{incident.title}** (ID: {incident.id}) - Due: {deadline:%Y-%m-%d %H:%M}")
        
        # Display upcoming deadlines
        if upcoming_deadlines:
            st.subheader("📅 Upcoming Deadlines")
            for incident, deadline in upcoming_deadlines:
                time_until = deadline - datetime.now()
                if time_until.total_seconds() < 86400:  # Less than 24 hours
                    st.warning(f"⚠️ **{incident.title}** (ID: {incident.id}) - Due: {deadline:%Y-%m-%d %H:%M} ({time_until.days}d {time_until.seconds//3600}h)")
                else:
                    st.info(f"📅 **{incident.title}** (ID: {incident.id}) - Due: {deadline:%Y-%m-%d %H:%M} ({time_until.days}d {time_until.seconds//3600}h)")
        
        # Timeline visualization
        st.subheader("📊 Incident Timeline Overview")
        
        timeline_data = []
        for incident in organization_incidents:
            timeline_data.append({
                "Incident": incident.title,
                "Detection": incident.timeline.detection_time,
                "Initial Report": incident.timeline.initial_report_time or "Not Submitted",
                "Status": incident.status.name.title(),
                "Severity": incident.severity.name.title()
            })
        
        if timeline_data:
            df = pd.DataFrame(timeline_data)
            st.dataframe(df, use_container_width=True)
    
    def display_incident_analytics(self):
        """Display incident analytics and compliance metrics."""
        st.subheader("📈 Incident Analytics & Compliance")
        
        if not self.incidents:
            st.info("No incidents to analyze.")
            return
        
        # Get current organization context from session state
        current_org_id = st.session_state.get('current_organization_id')
        if not current_org_id:
            st.error("Unable to determine organization context.")
            return
        
        # Filter incidents by current organization
        organization_incidents = [
            incident for incident in self.incidents.values() 
            if str(incident.organization_id) == str(current_org_id)
        ]
        
        if not organization_incidents:
            st.info(f"No incidents found for the current organization.")
            return
        
        # Compliance metrics
        col1, col2, col3, col4 = st.columns(4)
        
        total_incidents = len(organization_incidents)
        resolved_incidents = len([i for i in organization_incidents if i.status == IncidentStatus.RESOLVED])
        closed_incidents = len([i for i in organization_incidents if i.status == IncidentStatus.CLOSED])
        overdue_reports = len([i for i in organization_incidents if i.timeline.is_overdue()])
        
        with col1:
            st.metric("Total Incidents", total_incidents)
        with col2:
            st.metric("Resolved", resolved_incidents)
        with col3:
            st.metric("Closed", closed_incidents)
        with col4:
            st.metric("Overdue Reports", overdue_reports, delta=f"{overdue_reports} overdue")
        
        # Severity distribution
        st.subheader("📊 Incident Severity Distribution")
        severity_counts = {}
        for incident in organization_incidents:
            severity = incident.severity.name
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts:
            severity_df = pd.DataFrame(list(severity_counts.items()), columns=["Severity", "Count"])
            st.bar_chart(severity_df.set_index("Severity"))
        
        # Category distribution
        st.subheader("📊 Incident Category Distribution")
        category_counts = {}
        for incident in organization_incidents:
            category = incident.category.name.replace('_', ' ').title()
            category_counts[category] = category_counts.get(category, 0) + 1
        
        if category_counts:
            category_df = pd.DataFrame(list(category_counts.items()), columns=["Category", "Count"])
            st.bar_chart(category_df.set_index("Category"))
        
        # Status distribution
        st.subheader("📊 Incident Status Distribution")
        status_counts = {}
        for incident in organization_incidents:
            status = incident.status.name.title()
            status_counts[status] = status_counts.get(status, 0) + 1
        
        if status_counts:
            status_df = pd.DataFrame(list(status_counts.items()), columns=["Status", "Count"])
            st.bar_chart(status_df.set_index("Status"))
        
        # Time-based analysis
        st.subheader("📅 Time-Based Analysis")
        
        # Monthly incident trend
        monthly_data = {}
        for incident in organization_incidents:
            month_key = incident.timeline.detection_time.strftime("%Y-%m")
            monthly_data[month_key] = monthly_data.get(month_key, 0) + 1
        
        if monthly_data:
            monthly_df = pd.DataFrame(list(monthly_data.items()), columns=["Month", "Incidents"])
            monthly_df = monthly_df.sort_values("Month")
            st.line_chart(monthly_df.set_index("Month"))
        
        # Response time analysis
        st.subheader("⏱️ Response Time Analysis")
        response_times = []
        for incident in organization_incidents:
            if incident.timeline.initial_report_time and incident.timeline.detection_time:
                response_time = (incident.timeline.initial_report_time - incident.timeline.detection_time).total_seconds() / 3600  # Hours
                response_times.append(response_time)
        
        if response_times:
            avg_response = sum(response_times) / len(response_times)
            st.metric("Average Response Time", f"{avg_response:.1f} hours")
            
            # Response time distribution
            response_df = pd.DataFrame(response_times, columns=["Response Time (Hours)"])
            st.bar_chart(response_df)
    
    def close_incident(self, incident_id: str):
        """Close an incident."""
        if incident_id in self.incidents:
            incident = self.incidents[incident_id]
            incident.status = IncidentStatus.CLOSED
            incident.timeline.closure_time = datetime.now()
            self.save_incidents()
            st.success(f"✅ Incident {incident_id} closed successfully!")
            st.rerun()
    
    def save_report(self, incident_id: str, report_type: str, content: str):
        """Save a generated report."""
        # Create reports directory if it doesn't exist
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Save report file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"incident_{incident_id}_{report_type}_{timestamp}.md"
        filepath = reports_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        st.info(f"📄 Report saved as: {filename}")
    
    def save_incidents(self):
        """Save incidents to JSON file."""
        incidents_data = {}
        for incident_id, incident in self.incidents.items():
            incidents_data[incident_id] = {
                "id": incident.id,
                "title": incident.title,
                "description": incident.description,
                "category": incident.category.value,
                "severity": incident.severity.value,
                "status": incident.status.value,
                "timeline": {
                    "detection_time": incident.timeline.detection_time.isoformat(),
                    "initial_report_time": incident.timeline.initial_report_time.isoformat() if incident.timeline.initial_report_time else None,
                    "intermediate_reports": [t.isoformat() for t in incident.timeline.intermediate_reports],
                    "final_report_time": incident.timeline.final_report_time.isoformat() if incident.timeline.final_report_time else None,
                    "resolution_time": incident.timeline.resolution_time.isoformat() if incident.timeline.resolution_time else None,
                    "closure_time": incident.timeline.closure_time.isoformat() if incident.timeline.closure_time else None
                },
                "affected_services": incident.affected_services,
                "affected_entities": incident.affected_entities,
                "threat_intelligence_input": incident.threat_intelligence_input,
                "impact_assessment": incident.impact_assessment,
                "containment_measures": incident.containment_measures,
                "remediation_actions": incident.remediation_actions,
                "lessons_learned": incident.lessons_learned,
                "reported_to_authorities": incident.reported_to_authorities,
                "authority_report_date": incident.authority_report_date.isoformat() if incident.authority_report_date else None,
                "organization_id": incident.organization_id,
                "assigned_to": incident.assigned_to,
                "threat_intelligence": {
                    "indicators": incident.threat_intelligence.indicators,
                    "malware_families": incident.threat_intelligence.malware_families,
                    "attack_vectors": incident.threat_intelligence.attack_vectors,
                    "threat_actors": incident.threat_intelligence.threat_actors,
                    "ioc_sources": incident.threat_intelligence.ioc_sources,
                    "risk_score": incident.threat_intelligence.risk_score,
                    "confidence_level": incident.threat_intelligence.confidence_level,
                    "last_updated": incident.threat_intelligence.last_updated.isoformat() if incident.threat_intelligence.last_updated else None
                },
                "vulnerabilities": [v.to_dict() for v in incident.vulnerabilities],
                "report_recipients": [
                    {
                        "entity_name": r.entity_name,
                        "email_address": r.email_address,
                        "report_types": [rt.value for rt in r.report_types],
                        "priority": r.priority,
                        "contact_person": r.contact_person,
                        "phone": r.phone
                    }
                    for r in incident.report_recipients
                ],
                "email_sent": incident.email_sent,
                "email_sent_date": incident.email_sent_date.isoformat() if incident.email_sent_date else None
            }
        
        # Save to file
        with open("incidents.json", "w") as f:
            json.dump(incidents_data, f, indent=2)
    
    def load_incidents(self):
        """Load incidents from JSON file."""
        try:
            with open("incidents.json", "r") as f:
                incidents_data = json.load(f)
            
            for incident_id, data in incidents_data.items():
                # Reconstruct timeline
                timeline = IncidentTimeline(
                    detection_time=datetime.fromisoformat(data["timeline"]["detection_time"]),
                    initial_report_time=datetime.fromisoformat(data["timeline"]["initial_report_time"]) if data["timeline"]["initial_report_time"] else None,
                    intermediate_reports=[datetime.fromisoformat(t) for t in data["timeline"]["intermediate_reports"]],
                    final_report_time=datetime.fromisoformat(data["timeline"]["final_report_time"]) if data["timeline"]["final_report_time"] else None,
                    resolution_time=datetime.fromisoformat(data["timeline"]["resolution_time"]) if data["timeline"]["resolution_time"] else None,
                    closure_time=datetime.fromisoformat(data["timeline"]["closure_time"]) if data["timeline"]["closure_time"] else None
                )
                
                # Reconstruct threat intelligence
                threat_intelligence = ThreatIntelligence()
                if "threat_intelligence" in data:
                    ti_data = data["threat_intelligence"]
                    threat_intelligence.indicators = ti_data.get("indicators", [])
                    threat_intelligence.malware_families = ti_data.get("malware_families", [])
                    threat_intelligence.attack_vectors = ti_data.get("attack_vectors", [])
                    threat_intelligence.threat_actors = ti_data.get("threat_actors", [])
                    threat_intelligence.ioc_sources = ti_data.get("ioc_sources", {})
                    threat_intelligence.risk_score = ti_data.get("risk_score", 0)
                    threat_intelligence.confidence_level = ti_data.get("confidence_level", "Low")
                    threat_intelligence.last_updated = datetime.fromisoformat(ti_data["last_updated"]) if ti_data.get("last_updated") else None
                
                # Reconstruct vulnerabilities
                vulnerabilities = []
                if "vulnerabilities" in data:
                    for v_data in data["vulnerabilities"]:
                        vulnerability = Vulnerability.from_dict(v_data)
                        vulnerabilities.append(vulnerability)
                
                # Reconstruct report recipients
                report_recipients = []
                if "report_recipients" in data:
                    for r_data in data["report_recipients"]:
                        recipient = ReportRecipient(
                            entity_name=r_data["entity_name"],
                            email_address=r_data["email_address"],
                            report_types=[ReportType(rt) for rt in r_data.get("report_types", [])],
                            priority=r_data.get("priority", "Normal"),
                            contact_person=r_data.get("contact_person", ""),
                            phone=r_data.get("phone", "")
                        )
                        report_recipients.append(recipient)
                
                # Reconstruct incident
                incident = SecurityIncident(
                    id=data["id"],
                    title=data["title"],
                    description=data["description"],
                    category=IncidentCategory(data["category"]),
                    severity=IncidentSeverity(data["severity"]),
                    status=IncidentStatus(data["status"]),
                    timeline=timeline,
                    affected_services=data["affected_services"],
                    affected_entities=data.get("affected_entities", []),  # Backward compatibility
                    threat_intelligence_input=data.get("threat_intelligence_input", ""),  # Backward compatibility
                    impact_assessment=data["impact_assessment"],
                    containment_measures=data["containment_measures"],
                    remediation_actions=data["remediation_actions"],
                    lessons_learned=data["lessons_learned"],
                    reported_to_authorities=data["reported_to_authorities"],
                    authority_report_date=datetime.fromisoformat(data["authority_report_date"]) if data["authority_report_date"] else None,
                    organization_id=data["organization_id"],
                    assigned_to=data["assigned_to"],
                    threat_intelligence=threat_intelligence,
                    vulnerabilities=vulnerabilities,
                    report_recipients=report_recipients,
                    email_sent=data.get("email_sent", False),
                    email_sent_date=datetime.fromisoformat(data["email_sent_date"]) if data.get("email_sent_date") else None
                )
                
                self.incidents[incident_id] = incident
                
        except FileNotFoundError:
            # No incidents file yet, start with empty dict
            pass
        except Exception as e:
            st.error(f"Error loading incidents: {e}")
