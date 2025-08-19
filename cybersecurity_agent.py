"""
Enhanced Cybersecurity Reporting Agent
A comprehensive cybersecurity analysis and reporting tool with NIS2 compliance and multi-organization support.
"""

import os
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta, date
from typing import Dict, List, Optional, Tuple
import streamlit as st
from dotenv import load_dotenv
import hashlib
import requests
import dns.resolver
import whois
import yaml
import markdown
from cryptography.fernet import Fernet
import base64

# Branding utilities
def _load_svg_data_url(filename: str) -> str:
    """Load an SVG file from this directory and return a data URL string."""
    try:
        base_dir = os.path.dirname(__file__)
        svg_path = os.path.join(base_dir, filename)
        with open(svg_path, 'rb') as f:
            data = f.read()
        b64 = base64.b64encode(data).decode('utf-8')
        return f"data:image/svg+xml;base64,{b64}"
    except Exception:
        return ""

def get_branding_header_html(title_text: str = "Security Report") -> str:
    """Return a branded HTML header with Cohesive logo and a title."""
    logo_data_url = _load_svg_data_url('cohesive_logo.svg')
    brand = "Cohesive"
    subtitle = "Technology"
    return f'''
<div style="display:flex; align-items:center; gap:16px; padding:12px 0 8px 0; border-bottom:1px solid #e9eef5;">
  <img src="{logo_data_url}" alt="{brand} logo" style="height:72px; width:auto;"/>
  <div>
    <div style="font: 700 24px/1.2 Inter, Segoe UI, Arial; color:#0B1020;">{brand}</div>
    <div style="font: 500 14px/1.2 Inter, Segoe UI, Arial; color:#5A6275; letter-spacing:2px; text-transform:uppercase;">{subtitle} • {title_text}</div>
  </div>
</div>
'''

# Import custom modules
from auth_system import AuthenticationSystem, StreamlitAuth, User, UserRole, Organization
from nis2_compliance import NIS2ComplianceModule, SecurityIncident, IncidentSeverity, IncidentStatus
from user_management import UserManagementInterface
from nis2_scope_assessment import NIS2ScopeAssessment
from incident_reporting import IncidentReportingModule
from reporting_entities import ReportingEntitiesInterface
from security_controls import SecurityControlsInterface
from risk_management import RiskManagementSystem, RiskManagementInterface
from nis2_scope_assessment import NIS2ScopeAssessment
from reporting_entities import ReportingEntitiesModule

# Load environment variables
load_dotenv()

class CybersecurityAgent:
    """Main class for cybersecurity analysis and reporting."""
    
    def __init__(self):
        """Initialize the cybersecurity agent."""
        self.api_key = os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            st.error("Please set OPENAI_API_KEY in your .env file")
            st.stop()
        
        # Initialize security tools
        self.vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.shodan_api_key = os.getenv("SHODAN_API_KEY")
        self.censys_api_id = os.getenv("CENSYS_API_ID")
        self.censys_api_secret = os.getenv("CENSYS_API_SECRET")
        
        # Initialize NIS2 modules
        self.nis2_scope_assessment = NIS2ScopeAssessment()
        self.incident_reporting = IncidentReportingModule()
        self.reporting_entities = ReportingEntitiesInterface()
        self.security_controls = SecurityControlsInterface()
        self.risk_management = RiskManagementSystem()
        
        # Set up plotting style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
    def analyze_domain(self, domain: str) -> Dict:
        """
        Perform comprehensive domain analysis.
        
        Args:
            domain: Domain name to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'dns_records': {},
            'whois_info': {},
            'security_headers': {},
            'ssl_certificate': {},
            'subdomain_enumeration': [],
            'threat_intelligence': {},
            'risk_score': 0
        }
        
        try:
            # DNS Analysis
            results['dns_records'] = self._analyze_dns(domain)
            
            # WHOIS Information
            results['whois_info'] = self._analyze_whois(domain)
            
            # Security Headers
            results['security_headers'] = self._analyze_security_headers(domain)
            
            # SSL Certificate
            results['ssl_certificate'] = self._analyze_ssl_certificate(domain)
            
            # Subdomain Enumeration
            results['subdomain_enumeration'] = self._enumerate_subdomains(domain)
            
            # Threat Intelligence
            results['threat_intelligence'] = self._gather_threat_intelligence(domain)
            
            # Calculate Risk Score
            results['risk_score'] = self._calculate_risk_score(results)
            
        except Exception as e:
            st.error(f"Error analyzing domain {domain}: {str(e)}")
            
        return results
    
    def analyze_ip_address(self, ip_address: str) -> Dict:
        """
        Perform comprehensive IP address analysis.
        
        Args:
            ip_address: IP address to analyze
            
        Returns:
            Dictionary containing analysis results
        """
        results = {
            'ip_address': ip_address,
            'timestamp': datetime.now().isoformat(),
            'geolocation': {},
            'ports': [],
            'services': [],
            'threat_intelligence': {},
            'reputation': {},
            'risk_score': 0
        }
        
        try:
            # Geolocation
            results['geolocation'] = self._get_ip_geolocation(ip_address)
            
            # Port Scanning
            results['ports'] = self._scan_ports(ip_address)
            
            # Service Detection
            results['services'] = self._detect_services(ip_address, results['ports'])
            
            # Threat Intelligence
            results['threat_intelligence'] = self._gather_ip_threat_intelligence(ip_address)
            
            # Reputation Check
            results['reputation'] = self._check_ip_reputation(ip_address)
            
            # Calculate Risk Score
            results['risk_score'] = self._calculate_ip_risk_score(results)
            
        except Exception as e:
            st.error(f"Error analyzing IP {ip_address}: {str(e)}")
            
        return results
    
    def analyze_file_hash(self, file_hash: str) -> Dict:
        """
        Analyze file hash for malware detection.
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
            
        Returns:
            Dictionary containing analysis results
        """
        results = {
            'hash': file_hash,
            'hash_type': self._detect_hash_type(file_hash),
            'timestamp': datetime.now().isoformat(),
            'virustotal_results': {},
            'file_metadata': {},
            'risk_score': 0
        }
        
        try:
            # VirusTotal Analysis
            if self.vt_api_key:
                results['virustotal_results'] = self._query_virustotal(file_hash)
            
            # File Metadata
            results['file_metadata'] = self._analyze_file_metadata(file_hash)
            
            # Calculate Risk Score
            results['risk_score'] = self._calculate_file_risk_score(results)
            
        except Exception as e:
            st.error(f"Error analyzing hash {file_hash}: {str(e)}")
            
        return results
    
    def generate_security_report(self, analysis_results: Dict, report_type: str = "comprehensive") -> str:
        """
        Generate a comprehensive security report.
        
        Args:
            analysis_results: Analysis results dictionary
            report_type: Type of report to generate
            
        Returns:
            Formatted report string
        """
        if report_type == "executive":
            body = self._generate_executive_summary(analysis_results)
            header_title = "Executive Security Summary"
        elif report_type == "technical":
            body = self._generate_technical_report(analysis_results)
            header_title = "Technical Security Report"
        else:
            body = self._generate_comprehensive_report(analysis_results)
            header_title = "Comprehensive Security Report"

        header_html = get_branding_header_html(header_title)
        return f"{header_html}\n{body}"
    
    def _analyze_dns(self, domain: str) -> Dict:
        """Analyze DNS records for a domain."""
        dns_info = {}
        
        try:
            # A Records
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                dns_info['A'] = [str(record) for record in a_records]
            except:
                dns_info['A'] = []
            
            # AAAA Records
            try:
                aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                dns_info['AAAA'] = [str(record) for record in aaaa_records]
            except:
                dns_info['AAAA'] = []
            
            # MX Records
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                dns_info['MX'] = [str(record.exchange) for record in mx_records]
            except:
                dns_info['MX'] = []
            
            # TXT Records
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                dns_info['TXT'] = [str(record) for record in txt_records]
            except:
                dns_info['TXT'] = []
            
            # NS Records
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                dns_info['NS'] = [str(record) for record in ns_records]
            except:
                dns_info['NS'] = []
                
        except Exception as e:
            st.warning(f"DNS analysis failed: {str(e)}")
            
        return dns_info
    
    def _analyze_whois(self, domain: str) -> Dict:
        """Analyze WHOIS information for a domain."""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'updated_date': str(w.updated_date),
                'status': w.status,
                'name_servers': w.name_servers
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_security_headers(self, domain: str) -> Dict:
        """Analyze security headers for a domain."""
        headers = {}
        try:
            url = f"https://{domain}"
            response = requests.get(url, timeout=10, allow_redirects=False)
            
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Permissions-Policy'
            ]
            
            for header in security_headers:
                if header in response.headers:
                    headers[header] = response.headers[header]
                else:
                    headers[header] = 'Not Set'
                    
        except Exception as e:
            headers['error'] = str(e)
            
        return headers
    
    def _analyze_ssl_certificate(self, domain: str) -> Dict:
        """Analyze SSL certificate for a domain."""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
        except Exception as e:
            return {'error': str(e)}
    
    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains for a domain."""
        subdomains = []
        
        # Common subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test',
            'api', 'cdn', 'ns1', 'ns2', 'smtp', 'pop', 'imap'
        ]
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                dns.resolver.resolve(full_domain, 'A')
                subdomains.append(full_domain)
            except:
                continue
                
        return subdomains
    
    def _gather_threat_intelligence(self, domain: str) -> Dict:
        """Gather threat intelligence for a domain."""
        intel = {}
        
        # Check if domain is in common threat lists
        threat_lists = [
            'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
            'https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt'
        ]
        
        # This is a simplified version - in production you'd use proper threat intel APIs
        intel['suspicious_indicators'] = []
        intel['reputation_score'] = 'Unknown'
        
        return intel
    
    def _get_ip_geolocation(self, ip_address: str) -> Dict:
        """Get geolocation information for an IP address."""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}")
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'isp': data.get('isp'),
                    'org': data.get('org')
                }
        except:
            pass
        return {'error': 'Unable to determine geolocation'}
    
    def _scan_ports(self, ip_address: str) -> List[int]:
        """Scan common ports on an IP address."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                continue
                
        return open_ports
    
    def _detect_services(self, ip_address: str, ports: List[int]) -> List[Dict]:
        """Detect services running on open ports."""
        services = []
        
        service_mapping = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        
        for port in ports:
            service_name = service_mapping.get(port, 'Unknown')
            services.append({
                'port': port,
                'service': service_name,
                'status': 'Open'
            })
            
        return services
    
    def _gather_ip_threat_intelligence(self, ip_address: str) -> Dict:
        """Gather threat intelligence for an IP address."""
        intel = {}
        
        # Check against common threat lists
        intel['suspicious_indicators'] = []
        intel['reputation_score'] = 'Unknown'
        intel['last_seen'] = 'Unknown'
        
        return intel
    
    def _check_ip_reputation(self, ip_address: str) -> Dict:
        """Check IP address reputation."""
        reputation = {}
        
        # Check against abuse databases
        abuse_checks = [
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}",
            f"https://api.virustotal.com/v3/ip_addresses/{ip_address}"
        ]
        
        reputation['abuse_score'] = 'Unknown'
        reputation['category'] = 'Unknown'
        
        return reputation
    
    def _detect_hash_type(self, file_hash: str) -> str:
        """Detect the type of hash based on length."""
        hash_length = len(file_hash)
        
        if hash_length == 32:
            return 'MD5'
        elif hash_length == 40:
            return 'SHA1'
        elif hash_length == 64:
            return 'SHA256'
        else:
            return 'Unknown'
    
    def _query_virustotal(self, file_hash: str) -> Dict:
        """Query VirusTotal for file analysis."""
        if not self.vt_api_key:
            return {'error': 'VirusTotal API key not configured'}
        
        try:
            headers = {
                'x-apikey': self.vt_api_key
            }
            
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {'apikey': self.vt_api_key, 'resource': file_hash}
            
            response = requests.get(url, params=params, headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'VirusTotal API error: {response.status_code}'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_file_metadata(self, file_hash: str) -> Dict:
        """Analyze file metadata based on hash."""
        metadata = {}
        
        # This would typically involve file analysis tools
        metadata['file_type'] = 'Unknown'
        metadata['file_size'] = 'Unknown'
        metadata['entropy'] = 'Unknown'
        
        return metadata
    
    def _calculate_risk_score(self, results: Dict) -> int:
        """Calculate overall risk score for domain analysis."""
        risk_score = 0
        
        # DNS Security
        if not results.get('dns_records', {}).get('A'):
            risk_score += 20
        
        # SSL Certificate
        if results.get('ssl_certificate', {}).get('error'):
            risk_score += 30
        
        # Security Headers
        security_headers = results.get('security_headers', {})
        missing_headers = sum(1 for header, value in security_headers.items() 
                            if value == 'Not Set' and header != 'error')
        risk_score += missing_headers * 5
        
        # Threat Intelligence
        if results.get('threat_intelligence', {}).get('suspicious_indicators'):
            risk_score += 25
        
        return min(risk_score, 100)
    
    def _calculate_ip_risk_score(self, results: Dict) -> int:
        """Calculate risk score for IP address analysis."""
        risk_score = 0
        
        # Open Ports
        open_ports = results.get('ports', [])
        risky_ports = [23, 3389, 5900]  # Telnet, RDP, VNC
        for port in open_ports:
            if port in risky_ports:
                risk_score += 15
        
        # Services
        services = results.get('services', [])
        for service in services:
            if service['service'] in ['Telnet', 'RDP', 'VNC']:
                risk_score += 10
        
        # Threat Intelligence
        if results.get('threat_intelligence', {}).get('suspicious_indicators'):
            risk_score += 25
        
        return min(risk_score, 100)
    
    def _calculate_file_risk_score(self, results: Dict) -> int:
        """Calculate risk score for file analysis."""
        risk_score = 0
        
        # VirusTotal Results
        vt_results = results.get('virustotal_results', {})
        if 'positives' in vt_results and vt_results['positives'] > 0:
            risk_score += min(vt_results['positives'] * 10, 50)
        
        return min(risk_score, 100)
    
    def _generate_executive_summary(self, results: Dict) -> str:
        """Generate executive summary report."""
        report = f"""
# Executive Security Summary

## Analysis Overview
- **Target**: {results.get('domain', results.get('ip_address', results.get('hash', 'Unknown')))}
- **Analysis Date**: {results.get('timestamp', 'Unknown')}
- **Risk Score**: {results.get('risk_score', 0)}/100

## Key Findings
"""
        
        risk_score = results.get('risk_score', 0)
        if risk_score >= 70:
            report += "- **HIGH RISK**: Immediate attention required\n"
        elif risk_score >= 40:
            report += "- **MEDIUM RISK**: Review and monitoring recommended\n"
        else:
            report += "- **LOW RISK**: Standard security measures sufficient\n"
        
        report += "\n## Recommendations\n"
        if risk_score >= 70:
            report += "- Implement immediate security controls\n"
            report += "- Conduct detailed security assessment\n"
            report += "- Monitor for suspicious activity\n"
        elif risk_score >= 40:
            report += "- Review security configurations\n"
            report += "- Implement additional controls as needed\n"
        else:
            report += "- Maintain current security posture\n"
            report += "- Regular security reviews recommended\n"
        
        return report
    
    def _generate_technical_report(self, results: Dict) -> str:
        """Generate technical detailed report."""
        report = f"""
# Technical Security Report

## Analysis Details
- **Target**: {results.get('domain', results.get('ip_address', results.get('hash', 'Unknown')))}
- **Analysis Date**: {results.get('timestamp', 'Unknown')}
- **Risk Score**: {results.get('risk_score', 0)}/100

## Detailed Findings
"""
        
        # Add specific findings based on analysis type
        if 'dns_records' in results:
            report += "\n### DNS Analysis\n"
            for record_type, records in results['dns_records'].items():
                if records:
                    report += f"- **{record_type}**: {', '.join(records)}\n"
        
        if 'security_headers' in results:
            report += "\n### Security Headers\n"
            for header, value in results['security_headers'].items():
                if header != 'error':
                    status = "✅" if value != 'Not Set' else "❌"
                    report += f"- {status} {header}: {value}\n"
        
        if 'ports' in results:
            report += "\n### Open Ports\n"
            for port in results['ports']:
                report += f"- Port {port}\n"
        
        return report
    
    def _generate_comprehensive_report(self, results: Dict) -> str:
        """Generate comprehensive security report."""
        report = self._generate_executive_summary(results)
        report += "\n" + self._generate_technical_report(results)
        
        report += "\n## Risk Assessment Details\n"
        risk_score = results.get('risk_score', 0)
        
        if risk_score >= 70:
            report += "**Risk Level: HIGH**\n\n"
            report += "This target presents significant security risks that require immediate attention.\n"
        elif risk_score >= 40:
            report += "**Risk Level: MEDIUM**\n\n"
            report += "This target has moderate security risks that should be addressed.\n"
        else:
            report += "**Risk Level: LOW**\n\n"
            report += "This target has minimal security risks.\n"
        
        report += "\n## Next Steps\n"
        report += "1. Review all findings in detail\n"
        report += "2. Implement recommended security controls\n"
        report += "3. Schedule follow-up security assessment\n"
        report += "4. Document all security measures implemented\n"
        
        return report

def get_current_organization_context(auth_system, streamlit_auth, current_user):
    """Get the current organization context based on user role and selections."""
    # Get the user's default organization
    default_org = streamlit_auth.get_current_organization()
    
    if not default_org:
        return None, False
    
    # Check if admin/partner has explicitly selected a different organization
    admin_selected_org_id = st.session_state.get('admin_selected_org_id')
    admin_selected_org_name = st.session_state.get('admin_selected_org_name')
    partner_selected_org_id = st.session_state.get('partner_selected_org_id')
    partner_selected_org_name = st.session_state.get('partner_selected_org_name')
    
    # Use admin-selected organization if available and explicitly set
    if admin_selected_org_id and admin_selected_org_name and current_user.role.value == 'admin':
        # Get the admin-selected organization
        all_organizations = auth_system.get_all_organizations()
        admin_org = next((org for org in all_organizations if org.id == admin_selected_org_id), None)
        
        if admin_org:
            return admin_org, True  # True indicates admin mode
        else:
            # Clear invalid admin selection
            st.session_state.admin_selected_org_id = None
            st.session_state.admin_selected_org_name = None
            st.warning("⚠️ Selected organization not found. Reverted to user's organization.")
    
    # Use partner-selected organization if available and explicitly set
    elif partner_selected_org_id and partner_selected_org_name and current_user.role.value == 'partner':
        # Get organizations accessible to partner
        accessible_orgs = auth_system.get_user_organizations(current_user.id)
        partner_org = next((org for org in accessible_orgs if org.id == partner_selected_org_id), None)
        
        if partner_org:
            return partner_org, True  # True indicates partner mode
        else:
            # Clear invalid partner selection
            st.session_state.partner_selected_org_id = None
            st.session_state.partner_selected_org_name = None
            st.warning("⚠️ Selected organization not found. Reverted to user's organization.")
    
    # Return default organization (user's own organization)
    return default_org, False  # False indicates normal mode

def main():
    """Main function to run the Streamlit app."""
    # Configure page with Cohesive favicon
    base_dir = os.path.dirname(__file__)
    fav_path = os.path.join(base_dir, 'favicon.svg')
    # Page configuration
    st.set_page_config(
        page_title="Cohesive Cyber Compliance",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Initialize authentication system
    auth_system = AuthenticationSystem()
    streamlit_auth = StreamlitAuth(auth_system)
    
    # Initialize modules
    agent = CybersecurityAgent()
    nis2_module = NIS2ComplianceModule()
    user_management = UserManagementInterface(auth_system)
    
    # Check authentication
    if not streamlit_auth.require_auth():
        return
    
    # Get current user and organization
    current_user = streamlit_auth.get_current_user()
    
    # Initialize organization context (clear any existing selections on startup)
    if 'admin_selected_org_id' not in st.session_state:
        st.session_state.admin_selected_org_id = None
        st.session_state.admin_selected_org_name = None
    if 'partner_selected_org_id' not in st.session_state:
        st.session_state.partner_selected_org_id = None
        st.session_state.partner_selected_org_name = None
    
    # Get dynamic organization context
    current_org, is_context_switched = get_current_organization_context(auth_system, streamlit_auth, current_user)
    
    if not current_user or not current_org:
        st.error("Unable to determine user or organization context.")
        return
    
    # Show context switching indicator
    # if is_context_switched:
    #     if current_user.role.value == 'admin':
    #         st.info(f"🔧 **Admin Mode**: Managing organization **{current_org.name}** (ID: {current_org.id})")
    #     elif current_user.role.value == 'partner':
    #         st.info(f"🤝 **Partner Mode**: Managing organization **{current_org.name}** (ID: {current_org.id})")
    
    # Store current organization context in session state for forms to use
    st.session_state.current_organization_id = str(current_org.id)
    st.session_state.current_organization_name = current_org.name
    
    # Sidebar branding logo
    sidebar_logo_path = os.path.join(base_dir, 'cohesive_logo.svg')
    if os.path.exists(sidebar_logo_path):
        st.sidebar.image(sidebar_logo_path, width=240)
    else:
        st.sidebar.markdown("### 🚀")
    
    st.sidebar.title("Cohesive Cyber Compliance")
    
    if current_user.role.value in ['admin', 'partner']:
        if current_user.role.value == 'admin':
            all_orgs = auth_system.get_all_organizations()
            org_options = [f"{org.name} (ID: {org.id})" for org in all_orgs]
            org_values = [org.id for org in all_orgs]
        else:
            accessible_orgs = auth_system.get_user_organizations(current_user.id)
            org_options = [f"{org.name} (ID: {org.id})" for org in accessible_orgs]
            org_values = [org.id for org in accessible_orgs]
        current_org_index = org_values.index(current_org.id) if current_org.id in org_values else 0
        selected_org_option = st.sidebar.selectbox(
            "Select Organization",
            options=org_options,
            index=current_org_index,
            key="sidebar_org_switcher"
        )
        selected_org_id = org_values[org_options.index(selected_org_option)]
        if selected_org_id != current_org.id:
            if st.sidebar.button("🔄 Switch Context", use_container_width=True, type="primary"):
                if current_user.role.value == 'admin':
                    st.session_state.admin_selected_org_id = selected_org_id
                    st.session_state.admin_selected_org_name = next(org.name for org in all_orgs if org.id == selected_org_id)
                else:
                    st.session_state.partner_selected_org_id = selected_org_id
                    st.session_state.partner_selected_org_name = next(org.name for org in accessible_orgs if org.id == selected_org_id)
                st.rerun()
        if is_context_switched:
            if st.sidebar.button("🏠 Return to My Org", use_container_width=True, type="secondary"):
                if current_user.role.value == 'admin':
                    st.session_state.admin_selected_org_id = None
                    st.session_state.admin_selected_org_name = None
                else:
                    st.session_state.partner_selected_org_id = None
                    st.session_state.partner_selected_org_name = None
                st.rerun()
        st.sidebar.markdown("---")
    
    # Organization details
    st.sidebar.markdown(f"**Organization:** {current_org.name}")
    if is_context_switched:
        if current_user.role.value == 'admin':
            st.sidebar.info(f"🔧 **Admin Mode**: Managing {current_org.name}")
        else:
            st.sidebar.info(f"🤝 **Partner Mode**: Managing {current_org.name}")
    else:
        st.sidebar.info(f"🏢 **Your Organization**: {current_org.name}")
    
    # NIS2 Category (if available from scope assessment)
    # Check if scope assessment was recently completed and refresh data
    if st.session_state.get('scope_assessment_completed', False):
        # Clear the flag and refresh scope data
        st.session_state.scope_assessment_completed = False
        agent.nis2_scope_assessment.load_assessments()
    
    # Ensure scope assessment data is loaded
    try:
        agent.nis2_scope_assessment.load_assessments()
        scope_assessment = agent.nis2_scope_assessment.get_organization_scope(str(current_org.id))
    except Exception as e:
        scope_assessment = None
    
    if scope_assessment:
        st.sidebar.header("📋 NIS2 Status")
        
        # Determine the detailed scope status
        if scope_assessment.in_scope:
            if scope_assessment.sector_type.value == "essential":
                st.sidebar.markdown("🔴 **ESSENTIAL SECTOR**")
                st.sidebar.markdown("**Status:** In Scope")
            elif scope_assessment.sector_type.value == "important":
                st.sidebar.markdown("🟡 **IMPORTANT SECTOR**")
                st.sidebar.markdown("**Status:** In Scope")
            elif scope_assessment.sector_type.value == "digital":
                st.sidebar.markdown("🔵 **DIGITAL SERVICES**")
                st.sidebar.markdown("**Status:** In Scope")
            else:
                st.sidebar.markdown("✅ **IN SCOPE**")
        else:
            st.sidebar.markdown("⚪ **NOT IN SCOPE**")
            st.sidebar.markdown("**Status:** Not In Scope")
        
        st.sidebar.markdown(f"**Sector:** {scope_assessment.sector_type.value.replace('_', ' ').title()}")
        st.sidebar.markdown(f"**Assessment Date:** {scope_assessment.assessment_date.strftime('%Y-%m-%d')}")
        st.sidebar.markdown(f"**Score:** {scope_assessment.assessment_score}/100")
        
        # Show last update time if available
        if st.session_state.get('last_assessment_time'):
            last_update = datetime.fromisoformat(st.session_state.last_assessment_time)
            st.sidebar.markdown(f"**Last Updated:** {last_update.strftime('%Y-%m-%d %H:%M')}")
        
        # Refresh button for scope data
        if st.sidebar.button("🔄 Refresh Scope Data", use_container_width=True):
            agent.nis2_scope_assessment.load_assessments()
            st.rerun()
    else:
        st.sidebar.header("📋 NIS2 Status")
        st.sidebar.info("Complete a scope assessment to see your NIS2 obligations.")
    
    st.sidebar.markdown("---")
    
    # User Information
    st.sidebar.header("👤 User Context")
    st.sidebar.markdown(f"**User:** {current_user.username}")
    st.sidebar.markdown(f"**Role:** {current_user.role.value.title()}")
    
    st.sidebar.markdown("---")
    
    # Active incidents summary
    st.sidebar.header("🚨 Active Incidents")
    
    active_incidents = [inc for inc in agent.incident_reporting.incidents.values() 
                       if inc.status not in [IncidentStatus.CLOSED, IncidentStatus.RESOLVED]
                       and inc.organization_id == str(current_org.id)]
    
    if active_incidents:
        st.sidebar.markdown(f"**Active:** {len(active_incidents)}")
        for incident in active_incidents[:3]:  # Show first 3
            severity_color = {
                "LOW": "🟢",
                "MEDIUM": "🟡", 
                "HIGH": "🟠",
                "CRITICAL": "🔴"
            }.get(incident.severity.value.upper(), "⚪")
            st.sidebar.markdown(f"{severity_color} {incident.title[:30]}...")
    else:
        st.sidebar.info("✅ No active incidents")
    
    st.sidebar.markdown("---")
    
    # Quick Actions
    st.sidebar.header("⚡ Quick Actions")
    if st.sidebar.button("🚨 Report New Incident", use_container_width=True):
        st.session_state.active_tab = "🚨 Incident Reporting"
        st.rerun()
    
    if st.sidebar.button("🔍 Assess NIS2 Scope", use_container_width=True):
        st.session_state.active_tab = "🔍 Scope Assessment"
        st.rerun()
    
    if st.sidebar.button("🏛️ Manage Reporting Entities", use_container_width=True):
        st.session_state.active_tab = "🏛️ Reporting Entities"
        st.rerun()
    
    st.sidebar.markdown("---")
    
    # Logout button at bottom
    if st.sidebar.button("🚪 Logout", use_container_width=True, type="secondary"):
        streamlit_auth.logout()
    
    # App branding header
    # header_html = get_branding_header_html("Cybersecurity Reporting Platform")
    # st.markdown(header_html, unsafe_allow_html=True)
    
    # Organization Switcher for Admin/Partner users (main UI)
    # Disabled - moved to sidebar per request
    # if current_user.role.value in ['admin', 'partner']:
    #     st.markdown("---")
    #     st.subheader("🔀 Organization Context")
    #     col1, col2, col3 = st.columns([2, 1, 1])
    #     ...
    
    # Main content tabs
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "📊 Dashboard", 
        "🚨 Incident Reporting", 
        "🛡️ Security Controls", 
        "🛡️ Risk Management",
        "🔍 Scope Assessment", 
        "🏛️ Reporting Entities", 
        "⚙️ Settings"
    ])
    
    with tab1:
        # Dashboard content - no header needed
        # Organization Branding Section
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            # Try to display organization logo first
            if hasattr(current_org, 'logo_url') and current_org.logo_url:
                try:
                    st.image(current_org.logo_url, width=200)
                except:
                    # Fallback to organization name if logo fails to load
                    st.markdown(f"### 🏢 {current_org.name}")
            else:
                # Fallback to organization name if no logo
                st.markdown(f"### 🏢 {current_org.name}")
        
        st.markdown(f"## 🏢 {current_org.name}")
        st.markdown("---")
        
        # Key Metrics Row
        col1, col2, col3, col4 = st.columns(4)
        
        # Load incidents for metrics
        try:
            # Access incidents directly from the incident reporting module
            incidents = agent.incident_reporting.incidents
            if incidents:
                # Filter incidents by current organization
                org_incidents = [inc for inc in incidents.values() if str(inc.organization_id) == str(current_org.id)]
                active_incidents = [inc for inc in org_incidents if inc.status.value not in ['CLOSED', 'RESOLVED']]
                critical_incidents = [inc for inc in active_incidents if inc.severity.value == 'CRITICAL']
                high_incidents = [inc for inc in active_incidents if inc.severity.value == 'MAJOR']
            else:
                active_incidents = []
                critical_incidents = []
                high_incidents = []
        except Exception as e:
            active_incidents = []
            critical_incidents = []
            high_incidents = []
        
        # Load security controls for compliance metrics
        try:
            # Access the security controls manager directly
            controls_manager = agent.security_controls.manager
            current_org_assessment = controls_manager.get_organization_assessment(str(current_org.id))
            
            if current_org_assessment and current_org_assessment.controls:
                controls = current_org_assessment.controls
                implemented_controls = len([c for c in controls.values() if c.status.value == 'Fully Implemented'])
                partially_controls = len([c for c in controls.values() if c.status.value == 'Partially Implemented'])
                not_implemented_controls = len([c for c in controls.values() if c.status.value == 'Not Implemented'])
                total_controls = len(controls)
                compliance_percentage = round((implemented_controls / total_controls) * 100, 1) if total_controls > 0 else 0
            else:
                implemented_controls = 0
                partially_controls = 0
                not_implemented_controls = 0
                total_controls = 0
                compliance_percentage = 0
        except Exception as e:
            # Fallback if there's an error
            implemented_controls = 0
            partially_controls = 0
            not_implemented_controls = 0
            total_controls = 0
            compliance_percentage = 0
        
        # Load scope assessment for NIS2 status
        try:
            # Ensure scope assessment data is loaded
            agent.nis2_scope_assessment.load_assessments()
            # Access the scope assessment data directly from the module
            scope_assessment = agent.nis2_scope_assessment.get_organization_scope(str(current_org.id))
            has_scope_assessment = scope_assessment is not None
        except Exception as e:
            has_scope_assessment = False
        
        with col1:
            st.metric(
                label="Active Incidents",
                value=len(active_incidents),
                delta=f"{len(critical_incidents)} Critical"
            )
        
        with col2:
            st.metric(
                label="Security Controls",
                value=f"{compliance_percentage}%",
                delta=f"{implemented_controls}/{total_controls} Implemented"
            )
        
        with col3:
            # Risk Management Metrics
            try:
                risk_stats = agent.risk_management.get_risk_statistics(str(current_org.id))
                st.metric(
                    label="Total Risks",
                    value=risk_stats['total_risks'],
                    delta=f"{risk_stats['high_priority_count']} High Priority"
                )
            except Exception as e:
                st.metric(
                    label="Total Risks",
                    value=0,
                    delta="No data"
                )
        
        with col4:
            if has_scope_assessment:
                # Determine the scope status for the metric
                if scope_assessment.in_scope:
                    if scope_assessment.sector_type.value == "essential":
                        scope_value = "ESSENTIAL"
                        scope_delta = "Critical Sector"
                    elif scope_assessment.sector_type.value == "important":
                        scope_value = "IMPORTANT"
                        scope_delta = "Important Sector"
                    elif scope_assessment.sector_type.value == "digital":
                        scope_value = "DIGITAL"
                        scope_delta = "Digital Services"
                    else:
                        scope_value = "IN SCOPE"
                        scope_delta = "Scope Complete"
                else:
                    scope_value = "NOT IN SCOPE"
                    scope_delta = "No Obligations"
                
                st.metric(
                    label="NIS2 Scope",
                    value=scope_value,
                    delta=scope_delta
                )
            else:
                st.metric(
                    label="NIS2 Scope",
                    value="Pending",
                    delta="Assessment Required"
                )
        
        st.markdown("---")
        
        # Detailed Sections
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🚨 Incident Overview")
            
            if active_incidents:
                # Incident status breakdown
                status_counts = {}
                severity_counts = {}
                
                for incident in active_incidents:
                    status = incident.status.value
                    severity = incident.severity.value
                    
                    status_counts[status] = status_counts.get(status, 0) + 1
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                # Display incident breakdown
                for status, count in status_counts.items():
                    st.markdown(f"**{status.title()}**: {count} incidents")
                
                st.markdown("---")
                
                # Recent incidents
                st.markdown("**Recent Active Incidents:**")
                for incident in active_incidents[:3]:  # Show top 3
                    with st.expander(f"🔴 {incident.title} - {incident.severity.value}"):
                        st.markdown(f"**Description:** {incident.description}")
                        st.markdown(f"**Status:** {incident.status.value}")
                        st.markdown(f"**Date:** {incident.timeline.detection_time.strftime('%Y-%m-%d')}")
            else:
                st.success("✅ No active incidents")
                st.info("All security incidents have been resolved.")
        
        with col2:
            st.subheader("🛡️ Security Controls Status")
            
            if total_controls > 0:
                # Compliance progress bar
                st.progress(compliance_percentage / 100)
                st.markdown(f"**Overall Compliance: {compliance_percentage}%**")
                
                # Control status breakdown
                st.markdown("**Control Status Breakdown:**")
                
                col_a, col_b, col_c = st.columns(3)
                with col_a:
                    st.metric("✅ Implemented", implemented_controls)
                with col_b:
                    st.metric("⚠️ Partial", partially_controls)
                with col_c:
                    st.metric("❌ Not Implemented", not_implemented_controls)
                
                # Priority breakdown
                if current_org_assessment and current_org_assessment.controls:
                    priority_counts = {}
                    for control_id, control_assessment in current_org_assessment.controls.items():
                        # Get the actual control definition to access priority
                        control_def = controls_manager.get_control(control_id)
                        if control_def:
                            priority = control_def.priority.value
                            priority_counts[priority] = priority_counts.get(priority, 0) + 1
                    
                    st.markdown("**Priority Distribution:**")
                    for priority, count in priority_counts.items():
                        if priority == 'Mandatory':
                            st.markdown(f"🔴 **Mandatory:** {count} controls")
                        elif priority == 'Recommended':
                            st.markdown(f"🟡 **Recommended:** {count} controls")
                        elif priority == 'Optional':
                            st.markdown(f"🟢 **Optional:** {count} controls")
            else:
                st.warning("⚠️ No security controls assessment found")
                st.info("Complete a security controls assessment to see compliance metrics.")
        
        # Risk Management Section
        st.markdown("---")
        st.subheader("🛡️ Risk Management Overview")
        
        try:
            risk_stats = agent.risk_management.get_risk_statistics(str(current_org.id))
            
            if risk_stats['total_risks'] > 0:
                col_a, col_b, col_c, col_d = st.columns(4)
                
                with col_a:
                    st.metric("Total Risks", risk_stats['total_risks'])
                
                with col_b:
                    st.metric("High Priority", risk_stats['high_priority_count'], 
                            delta=f"{risk_stats['high_priority_count']} require attention" if risk_stats['high_priority_count'] > 0 else "All clear")
                
                with col_c:
                    st.metric("Average Risk Score", risk_stats['average_risk_score'])
                
                with col_d:
                    active_risks = risk_stats['risk_by_status'].get('Treatment In Progress', 0) + risk_stats['risk_by_status'].get('Monitoring', 0)
                    st.metric("Active Risks", active_risks)
                
                # Risk level distribution
                st.markdown("**Risk Level Distribution:**")
                level_cols = st.columns(4)
                level_colors = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}
                
                for i, (level, count) in enumerate(risk_stats['risk_by_level'].items()):
                    with level_cols[i]:
                        if count > 0:
                            st.metric(f"{level_colors[level]} {level}", count)
                        else:
                            st.metric(f"{level_colors[level]} {level}", 0)
                
                # Risk status summary
                if any(count > 0 for count in risk_stats['risk_by_status'].values()):
                    st.markdown("**Risk Status Summary:**")
                    status_data = {k: v for k, v in risk_stats['risk_by_status'].items() if v > 0}
                    if status_data:
                        st.bar_chart(status_data)
            else:
                st.success("✅ No risks identified. Your organization appears to have a clean risk profile!")
                
        except Exception as e:
            st.info("📊 Risk management data not available. Use the Risk Management tab to start identifying and assessing risks.")
        
        # NIS2 Compliance Section
        st.markdown("---")
        st.subheader("🔍 NIS2 Compliance Overview")
        
        col1, col2 = st.columns(2)
        
        with col1:
            if has_scope_assessment:
                # Determine the scope status based on sector type and in_scope
                if scope_assessment.in_scope:
                    if scope_assessment.sector_type.value == "essential":
                        st.success("🔴 **ESSENTIAL SECTOR - IN SCOPE**")
                    elif scope_assessment.sector_type.value == "important":
                        st.warning("🟡 **IMPORTANT SECTOR - IN SCOPE**")
                    elif scope_assessment.sector_type.value == "digital":
                        st.info("🔵 **DIGITAL SERVICES - IN SCOPE**")
                    else:
                        st.success("✅ **IN SCOPE**")
                else:
                    st.info("⚪ **NOT IN SCOPE**")
                
                st.markdown(f"**Organization:** {current_org.name}")
                st.markdown(f"**Assessment Date:** {scope_assessment.assessment_date.strftime('%Y-%m-%d')}")
                
                # Show key scope details
                if scope_assessment:
                    sector = scope_assessment.sector_type.value
                    st.markdown(f"**Sector Type:** {sector.replace('_', ' ').title()}")
                    st.markdown(f"**Assessment Score:** {scope_assessment.assessment_score}/100")
                    
                    # Show reporting obligations if any
                    if scope_assessment.reporting_obligations:
                        st.markdown("**Reporting Obligations:**")
                        for obligation in scope_assessment.reporting_obligations[:3]:  # Show first 3
                            st.markdown(f"• {obligation}")
                        if len(scope_assessment.reporting_obligations) > 3:
                            st.markdown(f"• ... and {len(scope_assessment.reporting_obligations) - 3} more")
            else:
                st.warning("⚠️ Scope Assessment Required")
                st.info("Complete a NIS2 scope assessment to determine your obligations.")
                if st.button("🔍 Start Scope Assessment", use_container_width=True):
                    st.switch_page("cybersecurity_agent.py")
        
        with col2:
            # Quick actions
            st.markdown("**Quick Actions:**")
            
            if st.button("📝 Report New Incident", use_container_width=True):
                st.switch_page("cybersecurity_agent.py")
            
            if st.button("🛡️ Assess Controls", use_container_width=True):
                st.switch_page("cybersecurity_agent.py")
            
            if st.button("🛡️ Manage Risks", use_container_width=True):
                st.switch_page("cybersecurity_agent.py")
            
            if st.button("🔄 Refresh Data", use_container_width=True):
                st.rerun()
        
        # Footer
        st.markdown("---")
        st.markdown("*Dashboard data refreshes automatically. Use the refresh button to update metrics.*")
    
    with tab2:
        if current_user.role.value in ['admin', 'partner', 'reporter']:
            # Incident Reporting content - no header needed
            agent.incident_reporting.display_incident_reporting_interface()
        else:
            st.error("You don't have permission to access incident reporting.")
    
    with tab3:
        # Security Controls content - no header needed
        agent.security_controls.display_main_interface(str(current_org.id), current_org.name)
    
    with tab4:
        # Risk Management content - no header needed
        agent.risk_management.display_main_interface(str(current_org.id), current_org.name)
    
    with tab5:
        # Scope Assessment content - no header needed
        agent.nis2_scope_assessment.display_main_interface(str(current_org.id))
    
    with tab6:
        # Reporting Entities content - no header needed
        agent.reporting_entities.display_main_interface()
    
    with tab7:
        # Settings content - no header needed
        if current_user.role.value in ['admin', 'partner']:
            if current_user.role.value == 'admin':
                st.subheader("🏢 Organization Management")
                st.info("Switch between organizations to manage their data and settings across your cybersecurity compliance platform.")
                
                # Get all organizations
                all_organizations = auth_system.get_all_organizations()
                
                if all_organizations:
                    # Organization statistics
                    st.markdown("---")
                    col1, col2, col3 = st.columns(3)
                    
                    total_orgs = len(all_organizations)
                    active_orgs = len([org for org in all_organizations if org.is_active])
                    orgs_with_logos = len([org for org in all_organizations if org.logo_url])
                    
                    with col1:
                        st.metric("Total Organizations", total_orgs, f"{active_orgs} Active")
                    with col2:
                        st.metric("Active Organizations", active_orgs, f"{total_orgs - active_orgs} Inactive")
                    with col3:
                        st.metric("Organizations with Logos", orgs_with_logos, f"{total_orgs - orgs_with_logos} Need Logos")
                    
                    st.markdown("---")
                    
                    # Organization switcher with enhanced styling
                    st.markdown("### 🔀 Organization Context Switcher")
                    
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        # Create organization selection
                        org_names = [org.name for org in all_organizations]
                        org_ids = [org.id for org in all_organizations]
                        
                        # Find current organization index
                        current_org_index = org_ids.index(current_org.id) if current_org.id in org_ids else 0
                        
                        selected_org_name = st.selectbox(
                            "Select Organization to Manage",
                            options=org_names,
                            index=current_org_index,
                            key="admin_org_selector",
                            help="Choose which organization's data and settings to manage"
                        )
                    
                    with col2:
                        # Get selected organization object
                        selected_org = next((org for org in all_organizations if org.name == selected_org_name), None)
                        
                        if selected_org and selected_org.id != current_org.id:
                            st.warning(f"⚠️ **Organization Context Change Required**")
                            st.markdown(f"""
                            **Current Context:** {current_org.name} (ID: {current_org.id})
                            **Selected Organization:** {selected_org.name} (ID: {selected_org.id})
                            
                            To switch to managing **{selected_org.name}**, click the button below.
                            """)
                            
                            if st.button(f"🔄 Switch to {selected_org.name}", type="primary", use_container_width=True):
                                # Store the selected organization in session state
                                st.session_state.admin_selected_org_id = selected_org.id
                                st.session_state.admin_selected_org_name = selected_org.name
                                st.success(f"✅ Organization context switched to {selected_org.name}")
                                st.rerun()
                    
                    # Current organization context display
                    st.markdown("---")
                    st.markdown("### 📍 Current Organization Context")
                    
                    col1, col2, col3 = st.columns([2, 2, 1])
                    
                    with col1:
                        st.info(f"🏢 **{current_org.name}**")
                        st.markdown(f"**ID:** {current_org.id}")
                        st.markdown(f"**Domain:** {current_org.domain}")
                    
                    with col2:
                        st.markdown(f"**Industry:** {current_org.industry}")
                        st.markdown(f"**Country:** {current_org.country}")
                        st.markdown(f"**Type:** {current_org.organization_type.title()}")
                    
                    with col3:
                        if hasattr(current_org, 'logo_url') and current_org.logo_url:
                            try:
                                st.image(current_org.logo_url, width=80)
                                st.success("✅ Logo Available")
                            except:
                                st.error("❌ Logo Failed to Load")
                        else:
                            st.warning("⚠️ No Logo")
                    
                    st.markdown("---")
                    
                    # Logo management with enhanced interface
                    st.markdown("### 🖼️ Logo Management")
                    st.info("Automatically fetch and update organization logos from the web.")
                    
                    col1, col2 = st.columns([1, 1])
                    
                    with col1:
                        if st.button("🔄 Refresh All Organization Logos", use_container_width=True, type="secondary"):
                            with st.spinner("🔄 Fetching logos from the web..."):
                                results = auth_system.refresh_organization_logos()
                                st.success("✅ Logo refresh completed!")
                                
                                # Display results in a more organized way
                                st.markdown("**Logo Refresh Results:**")
                                for org_name, result in results.items():
                                    if "✅" in result:
                                        st.success(f"**{org_name}**: {result}")
                                    elif "❌" in result:
                                        st.warning(f"**{org_name}**: {result}")
                                    else:
                                        st.info(f"**{org_name}**: {result}")
                    
                    with col2:
                        st.markdown("**Logo Sources:**")
                        st.markdown("• 🎯 Manual mappings for known organizations")
                        st.markdown("• 🌐 Organization websites and favicons")
                        st.markdown("• 📚 Wikipedia pages")
                        st.markdown("• 🎨 Generic icons for unknown organizations")
                    
                    # Add return button if admin is managing a different organization
                    admin_selected_org_id = st.session_state.get('admin_selected_org_id')
                    if admin_selected_org_id and admin_selected_org_id != streamlit_auth.get_current_organization().id:
                        st.markdown("---")
                        st.markdown("### 🏠 Return to My Organization")
                        st.info(f"You are currently managing **{st.session_state.get('admin_selected_org_name', 'Unknown')}** instead of your own organization.")
                        
                        if st.button("🏠 Return to My Organization", type="secondary", use_container_width=True):
                            st.session_state.admin_selected_org_id = None
                            st.session_state.admin_selected_org_name = None
                            st.success("✅ Returned to your organization context")
                            st.rerun()
                
                else:
                    st.warning("⚠️ No organizations found in the system.")
                    st.info("Create your first organization to get started with multi-organization management.")
                
                # User Management Section
                st.markdown("---")
                st.subheader("👥 User Management")
                st.info("Manage users across all organizations in your cybersecurity compliance platform.")
                
                # Get all users first
                all_users = auth_system.get_all_users()
                
                # Check if we're editing a user
                editing_user_id = st.session_state.get('editing_user')
                if editing_user_id:
                    editing_user = next((user for user in all_users if user.id == editing_user_id), None)
                    
                    if editing_user:
                        st.markdown("---")
                        st.subheader(f"✏️ Edit User: {editing_user.username}")
                        
                        # User info card
                        col1, col2, col3 = st.columns([2, 2, 1])
                        with col1:
                            st.markdown(f"**📧 Email:** {editing_user.email}")
                            st.markdown(f"**🏢 Organization:** {current_org.name if editing_user.organization_id == current_org.id else 'Other'}")
                        with col2:
                            st.markdown(f"**👤 Role:** {editing_user.role.value.title()}")
                            st.markdown(f"**📅 Created:** {editing_user.created_at.strftime('%Y-%m-%d')}")
                        with col3:
                            status_color = "🟢" if editing_user.is_active else "🔴"
                            st.markdown(f"**Status:** {status_color} {'Active' if editing_user.is_active else 'Inactive'}")
                        
                        st.markdown("---")
                        
                        with st.form("edit_user_form"):
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                edit_username = st.text_input("Username", value=editing_user.username, key=f"settings_edit_username_{editing_user.id}")
                                edit_email = st.text_input("Email", value=editing_user.email, key=f"settings_edit_email_{editing_user.id}")
                                edit_role = st.selectbox(
                                    "Role",
                                    options=[role.value for role in UserRole],
                                    index=[role.value for role in UserRole].index(editing_user.role.value),
                                    format_func=lambda x: x.title(),
                                    key=f"settings_edit_role_{editing_user.id}"
                                )
                            
                            with col2:
                                edit_org = st.selectbox(
                                    "Organization",
                                    options=[org.name for org in all_organizations],
                                    index=[org.id for org in all_organizations].index(editing_user.organization_id),
                                    key=f"settings_edit_org_{editing_user.id}"
                                )
                                edit_active = st.checkbox("Active Account", value=editing_user.is_active, key=f"settings_edit_active_{editing_user.id}")
                            
                            st.markdown("---")
                            
                            col1, col2, col3 = st.columns([1, 1, 1])
                            with col1:
                                if st.form_submit_button("💾 Save Changes", use_container_width=True, type="primary"):
                                    # Get organization ID
                                    org_id = next((org.id for org in all_organizations if org.name == edit_org), None)
                                    
                                    if org_id is not None:
                                        success = auth_system.update_user(
                                            editing_user.id,
                                            username=edit_username,
                                            email=edit_email,
                                            role=UserRole(edit_role),
                                            organization_id=org_id,
                                            is_active=edit_active
                                        )
                                        if success:
                                            st.success(f"✅ User **{edit_username}** updated successfully!")
                                            st.session_state.editing_user = None
                                            st.rerun()
                                        else:
                                            st.error("❌ Failed to update user")
                                    else:
                                        st.error("❌ Invalid organization selected")
                            
                            with col2:
                                if st.form_submit_button("❌ Cancel", use_container_width=True, type="secondary"):
                                    st.session_state.editing_user = None
                                    st.rerun()
                            
                            with col3:
                                if st.form_submit_button("🔒 Change Password", use_container_width=True, type="secondary"):
                                    st.session_state.changing_password = editing_user.id
                                    st.rerun()
                        
                        st.markdown("---")
                
                # Password change interface
                changing_password_id = st.session_state.get('changing_password')
                if changing_password_id:
                    changing_user = next((user for user in all_users if user.id == changing_password_id), None)
                    
                    if changing_user:
                        st.markdown("---")
                        st.subheader(f"🔒 Change Password: {changing_user.username}")
                        
                        with st.form("change_password_form"):
                            new_password = st.text_input("New Password", type="password", key="new_password")
                            confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                if st.form_submit_button("🔒 Update Password", use_container_width=True, type="primary"):
                                    if new_password and new_password == confirm_password:
                                        if len(new_password) >= 8:
                                            success = auth_system.change_user_password(changing_user.id, new_password)
                                            if success:
                                                st.success(f"✅ Password updated successfully for **{changing_user.username}**!")
                                                st.session_state.changing_password = None
                                                st.rerun()
                                            else:
                                                st.error("❌ Failed to update password")
                                        else:
                                            st.error("❌ Password must be at least 8 characters long")
                                    else:
                                        st.error("❌ Passwords do not match")
                            
                            with col2:
                                if st.form_submit_button("❌ Cancel", use_container_width=True, type="secondary"):
                                    st.session_state.changing_password = None
                                    st.rerun()
                        
                        st.markdown("---")
                
                # Get all users
                all_users = auth_system.get_all_users()
                
                if all_users:
                    # User statistics
                    st.markdown("---")
                    col1, col2, col3, col4 = st.columns(4)
                    
                    total_users = len(all_users)
                    active_users = len([u for u in all_users if u.is_active])
                    admin_users = len([u for u in all_users if u.role.value == 'admin'])
                    partner_users = len([u for u in all_users if u.role.value == 'partner'])
                    
                    with col1:
                        st.metric("Total Users", total_users, f"{active_users} Active")
                    with col2:
                        st.metric("Active Users", active_users, f"{total_users - active_users} Inactive")
                    with col3:
                        st.metric("Admin Users", admin_users, "System Administrators")
                    with col4:
                        st.metric("Partner Users", partner_users, "Organization Partners")
                    
                    st.markdown("---")
                    
                    # User list with enhanced styling
                    st.markdown("### 📋 User Directory")
                    
                    for user in all_users:
                        # Role badge colors
                        role_colors = {
                            'admin': '🔴',
                            'partner': '🟡', 
                            'reporter': '🔵',
                            'reader': '🟢'
                        }
                        
                        role_badge = role_colors.get(user.role.value, '⚪')
                        
                        with st.expander(f"{role_badge} **{user.username}** - {user.role.value.title()}", expanded=False):
                            # User header with status
                            col1, col2, col3 = st.columns([3, 2, 1])
                            
                            with col1:
                                st.markdown(f"**👤 Username:** {user.username}")
                                st.markdown(f"**📧 Email:** {user.email}")
                            
                            with col2:
                                st.markdown(f"**🏢 Organization:** {current_org.name if user.organization_id == current_org.id else 'Other'}")
                                st.markdown(f"**📅 Created:** {user.created_at.strftime('%Y-%m-%d')}")
                            
                            with col3:
                                # Status indicator
                                if user.is_active:
                                    st.success("🟢 Active")
                                else:
                                    st.error("🔴 Inactive")
                                
                                # Role badge
                                st.markdown(f"**{role_badge} {user.role.value.title()}**")
                            
                            st.markdown("---")
                            
                            # Action buttons
                            if user.id != current_user.id:  # Can't edit self
                                col1, col2, col3 = st.columns(3)
                                
                                with col1:
                                    if st.button(f"✏️ Edit {user.username}", key=f"settings_user_edit_{user.id}", use_container_width=True):
                                        st.session_state.editing_user = user.id
                                        st.rerun()
                                
                                with col2:
                                    if st.button(f"🔒 Change Password", key=f"settings_user_pwd_{user.id}", use_container_width=True, type="secondary"):
                                        st.session_state.changing_password = user.id
                                        st.rerun()
                                
                                with col3:
                                    if st.button(f"🗑️ Delete {user.username}", key=f"settings_user_delete_{user.id}", use_container_width=True, type="secondary"):
                                        # Confirmation dialog
                                        st.warning(f"⚠️ Are you sure you want to delete user **{user.username}**?")
                                        col_a, col_b = st.columns(2)
                                        with col_a:
                                            if st.button(f"✅ Yes, Delete {user.username}", key=f"settings_user_confirm_delete_{user.id}", use_container_width=True, type="primary"):
                                                if auth_system.delete_user(user.id):
                                                    st.success(f"✅ User **{user.username}** deleted successfully!")
                                                    st.rerun()
                                                else:
                                                    st.error("❌ Failed to delete user")
                                        with col_b:
                                            if st.button("❌ Cancel", key=f"settings_user_cancel_delete_{user.id}", use_container_width=True):
                                                st.rerun()
                            else:
                                st.info("👤 **This is your account** - You cannot edit or delete yourself")
                    
                    st.markdown("---")
                    
                    # Add new user form with enhanced styling
                    st.markdown("### ➕ Create New User")
                    st.info("Add new users to the system with appropriate roles and permissions.")
                    
                    with st.form("add_user_form"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            new_username = st.text_input("Username", key="settings_new_username", placeholder="Enter username")
                            new_email = st.text_input("Email", key="settings_new_email", placeholder="Enter email address")
                            new_password = st.text_input("Password", type="password", key="settings_new_user_password", placeholder="Minimum 8 characters")
                        
                        with col2:
                            new_role = st.selectbox(
                                "Role",
                                options=[role.value for role in UserRole],
                                format_func=lambda x: x.title(),
                                key="settings_new_role",
                                help="Select the user's role and permissions level"
                            )
                            new_org = st.selectbox(
                                "Organization",
                                options=[org.name for org in all_organizations],
                                key="settings_new_org",
                                help="Select the organization this user belongs to"
                            )
                        
                        # Password strength indicator
                        if st.session_state.get('settings_new_user_password'):
                            password = st.session_state.settings_new_user_password
                            if len(password) >= 8:
                                if any(c.isupper() for c in password) and any(c.islower() for c in password) and any(c.isdigit() for c in password):
                                    st.success("🔒 Strong password")
                                elif any(c.isupper() for c in password) or any(c.islower() for c in password) or any(c.isdigit() for c in password):
                                    st.warning("⚠️ Medium strength password")
                                else:
                                    st.error("❌ Weak password")
                            else:
                                st.error("❌ Password too short (minimum 8 characters)")
                        
                        st.markdown("---")
                        
                        if st.form_submit_button("➕ Create User", use_container_width=True, type="primary"):
                            if new_username and new_email and new_password:
                                if len(new_password) >= 8:
                                    # Get organization ID
                                    org_id = next((org.id for org in all_organizations if org.name == new_org), None)
                                    
                                    if org_id is not None:
                                        # Create user with all required parameters
                                        success = auth_system.create_user(
                                            new_username, 
                                            new_email, 
                                            new_password,
                                            org_id,
                                            UserRole(new_role)
                                        )
                                        if success:
                                            st.success(f"✅ User **{new_username}** created successfully!")
                                            st.rerun()
                                        else:
                                            st.error("❌ Failed to create user")
                                    else:
                                        st.error("❌ Invalid organization selected")
                                else:
                                    st.error("❌ Password must be at least 8 characters long")
                            else:
                                st.error("❌ Please fill in all required fields")
                
                else:
                    st.warning("⚠️ No users found in the system.")
                    st.info("Create your first user account to get started.")
                
                # Company Profile Section
                st.markdown("---")
                st.subheader("🏢 Company Profile")
                st.info("View and edit your organization's profile information.")
                
                # Display current organization info
                with st.expander("📋 Current Organization Details", expanded=True):
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.markdown(f"**Organization Name:** {current_org.name}")
                        st.markdown(f"**Domain:** {current_org.domain}")
                        st.markdown(f"**Industry:** {current_org.industry}")
                        st.markdown(f"**Country:** {current_org.country}")
                        st.markdown(f"**Compliance Framework:** {current_org.compliance_framework}")
                        st.markdown(f"**Organization Type:** {current_org.organization_type.title()}")
                        if hasattr(current_org, 'parent_organization_id') and current_org.parent_organization_id:
                            parent_org = next((org for org in all_organizations if org.id == current_org.parent_organization_id), None)
                            if parent_org:
                                st.markdown(f"**Parent Organization:** {parent_org.name}")
                    
                    with col2:
                        if hasattr(current_org, 'logo_url') and current_org.logo_url:
                            try:
                                st.image(current_org.logo_url, width=150)
                                st.markdown(f"**Logo URL:** {current_org.logo_url}")
                            except:
                                st.warning("🖼️ Logo unavailable")
                        else:
                            st.info("🖼️ No logo set")
                
                # Edit organization form
                st.markdown("**✏️ Edit Organization Profile**")
                with st.form("edit_organization_form"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        edit_name = st.text_input("Organization Name", value=current_org.name, key="settings_edit_org_name")
                        edit_domain = st.text_input("Domain", value=current_org.domain, key="settings_edit_org_domain")
                        edit_industry = st.text_input("Industry", value=current_org.industry, key="settings_edit_org_industry")
                        edit_country = st.text_input("Country", value=current_org.country, key="settings_edit_org_country")
                    
                    with col2:
                        edit_compliance = st.selectbox(
                            "Compliance Framework", 
                            options=["NIS2", "ISO27001", "SOC2", "GDPR", "Other"],
                            index=["NIS2", "ISO27001", "SOC2", "GDPR", "Other"].index(current_org.compliance_framework) if current_org.compliance_framework in ["NIS2", "ISO27001", "SOC2", "GDPR", "Other"] else 0,
                            key="settings_edit_org_compliance"
                        )
                        edit_type = st.selectbox(
                            "Organization Type",
                            options=["client", "partner", "subsidiary", "branch"],
                            index=["client", "partner", "subsidiary", "branch"].index(current_org.organization_type) if current_org.organization_type in ["client", "partner", "subsidiary", "branch"] else 0,
                            key="settings_edit_org_type"
                        )
                        edit_parent = st.selectbox(
                            "Parent Organization",
                            options=["None"] + [org.name for org in all_organizations if org.id != current_org.id],
                            index=0 if not hasattr(current_org, 'parent_organization_id') or not current_org.parent_organization_id else 
                                  [org.name for org in all_organizations if org.id == current_org.parent_organization_id].index(
                                      next((org.name for org in all_organizations if org.id == current_org.parent_organization_id), "None")
                                  ) + 1,
                            key="settings_edit_org_parent"
                        )
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.form_submit_button("💾 Save Changes", use_container_width=True, type="primary"):
                            # Get parent organization ID
                            parent_id = None
                            if edit_parent != "None":
                                parent_org = next((org for org in all_organizations if org.name == edit_parent), None)
                                if parent_org:
                                    parent_id = parent_org.id
                            
                            # Update organization
                            success = auth_system.update_organization(
                                current_org.id,
                                edit_name,
                                edit_domain,
                                edit_industry,
                                edit_country,
                                edit_compliance,
                                True,  # is_active
                                parent_id
                            )
                            
                            if success:
                                st.success("✅ Organization profile updated successfully!")
                                st.rerun()
                            else:
                                st.error("❌ Failed to update organization profile")
                    
                    with col2:
                        if st.form_submit_button("🔄 Refresh Logo", use_container_width=True, type="secondary"):
                            new_logo = auth_system.auto_fetch_organization_logo(edit_name)
                            if new_logo:
                                # Update logo in database
                                if auth_system.update_organization_logo(current_org.id, new_logo):
                                    st.success("✅ Organization logo refreshed successfully!")
                                    st.rerun()
                                else:
                                    st.error("❌ Failed to update logo in database")
                            else:
                                st.warning("⚠️ No new logo found")
                
                st.markdown("---")
                
                # Partner Organization Management
                if current_user.role.value == 'partner':
                    st.subheader("🤝 Partner Organization Management")
                    st.info("Switch between organizations in your remit to manage their data and settings.")
                    
                    # Get organizations accessible to partner
                    accessible_organizations = auth_system.get_user_organizations(current_user.id)
                    
                    if accessible_organizations:
                        # Create organization selection
                        org_names = [org.name for org in accessible_organizations]
                        org_ids = [org.id for org in accessible_organizations]
                        
                        # Find current organization index
                        current_org_index = org_ids.index(current_org.id) if current_org.id in org_ids else 0
                        
                        selected_org_name = st.selectbox(
                            "Select Organization to Manage",
                            options=org_names,
                            index=current_org_index,
                            key="partner_org_selector"
                        )
                        
                        # Get selected organization object
                        selected_org = next((org for org in accessible_organizations if org.name == selected_org_name), None)
                        
                        if selected_org and selected_org.id != current_org.id:
                            st.warning(f"⚠️ **Organization Context Change Required**")
                            st.markdown(f"""
                            **Current Context:** {current_org.name} (ID: {current_org.id})
                            **Selected Organization:** {selected_org.name} (ID: {selected_org.id})
                            
                            To switch to managing **{selected_org.name}**, click the button below.
                            """)
                            
                            if st.button(f"🔄 Switch to {selected_org.name}", type="primary"):
                                # Store the selected organization in session state
                                st.session_state.partner_selected_org_id = selected_org.id
                                st.session_state.partner_selected_org_name = selected_org.name
                                st.success(f"✅ Organization context switched to {selected_org.name}")
                                st.rerun()
                        
                        # Show current organization context
                        st.markdown("**Current Organization Context:**")
                        st.info(f"🏢 **{current_org.name}** (ID: {current_org.id})")
                        
                        # Add return button if partner is managing a different organization
                        partner_selected_org_id = st.session_state.get('partner_selected_org_id')
                        if partner_selected_org_id and partner_selected_org_id != streamlit_auth.get_current_organization().id:
                            if st.button("🏠 Return to My Organization", type="secondary"):
                                st.session_state.partner_selected_org_id = None
                                st.session_state.partner_selected_org_name = None
                                st.success("✅ Returned to your organization context")
                                st.rerun()
                    
                    else:
                        st.warning("No organizations accessible to you as a partner.")
                
                st.markdown("---")
        else:
            st.info("System configuration options will be available here.")
    
    # User Management Tab (removed old reference to tab7)
    # Previously: with tab7: ... now removed to avoid NameError
    

    
    # Settings Tab - Now handled in main tabs above
    # Removed tab8 block to avoid NameError
    
    # Footer with small logo
    st.markdown("---")
    footer_logo = _load_svg_data_url('cohesive_symbol.svg')
    st.markdown(
        f"<div style='display:flex;align-items:center;gap:8px;opacity:0.8'>"
        f"<img src='{footer_logo}' alt='Cohesive symbol' style='height:24px;width:auto'/>"
        f"<span style='font:500 12px Inter, Segoe UI, Arial;color:#5A6275'>Cohesive • Enhanced Cybersecurity Reporting Agent with NIS2 Compliance and Multi-Organization Support</span>"
        f"</div>",
        unsafe_allow_html=True,
    )

if __name__ == "__main__":
    main()
