# NIS2 Incident Reporting System - Enhanced Guide

## Overview

The enhanced NIS2 Incident Reporting System now provides professional PDF report generation and automated email distribution to relevant authorities and stakeholders. This system ensures compliance with NIS2 Article 23 requirements while providing rich threat intelligence and professional documentation.

## Key Features

### 🚨 Incident Management
- **Comprehensive Incident Tracking**: Full lifecycle management from detection to resolution
- **NIS2 Compliance**: Automatic timeline management for reporting deadlines
- **Multi-Severity Support**: Handles minor to critical incidents with appropriate escalation

### 📊 Professional PDF Reports
- **Executive Summary**: Clean, professional formatting suitable for regulatory submission
- **Threat Intelligence Integration**: Rich context with links to external threat intelligence platforms
- **Timeline Tracking**: Complete incident timeline with all key events
- **Professional Styling**: Corporate-ready formatting with proper branding

### 📧 Automated Email Distribution
- **Smart Recipient Management**: Configurable recipients based on incident type and severity
- **PDF Attachments**: Professional reports automatically attached to outgoing emails
- **HTML Email Bodies**: Rich email content with incident summaries and threat intelligence
- **Delivery Tracking**: Confirmation of successful email delivery

### 🔍 Threat Intelligence Enrichment
- **Automatic IOC Extraction**: Identifies IPs, domains, hashes, and URLs from incident descriptions
- **Multi-Source Integration**: Links to VirusTotal, AbuseIPDB, Shodan, and other platforms
- **Risk Scoring**: Automated risk assessment based on indicators and incident severity
- **Confidence Levels**: Assessment of threat intelligence quality and reliability

## Setup and Configuration

### 1. Email Configuration

#### Gmail Setup (Recommended for Testing)
1. **Enable 2-Factor Authentication** on your Gmail account
2. **Generate App Password**:
   - Go to Google Account Settings
   - Security → 2-Step Verification → App passwords
   - Generate password for "Mail"
3. **Configure Environment Variables**:
   ```bash
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your_email@gmail.com
   SMTP_PASSWORD=your_app_password
   SMTP_USE_TLS=true
   SMTP_USE_SSL=false
   SENDER_NAME=NIS2 Incident Reporting System
   SENDER_EMAIL=your_email@gmail.com
   ```

#### Office 365 Setup
```bash
SMTP_SERVER=smtp.office365.com
SMTP_PORT=587
SMTP_USERNAME=your_email@company.com
SMTP_PASSWORD=your_password
SMTP_USE_TLS=true
SMTP_USE_SSL=false
```

#### Custom SMTP Server
```bash
SMTP_SERVER=mail.yourcompany.com
SMTP_PORT=587
SMTP_USERNAME=incidents@yourcompany.com
SMTP_PASSWORD=your_password
SMTP_USE_TLS=true
SMTP_USE_SSL=false
```

### 2. Report Recipients Configuration

The system comes pre-configured with key NIS2 authorities:

- **National Cyber Security Centre (Ireland)** - incidents@ncsc.gov.ie
- **Garda Cyber Crime Unit** - cybercrime@garda.ie
- **Data Protection Commission** - info@dataprotection.ie
- **ENISA** - incidents@enisa.europa.eu

#### Adding Custom Recipients
1. Navigate to **Configuration** tab
2. Use **Add New Recipient** form
3. Configure priority levels and report types
4. Set contact information

#### Priority Levels
- **Low**: Receives only final reports
- **Normal**: Receives initial and final reports
- **High**: Receives all report types
- **Critical**: Receives all reports regardless of incident severity

### 3. Threat Intelligence Sources

The system automatically enriches incidents with threat intelligence from:

- **VirusTotal**: File hashes, URLs, domains, IP addresses
- **AbuseIPDB**: IP reputation and threat data
- **Shodan**: Internet-wide scanning data
- **Cisco Talos**: Domain reputation
- **Hybrid Analysis**: Malware analysis
- **MalwareBazaar**: Malware samples and analysis

## Usage Workflow

### 1. Report New Incident
1. Navigate to **Report New Incident** tab
2. Fill in incident details:
   - **Title**: Clear, descriptive incident name
   - **Category**: NIS2 incident classification
   - **Severity**: Impact assessment level
   - **Description**: Detailed incident description (include IOCs for enrichment)
   - **Impact Assessment**: Business impact analysis
   - **Containment Measures**: Immediate response actions
3. Submit incident report

### 2. Automatic Processing
Upon submission, the system:
1. **Extracts Threat Indicators** from incident description
2. **Enriches Intelligence** with external sources
3. **Generates Professional PDF** report
4. **Distributes via Email** to relevant recipients
5. **Tracks Timeline** for compliance deadlines

### 3. Report Generation
- **Initial Report**: Generated immediately upon incident creation
- **Intermediate Reports**: Every 72 hours for significant+ incidents
- **Final Report**: Upon incident resolution

### 4. Email Distribution
- **Smart Routing**: Recipients receive reports based on incident severity and report type
- **PDF Attachments**: Professional reports automatically attached
- **HTML Content**: Rich email summaries with key information
- **Delivery Confirmation**: Success/failure tracking for each recipient

## Report Structure

### PDF Report Sections
1. **Header**: NIS2 Article 23 Security Incident Report
2. **Incident Summary**: Key details in professional table format
3. **Description**: Detailed incident narrative
4. **Impact Assessment**: Business impact analysis
5. **Containment Measures**: Immediate response actions
6. **Threat Intelligence**: Risk score, confidence level, and indicators
7. **Timeline**: Complete incident timeline
8. **Footer**: Generation timestamp and system information

### Email Content
- **Subject**: Clear incident identification
- **HTML Body**: Rich formatting with incident summary
- **Threat Intelligence**: Risk assessment and indicators
- **PDF Attachment**: Complete professional report

## Threat Intelligence Features

### Automatic IOC Extraction
The system automatically identifies:
- **IP Addresses**: IPv4 addresses with validation
- **Domains**: Valid domain names
- **File Hashes**: MD5, SHA1, SHA256 hashes
- **URLs**: HTTP/HTTPS URLs

### Risk Scoring Algorithm
- **Base Score**: Incident severity (Minor: 10, Significant: 30, Major: 60, Critical: 90)
- **Indicator Bonus**: +5 points per threat indicator
- **Malware Bonus**: +10 points per malware family
- **Actor Bonus**: +15 points per threat actor
- **Maximum Score**: Capped at 100

### Confidence Levels
- **High**: 5+ indicators from 3+ sources
- **Medium**: 2+ indicators from 2+ sources
- **Low**: Fewer indicators or limited sources

## Configuration Management

### Export/Import Configuration
1. **Export**: Download current configuration as JSON
2. **Import**: Upload previously exported configurations
3. **Backup**: Maintain configuration backups for disaster recovery

### Test Email Functionality
- **Configuration Testing**: Verify SMTP settings before production use
- **Delivery Confirmation**: Ensure emails reach intended recipients
- **Format Validation**: Confirm PDF attachments and HTML content

## Compliance Features

### NIS2 Article 23 Requirements
- **24-Hour Initial Reporting**: Automatic deadline tracking
- **72-Hour Intermediate Reports**: For significant+ incidents
- **Final Reports**: Upon incident resolution
- **Authority Notification**: Automatic distribution to relevant authorities

### Audit Trail
- **Email Delivery Tracking**: Confirmation of successful distribution
- **Report Generation Logs**: Timestamp and content tracking
- **Recipient Management**: Complete audit trail of configuration changes

## Troubleshooting

### Common Issues

#### Email Delivery Failures
1. **Check SMTP Configuration**: Verify server, port, and credentials
2. **Authentication Issues**: Ensure proper username/password or app password
3. **Network Restrictions**: Check firewall and network policies
4. **Rate Limiting**: Some providers limit email frequency

#### PDF Generation Issues
1. **File Permissions**: Ensure write access to reports directory
2. **Dependencies**: Verify ReportLab installation
3. **Memory Issues**: Large reports may require additional memory

#### Threat Intelligence Enrichment
1. **Indicator Quality**: Ensure clear, valid indicators in descriptions
2. **API Limits**: Some services have rate limits
3. **Network Access**: Verify internet connectivity for external services

### Support and Maintenance
- **Regular Testing**: Test email configuration monthly
- **Configuration Backups**: Export configurations regularly
- **Recipient Updates**: Keep recipient lists current
- **Security Review**: Regular review of access and permissions

## Best Practices

### Incident Description
- **Include IOCs**: Mention IPs, domains, hashes, URLs for enrichment
- **Clear Narrative**: Provide detailed, chronological incident description
- **Business Context**: Explain impact on operations and services
- **Technical Details**: Include relevant technical information

### Recipient Management
- **Regular Review**: Update recipient lists quarterly
- **Priority Alignment**: Align priorities with organizational needs
- **Contact Verification**: Verify email addresses and contact information
- **Testing**: Test new recipient configurations

### Threat Intelligence
- **Quality Indicators**: Focus on high-quality, actionable intelligence
- **Source Diversity**: Leverage multiple intelligence sources
- **Regular Updates**: Keep threat intelligence current
- **Context Integration**: Integrate intelligence with incident context

## Future Enhancements

### Planned Features
- **API Integration**: Direct integration with threat intelligence platforms
- **Advanced Analytics**: Machine learning for incident pattern recognition
- **Custom Templates**: Organization-specific report templates
- **Multi-Language Support**: International language support
- **Mobile Notifications**: Push notifications for critical incidents

### Integration Opportunities
- **SIEM Systems**: Integration with Security Information and Event Management
- **Ticketing Systems**: Integration with IT service management platforms
- **Compliance Tools**: Integration with regulatory compliance platforms
- **Communication Platforms**: Integration with team communication tools

---

## Contact and Support

For technical support or feature requests, please contact your system administrator or refer to the system documentation.

**System Version**: Enhanced Incident Reporting v2.0  
**Last Updated**: August 2025  
**Compliance**: NIS2 Article 23 Ready
