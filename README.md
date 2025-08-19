# 🔒 NIS2 Article 23 Cybersecurity Reporting Agent

A comprehensive cybersecurity incident reporting and compliance tool specifically designed to support organizations in meeting their **NIS2 Article 23 incident reporting obligations**. Built with OpenAI Agents and Python, this application provides scope assessment, timeline management, incident reporting, and regulatory compliance through an intuitive Streamlit interface with **multi-organization authentication** and role-based access control.

## 🚀 Features

- **🔍 NIS2 Scope Assessment**: Determine if your organization is in scope for Article 23 reporting requirements
- **🚨 Incident Reporting**: Complete incident lifecycle management with mandatory timeline compliance
- **📋 Timeline Management**: Automated tracking of 24-hour initial reports and 72-hour intermediate updates
- **📊 Compliance Dashboard**: Real-time monitoring of NIS2 compliance status and reporting obligations
- **🛡️ Security Controls**: Comprehensive assessment framework based on NIST CSF and Cyber Essentials
- **🔐 Multi-Organization Authentication**: Secure user management with role-based access control
- **👥 User Role Management**: Admin, Partner, Reporter, and Reader roles with appropriate permissions
- **🏢 Organization Isolation**: Secure data separation between different organizations
- **📈 Analytics & Reporting**: Comprehensive compliance metrics and incident analytics
- **💾 Export Capabilities**: Download assessments and reports in multiple formats

## 🛡️ Security Analysis Capabilities

### Domain Analysis
- **DNS Records**: A, AAAA, MX, TXT, NS record analysis
- **WHOIS Information**: Registrar details, creation dates, expiration dates
- **Security Headers**: Analysis of critical security headers (HSTS, CSP, X-Frame-Options, etc.)
- **SSL Certificate**: Certificate validation, expiry dates, key strength analysis
- **Subdomain Enumeration**: Discovery of potential attack vectors
- **Threat Intelligence**: Reputation scoring and suspicious indicator detection

### IP Address Analysis
- **Geolocation**: Country, region, city, ISP, and organization information
- **Port Scanning**: Common port analysis (21, 22, 23, 80, 443, 3389, etc.)
- **Service Detection**: Identification of running services and their security implications
- **Reputation Check**: Integration with abuse databases and threat feeds
- **Risk Assessment**: Scoring based on open ports, services, and threat intelligence

### File Hash Analysis
- **Hash Type Detection**: Automatic MD5, SHA1, SHA256 identification
- **VirusTotal Integration**: Multi-engine malware scanning results
- **File Metadata**: File type, size, and entropy analysis
- **Risk Scoring**: Malware detection rate and threat assessment

## 📊 Risk Assessment Framework

The application uses a sophisticated risk scoring system:

- **LOW RISK (0-30)**: Minimal security concerns, standard measures sufficient
- **MEDIUM RISK (31-60)**: Moderate concerns requiring attention and monitoring
- **HIGH RISK (61-100)**: Significant security risks requiring immediate action

### Risk Factors Considered

**Domain Analysis:**
- DNS security configuration (25%)
- SSL certificate validity (30%)
- Security headers implementation (25%)
- Threat intelligence indicators (20%)

**IP Address Analysis:**
- Open ports and services (30%)
- Service security implications (25%)
- Geographic risk factors (15%)
- Reputation and abuse history (30%)

**File Analysis:**
- VirusTotal detection rate (60%)
- File metadata analysis (20%)
- Hash analysis and patterns (20%)

## 🔐 Authentication & User Management

### User Roles & Permissions

- **🔑 Admin**: Full system access, can manage all aspects including users, organizations, and system configuration
- **🤝 Partner**: Multi-organization access, can manage users and organizations across multiple entities
- **📝 Reporter**: Can create security analysis reports and access compliance features
- **👁️ Reader**: Read-only access to reports and basic features

### Organization Management

- **Multi-tenant Architecture**: Secure isolation between different organizations
- **Role-based Access Control**: Users only see data from organizations they have access to
- **Compliance Framework Support**: NIS2, ISO 27001, NIST, GDPR, SOC 2, and custom frameworks

## 📋 NIS2 Article 23 Compliance

### What is NIS2 Article 23?

Article 23 of the NIS2 Directive requires organizations in scope to:
- **Report significant incidents within 24 hours** of detection
- **Provide intermediate updates** every 72 hours for ongoing incidents  
- **Submit final reports** upon incident resolution
- **Maintain records** for at least 3 years

### New Compliance Features

#### 🔍 Scope Assessment Tool
- **Sector Classification**: Essential, Important, Digital Services, and Other sectors
- **Organization Size Assessment**: Micro, Small, Medium, and Large organizations
- **Risk Factor Evaluation**: Automated scoring based on multiple criteria
- **Scope Determination**: Clear in-scope/out-of-scope classification
- **Compliance Recommendations**: Actionable next steps for organizations

#### 🚨 Incident Reporting with Timeline Management
- **Initial Report Generation**: Automatic 24-hour deadline tracking
- **Intermediate Reports**: 72-hour update cycle for significant+ incidents
- **Final Report**: Upon incident resolution with lessons learned
- **Timeline Management**: Automated deadline tracking and overdue alerts
- **Report Templates**: Pre-formatted reports for each reporting stage

#### 🛡️ Security Controls Assessment
- **NIST CSF Framework**: Industry-standard controls organized by function (Identify, Protect, Detect, Respond, Recover)
- **Cyber Essentials**: UK NCSC essential cybersecurity controls
- **NIS2 Compliance**: Specific controls required for Article 23 compliance
- **Implementation Tracking**: Monitor control implementation status and progress
- **Risk-based Prioritization**: Focus on mandatory controls first, then recommended
- **Assessment Workflow**: Document evidence, assign responsibilities, and track progress

#### 📊 Compliance Dashboard
- **Real-time Metrics**: Track compliance rates and reporting deadlines
- **Overdue Alerts**: Immediate notification of missed deadlines
- **Incident Analytics**: Severity distribution, category analysis, and trends
- **Compliance Timeline**: Visual representation of reporting obligations

### NIS2 Requirements Covered

- **23.1 Incident Detection and Reporting**: Automated detection mechanisms and mandatory reporting procedures
- **23.2 Incident Response and Management**: Complete incident lifecycle with timeline compliance
- **23.3 Authority Notification**: Proper notification procedures with automated tracking
- **23.4 Record Keeping**: Maintain incident records for regulatory compliance

## 🚀 Quick Start - NIS2 Article 23 Compliance

### Step 1: Scope Assessment
1. Navigate to the **"Scope Assessment"** tab
2. Complete the assessment form with your organization's details
3. Review the automated scope determination
4. Download assessment results for compliance planning

### Step 2: Incident Reporting Setup
1. Navigate to the **"Incident Reporting"** tab
2. Configure your organization profile and incident response team
3. Review the 24-hour and 72-hour reporting requirements
4. Set up notification preferences for reporting deadlines

### Step 3: Security Controls Assessment
1. Navigate to the **"Security Controls"** tab
2. Review the pre-populated NIST CSF and Cyber Essentials controls
3. Assess your organization's implementation status for each control
4. Prioritize mandatory controls and document implementation evidence

### Step 4: Monitor Compliance
1. Use the **"Compliance Dashboard"** to track overall status
2. Monitor reporting deadlines and overdue alerts
3. Review compliance metrics and analytics
4. Generate required reports on time

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- OpenAI API key
- SQLite database (automatically created)
- Optional: VirusTotal, Shodan, Censys API keys for enhanced functionality

### Setup

1. **Clone or download this workspace**
   ```bash
   cd cybersecurity_reporting_workspace
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   - Copy `env_example.txt` to `.env`
   - Add your API keys:
   ```bash
   OPENAI_API_KEY=your_openai_api_key_here
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   SHODAN_API_KEY=your_shodan_api_key_here
   CENSYS_API_ID=your_censys_api_id_here
   ```

4. **Run the application**
   ```bash
   streamlit run cybersecurity_agent.py
   ```

5. **First-time setup**
   - The application will automatically create a default organization and admin user
   - **Default credentials**: `admin` / `admin123` (change immediately in production)
   - Create additional organizations and users through the User Management interface

## 🎯 Usage

### 1. Launch and Authenticate
- Launch the application and log in with your credentials
- Select your organization (if you have access to multiple)
- The interface adapts based on your role and permissions

### 2. Security Analysis
- **Domain Analysis**: Enter domain names (e.g., example.com, google.com)
- **IP Address Analysis**: Enter IP addresses (e.g., 8.8.8.8, 1.1.1.1)
- **File Hash Analysis**: Enter file hashes (MD5, SHA1, or SHA256)

### 3. NIS2 Compliance Management
- **Incident Reports**: Create and manage security incidents
- **Compliance Dashboard**: Monitor compliance metrics and status
- **Regulatory Reports**: Generate NIS2 Article 23 compliance reports

### 4. User & Organization Management (Admin/Partner)
- **User Management**: Create, edit, and manage user accounts
- **Organization Management**: Manage organizations and compliance frameworks
- **Permission Control**: Configure role-based access and permissions

### 5. Review Results & Reports
- Risk scores and key metrics
- Detailed security analysis
- Professional security reports
- NIS2 compliance reports
- Actionable recommendations

## 🔧 Configuration

### Environment Variables

**Required:**
- `OPENAI_API_KEY`: OpenAI API key for AI-powered analysis

**Optional (for enhanced functionality):**
- `VIRUSTOTAL_API_KEY`: VirusTotal API for malware detection
- `SHODAN_API_KEY`: Shodan API for internet-wide scanning
- `CENSYS_API_ID`: Censys API for network intelligence
- `CENSYS_API_SECRET`: Censys API secret

### Customization

Edit `config.py` to modify:
- Risk scoring weights and thresholds
- Port scanning configurations
- Security header priorities
- Subdomain enumeration lists
- API rate limits and timeouts

## 📈 Report Types

### Executive Summary
- High-level risk assessment
- Key security findings
- Business impact analysis
- Strategic recommendations

### Technical Report
- Detailed technical analysis
- Security configuration review
- Vulnerability assessment
- Technical remediation steps

### Comprehensive Report
- Complete security analysis
- Risk assessment details
- Compliance framework mapping
- Incident response guidance

## 🛠️ Technical Architecture

### Core Components
- **CybersecurityAgent**: Main analysis engine
- **Risk Scoring Engine**: Multi-factor risk assessment
- **Report Generator**: Professional report creation
- **API Integrations**: Threat intelligence and security tools

### Security Tools Integration
- **DNS Analysis**: dnspython for DNS queries
- **WHOIS Lookup**: python-whois for domain information
- **Port Scanning**: Custom port scanner with service detection
- **SSL Analysis**: Built-in SSL certificate validation
- **Hash Analysis**: Multiple hash algorithm support

### Data Sources
- **VirusTotal**: Malware detection and file reputation
- **Shodan**: Internet-wide device and service discovery
- **Censys**: Network infrastructure intelligence
- **IP Geolocation**: Geographic and ISP information
- **Threat Feeds**: Community-maintained threat lists

## 🔒 Security Considerations

### Ethical Usage
- Only analyze domains, IPs, and files you own or have permission to test
- Respect rate limits and terms of service for all APIs
- Use for legitimate security research and assessment purposes

### Privacy and Compliance
- No data is stored permanently
- All analysis is performed in real-time
- Respect privacy and data protection regulations
- Follow responsible disclosure practices

## 🚨 Troubleshooting

### Common Issues

**"Module not found" errors**
```bash
pip install -r requirements.txt
```

**DNS resolution failures**
- Check internet connection
- Verify DNS server configuration
- Some corporate networks may block external DNS

**API rate limiting**
- Check API key validity and quotas
- Implement rate limiting in production use
- Use multiple API keys for high-volume analysis

**Port scanning issues**
- Ensure firewall allows outbound connections
- Some networks block port scanning
- Use appropriate scanning techniques for your environment

### Performance Optimization

- **Caching**: Results are cached to reduce API calls
- **Rate Limiting**: Built-in rate limiting for all APIs
- **Async Processing**: Non-blocking analysis for better performance
- **Resource Management**: Efficient memory and CPU usage

## 🎓 Learning Resources

### Security Concepts
- **DNS Security**: Understanding DNS vulnerabilities and protections
- **SSL/TLS**: Certificate validation and encryption best practices
- **Security Headers**: Web application security header implementation
- **Port Security**: Service hardening and network security

### Compliance Frameworks
- **ISO 27001**: Information Security Management System
- **NIST Cybersecurity Framework**: Risk management and security controls
- **GDPR**: Data protection and privacy requirements
- **SOC 2**: Security, availability, and privacy controls

## 🤝 Contributing

This is a template workspace that you can extend with:

- Additional threat intelligence sources
- More sophisticated risk scoring algorithms
- Enhanced reporting templates
- Integration with SIEM and security tools
- Custom compliance frameworks
- Advanced malware analysis capabilities

## 📄 License

This project is for educational and legitimate security research purposes. Please ensure compliance with:

- Relevant cybersecurity regulations
- API terms of service
- Ethical hacking guidelines
- Responsible disclosure practices

## ⚠️ Disclaimer

This tool is for legitimate security research and assessment purposes only. Users are responsible for:

- Obtaining proper authorization before testing
- Complying with applicable laws and regulations
- Following ethical security practices
- Respecting privacy and data protection rights

**Always conduct security testing responsibly and ethically.**

## 🆘 Support

For issues or questions:
1. Check the troubleshooting section
2. Verify your API keys and configuration
3. Ensure all dependencies are properly installed
4. Check the console for error messages
5. Review API rate limits and quotas

---

**Built with ❤️ using OpenAI Agents and Streamlit for Cybersecurity Professionals**
