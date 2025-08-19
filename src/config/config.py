"""
Configuration file for the Cybersecurity Reporting Agent.
Modify these settings to customize the application behavior.
"""

# Security Analysis Parameters
SECURITY_ANALYSIS = {
    'DNS_TIMEOUT': 10,           # DNS query timeout in seconds
    'HTTP_TIMEOUT': 15,          # HTTP request timeout
    'PORT_SCAN_TIMEOUT': 1,      # Port scan timeout per port
    'MAX_SUBDOMAINS': 50,        # Maximum subdomains to enumerate
    'RISK_THRESHOLDS': {
        'LOW': 30,
        'MEDIUM': 60,
        'HIGH': 80
    }
}

# Port Scanning Configuration
PORT_SCANNING = {
    'COMMON_PORTS': [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443],
    'RISKY_PORTS': [23, 3389, 5900, 1433, 3306],  # Telnet, RDP, VNC, MSSQL, MySQL
    'WEB_PORTS': [80, 443, 8080, 8443],
    'DATABASE_PORTS': [1433, 3306, 5432, 6379],
    'SCAN_TIMEOUT': 1
}

# Security Headers Analysis
SECURITY_HEADERS = {
    'CRITICAL_HEADERS': [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Frame-Options'
    ],
    'IMPORTANT_HEADERS': [
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Referrer-Policy'
    ],
    'OPTIONAL_HEADERS': [
        'Permissions-Policy',
        'X-Permitted-Cross-Domain-Policies'
    ]
}

# Threat Intelligence Configuration
THREAT_INTELLIGENCE = {
    'REPUTATION_SOURCES': [
        'virustotal',
        'abuseipdb',
        'alienvault',
        'threatfox'
    ],
    'UPDATE_FREQUENCY': 3600,  # Update threat intel every hour
    'CACHE_DURATION': 86400    # Cache results for 24 hours
}

# Report Generation
REPORT_CONFIG = {
    'REPORT_TYPES': ['executive', 'technical', 'comprehensive'],
    'DEFAULT_FORMAT': 'markdown',
    'INCLUDE_CHARTS': True,
    'INCLUDE_RECOMMENDATIONS': True,
    'RISK_COLORS': {
        'LOW': '#28a745',      # Green
        'MEDIUM': '#ffc107',   # Yellow
        'HIGH': '#dc3545'      # Red
    }
}

# API Configuration
API_CONFIG = {
    'VIRUSTOTAL': {
        'BASE_URL': 'https://www.virustotal.com/vtapi/v2',
        'RATE_LIMIT': 4,  # requests per minute
        'TIMEOUT': 30
    },
    'SHODAN': {
        'BASE_URL': 'https://api.shodan.io',
        'RATE_LIMIT': 1,  # requests per second
        'TIMEOUT': 30
    },
    'CENSYS': {
        'BASE_URL': 'https://search.censys.io/api/v2',
        'RATE_LIMIT': 5,  # requests per second
        'TIMEOUT': 30
    }
}

# Risk Scoring Weights
RISK_WEIGHTS = {
    'DOMAIN': {
        'DNS_SECURITY': 0.25,
        'SSL_CERTIFICATE': 0.30,
        'SECURITY_HEADERS': 0.25,
        'THREAT_INTELLIGENCE': 0.20
    },
    'IP_ADDRESS': {
        'OPEN_PORTS': 0.30,
        'SERVICES': 0.25,
        'GEOLOCATION': 0.15,
        'REPUTATION': 0.30
    },
    'FILE_HASH': {
        'VIRUSTOTAL_SCORE': 0.60,
        'FILE_METADATA': 0.20,
        'HASH_ANALYSIS': 0.20
    }
}

# Subdomain Enumeration
SUBDOMAIN_CONFIG = {
    'COMMON_SUBDOMAINS': [
        'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test',
        'api', 'cdn', 'ns1', 'ns2', 'smtp', 'pop', 'imap',
        'webmail', 'remote', 'vpn', 'portal', 'support', 'help'
    ],
    'BRUTEFORCE_WORDLIST': [
        'admin', 'administrator', 'backup', 'beta', 'cache',
        'cdn', 'dev', 'development', 'docs', 'download',
        'email', 'files', 'forum', 'ftp', 'git', 'help',
        'host', 'hosting', 'images', 'img', 'internal',
        'intranet', 'lab', 'local', 'login', 'mail', 'manage',
        'management', 'mobile', 'monitor', 'mysql', 'new',
        'news', 'ns1', 'ns2', 'old', 'online', 'panel',
        'phpmyadmin', 'pop', 'portal', 'private', 'proxy',
        'public', 'remote', 'root', 'router', 'secure',
        'security', 'server', 'service', 'shop', 'site',
        'smtp', 'sql', 'ssh', 'staff', 'stage', 'staging',
        'static', 'stats', 'status', 'store', 'support',
        'sys', 'system', 'test', 'testing', 'tools', 'upload',
        'user', 'users', 'vpn', 'web', 'webmail', 'wiki'
    ]
}

# SSL Certificate Analysis
SSL_CONFIG = {
    'MINIMUM_KEY_SIZE': 2048,
    'WEAK_CIPHERS': [
        'RC4', 'DES', '3DES', 'MD5', 'SHA1'
    ],
    'EXPIRY_WARNING_DAYS': 30,
    'CRITICAL_EXPIRY_DAYS': 7
}

# Logging Configuration
LOGGING_CONFIG = {
    'LEVEL': 'INFO',
    'FORMAT': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'FILE': 'cybersecurity_agent.log',
    'MAX_BYTES': 10485760,  # 10MB
    'BACKUP_COUNT': 5
}

# Export Configuration
EXPORT_CONFIG = {
    'SUPPORTED_FORMATS': ['markdown', 'html', 'pdf', 'json', 'csv'],
    'DEFAULT_FORMAT': 'markdown',
    'INCLUDE_TIMESTAMP': True,
    'TIMESTAMP_FORMAT': '%Y%m%d_%H%M%S'
}

# Security Recommendations
SECURITY_RECOMMENDATIONS = {
    'HIGH_RISK': [
        'Implement immediate security controls',
        'Conduct detailed security assessment',
        'Monitor for suspicious activity',
        'Review and update security policies',
        'Implement incident response procedures'
    ],
    'MEDIUM_RISK': [
        'Review security configurations',
        'Implement additional controls as needed',
        'Schedule security training for staff',
        'Update security documentation',
        'Conduct regular security reviews'
    ],
    'LOW_RISK': [
        'Maintain current security posture',
        'Regular security reviews recommended',
        'Monitor for changes in risk profile',
        'Keep security tools updated',
        'Document security procedures'
    ]
}

# Compliance Frameworks
COMPLIANCE_FRAMEWORKS = {
    'ISO_27001': {
        'description': 'Information Security Management System',
        'key_controls': ['Access Control', 'Cryptography', 'Physical Security']
    },
    'NIST_CYBER': {
        'description': 'NIST Cybersecurity Framework',
        'key_controls': ['Identify', 'Protect', 'Detect', 'Respond', 'Recover']
    },
    'GDPR': {
        'description': 'General Data Protection Regulation',
        'key_controls': ['Data Protection', 'Privacy by Design', 'Breach Notification']
    },
    'SOC_2': {
        'description': 'Service Organization Control 2',
        'key_controls': ['Security', 'Availability', 'Processing Integrity', 'Confidentiality', 'Privacy']
    }
}
