# 🚀 Quick Start Guide - Cybersecurity Reporting Agent

Get your Cybersecurity Reporting Agent up and running in 5 minutes!

## ⚡ Super Quick Start

1. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set up your API key**
   - Copy `env_example.txt` to `.env`
   - Add your OpenAI API key: `OPENAI_API_KEY=your_key_here`

3. **Run the app**
   ```bash
   streamlit run cybersecurity_agent.py
   ```

4. **Open your browser** to the displayed URL

## 🔧 Detailed Setup

### Prerequisites
- Python 3.8+ installed
- OpenAI API key ([Get one here](https://platform.openai.com/api-keys))
- Optional: VirusTotal, Shodan, Censys API keys for enhanced features

### Step 1: Install Dependencies
```bash
# Navigate to the workspace
cd cybersecurity_reporting_workspace

# Install all required packages
pip install -r requirements.txt
```

### Step 2: Configure API Keys
```bash
# Copy the example environment file
copy env_example.txt .env

# Edit .env and add your API keys
OPENAI_API_KEY=sk-your-actual-api-key-here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
SHODAN_API_KEY=your_shodan_key_here
```

### Step 3: Test Your Setup
```bash
# Run the test script to verify everything works
python test_setup.py
```

### Step 4: Launch the Application
```bash
# Start the Streamlit app
streamlit run cybersecurity_agent.py
```

## 🎯 First Use

1. **Launch the application** - The Streamlit app will open in your browser
2. **Choose analysis type**:
   - **Domain Analysis**: Enter domains (e.g., example.com, google.com)
   - **IP Address Analysis**: Enter IPs (e.g., 8.8.8.8, 1.1.1.1)
   - **File Hash Analysis**: Enter hashes (MD5, SHA1, SHA256)
3. **Select report type**: Executive Summary, Technical Report, or Comprehensive Report
4. **Click "Analyze"** - The agent will perform security analysis
5. **Review results**: Risk scores, detailed findings, and professional reports

## 🆘 Troubleshooting

### Common Issues

**"Module not found" errors**
```bash
pip install -r requirements.txt
```

**DNS analysis failures**
- Check internet connection
- Verify DNS server configuration
- Some corporate networks block external DNS

**API key errors**
- Ensure `.env` file exists and contains valid API keys
- Check API key permissions and quotas
- Verify OpenAI account has credits

**Port scanning issues**
- Ensure firewall allows outbound connections
- Some networks block port scanning
- Use appropriate scanning techniques

**Streamlit won't start**
```bash
# Check if Streamlit is installed
pip show streamlit

# Reinstall if needed
pip install streamlit --upgrade
```

## 🎨 Customization

### Modify Security Analysis
Edit `config.py` to change:
- Risk scoring weights and thresholds
- Port scanning configurations
- Security header priorities
- Subdomain enumeration lists

### Add New Features
- Extend `CybersecurityAgent` class
- Integrate additional threat intelligence sources
- Add new analysis types
- Customize report templates

## 📱 Alternative Launch Methods

### Windows Batch File
Double-click `run_app.bat`

### PowerShell Script
Right-click `run_app.ps1` → "Run with PowerShell"

### Command Line
```bash
streamlit run cybersecurity_agent.py
```

## 🔍 What You'll See

- **Real-time security analysis** of domains, IPs, and files
- **Professional security reports** in multiple formats
- **Risk scoring** with detailed breakdowns
- **Threat intelligence** from multiple sources
- **Actionable recommendations** for security improvements

## 🎓 Learning Resources

- **Security Analysis**: Learn about DNS, SSL, and network security
- **Risk Assessment**: Understand risk scoring and security metrics
- **Threat Intelligence**: Explore threat detection and analysis
- **Compliance**: Review security frameworks and best practices

## 🚨 Important Notes

- **Ethical Usage**: Only analyze systems you own or have permission to test
- **API Costs**: Some APIs may incur charges (check individual service pricing)
- **Rate Limits**: Respect API rate limits and terms of service
- **Legal Compliance**: Ensure compliance with applicable laws and regulations

## 🔐 Security Best Practices

- **Authorization**: Always obtain proper authorization before testing
- **Documentation**: Document all security testing activities
- **Responsible Disclosure**: Follow responsible disclosure practices
- **Privacy**: Respect privacy and data protection requirements

---

**Need help?** Check the main README.md for detailed documentation!
