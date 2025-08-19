"""
Test script to verify the cybersecurity reporting agent setup.
Run this script to check if all dependencies are properly installed.
"""

import sys
import importlib

def test_imports():
    """Test if all required packages can be imported."""
    required_packages = [
        'pandas',
        'numpy',
        'matplotlib',
        'seaborn',
        'requests',
        'plotly',
        'streamlit',
        'dotenv',
        'dns',
        'whois',
        'cryptography'
    ]
    
    print("Testing package imports...")
    failed_imports = []
    
    for package in required_packages:
        try:
            importlib.import_module(package)
            print(f"✅ {package}")
        except ImportError as e:
            print(f"❌ {package}: {e}")
            failed_imports.append(package)
    
    if failed_imports:
        print(f"\n❌ Failed to import: {', '.join(failed_imports)}")
        print("Please install missing packages using: pip install -r requirements.txt")
        return False
    else:
        print("\n✅ All packages imported successfully!")
        return True

def test_dns_functionality():
    """Test if DNS resolution works."""
    try:
        import dns.resolver
        print("\nTesting DNS functionality...")
        
        # Try to resolve a simple domain
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        
        try:
            answers = resolver.resolve("google.com", "A")
            if answers:
                print(f"✅ DNS working - google.com resolves to: {answers[0]}")
                return True
        except Exception as e:
            print(f"⚠️  DNS resolution failed: {e}")
            return False
            
    except Exception as e:
        print(f"❌ DNS test failed: {e}")
        return False

def test_network_functionality():
    """Test if network requests work."""
    try:
        import requests
        print("\nTesting network functionality...")
        
        # Test a simple HTTP request
        response = requests.get("https://httpbin.org/ip", timeout=10)
        if response.status_code == 200:
            print("✅ Network requests working")
            return True
        else:
            print(f"❌ Network request failed with status: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Network test failed: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality without requiring API keys."""
    try:
        print("\nTesting basic functionality...")
        
        # Test pandas operations
        import pandas as pd
        import numpy as np
        
        # Create sample security data
        security_events = pd.DataFrame({
            'timestamp': pd.date_range('2023-01-01', periods=100, freq='H'),
            'event_type': np.random.choice(['login', 'file_access', 'network_scan'], 100),
            'risk_score': np.random.randint(1, 100, 100),
            'source_ip': [f"192.168.1.{i % 255}" for i in range(100)]
        })
        
        # Test security analysis
        high_risk_events = security_events[security_events['risk_score'] > 70]
        avg_risk = security_events['risk_score'].mean()
        
        print(f"✅ Basic calculations working - DataFrame shape: {security_events.shape}")
        print(f"✅ High risk events: {len(high_risk_events)}")
        print(f"✅ Average risk score: {avg_risk:.2f}")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False

def test_security_tools():
    """Test security-specific tools."""
    try:
        print("\nTesting security tools...")
        
        # Test hash generation
        import hashlib
        test_string = "test_security_string"
        md5_hash = hashlib.md5(test_string.encode()).hexdigest()
        sha1_hash = hashlib.sha1(test_string.encode()).hexdigest()
        sha256_hash = hashlib.sha256(test_string.encode()).hexdigest()
        
        print(f"✅ Hash generation working:")
        print(f"   MD5: {md5_hash}")
        print(f"   SHA1: {sha1_hash}")
        print(f"   SHA256: {sha256_hash}")
        
        # Test basic cryptography
        try:
            from cryptography.fernet import Fernet
            key = Fernet.generate_key()
            cipher = Fernet(key)
            encrypted = cipher.encrypt(test_string.encode())
            decrypted = cipher.decrypt(encrypted).decode()
            
            if decrypted == test_string:
                print("✅ Cryptography working")
            else:
                print("❌ Cryptography test failed")
                return False
                
        except Exception as e:
            print(f"⚠️  Cryptography test failed: {e}")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Security tools test failed: {e}")
        return False

def test_api_configuration():
    """Test if API keys are configured."""
    try:
        import os
        from dotenv import load_dotenv
        
        load_dotenv()
        
        print("\nTesting API configuration...")
        
        # Check for required API keys
        required_keys = ['OPENAI_API_KEY']
        optional_keys = ['VIRUSTOTAL_API_KEY', 'SHODAN_API_KEY', 'CENSYS_API_ID']
        
        missing_required = []
        configured_optional = []
        
        for key in required_keys:
            if os.getenv(key):
                print(f"✅ {key}: Configured")
            else:
                print(f"❌ {key}: Missing (Required)")
                missing_required.append(key)
        
        for key in optional_keys:
            if os.getenv(key):
                print(f"✅ {key}: Configured")
                configured_optional.append(key)
            else:
                print(f"⚠️  {key}: Not configured (Optional)")
        
        if missing_required:
            print(f"\n❌ Missing required API keys: {', '.join(missing_required)}")
            return False
        
        if configured_optional:
            print(f"\n✅ Optional APIs configured: {', '.join(configured_optional)}")
        else:
            print("\n⚠️  No optional APIs configured - some features will be limited")
        
        return True
        
    except Exception as e:
        print(f"❌ API configuration test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🔒 Cybersecurity Reporting Agent - Setup Test")
    print("=" * 60)
    
    # Test imports
    imports_ok = test_imports()
    
    if not imports_ok:
        print("\n❌ Setup incomplete. Please fix import issues first.")
        return
    
    # Test DNS functionality
    dns_ok = test_dns_functionality()
    
    # Test network functionality
    network_ok = test_network_functionality()
    
    # Test basic functionality
    basic_ok = test_basic_functionality()
    
    # Test security tools
    security_ok = test_security_tools()
    
    # Test API configuration
    api_ok = test_api_configuration()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST SUMMARY")
    print("=" * 60)
    
    all_tests_passed = all([imports_ok, dns_ok, network_ok, basic_ok, security_ok, api_ok])
    
    if all_tests_passed:
        print("🎉 All tests passed! Your cybersecurity setup is ready.")
        print("\nNext steps:")
        print("1. Configure your API keys in the .env file")
        print("2. Run: streamlit run cybersecurity_agent.py")
        print("3. Open your browser to the displayed URL")
        print("4. Start analyzing domains, IPs, and file hashes!")
    else:
        print("⚠️  Some tests failed. Please review the errors above.")
        
        if not dns_ok:
            print("\nFor DNS issues:")
            print("- Check your internet connection")
            print("- Some corporate networks may block DNS queries")
        
        if not network_ok:
            print("\nFor network issues:")
            print("- Check your internet connection")
            print("- Verify firewall/proxy settings")
        
        if not api_ok:
            print("\nFor API configuration:")
            print("- Copy env_example.txt to .env")
            print("- Add your API keys")
            print("- Get API keys from:")
            print("  - OpenAI: https://platform.openai.com/api-keys")
            print("  - VirusTotal: https://www.virustotal.com/gui/join-us")
            print("  - Shodan: https://account.shodan.io/register")
        
        print("\nFor general issues:")
        print("- Ensure you're using Python 3.8+")
        print("- Try creating a fresh virtual environment")
        print("- Reinstall requirements: pip install -r requirements.txt")

if __name__ == "__main__":
    main()
