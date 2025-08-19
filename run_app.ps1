# Cybersecurity Reporting Agent Launcher
# PowerShell script to run the Streamlit application

Write-Host "🔒 Cybersecurity Reporting Agent Launcher" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host ""

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python not found in PATH" -ForegroundColor Red
    Write-Host "Please install Python and add it to your PATH" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if requirements are installed
Write-Host "Checking dependencies..." -ForegroundColor Yellow
try {
    python -c "import streamlit, pandas, numpy, requests, dns, whois, cryptography" 2>$null
    Write-Host "✅ Dependencies are installed" -ForegroundColor Green
} catch {
    Write-Host "❌ Some dependencies are missing" -ForegroundColor Red
    Write-Host "Installing requirements..." -ForegroundColor Yellow
    pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to install requirements" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

# Check for .env file
if (Test-Path ".env") {
    Write-Host "✅ .env file found" -ForegroundColor Green
} else {
    Write-Host "⚠️  .env file not found" -ForegroundColor Yellow
    Write-Host "Please create a .env file with your OPENAI_API_KEY" -ForegroundColor Yellow
    Write-Host "You can copy env_example.txt to .env and add your API key" -ForegroundColor Yellow
    Write-Host ""
}

Write-Host ""
Write-Host "Starting Cybersecurity Reporting Agent..." -ForegroundColor Green
Write-Host "The app will open in your default browser" -ForegroundColor Cyan
Write-Host "Press Ctrl+C to stop the application" -ForegroundColor Yellow
Write-Host ""

# Start Streamlit
try {
    streamlit run cybersecurity_agent.py
} catch {
    Write-Host "❌ Failed to start Streamlit" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
}
