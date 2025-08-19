@echo off
echo Starting Cybersecurity Reporting Agent...
echo.
echo Make sure you have:
echo 1. Python installed and in PATH
echo 2. Dependencies installed (pip install -r requirements.txt)
echo 3. .env file with OPENAI_API_KEY
echo.
pause
echo.
echo Starting Streamlit app...
python -m streamlit run cybersecurity_agent.py
pause
