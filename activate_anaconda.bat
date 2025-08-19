@echo off
REM Anaconda Activation Script for Command Prompt
REM Run this script to activate Anaconda in your current Command Prompt session

echo 🔧 Activating Anaconda Environment...

REM Set Anaconda paths
set "ANACONDA_PATH=C:\Users\%USERNAME%\anaconda3"
set "SCRIPTS_PATH=%ANACONDA_PATH%\Scripts"
set "LIBRARY_BIN_PATH=%ANACONDA_PATH%\Library\bin"

REM Add to PATH
set "PATH=%ANACONDA_PATH%;%SCRIPTS_PATH%;%LIBRARY_BIN_PATH%;%PATH%"

REM Activate base environment
call "%SCRIPTS_PATH%\activate.bat" base

echo ✅ Anaconda activated successfully!
echo 📍 Python location: %ANACONDA_PATH%\python.exe
echo 🐍 Python version:
python --version
echo 🔍 Conda environments:
conda info --envs

echo.
echo 💡 To activate a specific environment, use: conda activate ^<env_name^>
echo 💡 To deactivate, use: conda deactivate
echo.
echo 🚀 Ready to use Anaconda!

