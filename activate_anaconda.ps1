# Anaconda Activation Script for PowerShell
# Run this script to activate Anaconda in your current PowerShell session

Write-Host "🔧 Activating Anaconda Environment..." -ForegroundColor Green

# Set Anaconda paths
$anaconda_path = "C:\Users\$env:USERNAME\anaconda3"
$scripts_path = "$anaconda_path\Scripts"
$library_bin_path = "$anaconda_path\Library\bin"

# Add to PATH
$env:PATH = "$anaconda_path;$scripts_path;$library_bin_path;" + $env:PATH

# Activate base environment
& "$scripts_path\activate.bat" base

Write-Host "✅ Anaconda activated successfully!" -ForegroundColor Green
Write-Host "📍 Python location: $(Get-Command python | Select-Object -ExpandProperty Source)" -ForegroundColor Cyan
Write-Host "🐍 Python version: $(python --version)" -ForegroundColor Cyan
Write-Host "🔍 Conda environments:" -ForegroundColor Cyan
conda info --envs

Write-Host "`n💡 To activate a specific environment, use: conda activate <env_name>" -ForegroundColor Yellow
Write-Host "💡 To deactivate, use: conda deactivate" -ForegroundColor Yellow

