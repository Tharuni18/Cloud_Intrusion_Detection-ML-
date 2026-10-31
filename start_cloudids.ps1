$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    Write-Host "Creating the Python environment..."
    py -3 -m venv (Join-Path $PSScriptRoot ".venv")
    if ($LASTEXITCODE -ne 0) {
        throw "Python 3 was not found. Install Python 3, then run this script again."
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot "results-live\model.joblib"))) {
    throw "The trained model is missing: results-live\model.joblib"
}

Write-Host "Checking/installing Python packages..."
& $python -m pip install -r (Join-Path $PSScriptRoot "requirements-runtime.txt")
if ($LASTEXITCODE -ne 0) {
    throw "Package installation failed. Check your internet connection and try again."
}

$env:CLOUDIDS_API_TOKEN = (& $python -c "import secrets; print(secrets.token_urlsafe(32))").Trim()
Write-Host ""
Write-Host "CloudIDS token (paste into the dashboard):" -ForegroundColor Yellow
Write-Host $env:CLOUDIDS_API_TOKEN -ForegroundColor Yellow
Write-Host ""
Write-Host "Starting CloudIDS at http://127.0.0.1:8766. Keep this window open; press Ctrl+C to stop."
Start-Job -ScriptBlock { Start-Sleep -Seconds 2; Start-Process "http://127.0.0.1:8766" } | Out-Null
& $python (Join-Path $PSScriptRoot "serve_realtime.py") `
    --model (Join-Path $PSScriptRoot "results-live\model.joblib") `
    --db (Join-Path $PSScriptRoot "data\cloudids-events.sqlite3")
