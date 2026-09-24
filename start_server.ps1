# start_server.ps1 — Run this to start the SwarmSentinel server with all env vars
# Usage: .\start_server.ps1

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvFile = Join-Path $ProjectRoot ".env"
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

# Load .env file
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+?)\s*=\s*(.*)\s*$') {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim()
            [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
            Write-Host "  Loaded: $key"
        }
    }
    Write-Host ""
}

Write-Host "Starting SwarmSentinel at http://127.0.0.1:8000 ..."
Write-Host "Press Ctrl+C to stop.`n"

& $VenvPython -m uvicorn main:app --host 127.0.0.1 --port 8000
