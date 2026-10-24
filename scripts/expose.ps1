# scripts/expose.ps1 — start CodeGuard (uvicorn) + ngrok and print the public URL.
#
#   powershell -ExecutionPolicy Bypass -File scripts\expose.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\expose.ps1 -Port 8000
#
# Prereqs: `ngrok config add-authtoken <TOKEN>` (one-time), dependencies installed.
# Keep this window open while the URL is in use. Ctrl+C stops both processes.

param([int]$Port = 8000)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)   # repo root

function Find-Ngrok {
    $cmd = Get-Command ngrok -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $cand = Join-Path $env:LOCALAPPDATA "ngrok\ngrok.exe"
    if (Test-Path $cand) { return $cand }
    return $null
}

$ngrok = Find-Ngrok
if (-not $ngrok) {
    Write-Host "[x] ngrok not found. Install it, or set PATH, then retry." -ForegroundColor Red
    exit 1
}

Write-Host "[1/3] Starting uvicorn on port $Port ..." -ForegroundColor Cyan
$py = (Get-Command python).Source
$uv = Start-Process -FilePath $py `
    -ArgumentList @("-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "$Port", "--workers", "1") `
    -PassThru -NoNewWindow

$healthy = $false
for ($i = 0; $i -lt 80; $i++) {
    try { Invoke-RestMethod "http://127.0.0.1:$Port/health" -TimeoutSec 2 | Out-Null; $healthy = $true; break } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $healthy) {
    Write-Host "[x] uvicorn did not become healthy on port $Port." -ForegroundColor Red
    Stop-Process -Id $uv.Id -Force -ErrorAction SilentlyContinue
    exit 1
}
Write-Host "      /health OK (models loaded)." -ForegroundColor Green

Write-Host "[2/3] Starting ngrok tunnel ..." -ForegroundColor Cyan
$ng = Start-Process -FilePath $ngrok -ArgumentList @("http", "$Port") -PassThru -NoNewWindow

$public = $null
for ($i = 0; $i -lt 60; $i++) {
    try {
        $t = Invoke-RestMethod "http://127.0.0.1:4040/api/tunnels" -TimeoutSec 2
        $public = ($t.tunnels | Where-Object { $_.public_url -like "https*" } | Select-Object -First 1).public_url
        if ($public) { break }
    } catch { }
    Start-Sleep -Milliseconds 500
}

if (-not $public) {
    Write-Host "[x] No public URL from ngrok." -ForegroundColor Red
    Write-Host "    Most common cause: auth token not set. Run:" -ForegroundColor Yellow
    Write-Host "      & `"$ngrok`" config add-authtoken <YOUR_AUTHTOKEN>" -ForegroundColor Yellow
    Stop-Process -Id $ng.Id, $uv.Id -Force -ErrorAction SilentlyContinue
    exit 1
}

$endpoint = "$public/check"
Write-Host ""
Write-Host "[3/3] PUBLIC ENDPOINT: $endpoint" -ForegroundColor Green
Write-Host ""
Write-Host "Verify from the public URL (not localhost):" -ForegroundColor Cyan
Write-Host "  curl -X POST $endpoint -H `"Content-Type: application/json`" -H `"ngrok-skip-browser-warning: true`" -d '{`"code`":`"rm -rf /`"}'"
Write-Host ""
Write-Host "Callers must send:  Content-Type: application/json  +  ngrok-skip-browser-warning: true"
Write-Host "Do NOT restart ngrok (the URL changes). Ctrl+C here stops both."
Write-Host ""

try {
    Wait-Process -Id $uv.Id
} finally {
    Write-Host "Stopping ..." -ForegroundColor Yellow
    Stop-Process -Id $ng.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $uv.Id -Force -ErrorAction SilentlyContinue
}
