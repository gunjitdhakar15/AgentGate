# AgentGate one-command demo.
# Starts the firewall + live dashboard, feeds it a scripted agent session
# (allowed calls, dangerous calls, secret-laden calls), and lets you watch
# every decision in the browser.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1 -Port 9000
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1 -Duration 15   (auto-stop)

param(
    [int]$Port = 8700,
    [string]$Config = "configs\smoke.yaml",
    [int]$Duration = 0
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
$Root = (Resolve-Path ".").Path

if (-not (Test-Path ".\agentgate.exe")) {
    Write-Host "Building agentgate.exe..." -ForegroundColor Cyan
    go build -o agentgate.exe ./cmd/agentgate
}
if (-not (Test-Path ".\mock-tools.exe")) {
    Write-Host "Building mock-tools.exe..." -ForegroundColor Cyan
    go build -o mock-tools.exe ./cmd/mock-tools
}

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = (Join-Path $Root "agentgate.exe")
$psi.Arguments = "-config $Config -serve :$Port"
$psi.WorkingDirectory = $Root
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true

$gate = [System.Diagnostics.Process]::Start($psi)
Start-Sleep -Milliseconds 900

Write-Host ""
Write-Host "Open http://localhost:$Port in your browser" -ForegroundColor Green
Write-Host "Generating traffic in 3 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

$requests = @(
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"C:\\secrets\\keys.json","api_key":"sk-abcd1234efgh5678ijkl9012"}}}',
    '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"shell","arguments":{"cmd":"echo hello world"}}}',
    '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"shell","arguments":{"cmd":"rm -rf /"}}}',
    '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"C:\\evil.exe","content":"malware"}}}',
    '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"C:\\notes.txt","token":"bearer-abcdefghijklmnopqrstuvwxyz"}}}',
    '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"shell","arguments":{"cmd":"dir"}}}',
    '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"C:\\db\\config.yaml","password":"P@ssw0rd!"}}}',
    '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"shell","arguments":{"cmd":"format C:"}}}'
)

for ($i = 0; $i -lt $requests.Count; $i++) {
    $gate.StandardInput.WriteLine($requests[$i])
    $gate.StandardInput.Flush()
    Write-Host ("sent request #{0}: {1}" -f ($i + 1), ($requests[$i] -replace '\s+', ' ')) -ForegroundColor DarkGray
    Start-Sleep -Milliseconds 700
}

if ($Duration -gt 0) {
    Write-Host ""
    Write-Host ("Watching for {0} more seconds..." -f $Duration) -ForegroundColor Yellow
    Start-Sleep -Seconds $Duration
    if (-not $gate.HasExited) { $gate.Kill() }
    Write-Host "Demo finished." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Traffic done. Watch the dashboard, then press Enter to stop." -ForegroundColor Yellow
    $null = Read-Host
    if (-not $gate.HasExited) { $gate.Kill() }
    Write-Host "Stopped." -ForegroundColor Green
}