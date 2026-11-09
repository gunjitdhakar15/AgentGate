Set-Location $PSScriptRoot
Write-Host "Starting AgentGate v2 Decision Studio Cockpit on http://localhost:8700/dashboard..." -ForegroundColor Cyan
go run . demo
