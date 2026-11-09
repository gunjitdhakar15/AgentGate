@echo off
cd /d "%~dp0"
echo Starting AgentGate v2 Decision Studio Cockpit...
go run . demo
pause
