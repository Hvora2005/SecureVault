@echo off
setlocal
cd /d "%~dp0frontend"
where node >nul 2>nul || (echo Install Node.js 18 or newer first.& pause& exit /b 1)
if not exist node_modules (call npm install || (echo Frontend dependencies could not be installed.& pause& exit /b 1))
call npm run dev -- --host 127.0.0.1
