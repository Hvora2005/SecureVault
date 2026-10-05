@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul || (echo Install Node.js 18 or newer first.& pause& exit /b 1)
if not exist "backend\.venv\Scripts\python.exe" (py -3 -m venv "backend\.venv" 2>nul || python -m venv "backend\.venv")
if not exist "backend\.venv\Scripts\python.exe" (echo Install Python 3.10 or newer first.& pause& exit /b 1)
if not exist "backend\.venv\installed.ok" (
 call "backend\.venv\Scripts\python.exe" -m pip install --upgrade pip
 call "backend\.venv\Scripts\python.exe" -m pip install -r backend\requirements.txt
 if errorlevel 1 (echo Backend dependency setup failed. Internet needed only for initial setup.& pause& exit /b 1)
 echo ready>"backend\.venv\installed.ok"
)
if not exist "frontend\node_modules" (pushd frontend& call npm install& if errorlevel 1 (popd& echo Frontend dependency setup failed.& pause& exit /b 1)& popd)
start "SecureVault backend" /min "%~dp0start_backend.bat"
echo Starting SecureVault backend...
set /a attempts=0
:wait_backend
curl.exe -fsS http://127.0.0.1:8000/api/health >nul 2>nul
if not errorlevel 1 goto backend_ready
set /a attempts+=1
if %attempts% geq 45 (echo Backend did not become ready. See its console.& pause& exit /b 1)
timeout /t 1 /nobreak >nul
goto wait_backend
:backend_ready
echo Backend ready. Starting frontend...
start "SecureVault frontend" /min "%~dp0start_frontend.bat"
timeout /t 3 /nobreak >nul
start "" http://127.0.0.1:5173
echo SecureVault is running. Keep both console windows open while presenting.
