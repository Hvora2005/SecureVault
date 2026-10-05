@echo off
setlocal
cd /d "%~dp0backend"
if not exist ".venv\Scripts\python.exe" (py -3 -m venv .venv 2>nul || python -m venv .venv)
if not exist ".venv\Scripts\python.exe" (echo Python 3 was not found. Install Python 3.10 or newer.& pause& exit /b 1)
if not exist ".venv\installed.ok" (
  call .venv\Scripts\python.exe -m pip install --upgrade pip
  call .venv\Scripts\python.exe -m pip install -r requirements.txt
  if errorlevel 1 (echo Dependency installation failed. Check internet access for first setup.& pause& exit /b 1)
  echo ready>.venv\installed.ok
)
call .venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
