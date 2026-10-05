# SecureVault Installation Guide

## Requirements

- Windows 10/11, 64-bit.
- Python 3.10+; enable the Python launcher (`py`) or add Python to PATH.
- Node.js 18+ (includes npm).
- Internet for first dependency installation only. No keys, Docker, cloud service, or account is required.

## One-click setup

1. Copy the complete folder to the presentation laptop.
2. Install Python and Node.js if needed.
3. Double-click `start_project.bat` and allow first-run package installation.
4. Wait for the browser, then choose **Launch the demo workspace**.
5. Keep both minimized service windows open. Close them when finished.

The launcher creates an isolated backend virtual environment, installs dependencies, waits for API health, starts Vite, and opens the browser. After setup, use works offline. Both services bind to `127.0.0.1`.

## Manual setup

PowerShell window one:

```powershell
cd backend
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

PowerShell window two:

```powershell
cd frontend
npm install
npm run dev -- --host 127.0.0.1
```

Open `http://127.0.0.1:5173`. API documentation: `http://127.0.0.1:8000/docs`.

## Local data

`backend/data/` is created at first startup. It stores SQLite records, vault bytes, RSA keys, and backup archives. Removing it resets local accounts and stored data. Avoid using personal or confidential files in the demonstration.

## Troubleshooting

- **Python not found:** reinstall Python with the launcher enabled or put `python.exe` on PATH.
- **Node/npm not found:** install Node.js LTS and reopen the batch file.
- **Port 8000/5173 occupied:** close an older SecureVault service window, then retry.
- **Package download fails:** check initial internet access and retry. After packages are installed, runtime is offline.
- **API unavailable:** ensure backend window is still open; `http://127.0.0.1:8000/api/health` should report `status: ok`.
- **Demo action fails:** wait for backend startup to finish and refresh the browser.

Python versions are pinned in `backend/requirements.txt`; JavaScript dependencies are declared in `frontend/package.json`.

## Run verification checks

```powershell
cd backend
.venv\Scripts\python.exe -m unittest discover -s tests -v
cd ..\frontend
npm run build
```
