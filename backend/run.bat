@echo off
title Threat Hunting Workbench
cd /d "%~dp0"

echo ===================================================
echo   Starting Threat Hunting Workbench (Local Server)
echo ===================================================
echo.

if not exist "venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found in venv!
    pause
    exit /b 1
)

echo Opening Workbench at http://localhost:8000 ...
start http://localhost:8000

echo Starting backend server on http://127.0.0.1:8000 ...
venv\Scripts\python.exe -m app.main
pause
