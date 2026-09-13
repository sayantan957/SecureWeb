@echo off
title Secure File Upload & Malware Detection System
echo ============================================================
echo Starting Secure File Upload & Malware Detection System...
echo ============================================================
echo.

:: Check if virtual environment exists
if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found!
    echo Please run: python -m venv .venv ^&^& .venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)

:: Launch the default web browser after a brief delay
start "" http://127.0.0.1:5000

:: Start the Flask application server
echo Server is running at: http://127.0.0.1:5000
echo Press CTRL+C in this window to stop the server.
echo.
.venv\Scripts\python.exe app.py
pause
