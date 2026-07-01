@echo off
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.11 or newer, then run this file again.
  pause
  exit /b 1
)
python server.py --reset
if errorlevel 1 (
  echo Reset launch failed.
  pause
  exit /b 1
)
pause
