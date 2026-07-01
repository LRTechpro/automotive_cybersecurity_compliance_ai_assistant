@echo off
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.11 or newer, then run this file again.
  pause
  exit /b 1
)

if not exist "AutoCyber_Traceability_Workbench\server.py" (
  python assemble_v2_release.py
  if errorlevel 1 (
    echo Source package reconstruction failed.
    pause
    exit /b 1
  )
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath 'AutoCyber_Traceability_Workbench_v2.0_source.zip' -DestinationPath '.' -Force"
  if errorlevel 1 (
    echo Source package extraction failed.
    pause
    exit /b 1
  )
)

cd /d "%~dp0AutoCyber_Traceability_Workbench"
python server.py --reset
pause
