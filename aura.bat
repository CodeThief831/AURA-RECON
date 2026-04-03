@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "PYTHON_BIN="

:: Check if Python is installed
for %%X in (python.exe) do (set "PYTHON_BIN=%%~dp$PATH:Xpython.exe")
if not defined PYTHON_BIN (
    echo [!] Python is not installed or not in PATH. Please install Python 3.9+. 1>&2
    exit /b 1
)
set "PYTHON_BIN=python"

:: Automatically install requirements if requests module is missing
%PYTHON_BIN% -c "import requests" 2>nul || (
    echo [*] First time setup: Installing required Python packages...
    %PYTHON_BIN% -m pip install -r "%SCRIPT_DIR%requirements.txt"
)

:: Execute the orchestrator
%PYTHON_BIN% "%SCRIPT_DIR%bounty_bot.py" %*
