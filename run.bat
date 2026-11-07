@echo off
setlocal
cd /d "%~dp0"

where pythonw.exe >nul 2>&1
if not errorlevel 1 (
    start "" pythonw.exe "%~dp0CryptoCleaner.py" %*
    exit /b 0
)

where python.exe >nul 2>&1
if not errorlevel 1 (
    start "" python.exe "%~dp0CryptoCleaner.py" %*
    exit /b 0
)

echo.
echo Python не найден в PATH.
echo Установите Python 3.8+ с сайта python.org (при установке включите Add to PATH).
echo.
pause
exit /b 1
