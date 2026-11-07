@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul

where python.exe >nul 2>&1
if errorlevel 1 (
    echo Python не найден в PATH.
    pause
    exit /b 1
)

python "%~dp0CryptoCleaner.py" %*
set "CODE=%ERRORLEVEL%"
echo.
echo Код завершения: %CODE%
pause
exit /b %CODE%
