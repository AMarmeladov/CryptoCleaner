@echo off
setlocal
cd /d "%~dp0"

where python.exe >nul 2>&1
if errorlevel 1 (
    echo Python не найден в PATH.
    pause
    exit /b 1
)

python -c "import PyInstaller" >nul 2>&1
if errorlevel 1 (
    echo Установка PyInstaller...
    python -m pip install --upgrade pyinstaller
    if errorlevel 1 (
        echo Не удалось установить PyInstaller.
        pause
        exit /b 1
    )
)

python -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name CryptoCleaner ^
    --icon "%~dp0cryptocleaner\assets\cryptocleaner.ico" ^
    --add-data "%~dp0cryptocleaner\assets;cryptocleaner\assets" ^
    "%~dp0CryptoCleaner.py"

if errorlevel 1 (
    echo.
    echo Сборка не удалась. Смотрите сообщения выше.
    pause
    exit /b 1
)

echo.
echo Готово: dist\CryptoCleaner.exe
pause
