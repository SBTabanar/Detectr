@echo off
echo Building Detectr executable...
echo.
python -m PyInstaller --noconfirm --onefile --windowed --name "Detectr" --collect-all customtkinter nids.py
echo.
if %errorlevel% equ 0 (
    echo Build successful! Executable is located in the 'dist' folder.
) else (
    echo Build failed. Please check the errors above.
)
pause
