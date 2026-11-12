@echo off
REM ============================================================
REM  Gera um executavel unico (e01bde-gui.exe) para Windows.
REM  Requer Python 3.10+ e os pacotes de requirements.txt.
REM ============================================================
setlocal

echo [1/3] Instalando dependencias...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller
if errorlevel 1 goto erro

echo [2/3] Empacotando GUI com PyInstaller...
pyinstaller --noconfirm --onefile --windowed ^
    --name e01bde-gui ^
    --collect-submodules pyewf ^
    --collect-submodules cryptography ^
    e01bde_gui.py
if errorlevel 1 goto erro

echo [3/3] Empacotando CLI...
pyinstaller --noconfirm --onefile ^
    --name e01bde ^
    --collect-submodules pyewf ^
    --collect-submodules cryptography ^
    -p . ^
    e01bde\cli.py
if errorlevel 1 goto erro

echo.
echo Concluido. Binarios em:  dist\e01bde-gui.exe  e  dist\e01bde.exe
goto fim

:erro
echo.
echo FALHA no build. Verifique as mensagens acima.
exit /b 1

:fim
endlocal
