@echo off
REM ===================================================================
REM  e01bde - Instalador e inicializador (Windows)
REM  Faz: detecta/instala Python -> instala dependencias ->
REM       roda a interface grafica OU gera o executavel .exe
REM  Basta dar DUPLO-CLIQUE neste arquivo.
REM ===================================================================
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title e01bde - Instalacao

echo ===================================================================
echo   e01bde - Analise de imagem E01 e recuperacao do BitLocker
echo ===================================================================
echo.

REM -------------------------------------------------------------------
REM  [1/3] Detectar o Python
REM -------------------------------------------------------------------
echo [1/3] Verificando o Python...
set "PYEXE="

REM Preferir o launcher "py -3" (mais confiavel), depois "python"
py -3 --version >nul 2>&1
if %errorlevel%==0 (
    set "PYEXE=py -3"
) else (
    python --version >nul 2>&1
    if %errorlevel%==0 set "PYEXE=python"
)

if defined PYEXE goto PY_OK

echo     Python nao encontrado. Tentando instalar automaticamente...
where winget >nul 2>&1
if %errorlevel%==0 (
    echo     Instalando via winget ^(pode pedir confirmacao^)...
    winget install -e --id Python.Python.3.12 --accept-source-agreements --accept-package-agreements
    echo.
    echo     ==================================================================
    echo     Python instalado. FECHE esta janela e execute o build.bat DE NOVO
    echo     ^(e necessario para o Windows reconhecer o Python no PATH^).
    echo     ==================================================================
    pause
    exit /b 0
) else (
    echo.
    echo     Nao foi possivel instalar automaticamente ^(winget ausente^).
    echo     Abrindo a pagina de download do Python...
    echo     IMPORTANTE: na instalacao, MARQUE "Add Python to PATH".
    start "" "https://www.python.org/downloads/"
    echo     Depois de instalar, execute este build.bat novamente.
    pause
    exit /b 1
)

:PY_OK
for /f "delims=" %%v in ('%PYEXE% --version 2^>^&1') do set "PYVER=%%v"
echo     OK: !PYVER!  ^(comando: %PYEXE%^)
echo.

REM -------------------------------------------------------------------
REM  [2/3] Instalar as dependencias
REM -------------------------------------------------------------------
echo [2/3] Instalando dependencias ^(libewf-python, cryptography^)...
%PYEXE% -m pip install --upgrade pip
%PYEXE% -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo     [!] Falha ao instalar dependencias. Verifique a conexao de rede.
    echo         Se persistir, tente:  %PYEXE% -m pip install --user -r requirements.txt
    pause
    exit /b 1
)
echo     OK: dependencias instaladas.
echo.

REM -------------------------------------------------------------------
REM  [3/3] Escolher o que fazer
REM -------------------------------------------------------------------
:MENU
echo [3/3] O que deseja fazer?
echo.
echo     [1] Abrir a INTERFACE GRAFICA agora
echo     [2] Gerar o EXECUTAVEL ^(dist\e01bde-gui.exe + dist\e01bde.exe^)
echo     [3] Rodar a validacao ^(teste do vetor real do hashcat^)
echo     [4] Sair
echo.
set /p "OPC=    Opcao (1-4): "

if "%OPC%"=="1" goto RUN_GUI
if "%OPC%"=="2" goto BUILD_EXE
if "%OPC%"=="3" goto RUN_TEST
if "%OPC%"=="4" exit /b 0
echo     Opcao invalida.
echo.
goto MENU

:RUN_GUI
echo.
echo     Abrindo a interface grafica...
%PYEXE% e01bde_gui.py
echo.
goto MENU

:BUILD_EXE
echo.
echo     Instalando PyInstaller e empacotando ^(pode demorar alguns minutos^)...
%PYEXE% -m pip install pyinstaller
%PYEXE% -m PyInstaller --noconfirm --onefile --windowed ^
    --name e01bde-gui ^
    --collect-submodules pyewf ^
    --collect-submodules cryptography ^
    e01bde_gui.py
if errorlevel 1 goto BUILD_ERR
%PYEXE% -m PyInstaller --noconfirm --onefile ^
    --name e01bde ^
    --collect-submodules pyewf ^
    --collect-submodules cryptography ^
    -p . ^
    e01bde\cli.py
if errorlevel 1 goto BUILD_ERR
echo.
echo     ==================================================================
echo     Concluido!  Executaveis em:
echo        dist\e01bde-gui.exe   ^(interface grafica - duplo-clique^)
echo        dist\e01bde.exe       ^(linha de comando^)
echo     ==================================================================
echo.
goto MENU

:BUILD_ERR
echo.
echo     [!] Falha ao gerar o executavel. Veja as mensagens acima.
echo.
goto MENU

:RUN_TEST
echo.
echo     Rodando validacao contra o vetor real do hashcat ^(~2s^)...
%PYEXE% tests\validate_real_vector.py
echo.
pause
goto MENU
