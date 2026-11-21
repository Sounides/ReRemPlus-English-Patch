@echo off
setlocal
if "%DETOURS_DIR%"=="" (
    echo Please set DETOURS_DIR to the path containing Microsoft Detours source files ^(detours.cpp, disasm.cpp, etc.^).
    echo Example: set DETOURS_DIR=C:\src\Detours\src
    exit /b 1
)

call "%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%TEMP%\vsdir.txt"
set /p VSDIR=<"%TEMP%\vsdir.txt"
del "%TEMP%\vsdir.txt" 2>nul
if "%VSDIR%"=="" (
    echo Could not find Visual Studio / Build Tools with x86 C++ workload.
    exit /b 1
)
call "%VSDIR%\VC\Auxiliary\Build\vcvars32.bat"
if errorlevel 1 exit /b 1

if not exist build mkdir build

cl /nologo /O2 /MT /W3 /EHsc /DDETOURS_X86 /D_CRT_SECURE_NO_WARNINGS ^
   /I"%DETOURS_DIR%" /Fo"build\\" /LD ^
   RioShiinaTL.cpp ^
   "%DETOURS_DIR%\detours.cpp" ^
   "%DETOURS_DIR%\disasm.cpp" ^
   "%DETOURS_DIR%\modules.cpp" ^
   "%DETOURS_DIR%\image.cpp" ^
   "%DETOURS_DIR%\creatwth.cpp" ^
   /Fe"build\RioShiinaTL.dll" ^
   /link /DEF:RioShiinaTL.def user32.lib gdi32.lib advapi32.lib kernel32.lib
if errorlevel 1 exit /b 1

copy /Y "build\RioShiinaTL.dll" "..\patch\RioShiinaTL.dll"
echo Built and updated ..\patch\RioShiinaTL.dll successfully!
