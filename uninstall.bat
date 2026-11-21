@echo off
setlocal
title Re:Rem Plus - English Patch Uninstaller
echo This will remove the English patch files (REMPLUS_tl.exe, RioShiinaTL.dll, p\, d\)
echo Your original REMPLUS.exe, .WAR archives, and savedata\ will NOT be touched.
echo.
set /p CONFIRM=Continue uninstall? (Y/N): 
if /I not "%CONFIRM%"=="Y" exit /b 0

if exist "%~dp0REMPLUS_tl.exe" del /F /Q "%~dp0REMPLUS_tl.exe"
if exist "%~dp0RioShiinaTL.dll" del /F /Q "%~dp0RioShiinaTL.dll"
if exist "%~dp0tl_guard.log" del /F /Q "%~dp0tl_guard.log"
if exist "%~dp0_patch_extract.flag" del /F /Q "%~dp0_patch_extract.flag"
if exist "%~dp0p" rmdir /S /Q "%~dp0p"
if exist "%~dp0d" rmdir /S /Q "%~dp0d"
if exist "%~dp0_patch_tmp" rmdir /S /Q "%~dp0_patch_tmp"

echo.
echo Uninstall complete. Original game files remain intact.
pause
