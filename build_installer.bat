@echo off
title ShieldX — Installer Builder
color 0B
echo.
echo  ================================================
echo   ShieldX Installer Builder
echo  ================================================
echo.
:: ── Step 1: NSIS ────────────────────────────────────────────
echo  [Step 1] Looking for NSIS...
set "NSIS="
if exist "C:\Program Files (x86)\NSIS\makensis.exe" set "NSIS=C:\Program Files (x86)\NSIS\makensis.exe"
if exist "C:\Program Files\NSIS\makensis.exe"       set "NSIS=C:\Program Files\NSIS\makensis.exe"
if not defined NSIS (
    echo  [ERROR] NSIS is NOT installed.
    echo  Install from: https://nsis.sourceforge.io/Download
    goto :end
)
echo  Found: %NSIS%
echo.
:: ── Step 2: EnVar plugin ────────────────────────────────────
echo  [Step 2] Checking EnVar plugin...
set "ENVAR_OK="
set "P1=C:\Program Files (x86)\NSIS\Plugins\x86-unicode\EnVar.dll"
set "P2=C:\Program Files\NSIS\Plugins\x86-unicode\EnVar.dll"
if exist "%P1%" set "ENVAR_OK=1"
if exist "%P2%" set "ENVAR_OK=1"
if not defined ENVAR_OK (
    echo  [ERROR] EnVar plugin missing.
    echo.
    echo  1. Download: https://nsis.sourceforge.io/EnVar_plug-in
    echo  2. Extract the zip
    echo  3. Copy EnVar.dll into:
    echo     C:\Program Files ^(x86^)\NSIS\Plugins\x86-unicode\
    goto :end
)
echo  EnVar plugin found.
echo.
:: ── Step 3: Assets ──────────────────────────────────────────
echo  [Step 3] Checking assets...
if not exist "assets\shieldx.ico" ( echo  [ERROR] Missing: assets\shieldx.ico & goto :end )
if not exist "assets\header.bmp"  ( echo  [ERROR] Missing: assets\header.bmp  & goto :end )
if not exist "assets\wizard.bmp"  ( echo  [ERROR] Missing: assets\wizard.bmp  & goto :end )
echo  Assets OK.
echo.
:: ── Step 4: NSI script ──────────────────────────────────────
echo  [Step 4] Checking ShieldX_Setup.nsi...
if not exist "ShieldX_Setup.nsi" (
    echo  [ERROR] ShieldX_Setup.nsi not found.
    echo  Run this .bat from your C:\ShieldX\ root folder.
    goto :end
)
echo  Found ShieldX_Setup.nsi.
echo.
:: ── Step 5: Write LICENSE.txt ────────────────────────────────
echo  [Step 5] Writing LICENSE.txt...
(
echo ShieldX License
echo Copyright ^(C^) 2026 Jahanzaib Ashraf Mir. All Rights Reserved.
echo.
echo ShieldX is publicly accessible for viewing and educational reference
echo purposes only. The source code, binaries, documentation, and related
echo materials ^(collectively, the "Software"^) remain the exclusive
echo intellectual property of Jahanzaib Ashraf Mir.
echo.
echo Permission is granted to access, clone, and review the Software for
echo personal, non-commercial, and educational purposes.
echo.
echo The following activities are strictly prohibited without prior written
echo permission from the copyright holder:
echo.
echo   - Commercial use of the Software
echo   - Redistribution of modified or unmodified copies
echo   - Sublicensing or reselling
echo   - Reverse engineering for competitive or commercial purposes
echo   - Incorporation into proprietary or commercial products
echo.
echo Contributions submitted via pull requests may be reviewed and
echo incorporated at the discretion of the copyright holder. By submitting
echo a contribution, you grant the copyright holder a perpetual,
echo royalty-free license to use, modify, and distribute that contribution
echo as part of the Software.
echo.
echo THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
echo EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF
echo MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND
echo NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
echo DAMAGES OR LIABILITY ARISING FROM THE USE OF THE SOFTWARE.
echo.
echo For commercial licensing, partnership, or distribution inquiries,
echo written authorization must be obtained directly from the copyright
echo holder.
) > LICENSE.txt
echo  LICENSE.txt written.
echo.
:: ── Step 6: Build ───────────────────────────────────────────
echo  [Step 6] Building ShieldX_Setup.exe...
echo  (this takes about 30 seconds)
echo.
"%NSIS%" ShieldX_Setup.nsi
set "RES=%errorlevel%"
echo.
if "%RES%"=="0" (
    echo  ================================================
    echo   SUCCESS!
    echo   ShieldX_Setup.exe is ready to distribute.
    echo  ================================================
) else (
    echo  [ERROR] NSIS failed - code %RES%
    echo  Check the errors printed above.
)
:end
echo.
echo  Press any key to close...
pause >nul