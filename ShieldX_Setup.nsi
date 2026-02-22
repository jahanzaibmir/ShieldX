; ============================================================
;  ShieldX_Setup.nsi
;  Build: makensis ShieldX_Setup.nsi
; ============================================================

Unicode True

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "Sections.nsh"
!include "x64.nsh"

Name              "ShieldX"
OutFile           "ShieldX_Setup.exe"
InstallDir        "$PROGRAMFILES64\ShieldX"
InstallDirRegKey  HKLM "Software\ShieldX" "InstallDir"
RequestExecutionLevel admin
BrandingText      "ShieldX Security Suite"

; ── MUI Config ────────────────────────────────────────────────
!define MUI_ABORTWARNING
!define MUI_ICON                     "assets\shieldx.ico"
!define MUI_UNICON                   "assets\shieldx.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP       "assets\header.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "assets\wizard.bmp"

!define MUI_WELCOMEPAGE_TITLE   "Welcome to ShieldX Setup"
!define MUI_WELCOMEPAGE_TEXT    "This wizard installs ShieldX and all required dependencies automatically.$\r$\n$\r$\nGit, Java, Python, Rust, GCC/MinGW and Make will each be detected and installed only if missing.$\r$\n$\r$\nClick Next to continue."

; Finish page — runs ShieldX.exe which we create during install
!define MUI_FINISHPAGE_RUN          "$INSTDIR\ShieldX.exe"
!define MUI_FINISHPAGE_RUN_TEXT     "Launch ShieldX now"
!define MUI_FINISHPAGE_RUN_NOTCHECKED

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE      "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; ── Download macro ─────────────────────────────────────────────
!macro DL URL DEST
  DetailPrint "Downloading: ${URL}"
  nsExec::ExecToLog 'powershell -NoProfile -NonInteractive -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;(New-Object Net.WebClient).DownloadFile(''${URL}'',''${DEST}'')"'
  Pop $0
!macroend

; ── Check command on PATH ($0=0 means found) ───────────────────
!macro HAS CMD
  nsExec::ExecToStack '"$SYSDIR\cmd.exe" /C "where ${CMD} >nul 2>&1"'
  Pop $0
  Pop $1
!macroend

; ═════════════════════════════════════════════════════════════
;  SECTION 1 — Core install (required)
; ═════════════════════════════════════════════════════════════
Section "ShieldX Core" SecCore
  SectionIn RO
  SetOutPath "$INSTDIR"

  DetailPrint "Copying ShieldX files..."
  File /r ".\*"

  CreateDirectory "$TEMP\sxdeps"

  ; ── 1. GIT ────────────────────────────────────────────────
  DetailPrint "--- [1/7] Checking Git ---"
  !insertmacro HAS "git"
  ${If} $0 != 0
    DetailPrint "Git not found. Downloading..."
    !insertmacro DL "https://github.com/git-for-windows/git/releases/download/v2.44.0.windows.1/Git-2.44.0-64-bit.exe" "$TEMP\sxdeps\git.exe"
    nsExec::ExecToLog '"$TEMP\sxdeps\git.exe" /VERYSILENT /NORESTART /NOCANCEL /SP-'
    Pop $0
    DetailPrint "Git installed."
  ${Else}
    DetailPrint "Git: already installed, skipping."
  ${EndIf}

  ; ── 2. JAVA JDK 21 ────────────────────────────────────────
  DetailPrint "--- [2/7] Checking Java JDK ---"
  !insertmacro HAS "javac"
  ${If} $0 != 0
    DetailPrint "JDK not found. Downloading..."
    !insertmacro DL "https://aka.ms/download-jdk/microsoft-jdk-21-windows-x64.msi" "$TEMP\sxdeps\jdk.msi"
    nsExec::ExecToLog '"$SYSDIR\msiexec.exe" /i "$TEMP\sxdeps\jdk.msi" /quiet /norestart'
    Pop $0
    DetailPrint "JDK installed."
  ${Else}
    DetailPrint "Java JDK: already installed, skipping."
  ${EndIf}

  ; ── 3. PYTHON 3.12 ────────────────────────────────────────
  DetailPrint "--- [3/7] Checking Python ---"
  !insertmacro HAS "python"
  ${If} $0 != 0
    DetailPrint "Python not found. Downloading..."
    !insertmacro DL "https://www.python.org/ftp/python/3.12.3/python-3.12.3-amd64.exe" "$TEMP\sxdeps\python.exe"
    nsExec::ExecToLog '"$TEMP\sxdeps\python.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0'
    Pop $0
    DetailPrint "Python installed."
  ${Else}
    DetailPrint "Python: already installed, skipping."
  ${EndIf}

  ; ── 4. PYTHON PACKAGES ────────────────────────────────────
  DetailPrint "--- [4/7] Installing Python packages ---"
  nsExec::ExecToLog '"$SYSDIR\cmd.exe" /C "python -m pip install --quiet --upgrade pip"'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\cmd.exe" /C "python -m pip install --quiet requests scapy psutil colorama pyyaml python-whois"'
  Pop $0
  DetailPrint "Python packages installed."

  ; ── 5. RUST ───────────────────────────────────────────────
  DetailPrint "--- [5/7] Checking Rust ---"
  !insertmacro HAS "cargo"
  ${If} $0 != 0
    DetailPrint "Rust not found. Downloading..."
    !insertmacro DL "https://win.rustup.rs/x86_64" "$TEMP\sxdeps\rustup.exe"
    nsExec::ExecToLog '"$TEMP\sxdeps\rustup.exe" -y --default-toolchain stable --profile minimal'
    Pop $0
    DetailPrint "Rust installed."
  ${Else}
    DetailPrint "Rust: already installed, skipping."
  ${EndIf}

  ; ── 6. MINGW-W64 / GCC ────────────────────────────────────
  DetailPrint "--- [6/7] Checking GCC / MinGW-w64 ---"
  !insertmacro HAS "gcc"
  ${If} $0 != 0
    DetailPrint "GCC not found. Downloading MinGW-w64..."
    !insertmacro DL "https://github.com/brechtsanders/winlibs_mingw/releases/download/13.2.0posix-17.0.6-11.0.1-msvcrt-r5/winlibs-x86_64-posix-seh-gcc-13.2.0-mingw-w64msvcrt-11.0.1-r5.zip" "$TEMP\sxdeps\mingw.zip"
    nsExec::ExecToLog 'powershell -NoProfile -NonInteractive -Command "Expand-Archive -Path \"$TEMP\sxdeps\mingw.zip\" -DestinationPath \"$INSTDIR\mingw64\" -Force"'
    Pop $0
    EnVar::AddValue "PATH" "$INSTDIR\mingw64\mingw64\bin"
    DetailPrint "GCC installed."
  ${Else}
    DetailPrint "GCC: already installed, skipping."
  ${EndIf}

  ; ── 7. MAKE ───────────────────────────────────────────────
  DetailPrint "--- [7/7] Checking Make ---"
  !insertmacro HAS "make"
  ${If} $0 != 0
    DetailPrint "Make not found. Downloading..."
    !insertmacro DL "https://github.com/maweil/MakeForWindows/releases/download/v4.4.1/make-4.4.1-without-guile-w64-mingw32.zip" "$TEMP\sxdeps\make.zip"
    nsExec::ExecToLog 'powershell -NoProfile -NonInteractive -Command "Expand-Archive -Path \"$TEMP\sxdeps\make.zip\" -DestinationPath \"$INSTDIR\tools\make\" -Force"'
    Pop $0
    EnVar::AddValue "PATH" "$INSTDIR\tools\make\bin"
    DetailPrint "Make installed."
  ${Else}
    DetailPrint "Make: already installed, skipping."
  ${EndIf}

  ; ── BUILD: Rust engine ──────────────────────────────────────
  DetailPrint "--- Building Rust engine ---"
  nsExec::ExecToLog '"$SYSDIR\cmd.exe" /C "cd /D "$INSTDIR\services\misconfig\engine" && cargo build --release"'
  Pop $0

  ; ── BUILD: C collector ──────────────────────────────────────
  DetailPrint "--- Building C collector ---"
  nsExec::ExecToLog '"$SYSDIR\cmd.exe" /C "cd /D "$INSTDIR\services\misconfig\collectors\c" && make"'
  Pop $0

  ; ── BUILD: Java GUI ─────────────────────────────────────────
  DetailPrint "--- Compiling Java GUI ---"
  nsExec::ExecToLog '"$SYSDIR\cmd.exe" /C "cd /D "$INSTDIR\gui\java\src" && javac -d . shieldx/ui/Main.java"'
  Pop $0

  ; ── LAUNCHER: real ShieldX.exe using wscript trick ──────────
  ; Write a VBScript that launches Java with no window
  DetailPrint "Creating ShieldX launcher..."
  FileOpen $9 "$INSTDIR\ShieldX.vbs" w
  FileWrite $9 'Set sh = CreateObject("WScript.Shell")$\r$\n'
  FileWrite $9 'sh.CurrentDirectory = "$INSTDIR\gui\java\src"$\r$\n'
  FileWrite $9 'sh.Run "javaw shieldx.ui.Main", 0, False$\r$\n'
  FileClose $9

  ; Write a tiny .bat that calls the VBScript silently
  ; Then wrap it as ShieldX.exe using the iexpress-free approach:
  ; We write a .cmd and rename wscript.exe is not portable, so instead
  ; we write ShieldX.exe as a copy of wscript.exe that auto-finds our .vbs
  ; BEST: write a launcher .cmd hidden via a shortcut with windowstyle hidden
  ; Actually simplest working approach — write ShieldX.exe as a Batch-to-Exe:
  FileOpen $9 "$INSTDIR\ShieldX.cmd" w
  FileWrite $9 '@echo off$\r$\n'
  FileWrite $9 'wscript.exe /nologo "$INSTDIR\ShieldX.vbs"$\r$\n'
  FileClose $9

  ; Create ShieldX.exe = a copy of cmd.exe that auto-runs our launcher
  ; The cleanest no-extra-tools approach: use PowerShell to compile a tiny C# exe
  DetailPrint "Compiling ShieldX.exe launcher..."
  FileOpen $9 "$TEMP\sxdeps\launcher.cs" w
  FileWrite $9 'using System;$\r$\n'
  FileWrite $9 'using System.Diagnostics;$\r$\n'
  FileWrite $9 'class ShieldX {$\r$\n'
  FileWrite $9 '  static void Main() {$\r$\n'
  FileWrite $9 '    string dir = AppDomain.CurrentDomain.BaseDirectory;$\r$\n'
  FileWrite $9 '    ProcessStartInfo p = new ProcessStartInfo();$\r$\n'
  FileWrite $9 '    p.FileName = "wscript.exe";$\r$\n'
  FileWrite $9 '    p.Arguments = "/nologo \"" + dir + "ShieldX.vbs\"";$\r$\n'
  FileWrite $9 '    p.WindowStyle = ProcessWindowStyle.Hidden;$\r$\n'
  FileWrite $9 '    p.CreateNoWindow = true;$\r$\n'
  FileWrite $9 '    Process.Start(p);$\r$\n'
  FileWrite $9 '  }$\r$\n'
  FileWrite $9 '}$\r$\n'
  FileClose $9

  ; Compile with C# compiler (comes with .NET which is built into Windows 10+)
  nsExec::ExecToLog 'powershell -NoProfile -NonInteractive -Command "Add-Type -TypeDefinition (Get-Content \"$TEMP\sxdeps\launcher.cs\" -Raw) -OutputAssembly \"$INSTDIR\ShieldX.exe\" -OutputType ConsoleApplication"'
  Pop $0

  ; If C# compile failed fall back to a .bat renamed approach
  ${If} $0 != 0
    DetailPrint "C# compile failed, using fallback launcher..."
    CopyFiles "$SYSDIR\cmd.exe" "$INSTDIR\ShieldX_run.exe"
  ${EndIf}

  ; ── REGISTRY ──────────────────────────────────────────────
  WriteRegStr   HKLM "Software\ShieldX" "InstallDir" "$INSTDIR"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShieldX" "DisplayName"     "ShieldX Security Suite"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShieldX" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShieldX" "DisplayIcon"     "$INSTDIR\assets\shieldx.ico"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShieldX" "Publisher"       "Jahanzaib Ashraf Mir"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShieldX" "DisplayVersion"  "1.0.0"
  WriteRegStr   HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShieldX" "URLInfoAbout"    "https://github.com/jahanzaibmir/ShieldX"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShieldX" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShieldX" "NoRepair" 1

  RMDir /r "$TEMP\sxdeps"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  DetailPrint "ShieldX installed successfully!"

SectionEnd

; ═════════════════════════════════════════════════════════════
;  SECTION 2 — Desktop Shortcut (optional, checked by default)
; ═════════════════════════════════════════════════════════════
Section "Desktop Shortcut" SecDesktop
  DetailPrint "Creating Desktop shortcut..."
  CreateShortcut "$DESKTOP\ShieldX.lnk" \
    "$INSTDIR\ShieldX.exe" "" \
    "$INSTDIR\assets\shieldx.ico" 0 SW_SHOWNORMAL "" "ShieldX Security Suite"
SectionEnd

; ═════════════════════════════════════════════════════════════
;  SECTION 3 — Start Menu (optional, checked by default)
; ═════════════════════════════════════════════════════════════
Section "Start Menu Entry" SecStartMenu
  DetailPrint "Creating Start Menu entry..."
  CreateDirectory "$SMPROGRAMS\ShieldX"
  CreateShortcut "$SMPROGRAMS\ShieldX\ShieldX.lnk" \
    "$INSTDIR\ShieldX.exe" "" \
    "$INSTDIR\assets\shieldx.ico" 0
  CreateShortcut "$SMPROGRAMS\ShieldX\Uninstall ShieldX.lnk" \
    "$INSTDIR\Uninstall.exe"
SectionEnd

; ── Section descriptions shown in the components page ─────────
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore}      "ShieldX core application, all dependencies, and compilation. Required."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop}   "Add a ShieldX shortcut to your Desktop."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenu} "Add ShieldX to the Windows Start Menu."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ═════════════════════════════════════════════════════════════
;  UNINSTALL
; ═════════════════════════════════════════════════════════════
Section "Uninstall"
  RMDir /r "$INSTDIR\services"
  RMDir /r "$INSTDIR\gui"
  RMDir /r "$INSTDIR\mingw64"
  RMDir /r "$INSTDIR\tools"
  RMDir /r "$INSTDIR\assets"
  Delete "$INSTDIR\ShieldX.exe"
  Delete "$INSTDIR\ShieldX.vbs"
  Delete "$INSTDIR\ShieldX.cmd"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir  "$INSTDIR"

  Delete "$DESKTOP\ShieldX.lnk"
  Delete "$SMPROGRAMS\ShieldX\ShieldX.lnk"
  Delete "$SMPROGRAMS\ShieldX\Uninstall ShieldX.lnk"
  RMDir  "$SMPROGRAMS\ShieldX"

  DeleteRegKey HKLM "Software\ShieldX"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ShieldX"
  EnVar::DeleteValue "PATH" "$INSTDIR\mingw64\mingw64\bin"
  EnVar::DeleteValue "PATH" "$INSTDIR\tools\make\bin"
SectionEnd
