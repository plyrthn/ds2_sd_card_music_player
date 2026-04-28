@echo off
echo Starting build...
cd /d "%~dp0"
echo CWD: %CD%
echo Calling vcvars64...
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

set MH=vendor\minhook
set MHSRC=%MH%\src
set MHINC=%MH%\include
set SH=vendor\single_header

if not exist "%MHSRC%\hook.c" (
    echo MinHook submodule missing. Run: git submodule update --init --recursive
    exit /b 1
)

echo Compiling MinHook (once if missing)...
if not exist mh_hook.obj      cl /nologo /O2 /MD /I"%MHINC%" /c "%MHSRC%\hook.c"          /Fo:mh_hook.obj      || ( echo MH HOOK COMPILE FAILED && exit /b 1 )
if not exist mh_buffer.obj    cl /nologo /O2 /MD /I"%MHINC%" /c "%MHSRC%\buffer.c"        /Fo:mh_buffer.obj    || ( echo MH BUFFER COMPILE FAILED && exit /b 1 )
if not exist mh_trampoline.obj cl /nologo /O2 /MD /I"%MHINC%" /c "%MHSRC%\trampoline.c"   /Fo:mh_trampoline.obj || ( echo MH TRAMP COMPILE FAILED && exit /b 1 )
if not exist mh_hde64.obj     cl /nologo /O2 /MD /I"%MHINC%" /c "%MHSRC%\hde\hde64.c"     /Fo:mh_hde64.obj     || ( echo MH HDE COMPILE FAILED && exit /b 1 )

echo Compiling ds2_musicplayer.cpp...
cl /nologo /O2 /std:c++17 /EHsc /MD /I"%MHINC%" /I"%SH%" /c src\ds2_musicplayer.cpp /Fo:ds2_musicplayer.obj
if errorlevel 1 (
    echo COMPILE FAILED
    exit /b 1
)
echo Linking...
link /nologo /DLL /OUT:ds2_musicplayer.asi ds2_musicplayer.obj mh_hook.obj mh_buffer.obj mh_trampoline.obj mh_hde64.obj kernel32.lib user32.lib
if errorlevel 1 (
    echo LINK FAILED
    exit /b 1
)
echo.
echo Killing DS2.exe and crs-video.exe so the .asi isn't locked...
taskkill /F /IM DS2.exe         >nul 2>&1
taskkill /F /IM crs-video.exe   >nul 2>&1
taskkill /F /IM crs-handler.exe >nul 2>&1
:: brief wait for the OS to release file locks
ping -n 2 127.0.0.1 >nul

echo Copying to game root...
copy /Y ds2_musicplayer.asi "..\ds2_musicplayer.asi" || (
    echo COPY FAILED -- waiting another 2s and retrying...
    ping -n 3 127.0.0.1 >nul
    copy /Y ds2_musicplayer.asi "..\ds2_musicplayer.asi" || (
        echo === BUILD FAILED: cannot copy .asi (file locked) ===
        exit /b 1
    )
)
del ds2_musicplayer.asi >nul 2>&1
echo === BUILD SUCCESS ===
