@echo off

rem Command-line build using CL and LINK from MSVC setup
rem Set %VCTOOLS% to point to the MSVC tools directory

setlocal

set OUTDIR=%CD%
set RESDIR=%CD%\res
set TMP=%CD%\tmp

mkdir %TMP% > NUL 2>&1

cd ..

set VCTOOLS=C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.11.25503
set WINSDK=C:\Program Files (x86)\Windows Kits\10
set WINSDKVER=10.0.15063.0
set PATH=%PATH%;%WINSDK%\bin\x86

set CL=/nologo /O2 /EHsc /fp:precise /Gd /GL /GS- /Zi /MD /W1 /TC /Fo%TMP%\
set LINK=/DYNAMICBASE "libz.lib"

set MAKE_KEY_SOURCE=make_key.c keyflate.c libb64\cencode.c
set MAKE_KEY_OUT=make_key.exe

set PKG_DEC_SOURCE=pkg_dec.c keyflate.c pkg.c sfo.c platform.c pkgdb.c libb64\cdecode.c aes\aes.c
set PKG_DEC_OUT=pkg_dec.exe

set INCLUDE=%VCTOOLS%\include;%WINSDK%\Include\%WINSDKVER%\ucrt;%WINSDK%\Include\%WINSDKVER%\um;%WINSDK%\Include\%WINSDKVER%\shared;%CD%\platform\include;%CD%\libb64

rc /nologo %RESDIR%\make_key.rc
rc /nologo %RESDIR%\pkg_dec.rc

mkdir %OUTDIR%\x86 > NUL 2>&1
mkdir %OUTDIR%\x64 > NUL 2>&1

rem x86 build
echo Building x86 version
setlocal

	set PATH=%PATH%;%VCTOOLS%\bin\HostX86\x86;
	set LIB=%VCTOOLS%\lib\x86;%WINSDK%\Lib\%WINSDKVER%\ucrt\x86;%WINSDK%\Lib\%WINSDKVER%\um\x86;%CD%\platform\lib\x86
	
	cl %MAKE_KEY_SOURCE% /link /OUT:%OUTDIR%\x86\%MAKE_KEY_OUT% /MACHINE:X86 %RESDIR%\make_key.res
	cl %PKG_DEC_SOURCE% /link /OUT:%OUTDIR%\x86\%PKG_DEC_OUT% /MACHINE:X86 %RESDIR%\pkg_dec.res
	
endlocal

rem x64 build
echo Building x64 version
setlocal

	set PATH=%PATH%;%VCTOOLS%\bin\HostX64\x64
	set LIB=%VCTOOLS%\lib\x64;%WINSDK%\Lib\%WINSDKVER%\ucrt\x64;%WINSDK%\Lib\%WINSDKVER%\um\x64;%CD%\platform\lib\x64
	
	cl %MAKE_KEY_SOURCE% /link /OUT:%OUTDIR%\x64\%MAKE_KEY_OUT% %RESDIR%\make_key.res
	cl %PKG_DEC_SOURCE% /link /OUT:%OUTDIR%\x64\%PKG_DEC_OUT% %RESDIR%\pkg_dec.res

endlocal

echo Compressing output

upx -9 %OUTDIR%\x86\*.exe %OUTDIR%\x64\*.exe

cd %OUTDIR%

endlocal
