@echo off
REM Build ps3pupextractor_gui.exe with the .NET Framework compiler (no SDK needed).
set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
"%CSC%" /nologo /optimize+ /target:winexe /out:"%~dp0ps3pupextractor_gui.exe" ^
  /r:System.dll /r:System.Core.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll ^
  "%~dp0Sce.cs" "%~dp0Keys.cs" "%~dp0Explode.cs" "%~dp0Ps3PupExtractorGui.cs"
echo done (exit %ERRORLEVEL%)
