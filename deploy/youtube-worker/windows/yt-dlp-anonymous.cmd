@echo off
setlocal DisableDelayedExpansion
set "TRANSCRIPT_EXTRACTOR=%USERPROFILE%\.openclaw\youtube-transcript-tools\yt-dlp-2026.08.19\yt-dlp.exe"
set "TRANSCRIPT_NODE=%ProgramFiles%\nodejs\node.exe"
if not exist "%TRANSCRIPT_EXTRACTOR%" (
  echo ERROR: pinned transcript extractor is unavailable 1>&2
  exit /b 2
)
if not exist "%TRANSCRIPT_NODE%" (
  echo ERROR: pinned transcript JavaScript runtime is unavailable 1>&2
  exit /b 2
)
if "%~1"=="--worker-preflight" goto preflight
"%TRANSCRIPT_EXTRACTOR%" --ignore-config --no-js-runtimes --js-runtimes "node:%TRANSCRIPT_NODE%" %*
exit /b %ERRORLEVEL%

:preflight
"%TRANSCRIPT_NODE%" --eval "if(Number(process.versions.node.split('.')[0])<22){console.error('ERROR: transcript Node runtime requires version 22 or later');process.exit(2)};console.log('node '+process.version)"
if errorlevel 1 exit /b %ERRORLEVEL%
"%TRANSCRIPT_EXTRACTOR%" --ignore-config --no-js-runtimes --js-runtimes "node:%TRANSCRIPT_NODE%" --version
exit /b %ERRORLEVEL%
