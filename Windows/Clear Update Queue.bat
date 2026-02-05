@ECHO OFF

NET SESSION >NUL 2>&1
IF %ERRORLEVEL% GTR 0 (
	ECHO This script requires administrator privileges.
	PAUSE > NUL
	EXIT /B 1
)

NET STOP wuauserv
NET STOP BITS

DEL "%WINDIR%\SoftwareDistribution\Download" /F /S /Q

NET START BITS
BITSADMIN /RESET /ALLUSERS

NET START wuauserv
wuauclt /detectnow