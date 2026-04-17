@ECHO OFF
REM This script turns off warnings for unsigned RDP files when attempting to connect to remote
REM hosts. These warnings were introduced with the latest Windows 10 (KB5082200) and Windows
REM 11 (KB5083769/KB5082052) updates and can cause convenience issues when working with RDP
REM sessions.

REM As this modifies security preferences in a Windows component, you need to be sure that
REM the hosts you connect to on your day-to-day basis are not malicious. All in all, any
REM "security" feature pales in comparison to common sense.

REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client" /F /V RedirectionWarningDialogVersion /T REG_DWORD /D 1
REG ADD "HKCU\Software\Microsoft\Terminal Server Client" /F /V RdpLaunchConsentAccepted /T REG_DWORD /D 1