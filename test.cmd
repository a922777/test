@echo off

echo.
echo Starting Microsoft Defender for Endpoint offboarding process...
echo.

set errorCode=0
set lastError=0
set "troubleshootInfo=For more information, visit: https://go.microsoft.com/fwlink/p/?linkid=822807"
set "errorDescription="

echo Testing administrator privileges

%windir%\System32\net.exe session >NUL 2>&1
if %ERRORLEVEL% NEQ 0 (
	@echo Script is running with insufficient privileges. Please run with administrator privileges> %WINDIR%\temp\senseTmp.txt
	set errorCode=65
 set lastError=%ERRORLEVEL%
	GOTO ERROR
)

echo Script is running with sufficient privileges
echo.
echo Performing offboarding operations
echo.

IF [%PROCESSOR_ARCHITEW6432%] EQU [] (
  set powershellPath=%windir%\System32\WindowsPowerShell\v1.0\powershell.exe
) ELSE (
  set powershellPath=%windir%\SysNative\WindowsPowerShell\v1.0\powershell.exe
)

%windir%\System32\reg.exe query "HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" /v OrgId >NUL 2>&1
if %ERRORLEVEL% NEQ 0 (
    GOTO AFTER_ORG_EQUALITY_CHECK
)
%windir%\System32\reg.exe query "HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status" /v OrgId | %windir%\System32\find.exe /i "7a2d111f-ff30-4d89-8410-09f890bb885e" >NUL 2>&1
if %ERRORLEVEL% NEQ 0 (  
    set "errorDescription=Offboarding script for org 7a2d111f-ff30-4d89-8410-09f890bb885e. Machine is onboarded to a different org."
    set errorCode=70
    set lastError=%ERRORLEVEL%
    GOTO ERROR
)
:AFTER_ORG_EQUALITY_CHECK

%windir%\System32\reg.exe query "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v OnboardingInfo /reg:64 > %WINDIR%\temp\senseTmp.txt 2>&1
if %ERRORLEVEL% EQU 0 (  
    %windir%\System32\reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v OnboardingInfo /f > %WINDIR%\temp\senseTmp.txt 2>&1
    if %ERRORLEVEL% NEQ 0 (
        set "errorDescription=Unable to delete previous onboarding information from registry."
        set errorCode=5
        set lastError=%ERRORLEVEL%
        GOTO ERROR
    )
)

%windir%\System32\reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection" /v 696C1FA1-4030-4FA4-8713-FAF9B2EA7C0A /t REG_SZ /f /d "{\"body\":\"{\\\"orgIds\\\":[\\\"7a2d111f-ff30-4d89-8410-09f890bb885e\\\"],\\\"orgId\\\":\\\"7a2d111f-ff30-4d89-8410-09f890bb885e\\\",\\\"expirationTimestamp\\\":133801094169602684,\\\"version\\\":\\\"1.7\\\",\\\"epoch\\\":0}\",\"sig\":\"6O9VScyyf7U4rt8HeiIttLxDCvHP1jdpnOZ0Ryg99xy8/q4WAV+eaoGxXbeW0F4wfkyF6+T5C16a5dH6mz5/EDtN/n5Lmgr+jF4zcpHzOBUuYxo9XfnhRvUafmr0M7CIDHK/cOy8mmPPSjJLzai6nlEGtphA7XuyO+GjjtEXQuh3Tj6uMIm0yOCmcCcBPBXDmeDjztVoVtOsTeOIRirg0PUx3oZ2tqy3Wc5Q6xu5OZ7XTUfwX8psUsGGjaoH4bVFGNeUhX9dJr6V/NZhh96xuwk+yzuhYx51xwN9f/gjDS197yZY7I7RAjwJKHkcQ6pTi8b6tSVdy5IN5mIh4XTVoQ==\",\"sha256sig\":\"6O9VScyyf7U4rt8HeiIttLxDCvHP1jdpnOZ0Ryg99xy8/q4WAV+eaoGxXbeW0F4wfkyF6+T5C16a5dH6mz5/EDtN/n5Lmgr+jF4zcpHzOBUuYxo9XfnhRvUafmr0M7CIDHK/cOy8mmPPSjJLzai6nlEGtphA7XuyO+GjjtEXQuh3Tj6uMIm0yOCmcCcBPBXDmeDjztVoVtOsTeOIRirg0PUx3oZ2tqy3Wc5Q6xu5OZ7XTUfwX8psUsGGjaoH4bVFGNeUhX9dJr6V/NZhh96xuwk+yzuhYx51xwN9f/gjDS197yZY7I7RAjwJKHkcQ6pTi8b6tSVdy5IN5mIh4XTVoQ==\",\"cert\":\"MIIFgzCCA2ugAwIBAgITMwAAAwiuH9Ak1Zb1UAAAAAADCDANBgkqhkiG9w0BAQsFADB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgU2VjdXJlIFNlcnZlciBDQSAyMDExMB4XDTI0MDgyMjIwMDYwOVoXDTI1MDgyMjIwMDYwOVowHjEcMBoGA1UEAxMTU2V2aWxsZS5XaW5kb3dzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK5GSnNoBWBUybDN/NOY+j+X4jpWFU84ZKKhoLD3JX1vcDBKId/o0xOoKVMIqcDGmdsX6Fjit2XssI9wHXvKiJdk/v9SQhJYhG3tFoip9+RmK+DPn3lMKDJx6KHhd/AIlMmp+4Ma433+BmDgMAIvbZDm1xRH4t9SwKlvBBwoQEs4zR0Nbz/aEkL7rD1CHIjIt++hGUQ4VRLnS4RUVXwIuFzvKiBnAR3WSbW0vVr5nU6al/WSinxJ+sLglC1aWWLO3EAGHrN4Ohnm5JK7lqEmbNyv7W6KOyFqnKfiDrk/DsUD0SJycoPNleRnJRTfbb6Rfmpbyr+bOt8yL27YF+crC/0CAwEAAaOCAVgwggFUMA4GA1UdDwEB/wQEAwIFIDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAeBgNVHREEFzAVghNTZXZpbGxlLldpbmRvd3MuY29tMB0GA1UdDgQWBBQC/j4kVANjV6pF/RIxeCyCfnEKnDAfBgNVHSMEGDAWgBQ2VollSctbmy88rEIWUE2RuTPXkTBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNTZWNTZXJDQTIwMTFfMjAxMS0xMC0xOC5jcmwwYAYIKwYBBQUHAQEEVDBSMFAGCCsGAQUFBzAChkRodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY1NlY1NlckNBMjAxMV8yMDExLTEwLTE4LmNydDANBgkqhkiG9w0BAQsFAAOCAgEAQy6ejw037hwXvDPZF1WzHp/K0XxSHqr2WpixK3X3DHLuvcWaZJR8PhrsQGnjt+4epxrPaGdYgbj7TRLkFeKtUKiQIVfG7wbAXahHcknqhRkrI0LvWTfmLZtc4I2YXdEuKOnRoRIcbOT9NKBvc7N1jqweFPX7/6K4iztP9fyPhrwIHl544uOSRcrTahpO80Bmpz8n/WEVNQDc+ie+LI78adJh+eoiGzCgXSNhc8QbTKMZXIhzRIIf1fRKkAQxbdsjb/6kQ1hQ0u5RCd/eFCWODuCfpOAevJkn0rHmEzutbbFps/QdWwLyIj1HE+qTv5dNpYUx0oEGYtc83EIbGFZZyfrB6iDQvainmVp82La+Ahtw4+guVBLTSE7HKudob78WHX4WKBzJBKWUBlHM/lm67Qus28oU144qFMtsOg/rfN3J1J1ydT0GfulGJ8MR0+qJ9pk6ojv0W+F4mwuqkMWQuNAH9BL+5NkghtwBL0BwHpNyFtXzXiNf6s+cYuKGQsS4/ku4eczk/NRWryfXGjGM23zrpIsLkr5DCer34gjdTwn2TmQbWt+65pYyCpFc53v3ejCyTLz13O6JOFuXkL4K9QRqak9xtiGZik6EgTzKE4Ve6SIRFluxleV4UQ3XdzLb+903YD2Ke57PCpBHq/x35xcn+DzHVU3S2C/i43wUeKo=\",\"chain\":[\"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\"]}" > %WINDIR%\temp\senseTmp.txt 2>&1
if %ERRORLEVEL% NEQ 0 (
   set "errorDescription=Unable to write offboarding information to registry."
   set errorCode=10
   set lastError=%ERRORLEVEL%
   GOTO ERROR
)

set /a counter=0

:SENSE_STOPPED_WAIT
%windir%\System32\sc.exe query "SENSE" | %windir%\System32\find.exe /i "STOPPED" >NUL 2>&1
if %ERRORLEVEL% NEQ 0 (
	IF %counter% EQU 10 (
		@echo Microsoft Defender for Endpoint Service failed to stop running!> %WINDIR%\temp\senseTmp.txt
		set errorCode=15
     set lastError=%ERRORLEVEL%
		GOTO ERROR
	)

	set /a counter=%counter%+1
	%windir%\System32\timeout.exe 10 >NUL 2>&1

	GOTO :SENSE_STOPPED_WAIT
)

set "successOutput=Successfully offboarded machine from Microsoft Defender for Endpoint"
%powershellPath% -ExecutionPolicy Bypass -NoProfile -Command "Add-Type 'using System; using System.Diagnostics; using System.Diagnostics.Tracing; namespace Sense { [EventData(Name = \"Offboarding\")]public struct Offboarding{public string Message { get; set; }} public class Trace {public static EventSourceOptions TelemetryCriticalOption = new EventSourceOptions(){Level = EventLevel.Informational, Keywords = (EventKeywords)0x0000200000000000, Tags = (EventTags)0x0200000}; public void WriteOffboardingMessage(string message){es.Write(\"OffboardingScript\", TelemetryCriticalOption, new Offboarding {Message = message});} private static readonly string[] telemetryTraits = { \"ETW_GROUP\", \"{5ECB0BAC-B930-47F5-A8A4-E8253529EDB7}\" }; private EventSource es = new EventSource(\"Microsoft.Windows.Sense.Client.Management\",EventSourceSettings.EtwSelfDescribingEventFormat,telemetryTraits);}}'; $logger = New-Object -TypeName Sense.Trace; $logger.WriteOffboardingMessage('%successOutput%')" >NUL 2>&1
echo %successOutput%
echo.
%windir%\System32\eventcreate.exe /l Application /so WDATPOffboarding /t Information /id 20 /d "%successOutput%" >NUL 2>&1

goto EXIT

:ERROR
Set /P errorMsg=<%WINDIR%\temp\senseTmp.txt
set "errorOutput=[Error Id: %errorCode%, Error Level: %lastError%] %errorDescription% Error message: %errorMsg%"
%powershellPath% -ExecutionPolicy Bypass -NoProfile -Command "Add-Type 'using System; using System.Diagnostics; using System.Diagnostics.Tracing; namespace Sense { [EventData(Name = \"Offboarding\")]public struct Offboarding{public string Message { get; set; }} public class Trace {public static EventSourceOptions TelemetryCriticalOption = new EventSourceOptions(){Level = EventLevel.Error, Keywords = (EventKeywords)0x0000200000000000, Tags = (EventTags)0x0200000}; public void WriteOffboardingMessage(string message){es.Write(\"OffboardingScript\", TelemetryCriticalOption, new Offboarding {Message = message});} private static readonly string[] telemetryTraits = { \"ETW_GROUP\", \"{5ECB0BAC-B930-47F5-A8A4-E8253529EDB7}\" }; private EventSource es = new EventSource(\"Microsoft.Windows.Sense.Client.Management\",EventSourceSettings.EtwSelfDescribingEventFormat,telemetryTraits);}}'; $logger = New-Object -TypeName Sense.Trace; $logger.WriteOffboardingMessage('%errorOutput%')" >NUL 2>&1
echo %errorOutput%
echo %troubleshootInfo%
echo.
%windir%\System32\eventcreate.exe /l Application /so WDATPOffboarding /t Error /id %errorCode% /d "%errorOutput%" >NUL 2>&1
goto EXIT

:EXIT
if exist %WINDIR%\temp\senseTmp.txt del %WINDIR%\temp\senseTmp.txt
pause
EXIT /B %errorCode%

